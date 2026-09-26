import re
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

import dns.resolver

from .cache import dns_cache, reverse_dns_cache
from .textalgo import typosquat_match, shannon_entropy

SUSPICIOUS_TLDS = {'xyz', 'top', 'click', 'work', 'support', 'gq', 'tk', 'cam', 'zip'}

# High entropy in the registrable label (excluding TLD) is a strong signal
# for algorithmically-generated / randomized hostnames used by phishing
# kits and malware C2 (DGA domains). Ordinary dictionary words/brand names
# sit well below this; random alphanumeric strings sit well above it.
ENTROPY_FLAG_THRESHOLD = 3.6


def _resolve_one(domain, typ):
    try:
        ans = dns.resolver.resolve(domain, typ, lifetime=2)
        return typ, [str(x).rstrip('.') for x in ans][:10]
    except Exception:
        return typ, []


def dns_intel(domain):
    """DNS lookups are network I/O — cache results and resolve the four
    record types concurrently instead of four sequential round trips."""
    def compute():
        out = {'domain': domain, 'a': [], 'mx': [], 'ns': [], 'txt': [], 'status': 'available'}
        with ThreadPoolExecutor(max_workers=4) as ex:
            for typ, key in ex.map(lambda tk: _resolve_one(domain, tk[0]),
                                    [('A', 'a'), ('MX', 'mx'), ('NS', 'ns'), ('TXT', 'txt')]):
                out[{'A': 'a', 'MX': 'mx', 'NS': 'ns', 'TXT': 'txt'}[typ]] = key
        return out
    return dns_cache.get_or_set(f'dns:{domain}', compute)


def domain_intel(domain):
    labels = domain.split('.')
    tld = labels[-1] if labels else ''
    risk = 0
    reasons = []

    if tld in SUSPICIOUS_TLDS:
        risk += 20
        reasons.append(f'Uncommon/suspicious TLD .{tld}')
    if re.search(r'\d', domain):
        risk += 8
        reasons.append('Numeric characters suggest possible lookalike naming')

    # Algorithmic brand-impersonation check (edit distance + homoglyph
    # normalization) replaces a fixed lookalike-spelling dictionary, so
    # novel misspellings ("micros0ft-support", "paypaII-secure", ...) are
    # caught without needing to be enumerated in advance.
    squat = typosquat_match(domain)
    if squat:
        risk += 30
        via = ' via homoglyph substitution' if squat.get('via_homoglyph') else ''
        reasons.append(f"Possible brand lookalike of '{squat['brand']}' (edit distance {squat['distance']}{via})")

    if any(w in domain.lower() for w in ('secure', 'login', 'verify', 'account', 'billing', 'payment')):
        risk += 10
        reasons.append('Security/transaction keyword in domain')

    base_label = labels[0] if labels else domain
    entropy = round(shannon_entropy(base_label), 2)
    if len(base_label) >= 8 and entropy >= ENTROPY_FLAG_THRESHOLD:
        risk += 15
        reasons.append(f'High-entropy hostname label (H={entropy}) suggests algorithmic generation')

    dns_rec = dns_intel(domain)
    if not dns_rec['mx'] and not dns_rec['a']:
        risk += 8
        reasons.append('No resolvable A/MX record observed')

    return {
        'domain': domain, 'risk_score': min(risk, 60), 'risk_reasons': reasons, 'dns': dns_rec,
        'entropy': entropy, 'typosquat': squat,
        'registrar': 'Not available without a WHOIS provider', 'whois_status': 'provider-not-configured',
    }


def _reverse_dns(ip):
    def compute():
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
    return reverse_dns_cache.get_or_set(f'rdns:{ip}', compute)


def ip_intel(ip):
    r = {'ip': ip, 'classification': 'public', 'reverse_dns': 'Unavailable', 'hosting_indicator': 'unknown',
         'vpn_proxy_indicator': 'unknown', 'tor_indicator': 'unknown', 'blacklist_hits': []}
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private or obj.is_reserved or obj.is_loopback:
            r['classification'] = 'non-public'
    except ValueError:
        r['classification'] = 'invalid'
        r['reputation'] = 'Invalid IP literal — skipped'
        return r

    rdns = _reverse_dns(ip)
    if rdns:
        r['reverse_dns'] = rdns

    # Safe demo heuristics: no claim of definitive attribution.
    host = (r['reverse_dns'] or '').lower()
    if any(x in host for x in ('cloud', 'compute', 'vps', 'hosting', 'server')):
        r['hosting_indicator'] = 'possible-hosting'
    if any(x in host for x in ('tor-exit', 'tor-relay', 'torproject', '.tor.')) or re.search(r'(?:^|[.-])tor(?:[.-]|$)', host):
        r['tor_indicator'] = 'possible-tor-exit-node'
    if any(x in host for x in ('vpn', 'proxy', 'anonymiz', 'privacy')):
        r['vpn_proxy_indicator'] = 'possible-vpn-or-proxy'
    r['reputation'] = 'No external feed configured'
    return r


def bulk_ip_intel(ips, max_workers=8):
    """Run ip_intel (reverse-DNS bound) concurrently — the original
    sequential version paid a full DNS round-trip per IP even though
    lookups are independent and embarrassingly parallel."""
    if not ips:
        return []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        return list(ex.map(ip_intel, ips))


def bulk_domain_intel(domains, max_workers=8):
    if not domains:
        return {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        results = ex.map(domain_intel, domains)
    return dict(zip(domains, results))


def campaign_key(a):
    subject = re.sub(r'[^a-z0-9 ]', ' ', a.get('subject', '').lower())
    subject = re.sub(r'\s+', ' ', subject).strip()
    return {'subject_tokens': set(subject.split()) - {'urgent', 'action', 'required', 're', 'fw', 'fwd'},
            'domains': set(a.get('domains', [])), 'ips': set(a.get('public_ips', []))}


def correlate(current, prior):
    matches = []
    ck = campaign_key(current)
    for p in prior:
        pk = campaign_key(p)
        shared_domains = ck['domains'] & pk['domains']
        shared_ips = ck['ips'] & pk['ips']
        shared_words = ck['subject_tokens'] & pk['subject_tokens']
        score = (35 if shared_domains else 0) + (35 if shared_ips else 0) + (20 if len(shared_words) >= 2 else 0)
        if score >= 35:
            matches.append({'case_id': p.get('id'), 'score': score, 'shared_domains': sorted(shared_domains),
                             'shared_ips': sorted(shared_ips), 'shared_subject_terms': sorted(shared_words)[:10]})
    return sorted(matches, key=lambda x: x['score'], reverse=True)[:10]
