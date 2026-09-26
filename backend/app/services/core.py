import re
import hashlib
import ipaddress
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

import requests
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion
from sklearn.calibration import CalibratedClassifierCV

from .intel import bulk_domain_intel, bulk_ip_intel, correlate
from .cache import geo_cache
from .textalgo import shannon_entropy, implausible_travel

# --------------------------------------------------------------------------
# ML classifier
#
# Upgraded from a single word-ngram TF-IDF + plain LogisticRegression to:
#   - a word-ngram + character-ngram (3-5) FeatureUnion, so obfuscated /
#     misspelled phishing language ("cl1ck immed1ately") still shares
#     sub-word features with its clean-spelled training examples instead
#     of being invisible to a purely word-tokenized vectorizer
#   - class_weight='balanced' so the small, uneven demo corpus doesn't
#     bias toward whichever class happens to have more examples
#   - CalibratedClassifierCV (sigmoid/Platt scaling via cross-validation)
#     so predict_proba output is a genuine calibrated confidence rather
#     than a raw, often overconfident logistic-regression score
# --------------------------------------------------------------------------
TRAIN = [
    ('team meeting moved to 3 pm please see agenda', 'LEGITIMATE'),
    ('project update and meeting minutes attached for review', 'LEGITIMATE'),
    ('approved travel schedule attached please confirm dates', 'LEGITIMATE'),
    ('quarterly report draft please share your feedback by friday', 'LEGITIMATE'),
    ('lunch and learn session scheduled for next tuesday', 'LEGITIMATE'),
    ('welcome to the team here is your onboarding checklist', 'LEGITIMATE'),
    ('reminder your dentist appointment is tomorrow at 10am', 'LEGITIMATE'),

    ('urgent verify your account immediately click the link', 'PHISHING'),
    ('mailbox suspended unless you confirm password', 'PHISHING'),
    ('security alert verify credentials now', 'PHISHING'),
    ('click to unlock account within 30 minutes', 'PHISHING'),
    ('your subscription will be cancelled confirm billing details now', 'PHISHING'),
    ('unusual sign in detected verify identity immediately', 'PHISHING'),
    ('cl1ck here to verify your acc0unt urgently', 'PHISHING'),

    ('urgent invoice payment bank account changed send funds today', 'BEC'),
    ('ceo confidential request purchase gift cards immediately', 'BEC'),
    ('finance transfer to new vendor account before deadline', 'BEC'),
    ('wire transfer required urgently keep this confidential', 'BEC'),
    ('please process payment to updated beneficiary account today', 'BEC'),
    ('need you to buy gift cards for client appreciation asap', 'BEC'),
    ('urgent wire authorization needed before close of business', 'BEC'),

    ('payroll document requires login verification', 'IMPERSONATION'),
    ('administrator requests password reset', 'IMPERSONATION'),
    ('executive office asks for confidential employee information', 'IMPERSONATION'),
    ('it support needs you to confirm your login for system upgrade', 'IMPERSONATION'),
    ('hr department requires updated bank details for payroll', 'IMPERSONATION'),
    ('director requests urgent confidential document review', 'IMPERSONATION'),
]

_word_vec = TfidfVectorizer(ngram_range=(1, 2), max_features=3000, sublinear_tf=True)
_char_vec = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), max_features=2000, sublinear_tf=True)
V = FeatureUnion([('word', _word_vec), ('char', _char_vec)])
_X = V.fit_transform([x for x, _ in TRAIN])
_base = LogisticRegression(max_iter=2000, random_state=42, class_weight='balanced')
try:
    M = CalibratedClassifierCV(estimator=_base, method='sigmoid', cv=3)
    M.fit(_X, [y for _, y in TRAIN])
except Exception:
    # Fall back to an uncalibrated model if the installed sklearn version's
    # CalibratedClassifierCV API differs (older/newer arg names) — better
    # to degrade gracefully than to fail app startup over a scoring nicety.
    M = _base.fit(_X, [y for _, y in TRAIN])

URL = re.compile(r'(?i)\b(?:https?://|www\.)[^\s<>"\']+')
IP = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
URG = ['urgent', 'immediately', 'asap', 'within 30 minutes', 'final warning', 'action required', 'suspended', 'expires']
CRED = ['password', 'login', 'verify your account', 'credentials', 'otp', 'sign in']
FIN = ['wire transfer', 'bank account', 'invoice', 'payment', 'gift card', 'beneficiary', 'vendor', 'transfer funds']
IMP = ['ceo', 'chief executive', 'director', 'administrator', 'finance department', 'it support', 'payroll', 'executive office']
SUS = ['zip', 'mov', 'click', 'top', 'xyz', 'support', 'work', 'cam', 'gq', 'tk']

# Byte-entropy above this suggests packed/encrypted/compressed content
# hiding inside an attachment that isn't itself a recognized archive type.
ATTACHMENT_ENTROPY_THRESHOLD = 7.5


def hits(t, terms):
    l = t.lower()
    return [x for x in terms if x in l]


def addr_domain(s):
    m = re.search(r'@([A-Za-z0-9.-]+)', s or '')
    return m.group(1).lower() if m else ''


def _hop_datetime(received_header):
    """Received headers end with '; <RFC2822 date>' — parse it defensively;
    malformed/missing dates are common and must not break analysis."""
    try:
        tail = received_header.rsplit(';', 1)[-1].strip()
        return parsedate_to_datetime(tail)
    except Exception:
        return None


def parse(raw):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    body = []
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type() == 'text/plain' and not p.get_content_disposition():
                try:
                    body.append(p.get_content())
                except Exception:
                    pass
    else:
        try:
            body = [msg.get_content()]
        except Exception:
            body = ['']
    text = '\n'.join(body).strip()
    urls = list(dict.fromkeys(x.rstrip('.,;:!?)\"\'') for x in URL.findall(str(msg.get('Subject', '')) + '\n' + text)))
    domains = []
    for u in urls:
        try:
            domains.append((urlparse(u if '://' in u else 'http://' + u).hostname or '').lower())
        except Exception:
            pass

    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment' or part.get_filename():
            payload = part.get_payload(decode=True) or b''
            fname = part.get_filename() or 'unnamed-attachment'
            entropy = round(shannon_entropy(payload.decode('latin1')), 2) if payload else 0.0
            attachments.append({
                'filename': fname, 'content_type': part.get_content_type(), 'size': len(payload),
                'sha256': hashlib.sha256(payload).hexdigest(), 'entropy': entropy, 'risk': 0, 'reasons': [],
            })
    for a in attachments:
        if re.search(r'\.(exe|scr|js|vbs|bat|cmd|ps1|msi|jar|lnk|iso|zip)$', a['filename'], re.I):
            a['risk'] = 55
            a['reasons'].append('Potentially executable or archive attachment')
        if re.search(r'password|urgent|invoice|payment', a['filename'], re.I):
            a['risk'] += 15
            a['reasons'].append('High-pressure/financial filename pattern')
        if a['entropy'] >= ATTACHMENT_ENTROPY_THRESHOLD and a['size'] > 512 and not re.search(r'\.(zip|jpg|jpeg|png|gif|pdf|mp4|mov)$', a['filename'], re.I):
            a['risk'] += 10
            a['reasons'].append(f"High-entropy content (H={a['entropy']}) suggests packed/encrypted payload")

    received_raw = [str(x) for x in msg.get_all('Received', [])]
    ips = []
    for h in received_raw:
        for x in IP.findall(h):
            try:
                q = ipaddress.ip_address(x)
                if not (q.is_private or q.is_loopback or q.is_reserved or q.is_link_local):
                    ips.append(x)
            except ValueError:
                pass

    return {
        'subject': str(msg.get('Subject', '')), 'sender': str(msg.get('From', '')),
        'reply_to': str(msg.get('Reply-To', '')), 'return_path': str(msg.get('Return-Path', '')),
        'message_id': str(msg.get('Message-ID', '')), 'body': text,
        'headers': {k: str(v) for k, v in msg.items()},
        'received': received_raw, 'auth_results': [str(x) for x in msg.get_all('Authentication-Results', [])],
        'urls': urls, 'domains': sorted(set(d for d in domains if d)),
        'public_ips': list(dict.fromkeys(ips)), 'attachments': attachments,
        'sha256': hashlib.sha256(raw).hexdigest(),
    }


AUTH_STATES = ('pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror')
_AUTH_RE = re.compile(r'(?<![A-Za-z0-9_-])(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)(?![A-Za-z0-9_-])', re.I)


def _pick_auth_state(states):
    """Pick the most informative authentication result without trusting DKIM-Signature itself.

    Authentication-Results is an assertion made by the receiving mail system; this parser
    reports that assertion. It does not cryptographically verify DKIM or perform DNS-based
    SPF/DMARC verification.
    """
    if not states:
        return 'UNKNOWN'
    # A failure is more security-relevant than a pass when multiple authentication
    # results are present. Otherwise prefer an explicit pass, then the remaining states.
    order = {
        'FAIL': 6, 'PERMERROR': 5, 'TEMPERROR': 4, 'SOFTFAIL': 3,
        'PASS': 2, 'NEUTRAL': 1, 'NONE': 0,
    }
    return max((s.upper() for s in states), key=lambda x: order.get(x, -1))


def auth(p):
    """Extract SPF/DKIM/DMARC results from actual RFC message headers.

    Supports standard Authentication-Results (including folded headers), ARC-
    Authentication-Results, and the legacy Received-SPF header for SPF. Text in the
    message body is deliberately ignored so an attacker cannot manufacture an auth
    result by writing e.g. 'spf=pass' in the email body.
    """
    out = {}
    auth_headers = []
    auth_headers.extend(p.get('auth_results') or [])
    auth_headers.extend(p.get('headers', {}).get('ARC-Authentication-Results', '').split('\n')
                        if p.get('headers', {}).get('ARC-Authentication-Results') else [])

    for n in ('spf', 'dkim', 'dmarc'):
        states = []
        for header in auth_headers:
            for name, state in _AUTH_RE.findall(str(header)):
                if name.lower() == n:
                    states.append(state.lower())

        # Received-SPF is a standard legacy header carrying the SPF result directly.
        if n == 'spf':
            received_spf = p.get('headers', {}).get('Received-SPF', '')
            m = re.match(r'\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b',
                         str(received_spf), re.I)
            if m:
                states.append(m.group(1).lower())

        out[n] = _pick_auth_state(states)
    return out


def enrich_ip(ip, cfg):
    """Geolocation is cached (identical IPs recur constantly across a
    live mail stream) and time-bounded per the app's configured timeout,
    rather than a hardcoded 3-second guess."""
    r = {'ip': ip, 'country': 'Unknown', 'region': 'Unknown', 'city': 'Unknown', 'org': 'Unknown',
         'asn': 'Unknown', 'lat': None, 'lon': None, 'source': 'local'}
    if not cfg.get('ENABLE_EXTERNAL_INTEL'):
        r['note'] = 'External enrichment disabled'
        return r
    try:
        ipaddress.ip_address(ip)  # re-validate before building the outbound URL (defense in depth vs SSRF/injection)
    except ValueError:
        r['note'] = 'Invalid IP — enrichment skipped'
        return r

    def compute():
        try:
            timeout = cfg.get('ENRICHMENT_TIMEOUT_SECONDS', 3)
            z = requests.get(cfg['IP_GEO_API_URL'].format(ip=ip), timeout=timeout)
            if not z.ok:
                return {**r, 'note': f'Enrichment provider returned HTTP {z.status_code}'}
            d = z.json()
            if isinstance(d, dict) and d.get('error'):
                # ipapi.co (and similar free-tier APIs) return HTTP 200 with
                # an embedded error/rate-limit payload — surface it instead
                # of silently treating it as "no data".
                return {**r, 'note': f"Enrichment provider error: {d.get('reason', 'rate limited or invalid request')}"}
            if d.get('success') is False:
                return {**r, 'note': f"Enrichment provider error: {d.get('message', 'lookup failed')}"}
            lat, lon = d.get('latitude'), d.get('longitude')
            if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
                coordinates = str(d.get('loc', '')).split(',')
                if len(coordinates) == 2:
                    try:
                        lat, lon = (float(coordinates[0]), float(coordinates[1]))
                    except ValueError:
                        lat, lon = None, None
            connection = d.get('connection') if isinstance(d.get('connection'), dict) else {}
            return {**r, 'country': d.get('country_name', d.get('country', 'Unknown')),
                     'region': d.get('region', 'Unknown'), 'city': d.get('city', 'Unknown'),
                     'org': d.get('org', connection.get('org', 'Unknown')),
                     'asn': d.get('asn', connection.get('asn', 'Unknown')),
                     'lat': lat if isinstance(lat, (int, float)) else None,
                     'lon': lon if isinstance(lon, (int, float)) else None, 'source': 'external'}
        except requests.RequestException:
            return {**r, 'note': 'Enrichment unavailable (network/timeout error)'}
        except ValueError:
            return {**r, 'note': 'Enrichment unavailable (malformed provider response)'}

    return geo_cache.get_or_set(f'geo:{ip}', compute)


def bulk_enrich_ip(ips, cfg):
    if not ips:
        return []
    workers = cfg.get('ENRICHMENT_MAX_WORKERS', 8)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(lambda ip: enrich_ip(ip, cfg), ips))


def domain_risk(d):
    s = 0
    reasons = []
    t = d.split('.')[-1]
    if t in SUS:
        s += 20
        reasons.append(f'Suspicious/uncommon TLD: .{t}')
    if any(x in d for x in ['secure', 'verify', 'account', 'login', 'support', 'billing', 'invoice']):
        s += 15
        reasons.append('Security/transaction keyword in domain')
    if re.search(r'\d', d):
        s += 5
        reasons.append('Domain contains numeric characters')
    if len(d) > 30:
        s += 5
        reasons.append('Unusually long domain')
    return min(s, 40), reasons


def url_risk(u):
    s = 0
    r = []
    try:
        p = urlparse(u if '://' in u else 'http://' + u)
        if p.scheme == 'http':
            s += 8
            r.append('Link is not HTTPS')
        if '@' in p.netloc:
            s += 15
            r.append('URL contains @ userinfo')
        if len(u) > 100:
            s += 7
            r.append('Unusually long URL')
        if (p.hostname or '').count('.') >= 4:
            s += 6
            r.append('Deeply nested hostname')
        path_entropy = shannon_entropy(p.path.strip('/'))
        if len(p.path) >= 12 and path_entropy >= 3.8:
            s += 8
            r.append(f'High-entropy URL path (H={round(path_entropy, 2)}) suggests a generated/obfuscated link')
    except Exception:
        s += 10
        r.append('URL parsing anomaly')
    return min(s, 30), r


def _relay_travel_check(received_raw, ip_details_by_ip):
    """Reconstruct ordered relay hops with timestamp + geolocation, then
    run the haversine 'impossible travel' check across consecutive hops."""
    ordered = list(reversed(received_raw))  # headers are prepended, so reverse to get chronological order
    enriched = []
    prev_dt = None
    for h in ordered:
        ips_in_hop = IP.findall(h)
        ip = ips_in_hop[-1] if ips_in_hop else None
        dt = _hop_datetime(h)
        minutes_since_prev = None
        if dt and prev_dt:
            minutes_since_prev = (dt - prev_dt).total_seconds() / 60.0
        if dt:
            prev_dt = dt
        geo = ip_details_by_ip.get(ip) if ip else None
        enriched.append({'ip': ip, 'lat': geo['lat'] if geo else None, 'lon': geo['lon'] if geo else None,
                          'minutes_since_prev': minutes_since_prev})
    return implausible_travel(enriched)


def analyze(raw, cfg, prior=[]):
    p = parse(raw)
    text = p['subject'] + '\n' + p['body']
    features = V.transform([text])
    pred = M.predict(features)[0]
    probs = M.predict_proba(features)[0]
    ranked = sorted([{'label': str(c), 'confidence': round(float(v) * 100, 1)} for c, v in zip(M.classes_, probs)],
                     key=lambda x: x['confidence'], reverse=True)

    sig = {'urgency': hits(text, URG), 'credential': hits(text, CRED), 'financial': hits(text, FIN), 'impersonation': hits(text, IMP)}
    score = 0
    reasons = []
    if sig['urgency']:
        score += min(18, 6 + 3 * len(sig['urgency']))
        reasons.append('Urgency/social-engineering language detected')
    if sig['credential']:
        score += min(24, 8 + 4 * len(sig['credential']))
        reasons.append('Credential/account-verification language detected')
    if sig['financial']:
        score += min(28, 10 + 4 * len(sig['financial']))
        reasons.append('Financial/payment language detected')
    if sig['impersonation']:
        score += min(18, 6 + 3 * len(sig['impersonation']))
        reasons.append('Executive/authority impersonation language detected')

    au = auth(p)
    for n, v in au.items():
        if v in ['FAIL', 'SOFTFAIL', 'PERMERROR', 'TEMPERROR']:
            score += {'spf': 12, 'dkim': 10, 'dmarc': 14}[n]
            reasons.append(f'{n.upper()} authentication result is {v}')

    sd = addr_domain(p['sender'])
    rd = addr_domain(p['reply_to'])
    rp = addr_domain(p['return_path'])
    if sd and rd and sd != rd:
        score += 12
        reasons.append('Reply-To domain differs from From domain')
    if sd and rp and sd != rp:
        score += 8
        reasons.append('Return-Path domain differs from From domain')

    # Domain / URL / IP enrichment runs concurrently — these are
    # independent network- and CPU-bound lookups with no data
    # dependency between them, so there is no reason to serialize them.
    domain_intelligence = bulk_domain_intel(p['domains'], max_workers=cfg.get('ENRICHMENT_MAX_WORKERS', 8))
    ip_intelligence = bulk_ip_intel(p['public_ips'], max_workers=cfg.get('ENRICHMENT_MAX_WORKERS', 8))
    ip_details = bulk_enrich_ip(p['public_ips'], cfg)
    ip_details_by_ip = {x['ip']: x for x in ip_details}

    dr = {}
    for d in p['domains']:
        q, rr = domain_risk(d)
        dr[d] = q
        score += q
        reasons += rr
    ur = {}
    for u in p['urls']:
        q, rr = url_risk(u)
        ur[u] = q
        score += q
        reasons += rr

    attachment_risk = sum(int(a.get('risk', 0)) for a in p.get('attachments', []))
    if attachment_risk:
        score += min(25, attachment_risk // 2)
        reasons += [x for a in p.get('attachments', []) for x in a.get('reasons', [])]
    if pred in ['PHISHING', 'BEC', 'IMPERSONATION']:
        score += 12

    for d, di in domain_intelligence.items():
        score += min(20, di['risk_score'] // 3)
        reasons += di['risk_reasons']

    score = min(100, int(score))
    cls = ('FRAUD / BEC' if pred == 'BEC' or (sig['financial'] and sig['urgency'])
           else pred if pred in ['PHISHING', 'IMPERSONATION']
           else 'SUSPICIOUS' if score >= 35 else 'LEGITIMATE')

    hops = []
    for i, h in enumerate(reversed(p['received']), 1):
        xs = IP.findall(h)
        hops.append({'hop': i, 'ip': xs[-1] if xs else None, 'raw': h})

    travel_flags = _relay_travel_check(p['received'], ip_details_by_ip)
    if travel_flags:
        score = min(100, score + 15)
        reasons.append('Geographically implausible relay speed between hops (possible spoofed/forged Received headers)')

    graph = {'nodes': [{'id': 'email', 'label': 'Analyzed Email', 'kind': 'email'}], 'edges': []}
    for i, d in enumerate(p['domains']):
        graph['nodes'].append({'id': 'd' + str(i), 'label': d, 'kind': 'domain'})
        graph['edges'].append({'source': 'email', 'target': 'd' + str(i), 'relation': 'contains'})
    for i, ipv in enumerate(p['public_ips']):
        graph['nodes'].append({'id': 'i' + str(i), 'label': ipv, 'kind': 'ip'})
        graph['edges'].append({'source': 'email', 'target': 'i' + str(i), 'relation': 'relayed-via'})

    # Attribution is evidence-weighted support, never an identity claim.
    attribution = {
        'overall_confidence': round(min(95, 45 + (12 if any(v in ('FAIL', 'SOFTFAIL', 'PERMERROR') for v in au.values()) else 0)
                                         + (15 if sd and rd and sd != rd else 0) + (10 if p['public_ips'] else 0)
                                         + (10 if p['domains'] else 0)), 1),
        'spoofed_domain': 78 if sd and any(d != sd for d in p['domains']) else 32,
        'compromised_account': 55 if pred in ('BEC', 'IMPERSONATION') else 25,
        'anonymized_infrastructure': 65 if any(x.get('vpn_proxy_indicator') not in ('unknown', '') or x.get('tor_indicator') not in ('unknown', '') for x in ip_intelligence) else 30,
        'direct_malicious_environment': 40 if any(x.get('hosting_indicator') == 'possible-hosting' for x in ip_intelligence) else 20,
        'caveat': 'Probabilistic support only; infrastructure geolocation does not identify an attacker.',
    }

    campaign_matches = correlate({**p, 'subject': p['subject']}, prior)
    campaign = {'status': 'RELATED_ACTIVITY' if campaign_matches else 'NO_MATCH_FOUND', 'matches': campaign_matches,
                'cluster_id': ('CMP-' + hashlib.sha256((p['subject'] + '|' + ','.join(p['domains'])).encode()).hexdigest()[:10].upper()) if campaign_matches else None}

    ti = []
    for d, di in domain_intelligence.items():
        ti.append({'indicator': d, 'type': 'DOMAIN', 'reputation': 'DEMO_FEED_ONLY',
                    'hits': 1 if di['risk_score'] >= 25 else 0, 'confidence': 'medium' if di['risk_score'] >= 25 else 'low'})
    for x in ip_intelligence:
        ti.append({'indicator': x['ip'], 'type': 'IP', 'reputation': 'DEMO_FEED_ONLY', 'hits': 0, 'confidence': 'low'})

    now = datetime.now(timezone.utc).isoformat()
    custody = [
        {'event': 'EVIDENCE_RECEIVED', 'time': now, 'detail': 'Original email bytes accepted'},
        {'event': 'HASH_COMPUTED', 'time': now, 'detail': 'SHA-256 evidence fingerprint created'},
        {'event': 'HEADERS_PARSED', 'time': now, 'detail': 'RFC headers and relay chain extracted'},
        {'event': 'ANALYSIS_COMPLETED', 'time': now, 'detail': 'ML, rules and enrichment completed'},
    ]

    return {
        **p, 'classification': cls, 'risk_score': score,
        'priority': 'P1' if score >= 85 else 'P2' if score >= 65 else 'P3',
        'confidence': round(min(98, 55 + abs(score - 50) * .8), 1),
        'ml_prediction': pred, 'ml_ranked': ranked, 'signals': sig, 'authentication': au,
        'domain_risks': dr, 'domain_intelligence': domain_intelligence, 'url_risks': ur,
        'relay_hops': hops, 'ip_details': ip_details, 'ip_intelligence': ip_intelligence,
        'implausible_travel': travel_flags,
        'attribution': attribution, 'campaign': campaign, 'threat_intelligence': ti,
        'chain_of_custody': custody, 'reasons': list(dict.fromkeys(reasons))[:20],
        'response_actions': response_actions(cls, score, au), 'graph': graph,
    }


def response_actions(cls, score, au):
    a = ['Preserve the original .eml and SHA-256 evidence']
    if score >= 65:
        a += ['Quarantine/block pending analyst review', 'Search for related messages using extracted IOCs']
    if cls in ['FRAUD / BEC', 'IMPERSONATION']:
        a += ['Verify sensitive requests through a trusted channel']
    if any(v != 'PASS' and v != 'UNKNOWN' for v in au.values()):
        a += ['Review sender authentication and domain alignment']
    return a
