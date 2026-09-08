import re, socket, ipaddress
from datetime import datetime, timezone
import dns.resolver

SUSPICIOUS_TLDS={'xyz','top','click','work','support','gq','tk','cam','zip'}
LOOKALIKE={'micr0soft':'microsoft','paypa1':'paypal','paypaI':'paypal','goog1e':'google','app1e':'apple','amaz0n':'amazon'}

def dns_intel(domain):
    out={'domain':domain,'a':[],'mx':[],'ns':[],'txt':[],'status':'available'}
    for typ,key in [('A','a'),('MX','mx'),('NS','ns'),('TXT','txt')]:
        try:
            ans=dns.resolver.resolve(domain,typ,lifetime=2)
            out[key]=[str(x).rstrip('.') for x in ans][:10]
        except Exception: out[key]=[]
    return out

def domain_intel(domain):
    labels=domain.split('.')
    tld=labels[-1] if labels else ''
    risk=0; reasons=[]
    if tld in SUSPICIOUS_TLDS: risk+=20; reasons.append(f'Uncommon/suspicious TLD .{tld}')
    if re.search(r'\d',domain): risk+=8; reasons.append('Numeric characters suggest possible lookalike naming')
    for k,v in LOOKALIKE.items():
        if k.lower() in domain.lower(): risk+=30; reasons.append(f'Possible brand lookalike: {v}')
    if any(w in domain.lower() for w in ('secure','login','verify','account','billing','payment')):
        risk+=10; reasons.append('Security/transaction keyword in domain')
    dns=dns_intel(domain)
    if not dns['mx'] and not dns['a']:
        risk+=8; reasons.append('No resolvable A/MX record observed')
    return {'domain':domain,'risk_score':min(risk,60),'risk_reasons':reasons,'dns':dns,
            'registrar':'Not available without a WHOIS provider','whois_status':'provider-not-configured'}

def ip_intel(ip):
    r={'ip':ip,'classification':'public','reverse_dns':'Unavailable','hosting_indicator':'unknown','vpn_proxy_indicator':'unknown','tor_indicator':'unknown','blacklist_hits':[]}
    try:
        obj=ipaddress.ip_address(ip)
        if obj.is_private or obj.is_reserved or obj.is_loopback: r['classification']='non-public'
    except: pass
    try: r['reverse_dns']=socket.gethostbyaddr(ip)[0]
    except: pass
    # Safe demo heuristics: no claim of definitive attribution.
    host=(r['reverse_dns'] or '').lower()
    if any(x in host for x in ('cloud','compute','vps','hosting','server')): r['hosting_indicator']='possible-hosting'
    if any(x in host for x in ('tor-exit','tor-relay','torproject','.tor.')) or re.search(r'(?:^|[.-])tor(?:[.-]|$)',host): r['tor_indicator']='possible-tor-exit-node'
    if any(x in host for x in ('vpn','proxy','anonymiz','privacy')): r['vpn_proxy_indicator']='possible-vpn-or-proxy'
    r['reputation']='No external feed configured'
    return r

def campaign_key(a):
    subject=re.sub(r'[^a-z0-9 ]',' ',a.get('subject','').lower())
    subject=re.sub(r'\s+',' ',subject).strip()
    return {'subject_tokens':set(subject.split())-{'urgent','action','required','re','fw','fwd'},'domains':set(a.get('domains',[])),'ips':set(a.get('public_ips',[]))}

def correlate(current, prior):
    matches=[]
    ck=campaign_key(current)
    for p in prior:
        pk=campaign_key(p)
        shared_domains=ck['domains'] & pk['domains']; shared_ips=ck['ips'] & pk['ips']; shared_words=ck['subject_tokens'] & pk['subject_tokens']
        score=(35 if shared_domains else 0)+(35 if shared_ips else 0)+(20 if len(shared_words)>=2 else 0)
        if score>=35: matches.append({'case_id':p.get('id'),'score':score,'shared_domains':sorted(shared_domains),'shared_ips':sorted(shared_ips),'shared_subject_terms':sorted(shared_words)[:10]})
    return sorted(matches,key=lambda x:x['score'],reverse=True)[:10]
