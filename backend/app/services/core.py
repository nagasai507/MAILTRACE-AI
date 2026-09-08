import re,hashlib,ipaddress
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import requests,dns.resolver
from .intel import domain_intel, ip_intel, correlate

TRAIN=[
('team meeting moved to 3 pm please see agenda','LEGITIMATE'),('project update and meeting minutes','LEGITIMATE'),('approved travel schedule attached','LEGITIMATE'),
('urgent verify your account immediately click the link','PHISHING'),('mailbox suspended unless you confirm password','PHISHING'),('security alert verify credentials now','PHISHING'),('click to unlock account within 30 minutes','PHISHING'),
('urgent invoice payment bank account changed send funds today','BEC'),('ceo confidential request purchase gift cards immediately','BEC'),('finance transfer to new vendor account before deadline','BEC'),('wire transfer required urgently keep this confidential','BEC'),
('payroll document requires login verification','IMPERSONATION'),('administrator requests password reset','IMPERSONATION'),('executive office asks for confidential employee information','IMPERSONATION')]
V=TfidfVectorizer(ngram_range=(1,2),max_features=2000); X=V.fit_transform([x for x,_ in TRAIN]); M=LogisticRegression(max_iter=1200,random_state=42).fit(X,[y for _,y in TRAIN])
URL=re.compile(r'(?i)\b(?:https?://|www\.)[^\s<>"\']+')
IP=re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
URG=['urgent','immediately','asap','within 30 minutes','final warning','action required','suspended','expires']
CRED=['password','login','verify your account','credentials','otp','sign in']
FIN=['wire transfer','bank account','invoice','payment','gift card','beneficiary','vendor','transfer funds']
IMP=['ceo','chief executive','director','administrator','finance department','it support','payroll','executive office']
SUS=['zip','mov','click','top','xyz','support','work','cam','gq','tk']

def hits(t,terms):
 l=t.lower(); return [x for x in terms if x in l]
def addr_domain(s):
 m=re.search(r'@([A-Za-z0-9.-]+)',s or ''); return m.group(1).lower() if m else ''
def parse(raw):
 msg=BytesParser(policy=policy.default).parsebytes(raw); body=[]
 if msg.is_multipart():
  for p in msg.walk():
   if p.get_content_type()=='text/plain' and not p.get_content_disposition():
    try: body.append(p.get_content())
    except: pass
 else:
  try: body=[msg.get_content()]
  except: body=['']
 text='\n'.join(body).strip(); urls=list(dict.fromkeys(x.rstrip('.,;:!?)\"\'') for x in URL.findall(str(msg.get('Subject',''))+'\n'+text)))
 domains=[]
 for u in urls:
  try: domains.append((urlparse(u if '://' in u else 'http://'+u).hostname or '').lower())
  except: pass
 attachments=[]
 for part in msg.walk():
  if part.get_content_disposition()=='attachment' or part.get_filename():
   payload=part.get_payload(decode=True) or b''
   fname=part.get_filename() or 'unnamed-attachment'
   attachments.append({'filename':fname,'content_type':part.get_content_type(),'size':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),'risk':0,'reasons':[]})
 for a in attachments:
  if re.search(r'\.(exe|scr|js|vbs|bat|cmd|ps1|msi|jar|lnk|iso|zip)$',a['filename'],re.I): a['risk']=55;a['reasons'].append('Potentially executable or archive attachment')
  if re.search(r'password|urgent|invoice|payment',a['filename'],re.I): a['risk']+=15;a['reasons'].append('High-pressure/financial filename pattern')
 ips=[]
 for h in msg.get_all('Received',[]):
  for x in IP.findall(str(h)):
   try:
    q=ipaddress.ip_address(x)
    if not(q.is_private or q.is_loopback or q.is_reserved or q.is_link_local): ips.append(x)
   except: pass
 return {'subject':str(msg.get('Subject','')),'sender':str(msg.get('From','')),'reply_to':str(msg.get('Reply-To','')),'return_path':str(msg.get('Return-Path','')),'message_id':str(msg.get('Message-ID','')),'body':text,'headers':{k:str(v) for k,v in msg.items()},'received':[str(x) for x in msg.get_all('Received',[])],'auth_results':[str(x) for x in msg.get_all('Authentication-Results',[])],'urls':urls,'domains':sorted(set(d for d in domains if d)),'public_ips':list(dict.fromkeys(ips)),'attachments':attachments,'sha256':hashlib.sha256(raw).hexdigest()}
def auth(p):
 t='\n'.join(p['auth_results']+list(p['headers'].values())).lower(); out={}
 for n in ['spf','dkim','dmarc']:
  m=re.search(rf'\b{n}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b',t); out[n]=m.group(1).upper() if m else 'UNKNOWN'
 return out
def enrich_ip(ip,cfg):
 r={'ip':ip,'country':'Unknown','region':'Unknown','city':'Unknown','org':'Unknown','asn':'Unknown','lat':None,'lon':None,'source':'local'}
 if not cfg.get('ENABLE_EXTERNAL_INTEL'): r['note']='External enrichment disabled'; return r
 try:
  z=requests.get(cfg['IP_GEO_API_URL'].format(ip=ip),timeout=3); d=z.json() if z.ok else {}
  lat=d.get('latitude'); lon=d.get('longitude')
  r.update(country=d.get('country_name',d.get('country','Unknown')),region=d.get('region','Unknown'),city=d.get('city','Unknown'),org=d.get('org','Unknown'),asn=d.get('asn','Unknown'),lat=lat if isinstance(lat,(int,float)) else None,lon=lon if isinstance(lon,(int,float)) else None,source='ipapi')
 except: r['note']='Enrichment unavailable'
 return r
def domain_risk(d):
 s=0; reasons=[]; t=d.split('.')[-1]
 if t in SUS:s+=20;reasons.append(f'Suspicious/uncommon TLD: .{t}')
 if any(x in d for x in ['secure','verify','account','login','support','billing','invoice']):s+=15;reasons.append('Security/transaction keyword in domain')
 if re.search(r'\d',d):s+=5;reasons.append('Domain contains numeric characters')
 if len(d)>30:s+=5;reasons.append('Unusually long domain')
 return min(s,40),reasons
def url_risk(u):
 s=0;r=[]
 try:
  p=urlparse(u if '://' in u else 'http://'+u)
  if p.scheme=='http':s+=8;r.append('Link is not HTTPS')
  if '@' in p.netloc:s+=15;r.append('URL contains @ userinfo')
  if len(u)>100:s+=7;r.append('Unusually long URL')
  if (p.hostname or '').count('.')>=4:s+=6;r.append('Deeply nested hostname')
 except:s+=10;r.append('URL parsing anomaly')
 return min(s,30),r
def analyze(raw,cfg,prior=[]):
 p=parse(raw); text=p['subject']+'\n'+p['body']; features=V.transform([text]); pred=M.predict(features)[0]; probs=M.predict_proba(features)[0]
 ranked=sorted([{'label':str(c),'confidence':round(float(v)*100,1)} for c,v in zip(M.classes_,probs)],key=lambda x:x['confidence'],reverse=True)
 sig={'urgency':hits(text,URG),'credential':hits(text,CRED),'financial':hits(text,FIN),'impersonation':hits(text,IMP)}; score=0; reasons=[]
 if sig['urgency']:score+=min(18,6+3*len(sig['urgency']));reasons.append('Urgency/social-engineering language detected')
 if sig['credential']:score+=min(24,8+4*len(sig['credential']));reasons.append('Credential/account-verification language detected')
 if sig['financial']:score+=min(28,10+4*len(sig['financial']));reasons.append('Financial/payment language detected')
 if sig['impersonation']:score+=min(18,6+3*len(sig['impersonation']));reasons.append('Executive/authority impersonation language detected')
 au=auth(p)
 for n,v in au.items():
  if v in ['FAIL','SOFTFAIL','PERMERROR','TEMPERROR']: score += {'spf':12,'dkim':10,'dmarc':14}[n]; reasons.append(f'{n.upper()} authentication result is {v}')
 sd=addr_domain(p['sender']); rd=addr_domain(p['reply_to']); rp=addr_domain(p['return_path'])
 if sd and rd and sd!=rd:score+=12;reasons.append('Reply-To domain differs from From domain')
 if sd and rp and sd!=rp:score+=8;reasons.append('Return-Path domain differs from From domain')
 dr={}
 for d in p['domains']:
  q,rr=domain_risk(d);dr[d]=q;score+=q;reasons+=rr
 ur={}
 for u in p['urls']:
  q,rr=url_risk(u);ur[u]=q;score+=q;reasons+=rr
 attachment_risk=sum(int(a.get('risk',0)) for a in p.get('attachments',[]))
 if attachment_risk: score += min(25, attachment_risk//2); reasons += [x for a in p.get('attachments',[]) for x in a.get('reasons',[])]
 if pred in ['PHISHING','BEC','IMPERSONATION']:score+=12
 domain_intelligence={d:domain_intel(d) for d in p['domains']}
 for d,di in domain_intelligence.items():
  score += min(20, di['risk_score']//3)
  reasons += di['risk_reasons']
 ip_intelligence=[ip_intel(x) for x in p['public_ips']]
 score=min(100,int(score))
 cls='FRAUD / BEC' if pred=='BEC' or (sig['financial'] and sig['urgency']) else pred if pred in ['PHISHING','IMPERSONATION'] else 'SUSPICIOUS' if score>=35 else 'LEGITIMATE'
 hops=[]
 for i,h in enumerate(reversed(p['received']),1):
  xs=IP.findall(h);hops.append({'hop':i,'ip':xs[-1] if xs else None,'raw':h})
 graph={'nodes':[{'id':'email','label':'Analyzed Email','kind':'email'}],'edges':[]}
 for i,d in enumerate(p['domains']):graph['nodes'].append({'id':'d'+str(i),'label':d,'kind':'domain'});graph['edges'].append({'source':'email','target':'d'+str(i),'relation':'contains'})
 for i,ip in enumerate(p['public_ips']):graph['nodes'].append({'id':'i'+str(i),'label':ip,'kind':'ip'});graph['edges'].append({'source':'email','target':'i'+str(i),'relation':'relayed-via'})
 # Attribution is evidence-weighted support, never an identity claim.
 attribution={
  'overall_confidence': round(min(95, 45 + (12 if any(v in ('FAIL','SOFTFAIL','PERMERROR') for v in au.values()) else 0) + (15 if sd and rd and sd!=rd else 0) + (10 if p['public_ips'] else 0) + (10 if p['domains'] else 0)),1),
  'spoofed_domain': 78 if sd and any(d!=sd for d in p['domains']) else 32,
  'compromised_account': 55 if pred in ('BEC','IMPERSONATION') else 25,
  'anonymized_infrastructure': 65 if any(x.get('vpn_proxy_indicator') not in ('unknown','') or x.get('tor_indicator') not in ('unknown','') for x in ip_intelligence) else 30,
  'direct_malicious_environment': 40 if any(x.get('hosting_indicator')=='possible-hosting' for x in ip_intelligence) else 20,
  'caveat':'Probabilistic support only; infrastructure geolocation does not identify an attacker.'
 }
 campaign_matches=correlate({**p,'subject':p['subject']}, prior)
 campaign={'status':'RELATED_ACTIVITY' if campaign_matches else 'NO_MATCH_FOUND','matches':campaign_matches,'cluster_id':('CMP-'+hashlib.sha256((p['subject']+'|'+','.join(p['domains'])).encode()).hexdigest()[:10].upper()) if campaign_matches else None}
 ti=[]
 for d,di in domain_intelligence.items():
  ti.append({'indicator':d,'type':'DOMAIN','reputation':'DEMO_FEED_ONLY','hits':1 if di['risk_score']>=25 else 0,'confidence':'medium' if di['risk_score']>=25 else 'low'})
 for x in ip_intelligence:
  ti.append({'indicator':x['ip'],'type':'IP','reputation':'DEMO_FEED_ONLY','hits':0,'confidence':'low'})
 now=datetime.now(timezone.utc).isoformat()
 custody=[{'event':'EVIDENCE_RECEIVED','time':now,'detail':'Original email bytes accepted'}, {'event':'HASH_COMPUTED','time':now,'detail':'SHA-256 evidence fingerprint created'}, {'event':'HEADERS_PARSED','time':now,'detail':'RFC headers and relay chain extracted'}, {'event':'ANALYSIS_COMPLETED','time':now,'detail':'ML, rules and enrichment completed'}]
 return {**p,'classification':cls,'risk_score':score,'priority':'P1' if score>=85 else 'P2' if score>=65 else 'P3','confidence':round(min(98,55+abs(score-50)*.8),1),'ml_prediction':pred,'ml_ranked':ranked,'signals':sig,'authentication':au,'domain_risks':dr,'domain_intelligence':domain_intelligence,'url_risks':ur,'relay_hops':hops,'ip_details':[enrich_ip(x,cfg) for x in p['public_ips']],'ip_intelligence':ip_intelligence,'attribution':attribution,'campaign':campaign,'threat_intelligence':ti,'chain_of_custody':custody,'reasons':list(dict.fromkeys(reasons))[:20],'response_actions':response_actions(cls,score,au),'graph':graph}
def response_actions(cls,score,au):
 a=['Preserve the original .eml and SHA-256 evidence']
 if score>=65:a+=['Quarantine/block pending analyst review','Search for related messages using extracted IOCs']
 if cls in ['FRAUD / BEC','IMPERSONATION']:a+=['Verify sensitive requests through a trusted channel']
 if any(v!='PASS' and v!='UNKNOWN' for v in au.values()):a+=['Review sender authentication and domain alignment']
 return a
