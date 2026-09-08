import json
from datetime import datetime,timezone
from flask import Blueprint,request,jsonify,current_app,send_file
from flask_jwt_extended import jwt_required,create_access_token,get_jwt_identity
from werkzeug.security import generate_password_hash,check_password_hash
from .extensions import db
from .models import User,Case,CaseNote,Indicator
from .services.core import analyze
from .services.report import make_pdf
api=Blueprint('api',__name__)
def guard(f):
 def w(*a,**k):return f(*a,**k)
 w.__name__=f.__name__;return jwt_required()(w)
def out(c):
 a=json.loads(c.analysis_json)
 base={'id':c.id,'case_number':c.case_number,'subject':c.subject,'sender':c.sender,'classification':c.classification,'risk_score':c.risk_score,'priority':c.priority,'status':c.status,'evidence_hash':c.evidence_hash,'created_at':c.created_at.isoformat()}
 return {**a,**base,'analysis':a}
@api.get('/health')
def health():return jsonify({'status':'ok','service':'MAILTRACE AI'})
@api.post('/auth/login')
def login():
 d=request.get_json(silent=True) or {};u=User.query.filter_by(email=d.get('email','').strip().lower()).first()
 if not u or not check_password_hash(u.password_hash,d.get('password','')):return jsonify(error='Invalid credentials'),401
 return jsonify(token=create_access_token(identity=str(u.id)),user={'id':u.id,'email':u.email,'role':u.role})
@api.get('/dashboard/summary')
@guard
def summary():
 cs=Case.query.order_by(Case.created_at.desc()).all();counts={x:0 for x in ['LEGITIMATE','SUSPICIOUS','PHISHING','IMPERSONATION','FRAUD / BEC']}
 for c in cs:counts[c.classification]=counts.get(c.classification,0)+1
 return jsonify(total_cases=len(cs),high_risk=sum(c.risk_score>=65 for c in cs),open_cases=sum(c.status!='CLOSED' for c in cs),classifications=counts,recent=[out(c) for c in cs[:10]])
def run_analysis(raw):
 prior=[]
 for c in Case.query.order_by(Case.created_at.desc()).limit(50):
  a=json.loads(c.analysis_json);prior.append({'id':c.id,'domains':a.get('domains',[]),'public_ips':a.get('public_ips',[])})
 a=analyze(raw,current_app.config,prior);c=Case(case_number='MT-'+datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')[:18],subject=a['subject'][:500],sender=a['sender'][:500],classification=a['classification'],risk_score=a['risk_score'],priority=a['priority'],evidence_hash=a['sha256'],analysis_json=json.dumps(a,default=str));db.session.add(c);db.session.flush()
 for k,vals in [('IP',a['public_ips']),('DOMAIN',a['domains']),('URL',a['urls'])]:
  for v in vals:db.session.add(Indicator(case_id=c.id,kind=k,value=v))
 db.session.commit();return jsonify(out(c)),201
@api.post('/analyze/raw')
@guard
def raw():
 d=request.get_json(silent=True) or {};x=(d.get('raw_email') or '').encode()
 return run_analysis(x) if len(x)>=20 else (jsonify(error='Paste a complete raw email/header set.'),400)
@api.post('/analyze/upload')
@guard
def upload():
 f=request.files.get('file');
 if not f:return jsonify(error='No file uploaded'),400
 x=f.read();return run_analysis(x) if x else (jsonify(error='Empty file'),400)
@api.get('/cases')
@guard
def cases():return jsonify([out(c) for c in Case.query.order_by(Case.created_at.desc()).all()])
@api.get('/cases/<int:i>')
@guard
def detail(i):
 c=Case.query.get_or_404(i);r=out(c);r['notes']=[{'id':n.id,'author':n.author,'note':n.note,'created_at':n.created_at.isoformat()} for n in CaseNote.query.filter_by(case_id=i).order_by(CaseNote.created_at.desc())];return jsonify(r)
@api.post('/cases/<int:i>/notes')
@guard
def note(i):
 d=request.get_json(silent=True) or {};txt=str(d.get('note','')).strip();u=User.query.get(int(get_jwt_identity()));
 if not txt:return jsonify(error='Note is empty'),400
 db.session.add(CaseNote(case_id=i,author=u.email,note=txt));db.session.commit();return jsonify(message='saved')
@api.post('/cases/<int:i>/status')
@guard
def status(i):
 c=Case.query.get_or_404(i);s=str((request.get_json(silent=True) or {}).get('status','')).upper()
 if s not in ['OPEN','INVESTIGATING','CLOSED']:return jsonify(error='Invalid status'),400
 c.status=s;db.session.commit();return jsonify(out(c))
@api.get('/cases/<int:i>/report')
@guard
def report(i):
 c=Case.query.get_or_404(i);pdf=make_pdf(c,json.loads(c.analysis_json));return send_file(pdf,mimetype='application/pdf',as_attachment=True,download_name=f'{c.case_number}-forensic-report.pdf')
