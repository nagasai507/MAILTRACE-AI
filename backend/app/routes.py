import json
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify, current_app, send_file
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db
from .models import User, Case, CaseNote, Indicator, AuditLog
from .services.core import analyze, bulk_enrich_ip
from .services.report import make_pdf
from .security import rate_limited, require_strong_password

api = Blueprint('api', __name__)

MAX_RAW_EMAIL_BYTES = 10 * 1024 * 1024  # mirrors MAX_CONTENT_LENGTH; enforced explicitly for the JSON-body path too


def guard(f):
    def w(*a, **k):
        return f(*a, **k)
    w.__name__ = f.__name__
    return jwt_required()(w)


def audit(actor, action, outcome, detail=''):
    try:
        db.session.add(AuditLog(actor=actor, action=action, outcome=outcome,
                                 ip_address=request.remote_addr, detail=detail[:500]))
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception('Failed to write audit log entry')


def out(c):
    a = json.loads(c.analysis_json)
    base = {'id': c.id, 'case_number': c.case_number, 'subject': c.subject, 'sender': c.sender,
            'classification': c.classification, 'risk_score': c.risk_score, 'priority': c.priority,
            'status': c.status, 'evidence_hash': c.evidence_hash, 'created_at': c.created_at.isoformat()}
    return {**a, **base, 'analysis': a}


def refresh_case_geolocation(c, analysis):
    ips = analysis.get('public_ips', [])
    details = analysis.get('ip_details', [])
    if not ips or all(x.get('lat') is not None and x.get('lon') is not None for x in details):
        return analysis
    refreshed = bulk_enrich_ip(ips, current_app.config)
    if any(x.get('lat') is not None and x.get('lon') is not None for x in refreshed):
        analysis['ip_details'] = refreshed
        c.analysis_json = json.dumps(analysis, default=str)
        db.session.commit()
    return analysis


@api.get('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'MAILTRACE AI'})


@api.post('/auth/register')
def register():
    d = request.get_json(silent=True) or {}
    email = str(d.get('email', '')).strip().lower()
    password = str(d.get('password', ''))
    if not email or not password:
        return jsonify(error='Email and password are required.'), 400
    if User.query.filter_by(email=email).first():
        return jsonify(error='A user with this email already exists.'), 409

    weakness = require_strong_password(password)
    if weakness:
        return jsonify(error=weakness), 400

    user = User(email=email, password_hash=generate_password_hash(password), role='ANALYST')
    db.session.add(user)
    db.session.commit()
    audit(email, 'REGISTER', 'SUCCESS', 'New user created')
    return jsonify(
        token=create_access_token(identity=str(user.id)),
        user={'id': user.id, 'email': user.email, 'role': user.role}
    ), 201


def _login_rate_limited(fn):
    # Rate-limit thresholds live in app config (set from env), which only
    # exists once the app is created — so this wraps the view in a
    # closure that reads current_app.config at request time rather than
    # baking in a value at import time.
    def wrapper(*a, **k):
        cfg = current_app.config
        limited = rate_limited('login', cfg['LOGIN_RATE_LIMIT'], cfg['LOGIN_RATE_WINDOW_SECONDS'])(fn)
        return limited(*a, **k)
    wrapper.__name__ = fn.__name__
    return wrapper


@api.post('/auth/login')
@_login_rate_limited
def login():
    d = request.get_json(silent=True) or {}
    email = str(d.get('email', '')).strip().lower()
    password = d.get('password', '')
    u = User.query.filter_by(email=email).first()
    cfg = current_app.config

    if u and u.locked_until and u.locked_until.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
        audit(email or 'unknown', 'LOGIN', 'BLOCKED', 'Account temporarily locked')
        return jsonify(error='Account temporarily locked due to repeated failed attempts. Try again later.'), 423

    if not u or not check_password_hash(u.password_hash, password):
        if u:
            u.failed_attempts = (u.failed_attempts or 0) + 1
            if u.failed_attempts >= cfg['LOGIN_MAX_ATTEMPTS']:
                u.locked_until = datetime.now(timezone.utc) + timedelta(minutes=cfg['LOGIN_LOCKOUT_MINUTES'])
                u.failed_attempts = 0
            db.session.commit()
        audit(email or 'unknown', 'LOGIN', 'FAILURE', 'Invalid credentials')
        # Deliberately identical message/timing profile whether the email
        # exists or not, so the endpoint can't be used to enumerate accounts.
        return jsonify(error='Invalid credentials'), 401

    u.failed_attempts = 0
    u.locked_until = None
    u.last_login_at = datetime.now(timezone.utc)
    db.session.commit()
    audit(u.email, 'LOGIN', 'SUCCESS')
    return jsonify(token=create_access_token(identity=str(u.id)), user={'id': u.id, 'email': u.email, 'role': u.role})


@api.get('/dashboard/summary')
@guard
def summary():
    cs = Case.query.order_by(Case.created_at.desc()).all()
    counts = {x: 0 for x in ['LEGITIMATE', 'SUSPICIOUS', 'PHISHING', 'IMPERSONATION', 'FRAUD / BEC']}
    for c in cs:
        counts[c.classification] = counts.get(c.classification, 0) + 1
    return jsonify(total_cases=len(cs), high_risk=sum(c.risk_score >= 65 for c in cs),
                   open_cases=sum(c.status != 'CLOSED' for c in cs), classifications=counts,
                   recent=[out(c) for c in cs[:10]])


def run_analysis(raw):
    prior = []
    for c in Case.query.order_by(Case.created_at.desc()).limit(50):
        a = json.loads(c.analysis_json)
        prior.append({'id': c.id, 'domains': a.get('domains', []), 'public_ips': a.get('public_ips', [])})
    a = analyze(raw, current_app.config, prior)
    c = Case(case_number='MT-' + datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')[:18],
             subject=a['subject'][:500], sender=a['sender'][:500], classification=a['classification'],
             risk_score=a['risk_score'], priority=a['priority'], evidence_hash=a['sha256'],
             analysis_json=json.dumps(a, default=str))
    db.session.add(c)
    db.session.flush()
    for k, vals in [('IP', a['public_ips']), ('DOMAIN', a['domains']), ('URL', a['urls'])]:
        for v in vals:
            db.session.add(Indicator(case_id=c.id, kind=k, value=v))
    db.session.commit()
    identity = get_jwt_identity()
    actor_user = User.query.get(int(identity)) if identity else None
    actor = actor_user.email if actor_user else 'unknown'
    audit(actor, 'ANALYZE_EMAIL', 'SUCCESS', f'case={c.case_number} risk={a["risk_score"]}')
    return jsonify(out(c)), 201


def _analyze_rate_limited(fn):
    def wrapper(*a, **k):
        cfg = current_app.config
        limited = rate_limited('analyze', cfg['ANALYZE_RATE_LIMIT'], cfg['ANALYZE_RATE_WINDOW_SECONDS'])(fn)
        return limited(*a, **k)
    wrapper.__name__ = fn.__name__
    return wrapper


@api.post('/analyze/raw')
@guard
@_analyze_rate_limited
def raw():
    d = request.get_json(silent=True) or {}
    x = (d.get('raw_email') or '')
    if len(x) > MAX_RAW_EMAIL_BYTES:
        return jsonify(error='Submitted email exceeds the maximum allowed size.'), 413
    x = x.encode()
    return run_analysis(x) if len(x) >= 20 else (jsonify(error='Paste a complete raw email/header set.'), 400)


@api.post('/analyze/upload')
@guard
@_analyze_rate_limited
def upload():
    f = request.files.get('file')
    if not f:
        return jsonify(error='No file uploaded'), 400
    # Basic filetype allow-listing: this endpoint exists to ingest raw
    # email evidence, not arbitrary files. Content is still parsed
    # defensively regardless, but rejecting obviously-wrong extensions
    # early avoids wasting the parser/ML pipeline on non-email uploads.
    if f.filename and '.' in f.filename:
        ext = f.filename.rsplit('.', 1)[-1].lower()
        if ext not in ('eml', 'txt', 'msg'):
            return jsonify(error='Only .eml/.msg/.txt evidence files are accepted.'), 400
    x = f.read()
    if len(x) > MAX_RAW_EMAIL_BYTES:
        return jsonify(error='Uploaded file exceeds the maximum allowed size.'), 413
    return run_analysis(x) if x else (jsonify(error='Empty file'), 400)


@api.get('/cases')
@guard
def cases():
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(100, max(1, request.args.get('per_page', 50, type=int)))
    q = Case.query.order_by(Case.created_at.desc())
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    # Back-compatible: a bare GET /cases (no pagination params) still
    # returns the plain list the original frontend expects; pagination
    # metadata is available to any client that asks for it explicitly.
    if 'page' not in request.args and 'per_page' not in request.args:
        return jsonify([out(c) for c in q.all()])
    return jsonify(items=[out(c) for c in items], page=page, per_page=per_page, total=total)


@api.get('/cases/<int:i>')
@guard
def detail(i):
    c = Case.query.get_or_404(i)
    analysis = refresh_case_geolocation(c, json.loads(c.analysis_json))
    r = out(c)
    r.update(analysis)
    r['analysis'] = analysis
    r['notes'] = [{'id': n.id, 'author': n.author, 'note': n.note, 'created_at': n.created_at.isoformat()}
                  for n in CaseNote.query.filter_by(case_id=i).order_by(CaseNote.created_at.desc())]
    return jsonify(r)


@api.post('/cases/<int:i>/notes')
@guard
def note(i):
    Case.query.get_or_404(i)
    d = request.get_json(silent=True) or {}
    txt = str(d.get('note', '')).strip()[:4000]
    u = User.query.get(int(get_jwt_identity()))
    if not txt:
        return jsonify(error='Note is empty'), 400
    db.session.add(CaseNote(case_id=i, author=u.email, note=txt))
    db.session.commit()
    audit(u.email, 'ADD_CASE_NOTE', 'SUCCESS', f'case_id={i}')
    return jsonify(message='saved')


@api.post('/cases/<int:i>/status')
@guard
def status(i):
    c = Case.query.get_or_404(i)
    s = str((request.get_json(silent=True) or {}).get('status', '')).upper()
    if s not in ['OPEN', 'INVESTIGATING', 'CLOSED']:
        return jsonify(error='Invalid status'), 400
    c.status = s
    db.session.commit()
    identity = get_jwt_identity()
    actor = User.query.get(int(identity)).email if identity else 'unknown'
    audit(actor, 'UPDATE_CASE_STATUS', 'SUCCESS', f'case_id={i} status={s}')
    return jsonify(out(c))


@api.get('/cases/<int:i>/report')
@guard
def report(i):
    c = Case.query.get_or_404(i)
    pdf = make_pdf(c, json.loads(c.analysis_json))
    return send_file(pdf, mimetype='application/pdf', as_attachment=True,
                      download_name=f'{c.case_number}-forensic-report.pdf')
