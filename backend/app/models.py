from datetime import datetime, timezone
from .extensions import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(190), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), default='ANALYST')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    # Account-lockout state (brute-force defense; see security.py / routes.py)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)


class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(50), unique=True, nullable=False)
    subject = db.Column(db.String(500))
    sender = db.Column(db.String(500))
    classification = db.Column(db.String(80), index=True)
    risk_score = db.Column(db.Integer, index=True)
    priority = db.Column(db.String(10))
    status = db.Column(db.String(30), default='OPEN', index=True)
    evidence_hash = db.Column(db.String(64), nullable=False)
    analysis_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class CaseNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    author = db.Column(db.String(190), nullable=False)
    note = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class Indicator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    kind = db.Column(db.String(30), index=True)
    value = db.Column(db.String(1000))
    risk = db.Column(db.Integer, default=0)


class AuditLog(db.Model):
    """Append-only security/audit trail: who did what, when, from where.
    Kept independent of Case/User FKs so it still records failed logins
    for emails that don't map to a real account (enumeration attempts)."""
    id = db.Column(db.Integer, primary_key=True)
    at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    actor = db.Column(db.String(190))          # email or 'anonymous'
    action = db.Column(db.String(60), index=True)
    outcome = db.Column(db.String(20))          # SUCCESS / FAILURE / BLOCKED
    ip_address = db.Column(db.String(64))
    detail = db.Column(db.String(500))
