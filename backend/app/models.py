from datetime import datetime,timezone
from .extensions import db
class User(db.Model):
 id=db.Column(db.Integer,primary_key=True); email=db.Column(db.String(190),unique=True,nullable=False); password_hash=db.Column(db.String(255),nullable=False); role=db.Column(db.String(30),default='ANALYST'); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc))
class Case(db.Model):
 id=db.Column(db.Integer,primary_key=True); case_number=db.Column(db.String(50),unique=True,nullable=False); subject=db.Column(db.String(500)); sender=db.Column(db.String(500)); classification=db.Column(db.String(80)); risk_score=db.Column(db.Integer); priority=db.Column(db.String(10)); status=db.Column(db.String(30),default='OPEN'); evidence_hash=db.Column(db.String(64),nullable=False); analysis_json=db.Column(db.Text,nullable=False); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc))
class CaseNote(db.Model):
 id=db.Column(db.Integer,primary_key=True); case_id=db.Column(db.Integer,db.ForeignKey('case.id'),nullable=False); author=db.Column(db.String(190),nullable=False); note=db.Column(db.Text,nullable=False); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc))
class Indicator(db.Model):
 id=db.Column(db.Integer,primary_key=True); case_id=db.Column(db.Integer,db.ForeignKey('case.id'),nullable=False); kind=db.Column(db.String(30)); value=db.Column(db.String(1000)); risk=db.Column(db.Integer,default=0)
