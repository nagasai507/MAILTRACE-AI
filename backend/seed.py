from app import create_app
from app.extensions import db
from app.models import User
from werkzeug.security import generate_password_hash
app=create_app()
with app.app_context():
 u=User.query.filter_by(email='admin@mailtrace.local').first()
 if not u:
  db.session.add(User(email='admin@mailtrace.local',password_hash=generate_password_hash('ChangeMe123!'),role='ADMIN'));db.session.commit()
 print('Demo login: admin@mailtrace.local / ChangeMe123!')
