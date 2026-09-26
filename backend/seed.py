import os
from app import create_app
from app.extensions import db
from app.models import User
from app.security import require_strong_password
from werkzeug.security import generate_password_hash


def ensure_admin_user(email: str, password: str):
    if not password:
        raise RuntimeError('SEED_ADMIN_PASSWORD must be set before seeding an admin account.')

    weakness = require_strong_password(password)
    if weakness:
        raise RuntimeError(f'SEED_ADMIN_PASSWORD is too weak: {weakness}')

    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User(email=email, role='ADMIN')
        db.session.add(user)

    user.email = email
    user.password_hash = generate_password_hash(password)
    user.role = 'ADMIN'
    user.failed_attempts = 0
    user.locked_until = None
    db.session.commit()
    return user


if __name__ == '__main__':
    app = create_app()
    ADMIN_EMAIL = os.getenv('SEED_ADMIN_EMAIL', 'admin@mailtrace.local')
    ADMIN_PASSWORD = os.getenv('SEED_ADMIN_PASSWORD')

    with app.app_context():
        ensure_admin_user(ADMIN_EMAIL, ADMIN_PASSWORD)
        print(f'Admin account ready: {ADMIN_EMAIL}')
