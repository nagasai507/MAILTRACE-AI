import os
import tempfile
import unittest

from werkzeug.security import check_password_hash

os.environ['SEED_ADMIN_EMAIL'] = 'admin@mailtrace.local'
os.environ['SEED_ADMIN_PASSWORD'] = 'LocalOnly-ChangeMe-123!'

from app import create_app
from app.extensions import db
from app.models import User, Case, CaseNote
from seed import ensure_admin_user


class SeedAdminTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.tmp.close()
        os.environ['DATABASE_URL'] = f'sqlite:///{self.tmp.name}'
        self.app = create_app()
        self.app.app_context().push()
        db.drop_all()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        os.environ.pop('DATABASE_URL', None)
        os.unlink(self.tmp.name)

    def test_seed_replaces_existing_admin_password(self):
        db.session.add(User(email='admin@mailtrace.local', password_hash='hash-does-not-match', role='ANALYST'))
        db.session.commit()

        ensure_admin_user('admin@mailtrace.local', 'LocalOnly-ChangeMe-123!')

        stored = User.query.filter_by(email='admin@mailtrace.local').one()
        self.assertEqual(stored.role, 'ADMIN')
        self.assertTrue(check_password_hash(stored.password_hash, 'LocalOnly-ChangeMe-123!'))

    def test_create_app_auto_seeds_admin_from_env(self):
        os.environ['SEED_ADMIN_EMAIL'] = 'admin@mailtrace.local'
        os.environ['SEED_ADMIN_PASSWORD'] = 'LocalOnly-ChangeMe-123!'
        app = create_app()
        with app.app_context():
            stored = User.query.filter_by(email='admin@mailtrace.local').one()
            self.assertEqual(stored.role, 'ADMIN')
            self.assertTrue(check_password_hash(stored.password_hash, 'LocalOnly-ChangeMe-123!'))
        os.environ.pop('SEED_ADMIN_PASSWORD', None)
        os.environ.pop('SEED_ADMIN_EMAIL', None)

    def test_register_persists_real_user_in_database(self):
        app = create_app()
        with app.app_context():
            client = app.test_client()
            response = client.post('/api/auth/register', json={
                'email': 'newanalyst@example.com',
                'password': 'StrongPass-123!'
            })
            self.assertEqual(response.status_code, 201)
            payload = response.get_json()
            self.assertEqual(payload['user']['email'], 'newanalyst@example.com')
            stored = User.query.filter_by(email='newanalyst@example.com').one()
            self.assertEqual(stored.role, 'ANALYST')
            self.assertTrue(check_password_hash(stored.password_hash, 'StrongPass-123!'))

    def test_case_controls_persist_note_status_and_report(self):
        ensure_admin_user('admin@mailtrace.local', 'LocalOnly-ChangeMe-123!')
        client = self.app.test_client()
        login = client.post('/api/auth/login', json={
            'email': 'admin@mailtrace.local',
            'password': 'LocalOnly-ChangeMe-123!'
        })
        headers = {'Authorization': f"Bearer {login.get_json()['token']}"}
        analysis = client.post('/api/analyze/raw', headers=headers, json={
            'raw_email': 'From: sender@example.com\nTo: analyst@example.com\n'
                        'Subject: Case control test\n\nReview this message.'
        })
        case_id = analysis.get_json()['id']

        note = client.post(f'/api/cases/{case_id}/notes', headers=headers,
                           json={'note': 'Documented response action.'})
        status = client.post(f'/api/cases/{case_id}/status', headers=headers,
                             json={'status': 'INVESTIGATING'})
        detail = client.get(f'/api/cases/{case_id}', headers=headers)
        report = client.get(f'/api/cases/{case_id}/report', headers=headers)

        self.assertEqual(analysis.status_code, 201)
        self.assertEqual(note.status_code, 200)
        self.assertEqual(status.status_code, 200)
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.get_json()['status'], 'INVESTIGATING')
        self.assertEqual(detail.get_json()['notes'][0]['note'], 'Documented response action.')
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.mimetype, 'application/pdf')


if __name__ == '__main__':
    unittest.main()
