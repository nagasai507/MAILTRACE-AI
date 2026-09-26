import os
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parents[1]
load_dotenv(BASE.parent / '.env')

_INSECURE_DEFAULTS = {
    'mailtrace-dev-secret-key-change-in-production-32chars!',
    'mailtrace-jwt-secret-key-change-in-production-32chars!',
    'mailtrace-dev-secret-change-in-production-32chars',
    'mailtrace-jwt-secret-change-in-production-32chars',
    'change-this-secret',
    'change-this-jwt-secret',
}


def _env_flag(name, default='false'):
    return os.getenv(name, default).strip().lower() in ('1', 'true', 'yes', 'on')


class Config:
    ENV = os.getenv('FLASK_ENV', 'development')
    IS_PRODUCTION = ENV == 'production'

    # In development, fall back to a fixed (clearly-labelled) demo secret so
    # the app still runs out of the box. In production, a real secret is
    # mandatory — failing loudly at startup beats silently signing tokens
    # with a publicly-known default that anyone can forge.
    SECRET_KEY = os.getenv('SECRET_KEY') or ''
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY') or ''
    if not SECRET_KEY:
        if IS_PRODUCTION:
            raise RuntimeError('SECRET_KEY must be set via environment in production.')
        SECRET_KEY = 'mailtrace-dev-secret-key-change-in-production-32chars!'
    if not JWT_SECRET_KEY:
        if IS_PRODUCTION:
            raise RuntimeError('JWT_SECRET_KEY must be set via environment in production.')
        JWT_SECRET_KEY = 'mailtrace-jwt-secret-key-change-in-production-32chars!'
    if IS_PRODUCTION and (SECRET_KEY in _INSECURE_DEFAULTS or JWT_SECRET_KEY in _INSECURE_DEFAULTS):
        raise RuntimeError('Refusing to start in production with a default/placeholder secret key.')

    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', f"sqlite:///{BASE / 'mailtrace.db'}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,   # avoid serving on a dropped/stale DB connection
        'pool_recycle': 1800,
    }

    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:5174')
    # Local demo analysis uses real per-IP infrastructure locations by
    # default; production remains opt-in because mail IPs leave the system.
    ENABLE_EXTERNAL_INTEL = _env_flag('ENABLE_EXTERNAL_INTEL', 'false' if IS_PRODUCTION else 'true')
    IP_GEO_API_URL = os.getenv('IP_GEO_API_URL', 'https://ipwho.is/{ip}')
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024

    # --- JWT hardening ---
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=int(os.getenv('JWT_ACCESS_MINUTES', '30')))
    JWT_TOKEN_LOCATION = ['headers']

    # --- Rate limiting / account lockout ---
    LOGIN_MAX_ATTEMPTS = int(os.getenv('LOGIN_MAX_ATTEMPTS', '5'))
    LOGIN_LOCKOUT_MINUTES = int(os.getenv('LOGIN_LOCKOUT_MINUTES', '15'))
    LOGIN_RATE_LIMIT = int(os.getenv('LOGIN_RATE_LIMIT', '10'))          # requests
    LOGIN_RATE_WINDOW_SECONDS = int(os.getenv('LOGIN_RATE_WINDOW_SECONDS', '60'))
    ANALYZE_RATE_LIMIT = int(os.getenv('ANALYZE_RATE_LIMIT', '20'))
    ANALYZE_RATE_WINDOW_SECONDS = int(os.getenv('ANALYZE_RATE_WINDOW_SECONDS', '60'))

    FORCE_HTTPS = _env_flag('FORCE_HTTPS')

    # --- Performance ---
    ENRICHMENT_MAX_WORKERS = int(os.getenv('ENRICHMENT_MAX_WORKERS', '8'))
    ENRICHMENT_TIMEOUT_SECONDS = float(os.getenv('ENRICHMENT_TIMEOUT_SECONDS', '3'))
