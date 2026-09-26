"""
Security hardening helpers.

Deliberately dependency-free (no flask-limiter/flask-talisman) so this
upgrade doesn't require a new pip install to run: it's a sliding-window
in-memory limiter, which is correct for MailTrace's current single-process
deployment. If MailTrace is ever scaled to multiple worker processes,
swap RATE_STORE for a shared store (Redis) — the call sites don't need
to change.
"""
import time
import threading
from collections import deque
from flask import request, jsonify, current_app

_RATE_LOCK = threading.Lock()
_RATE_STORE = {}  # key -> deque[timestamps]


def rate_limited(bucket: str, max_requests: int, window_seconds: int, key_fn=None):
    """
    Decorator: sliding-window rate limit per (bucket, key). Default key is
    the caller's remote address, so brute-force login attempts or
    analysis-endpoint hammering from one source get throttled without
    penalizing other users.
    """
    def deco(fn):
        def wrapper(*args, **kwargs):
            key = key_fn() if key_fn else request.remote_addr or 'unknown'
            full_key = f'{bucket}:{key}'
            now = time.monotonic()
            with _RATE_LOCK:
                dq = _RATE_STORE.setdefault(full_key, deque())
                while dq and now - dq[0] > window_seconds:
                    dq.popleft()
                if len(dq) >= max_requests:
                    retry_after = int(window_seconds - (now - dq[0])) + 1
                    return jsonify(error='Too many requests. Please slow down.'), 429, {'Retry-After': str(retry_after)}
                dq.append(now)
            return fn(*args, **kwargs)
        wrapper.__name__ = fn.__name__
        return wrapper
    return deco


def apply_security_headers(response):
    """Defense-in-depth response headers. Safe defaults for an API-only
    backend serving a separately-hosted SPA."""
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault('Cache-Control', 'no-store')
    response.headers.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    if current_app.config.get('FORCE_HTTPS'):
        response.headers.setdefault('Strict-Transport-Security', 'max-age=63072000; includeSubDomains')
    return response


def require_strong_password(pw: str):
    """Returns an error string, or None if the password is acceptable."""
    if len(pw) < 12:
        return 'Password must be at least 12 characters.'
    classes = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw),
    ])
    if classes < 3:
        return 'Password must mix at least 3 of: lowercase, uppercase, digits, symbols.'
    return None
