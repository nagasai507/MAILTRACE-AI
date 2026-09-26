"""
Lightweight, dependency-free, thread-safe TTL cache.

Repeated analyses frequently reference the same domains/IPs (a phishing
kit is reused across many messages, an org's own mail servers show up in
every relay chain, etc). Hitting DNS / external geo APIs again for
already-seen indicators is pure latency with no analytical value, so we
cache results for a bounded time.

Kept in-process/in-memory (no Redis dependency) since MailTrace runs as a
single Flask process in its current deployment. If MailTrace is ever run
with multiple worker processes, swap this for a shared cache (Redis/
Memcached) using the same get_or_set interface.
"""
import time
import threading
from functools import wraps


class TTLCache:
    def __init__(self, ttl_seconds=600, max_entries=5000):
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._store = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._store.get(key)
            if not item:
                return None, False
            value, expires_at = item
            if expires_at < time.monotonic():
                del self._store[key]
                return None, False
            return value, True

    def set(self, key, value):
        with self._lock:
            if len(self._store) >= self.max_entries:
                # Evict the oldest ~10% of entries rather than the whole
                # cache, so a burst of unique indicators doesn't repeatedly
                # thrash a fully-populated cache.
                oldest = sorted(self._store.items(), key=lambda kv: kv[1][1])[: max(1, self.max_entries // 10)]
                for k, _ in oldest:
                    self._store.pop(k, None)
            self._store[key] = (value, time.monotonic() + self.ttl)

    def get_or_set(self, key, compute_fn):
        value, hit = self.get(key)
        if hit:
            return value
        value = compute_fn()
        self.set(key, value)
        return value

    def stats(self):
        with self._lock:
            return {'entries': len(self._store), 'ttl_seconds': self.ttl}


def cached(cache: TTLCache, key_fn=None):
    """Decorator form for simple single-arg lookups (e.g. def f(domain))."""
    def deco(fn):
        @wraps(fn)
        def wrapper(arg, *a, **k):
            key = key_fn(arg) if key_fn else arg
            return cache.get_or_set(key, lambda: fn(arg, *a, **k))
        return wrapper
    return deco


# Shared caches used across the enrichment pipeline.
dns_cache = TTLCache(ttl_seconds=900)      # DNS records change rarely within a session
geo_cache = TTLCache(ttl_seconds=3600)     # IP geolocation is effectively static
reverse_dns_cache = TTLCache(ttl_seconds=1800)
