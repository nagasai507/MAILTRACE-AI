"""
Production entrypoint. The Flask dev server (run.py) is single-threaded
and not meant to serve real traffic; run with a proper WSGI server:

    gunicorn -w 4 -k gthread --threads 4 -b 0.0.0.0:5000 wsgi:app

Notes:
- Use multiple worker *processes* (-w) for CPU-bound work (the ML
  pipeline) plus threads per worker for I/O-bound enrichment calls.
- The in-memory rate limiter and TTL caches in this codebase are
  per-process. With multiple workers, each process enforces its own
  limits/cache — acceptable for a single-host deployment, but swap them
  for a shared backing store (Redis) before scaling across hosts.
"""
from app import create_app

app = create_app()
