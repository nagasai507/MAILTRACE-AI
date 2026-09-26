# MailTrace AI — Upgrade Notes (Algorithms / Performance / Security)

This upgrade is scoped to the backend (Flask) engine and the frontend
fields needed to surface its new output. No new third-party dependencies
are required — every addition is either the standard library or built on
packages already in `requirements.txt`, so `pip install -r requirements.txt`
still works unchanged. (An optional `requirements-prod.txt` adds gunicorn
for real Linux deployments; it's separate because gunicorn doesn't run on
Windows, and the project's dev quick-start targets Windows.)

## Algorithms

- **New: `app/services/textalgo.py`**
  - `levenshtein` + `typosquat_match`: replaces the old hardcoded
    lookalike-spelling dictionary with real edit-distance comparison
    against a brand list. It tokenizes each domain label (so
    `micr0soft-support.xyz` is checked as `["micr0soft","support"]`,
    not as one long string that would never be "close" to `microsoft`
    once other words are appended) and also normalizes common
    homoglyphs (`0→o`, `1→l`, `rn→m`, ...) before comparing, so it
    catches misspellings *and* visual character-substitution tricks
    that were never in the old fixed list.
  - `shannon_entropy`: flags algorithmically-generated hostnames and
    URL paths (classic DGA / phishing-kit-hosting signal) — high
    entropy in a short label is a strong tell that it wasn't typed by
    a human.
  - `haversine_km` + `implausible_travel`: a real "impossible travel"
    check across the parsed relay chain — using each hop's actual
    timestamp and (when enrichment is on) real lat/lon, it flags when
    two consecutive relays imply a physically impossible speed, which
    is evidence of spoofed/forged `Received` headers.
- **`app/services/core.py` — ML pipeline**
  - Word (1–2 gram) **and** character (3–5 gram) TF-IDF features are
    combined via `FeatureUnion`, so obfuscated/misspelled phishing
    language ("cl1ck immed1ately") still shares sub-word features with
    correctly-spelled training examples instead of being invisible to
    a purely word-tokenized vectorizer.
  - `class_weight='balanced'` so the small, uneven training set doesn't
    bias toward whichever class has more examples; the training set
    itself was also expanded (~28 examples across 4 classes, up from 14)
    for better balance and coverage.
  - `CalibratedClassifierCV` (sigmoid/Platt scaling via 3-fold CV) wraps
    the logistic regression, so the confidence percentages shown in the
    UI are genuinely calibrated probabilities rather than a raw,
    typically overconfident logistic-regression score. Falls back to
    the uncalibrated model automatically if a different sklearn version
    changes the calibration API, so this can't break app startup.
  - Attachment entropy: flags attachments whose byte-entropy suggests
    packed/encrypted content hiding inside a file that isn't a
    recognized archive type.

## Performance

- **New: `app/services/cache.py`** — dependency-free, thread-safe TTL
  cache. DNS records, reverse-DNS, and IP geolocation are all cached
  (15/30/60-minute TTLs respectively), so repeated indicators across a
  live mail stream — an org's own mail servers, a reused phishing-kit
  domain — don't re-pay a network round trip every single analysis.
- **Concurrency**: DNS record lookups (A/MX/NS/TXT), reverse-DNS for
  multiple IPs, domain-intel lookups, and IP-geolocation enrichment all
  now run via `ThreadPoolExecutor` instead of sequential loops — these
  are independent, I/O-bound calls with no reason to serialize.
  Worker count and per-call timeout are both configurable
  (`ENRICHMENT_MAX_WORKERS`, `ENRICHMENT_TIMEOUT_SECONDS`).
- **DB**: added indexes on `Case.classification`, `Case.risk_score`,
  `Case.status`, `Case.created_at`, and `Indicator.case_id`/`kind` —
  the dashboard and case-list queries filter/sort on exactly these
  columns. Added `pool_pre_ping`/`pool_recycle` so the app doesn't try
  to serve a request on a dropped DB connection.
  `GET /api/cases` now accepts optional `page`/`per_page` (paginated
  response) while staying backward-compatible: a bare `GET /api/cases`
  with no query params still returns the plain list the original
  frontend expects.
- **`wsgi.py`** added as a production entrypoint with `gunicorn`
  guidance (multi-process + threaded workers) — the Flask dev server in
  `run.py` is single-threaded and was never meant to serve real traffic.

## Security

- **Secrets**: `SECRET_KEY`/`JWT_SECRET_KEY` are now *required* in
  production (`FLASK_ENV=production`) — the app refuses to start rather
  than silently signing tokens with a publicly-known default. Dev mode
  keeps a clearly-labelled fallback so local setup still works out of
  the box.
- **Rate limiting & account lockout**: new dependency-free sliding-window
  limiter (`app/security.py`) on `/auth/login` (default 10 req/min/IP)
  and the analyze endpoints (default 20 req/min/IP). Failed logins also
  trigger a per-account lockout after 5 attempts (15-minute cooldown) —
  brute-forcing a specific account is throttled independently of IP
  rotation. Login failure responses are identical whether or not the
  email exists, to resist account enumeration.
- **Audit log**: new `AuditLog` table records login success/failure/
  lockout, analysis runs, case-status changes, and note additions, each
  with actor, IP, and outcome — an append-only trail for incident
  review.
- **Security headers**: `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Permissions-Policy`,
  `Cache-Control: no-store`, and (when `FORCE_HTTPS=true`) HSTS are set
  on every response.
- **CORS**: narrowed from any implicit defaults to an explicit origin
  allow-list plus an explicit method/header allow-list, rather than a
  blanket wildcard.
- **Upload validation**: file-extension allow-listing (`.eml`/`.msg`/
  `.txt`) on the upload endpoint, plus explicit size checks on both the
  file-upload and raw-paste analyze paths (the old code relied only on
  the global `MAX_CONTENT_LENGTH`).
- **SSRF/defense-in-depth**: the IP passed into the outbound geolocation
  URL is re-validated as a real IP literal immediately before the
  request is built, on top of the existing private/reserved-range
  filtering when IPs are first extracted from headers.
- **Error handling**: a global 500 handler logs the real exception
  server-side but never returns a stack trace or internals to the
  client; 413/429 get clear, generic messages.
- **Password policy**: `require_strong_password()` (12+ chars, 3 of 4
  character classes) is available and used to warn on `seed.py` runs
  that leave the bundled default password in place.

## What changed in behavior (worth knowing)

- `GET /api/cases` is backward-compatible but now supports pagination —
  see above.
- Login responses for a locked account return **423** instead of 401,
  with a generic lockout message.
- The `/api/analyze/*` responses gained new fields: `implausible_travel`
  (array), and each entry in `domain_intelligence` gained `entropy` and
  `typosquat`. Existing fields are unchanged. The frontend (`main.jsx`)
  was updated to display these three additions; nothing else in the UI
  changed.
- Classification/priority thresholds (35/65/85) and the overall
  additive risk-scoring approach were **kept as-is** — only new signals
  were added into the same model — specifically to avoid silently
  shifting every case's risk score/priority in ways that couldn't be
  validated without a live run against your own historical cases.

## Known limitations / honest caveats

- The rate limiter and TTL caches are **in-process** (no Redis). Correct
  for the current single-process deployment; if you ever run multiple
  worker processes, swap them for a shared store — the call sites
  wouldn't need to change.
- The ML training set is still small (~28 examples). Calibration and
  the char-ngram features improve robustness, but this is not a
  substitute for training on real, larger, labeled data if that becomes
  available.
- I could not run the actual app end-to-end in this environment (no
  network to install `flask-cors`/`flask-jwt-extended`/`dnspython`/etc.
  here). Every file passes `py_compile`, and I functionally tested the
  new algorithm/security modules in isolation (typosquat detection,
  entropy, haversine impossible-travel, the calibrated ML pipeline
  against both bundled demo `.eml` files, the rate limiter, and the
  config secret-enforcement logic) using stubbed versions of the
  missing packages. Please do a normal local run-through
  (`pip install -r requirements.txt`, `python seed.py`, `python run.py`)
  before relying on this in anything beyond local testing.
