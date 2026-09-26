# MAILTRACE AI

AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform.

**Detect → Trace → Correlate → Investigate**

## Implemented

- React/Vite analyst console
- Flask REST API + JWT
- MySQL support with SQLite development fallback
- `.eml` upload and raw-email analysis
- TF-IDF + Logistic Regression NLP model trained on bundled demonstration corpus
- phishing / BEC / impersonation heuristics
- SPF/DKIM/DMARC interpretation from headers
- Reply-To / Return-Path mismatch checks
- URL/domain/IP extraction
- Received-header relay reconstruction
- optional IP geolocation + DNS enrichment
- explainable fraud score 0–100
- IOC correlation graph
- investigation cases, notes and status
- SHA-256 evidence fingerprint
- forensic PDF report
- Leaflet relay map + Chart.js dashboard
- demo `.eml` files

## Windows quick start

### Backend

```powershell
cd backend
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:SEED_ADMIN_EMAIL = 'admin@mailtrace.local'
$env:SEED_ADMIN_PASSWORD = 'LocalOnly-ChangeMe-123!'
python seed.py
python run.py
```

Backend: http://localhost:5001

### Frontend (new terminal)

```powershell
cd frontend
npm install
npm run dev
```

Frontend: http://localhost:5174

Use the `SEED_ADMIN_EMAIL` and `SEED_ADMIN_PASSWORD` values from your local
environment to sign in. The seed command intentionally refuses to create an
account when no password is supplied.

## Production publishing

1. Copy `.env.example` to `.env` in the deployment environment and replace
   every placeholder, especially both signing keys and the admin password.
2. Set `DOMAIN` to the public DNS name, `FLASK_ENV=production`,
   `FORCE_HTTPS=true`, and `CORS_ORIGINS` to the exact HTTPS origin. Never
   publish `.env`.
3. Point the domain's DNS A/AAAA record at the server. Caddy obtains and
   renews the HTTPS certificate automatically.
4. Use MySQL or PostgreSQL with persistent storage; SQLite is for local use.
5. Apply the versioned schema and then create the first admin account:

   ```bash
   cd backend
   flask --app wsgi db upgrade
   python seed.py
   ```

6. Run the backend behind a reverse proxy with the WSGI entrypoint:

   ```bash
   gunicorn -w 4 -k gthread --threads 4 -b 0.0.0.0:5000 wsgi:app
   ```

7. Build the frontend with `VITE_API_URL=/api` when the frontend and API share
   an origin, or set it to the full HTTPS API URL for separate domains:

   ```powershell
   cd frontend
   npm ci
   npm run build
   ```

Serve `frontend/dist` from the HTTPS reverse proxy or a static hosting service.
The local Vite server proxies `/api` to the development backend automatically.

### Container deployment

For a single-host deployment, configure the required variables in `.env`,
point the domain at the host, and run:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

The Caddy container exposes ports `80` and `443`, obtains the certificate for
`DOMAIN`, and proxies HTTPS traffic to the frontend. Do not expose MySQL or the
backend port publicly.

## MySQL

The default is SQLite for zero-friction development. For MySQL set:
`DATABASE_URL=mysql+pymysql://mailtrace:mailtrace@localhost:3306/mailtrace`

Optional Docker:
`docker compose up -d mysql`

## Optional external enrichment

Set `ENABLE_EXTERNAL_INTEL=true`. It uses the configured IP geolocation URL and DNS resolver. Keep disabled for confidential mail unless your organization authorizes external lookups.

## Forensic caveat

Geolocation identifies probable infrastructure, not a person's physical location or identity. IPs may belong to relays, cloud hosts, VPNs, proxies, compromised systems, or legitimate services. Results require corroboration.
