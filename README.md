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
python seed.py
python run.py
```
Backend: http://127.0.0.1:5000

### Frontend (new terminal)
```powershell
cd frontend
npm install
npm run dev
```
Frontend: http://localhost:5173

Demo login:
`admin@mailtrace.local` / `ChangeMe123!`

## MySQL
The default is SQLite for zero-friction development. For MySQL set:
`DATABASE_URL=mysql+pymysql://mailtrace:mailtrace@127.0.0.1:3306/mailtrace`

Optional Docker:
`docker compose up -d mysql`

## Optional external enrichment
Set `ENABLE_EXTERNAL_INTEL=true`. It uses the configured IP geolocation URL and DNS resolver. Keep disabled for confidential mail unless your organization authorizes external lookups.

## Forensic caveat
Geolocation identifies probable infrastructure, not a person's physical location or identity. IPs may belong to relays, cloud hosts, VPNs, proxies, compromised systems, or legitimate services. Results require corroboration.
