# Super Split

Cybersecurity site: threat intelligence feed (NVD, CISA KEV, EPSS, RSS) with Gemini summaries, threat level meter, security posture quiz, privacy and hygiene directory, and managed security consultation booking.

## Run locally
```
npm install
cp .env.example .env      # set SESSION_SECRET (32+ chars) and SETTINGS_SECRET
npm run create-admin      # prompts for admin email and password
npm start                 # http://127.0.0.1:3001
npm run backfill          # optional: fill history for the threat meter
npm test
```
Gemini and NVD keys are entered in the Admin tab (stored AES-256-GCM encrypted) or set in `.env`.

## Deploy (Azure Ubuntu VM)
1. Install Node 22, Nginx, PM2. Clone the repo to `~/super-split`, create `.env` (NODE_ENV=production).
2. Copy `nginx/super-split.conf`, replace `yourdomain.tech`, get ZeroSSL certificates, enable the TLS blocks.
3. `./deploy.sh production` (or `staging`, which uses port 3002, RUN_JOBS=false and its own DB via a separate `.env`/DB_PATH).
4. GitHub Actions: add secrets `VM_HOST`, `VM_USER`, `VM_SSH_KEY`; push to `main` deploys production, `staging` deploys staging.

## API
`GET /api/meter`, `/api/feed`, `/api/feed/digest`, `/api/directory`; `POST /api/auth/register|login|logout`, `GET /api/me`; `POST /api/quiz/results`; `POST /api/bookings`; admin-only `/api/admin/*`.

## Security notes
Helmet strict CSP, JSON-only writes, rate limits, bcrypt (bcryptjs, cost 12), session regeneration on login, admin accounts only via CLI, encrypted API keys, AI output sanitised and prompts fence untrusted data.

## Before launch
- Verify feed URLs in `config/feeds.json` and each source's terms of use.
- `data/quiz.json` and the quiz in `public/app.js` must stay in sync.
- Live ingest against NVD/CISA/EPSS/Gemini was not exercised in development; run Admin > "Run now" and check the job log.
