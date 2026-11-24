# Deployment, Chrome install and GitHub

## 1. Put the code on GitHub
```bash
cd phishguard
git init -b main
git add . && git status          # confirm .env, *.db and node_modules are NOT listed
git commit -m "PhishGuard AI: initial commit"
# create an EMPTY repo on github.com (no README/licence), then:
git remote add origin https://github.com/<you>/phishguard-ai.git
git push -u origin main
```
Never commit `.env`. If a secret ever lands in git history, rotate it - deleting the file is not enough.
GitHub Actions (`.github/workflows/ci.yml`) then runs all tests on every push.
Optional: protect `main` (Settings -> Branches) and enable Dependabot + secret scanning.

## 2. Run the backend in the cloud (Render example)
1. Render.com -> New -> **Blueprint** -> select your GitHub repo (it reads `render.yaml`).
2. Enter the secrets when prompted: `ADMIN_PASSWORD` (12+ chars, mixed case, digit), `ADMIN_MASTER_KEY` (16+ random chars; e.g.
   `python -c "import secrets;print(secrets.token_urlsafe(24))"`), and optionally `GOOGLE_SAFE_BROWSING_API_KEY`, `URLHAUS_AUTH_KEY`.
   `JWT_SECRET` is generated for you.
3. Deploy. Your API endpoint is `https://<service>.onrender.com`. Verify:
   ```bash
   curl https://<service>.onrender.com/health          # {"status":"ok","model_loaded":true,...}
   ```
4. Open `https://<service>.onrender.com/dashboard/` and sign in as `admin`.

Notes: SQLite needs the persistent disk in `render.yaml` (paid plan). On a free plan the database resets on each deploy - fine for
demos, not for real use. The same `Dockerfile` works on Fly.io, Railway, Google Cloud Run (set `PORT`; use a volume or move to Postgres)
or any VPS: `docker build -t phishguard . && docker run -p 8000:8000 --env-file .env -v pgdata:/data phishguard`.
Production refuses to start without `JWT_SECRET` and a strong `ADMIN_PASSWORD`.

**Free API keys (optional):**
Google Safe Browsing - Google Cloud Console -> enable "Safe Browsing API" -> create an API key (check their usage terms; free for non-commercial use).
URLhaus - free Auth-Key at https://auth.abuse.ch/ . Put both in the server environment, never in the extension.

## 3. Load the extension in Chrome
1. Open `chrome://extensions`, switch on **Developer mode** (top right).
2. **Load unpacked** -> choose the `extension/` folder. Pin the shield icon. Options page opens automatically.
3. In Options -> **Server**, enter `https://<service>.onrender.com` -> **Save & test connection** -> allow Chrome's permission prompt.
   (For local testing leave the default `http://127.0.0.1:8000`.)
4. Optional: tick **Screen watch** and accept Chrome's permission prompt.

Manual checklist (about 5 minutes - do this once; automated tests cannot open a real Chrome):
- [ ] Visit https://www.wikipedia.org -> badge shows OK, no alert.
- [ ] Popup shows score, reasons, recent scans; the ON/OFF switch changes the badge to OFF.
- [ ] Dashboard shows the scans within a few seconds.
- [ ] To see the blocking page safely, temporarily make a test URL: `http://paypa1-secure-login.example-test.tk/signin` (it does not resolve; the block
      happens before the page loads) -> warning page + desktop notification appear; "Take me to safety" works.
- [ ] Stop the server, browse again -> popup says "Backend unreachable - offline check".
- [ ] "Trust this site" then revisit -> no scan; remove it in Options.

## 4. Retrain with real data (strongly recommended)
Download a phishing URL list and a legitimate list (check each licence/terms; e.g. URLhaus CSV exports, OpenPhish community feed,
PhishTank (registration), Tranco top sites). Save as CSVs with a `url` header (Tranco `rank,domain` files also work), then:
```bash
python -m ml.train --phish-csv phishing_urls.csv --legit-csv legit_urls.csv
```
Commit `ml/model/metrics.json`; the dashboard's **Detection model** tab shows the new metrics. Rebuild/redeploy the image.

## 5. Updating the extension for a store release
Bump `version` in `manifest.json`, zip the contents of `extension/`, upload in the Chrome Web Store developer dashboard (one-time fee, privacy policy required -
you can adapt the Privacy section in Options).
