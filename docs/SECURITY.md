# Security model

## Data handling
| Never collected or stored | Stored (and visible to admins in the vault) |
|---|---|
| passwords, cookies, auth tokens, form values, page text, screenshots, query-string values, URL fragments | scheme, host, path, query *parameter names only*, risk score, verdict, reasons, timestamp, anonymous install id |

The extension strips query values/fragments/credentials **before** sending (`lib.js: redactUrl`); the backend strips them again
(`ssrf.py: redact_query`). Intranet/localhost/private-range addresses are never sent. Tested in both languages.

## "Screen monitoring"
Recording or screenshotting a user's screen would capture banking pages, messages and passwords - exactly what this tool must not collect,
and Chrome extensions cannot silently do it anyway. Instead the optional **Screen watch** analyses page *structure* locally
(login form posting to another domain, misleading link text, hidden frames) and sends five booleans/counters. It is off by default,
needs an explicit Chrome permission, and the API rejects any extra fields.

## Admin vault (the "master key" panel)
* Needs: (1) an admin account with password, then (2) the server's `ADMIN_MASTER_KEY`, compared in constant time.
* Unlock yields a 10-minute vault token bound to that admin; failures lock the vault for 15 minutes after 5 attempts.
* Every unlock, failed unlock, data view, security check, user creation and purge is written to the audit log (visible in the vault).
* It is intentionally **not secret or hidden**: a hidden panel with one shared key and no audit trail is a backdoor, not a safeguard.
  Users are told what is collected (extension Options -> Privacy, dashboard Settings).
* The key lives only in an environment variable on the server; it is never in code, the database or the frontend.
* The vault's **Security check** tab audits the live configuration (production mode, persistent JWT secret, key strength, hashed passwords,
  no query strings stored, CORS, retention, model present) and tells you how to fix each failure.

## Controls
SSRF (see header of `backend/app/ssrf.py`): public-IP-only, DNS pinning, per-hop redirect validation, header-only reads, port allow-list.
Auth: scrypt password hashes, short-lived HS256 JWTs, lockout, constant-time compare, generic error messages.
API: strict pydantic schemas (`extra=forbid`), 2048-char URL cap, 32 KB body cap, per-IP and per-install rate limits, parameterised SQL.
Browser: minimal permissions (`storage`, `webNavigation`, `notifications`, `scripting`; `localhost:8000` host access). Access to all sites and to your
own server origin is *optional* and requested at the moment you enable the feature. Dashboard CSP forbids inline/remote scripts and all data is rendered via `textContent`.
Install tokens are stored hashed. API keys exist only in server environment variables.

## Known limits
* Rate-limit counters are in-memory per process (use a single instance or add Redis for multi-instance).
* JWT is kept in `sessionStorage`; a cookie-based session with CSRF protection is a possible hardening step.
* The extension register endpoint is anonymous by design (rate-limited); abuse can inflate install counts.
* This build has had automated tests only; it has not had an independent penetration test.
