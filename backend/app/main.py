"""PhishGuard AI - FastAPI backend.

Run:  uvicorn backend.app.main:app --host 0.0.0.0 --port 8000   (from the project root)
"""
from __future__ import annotations

import json
import logging
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from ml.predict import MODEL_PATH, get_detector

from .config import ROOT, Settings, get_settings
from .db import Database
from .intel import ThreatIntel
from .scanner import Scanner
from .security import (Lockout, RateLimiter, constant_time_equals, decode_jwt, hash_password, make_jwt,
                       new_token, password_problems, sha256_hex, verify_password)
from .ssrf import UrlRejected

log = logging.getLogger("phishguard")
DASHBOARD_DIR = ROOT / "dashboard"


# ---------------------------------------------------------------- schemas
class PageSignals(BaseModel):
    """Booleans/counters computed inside the browser. Never contains page text, cookies or field values."""
    model_config = ConfigDict(extra="forbid")
    has_password_field: bool = False
    password_form_cross_origin: bool = False
    password_form_insecure: bool = False
    mismatched_links: int = Field(0, ge=0, le=500)
    hidden_iframes: int = Field(0, ge=0, le=100)


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(..., min_length=1, max_length=2048)
    deep: bool = False
    signals: PageSignals | None = None
    record: bool = True


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(..., max_length=256)
    new_password: str = Field(..., max_length=256)


class VaultUnlock(BaseModel):
    model_config = ConfigDict(extra="forbid")
    master_key: str = Field(..., min_length=1, max_length=256)


class NewUser(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(..., max_length=256)
    role: Literal["admin", "analyst"] = "analyst"


class Purge(BaseModel):
    model_config = ConfigDict(extra="forbid")
    older_than_days: int = Field(..., ge=0, le=3650)


# ---------------------------------------------------------------- app factory
def create_app(settings: Settings | None = None, intel: ThreatIntel | None = None) -> FastAPI:
    s = settings or get_settings()
    db = Database(s.database_path)
    limiter = RateLimiter()
    lockout = Lockout(db)
    scanner = Scanner(intel or ThreatIntel(s), s)

    def audit(actor: str, action: str, detail: str = "", ip: str = "") -> None:
        db.run("INSERT INTO audit_log(actor,action,detail,ip) VALUES(?,?,?,?)", (actor, action, detail[:500], ip))

    def bootstrap_admin() -> None:
        if db.one("SELECT 1 FROM users WHERE username=?", (s.admin_username,)):
            return
        pw = s.admin_password
        if not pw:
            if s.is_production:
                raise RuntimeError("ADMIN_PASSWORD must be set in production.")
            pw = secrets.token_urlsafe(12) + "aA1"
            log.warning("DEV ONLY - generated admin password for '%s': %s  (set ADMIN_PASSWORD to choose your own)",
                        s.admin_username, pw)
        if password_problems(pw) and s.is_production:
            raise RuntimeError("ADMIN_PASSWORD is too weak: needs " + ", ".join(password_problems(pw)))
        db.run("INSERT INTO users(username,password_hash,role) VALUES(?,?,'admin')", (s.admin_username, hash_password(pw)))
        audit("system", "admin_bootstrap", f"admin user '{s.admin_username}' created")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if s.is_production and s.ephemeral_jwt:
            raise RuntimeError("JWT_SECRET (>=32 chars) must be set in production.")
        if s.ephemeral_jwt:
            log.warning("JWT_SECRET not set: using an ephemeral key; dashboard sessions reset on restart.")
        bootstrap_admin()
        db.run("DELETE FROM scans WHERE created_at < strftime('%Y-%m-%dT%H:%M:%fZ','now',?)", (f"-{s.retention_days} days",))
        try:
            get_detector()
        except Exception:  # model missing and cannot be trained
            log.exception("ML model could not be loaded")
        yield
        db.close()

    app = FastAPI(title="PhishGuard AI", version="1.0.0", lifespan=lifespan,
                  docs_url=None if s.is_production else "/docs", redoc_url=None, openapi_url=None if s.is_production else "/openapi.json")
    app.state.db, app.state.settings, app.state.scanner = db, s, scanner

    if s.cors_origins:
        from fastapi.middleware.cors import CORSMiddleware
        app.add_middleware(CORSMiddleware, allow_origins=s.cors_origins, allow_methods=["GET", "POST"],
                           allow_headers=["Authorization", "Content-Type", "X-Install-Token", "X-Vault-Token"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if int(request.headers.get("content-length") or 0) > 32_768:
            return JSONResponse({"detail": "Request body too large."}, status_code=413)
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api") else resp.headers.get("Cache-Control", "no-cache")
        if request.url.path not in ("/docs", "/openapi.json"):
            resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self'; "
                                                       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if s.is_production:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError):
        msgs = [f"{'.'.join(str(p) for p in e['loc'][1:])}: {e['msg']}" for e in exc.errors()][:5]
        return JSONResponse({"detail": "Invalid request: " + "; ".join(msgs)}, status_code=422)

    # ---------------------------------------------------------------- helpers
    def client_ip(request: Request) -> str:
        if s.trust_proxy:
            fwd = request.headers.get("x-forwarded-for")
            if fwd:
                return fwd.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def limit(request: Request, bucket: str, per_min: int, extra: str = "") -> None:
        ok, retry = limiter.allow(f"{bucket}:{client_ip(request)}:{extra}", per_min)
        if not ok:
            raise HTTPException(429, f"Too many requests. Retry in {retry}s.", headers={"Retry-After": str(retry)})

    def current_user(request: Request, authorization: str | None = Header(None)) -> dict:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "Authentication required.", headers={"WWW-Authenticate": "Bearer"})
        claims = decode_jwt(s.jwt_secret, authorization[7:].strip())
        if not claims or claims.get("scope") != "dashboard":
            raise HTTPException(401, "Invalid or expired session.", headers={"WWW-Authenticate": "Bearer"})
        row = db.one("SELECT username, role, active FROM users WHERE username=?", (claims["sub"],))
        if not row or not row["active"]:
            raise HTTPException(401, "Account is disabled.")
        return {"username": row["username"], "role": row["role"]}

    def require_admin(user: dict = Depends(current_user)) -> dict:
        if user["role"] != "admin":
            raise HTTPException(403, "Administrator access required.")
        return user

    def vault_user(request: Request, user: dict = Depends(require_admin), x_vault_token: str | None = Header(None)) -> dict:
        claims = decode_jwt(s.jwt_secret, x_vault_token or "")
        if not claims or claims.get("scope") != "vault" or claims.get("sub") != user["username"]:
            raise HTTPException(403, "Vault is locked. Enter the master key.")
        return user

    def scan_caller(request: Request, x_install_token: str | None = Header(None), authorization: str | None = Header(None)) -> dict:
        if x_install_token:
            row = db.one("SELECT id FROM installs WHERE token_hash=?", (sha256_hex(x_install_token),))
            if not row:
                raise HTTPException(401, "Unknown installation. Register the extension again.")
            db.run("UPDATE installs SET last_seen=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?", (row["id"],))
            return {"install_id": row["id"], "key": f"i{row['id']}"}
        if authorization:
            u = current_user(request, authorization)
            return {"install_id": None, "key": "u" + u["username"]}
        raise HTTPException(401, "Provide X-Install-Token (extension) or a dashboard session.")

    # ---------------------------------------------------------------- public
    @app.get("/health")
    def health():
        return {"status": "ok", "model_loaded": MODEL_PATH.exists(), "time": time.time()}

    @app.get("/")
    def root():
        return RedirectResponse("/dashboard/")

    @app.post("/api/v1/extension/register")
    def register(request: Request):
        limit(request, "register", 10)
        token = new_token()
        db.run("INSERT INTO installs(token_hash) VALUES(?)", (sha256_hex(token),))
        return {"install_token": token}

    @app.post("/api/v1/scan")
    def scan(body: ScanRequest, request: Request, caller: dict = Depends(scan_caller)):
        limit(request, "scan", s.rate_limit_scan_per_min, caller["key"])
        try:
            result = scanner.scan(body.url, deep=body.deep, signals=body.signals.model_dump() if body.signals else None)
        except UrlRejected as exc:
            raise HTTPException(422, f"Invalid URL: {exc}")
        if body.record:
            db.run("INSERT INTO scans(install_id,scheme,host,path,risk_score,verdict,ml_probability,sources,reasons) VALUES(?,?,?,?,?,?,?,?,?)",
                   (caller["install_id"], result["scheme"], result["host"], result["path"], result["risk_score"], result["verdict"],
                    result["ml_probability"], json.dumps(result["sources"]), json.dumps(result["reasons"])))
        return result

    # ---------------------------------------------------------------- auth
    @app.post("/api/v1/auth/login")
    def login(body: LoginRequest, request: Request):
        limit(request, "auth", s.rate_limit_auth_per_min)
        ip = client_ip(request)
        key = f"login:{body.username.lower()}:{ip}"
        wait = lockout.locked_for(key)
        if wait:
            raise HTTPException(429, f"Too many failed attempts. Try again in {wait // 60 + 1} minutes.")
        row = db.one("SELECT * FROM users WHERE username=?", (body.username,))
        ok = verify_password(body.password, row["password_hash"]) if row else verify_password(body.password, hash_password("x"))
        if not row or not ok or not row["active"]:
            lockout.fail(key)
            audit(body.username[:64], "login_failed", "", ip)
            raise HTTPException(401, "Incorrect username or password.")
        lockout.reset(key)
        audit(row["username"], "login", "", ip)
        return {"access_token": make_jwt(s.jwt_secret, row["username"], row["role"], s.jwt_minutes),
                "token_type": "bearer", "expires_in": s.jwt_minutes * 60, "username": row["username"], "role": row["role"]}

    @app.post("/api/v1/auth/change-password")
    def change_password(body: PasswordChange, request: Request, user: dict = Depends(current_user)):
        limit(request, "auth", s.rate_limit_auth_per_min)
        row = db.one("SELECT password_hash FROM users WHERE username=?", (user["username"],))
        if not verify_password(body.current_password, row["password_hash"]):
            raise HTTPException(401, "Current password is incorrect.")
        problems = password_problems(body.new_password)
        if problems:
            raise HTTPException(422, "New password needs: " + ", ".join(problems) + ".")
        db.run("UPDATE users SET password_hash=? WHERE username=?", (hash_password(body.new_password), user["username"]))
        audit(user["username"], "password_changed", "", client_ip(request))
        return {"ok": True}

    @app.get("/api/v1/me")
    def me(user: dict = Depends(current_user)):
        return {**user, "retention_days": s.retention_days, "vault_configured": bool(s.admin_master_key)}

    # ---------------------------------------------------------------- dashboard data
    @app.get("/api/v1/stats")
    def stats(days: int = Query(14, ge=1, le=90), user: dict = Depends(current_user)):
        counts = {r["verdict"]: r["n"] for r in db.all("SELECT verdict, COUNT(*) n FROM scans GROUP BY verdict")}
        total = sum(counts.values())
        buckets = [0] * 10
        for r in db.all("SELECT risk_score/10 AS b, COUNT(*) n FROM scans GROUP BY b"):
            buckets[min(9, r["b"])] += r["n"]
        daily = db.all("SELECT substr(created_at,1,10) d, verdict, COUNT(*) n FROM scans "
                       "WHERE created_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now',?) GROUP BY d, verdict ORDER BY d", (f"-{days} days",))
        return {"total": total, "safe": counts.get("safe", 0), "suspicious": counts.get("suspicious", 0),
                "phishing": counts.get("phishing", 0), "risk_distribution": buckets,
                "daily": [{"date": r["d"], "verdict": r["verdict"], "count": r["n"]} for r in daily],
                "active_installs": db.one("SELECT COUNT(*) n FROM installs WHERE last_seen >= strftime('%Y-%m-%dT%H:%M:%fZ','now','-7 days')")["n"]}

    @app.get("/api/v1/history")
    def history(verdict: Literal["safe", "suspicious", "phishing"] | None = None, search: str = Query("", max_length=100),
                limit_: int = Query(50, alias="limit", ge=1, le=200), offset: int = Query(0, ge=0, le=100000),
                user: dict = Depends(current_user)):
        where, params = [], []
        if verdict:
            where.append("verdict=?"); params.append(verdict)
        if search:
            where.append("host LIKE ? ESCAPE '\\'"); params.append("%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        rows = db.all(f"SELECT id, scheme, host, path, risk_score, verdict, reasons, created_at FROM scans {w} ORDER BY id DESC LIMIT ? OFFSET ?",
                      tuple(params) + (limit_, offset))
        total = db.one(f"SELECT COUNT(*) n FROM scans {w}", tuple(params))["n"]
        return {"total": total, "items": [{**{k: r[k] for k in ("id", "scheme", "host", "path", "risk_score", "verdict", "created_at")},
                                           "reasons": json.loads(r["reasons"])} for r in rows]}

    @app.get("/api/v1/reports/threats")
    def threat_report(user: dict = Depends(current_user)):
        top = db.all("SELECT host, COUNT(*) n, MAX(risk_score) max_score, MAX(created_at) last_seen FROM scans "
                     "WHERE verdict='phishing' GROUP BY host ORDER BY n DESC, max_score DESC LIMIT 15")
        reason_counts: dict[str, int] = {}
        for r in db.all("SELECT reasons FROM scans WHERE verdict!='safe' ORDER BY id DESC LIMIT 2000"):
            for it in json.loads(r["reasons"]):
                if it.get("severity") != "info":
                    reason_counts[it["text"]] = reason_counts.get(it["text"], 0) + 1
        top_reasons = sorted(reason_counts.items(), key=lambda kv: -kv[1])[:10]
        return {"top_phishing_hosts": [dict(r) for r in top], "top_reasons": [{"reason": k, "count": v} for k, v in top_reasons]}

    @app.get("/api/v1/model")
    def model_info(user: dict = Depends(current_user)):
        p = Path(MODEL_PATH).parent / "metrics.json"
        return json.loads(p.read_text()) if p.exists() else {"detail": "No metrics file found. Run python -m ml.train."}

    # ---------------------------------------------------------------- admin vault (2nd factor: master key)
    @app.post("/api/v1/admin/unlock")
    def vault_unlock(body: VaultUnlock, request: Request, user: dict = Depends(require_admin)):
        limit(request, "vault", s.rate_limit_auth_per_min)
        ip = client_ip(request)
        if not s.admin_master_key:
            raise HTTPException(503, "Admin vault is disabled: set ADMIN_MASTER_KEY on the server.")
        key = f"vault:{user['username']}"
        wait = lockout.locked_for(key)
        if wait:
            raise HTTPException(429, f"Vault locked after repeated failures. Try again in {wait // 60 + 1} minutes.")
        if not constant_time_equals(body.master_key, s.admin_master_key):
            lockout.fail(key)
            audit(user["username"], "vault_unlock_failed", "", ip)
            raise HTTPException(403, "Master key is incorrect.")
        lockout.reset(key)
        audit(user["username"], "vault_unlock", f"valid {s.vault_minutes} min", ip)
        return {"vault_token": make_jwt(s.jwt_secret, user["username"], "admin", s.vault_minutes, scope="vault"),
                "expires_in": s.vault_minutes * 60}

    @app.get("/api/v1/admin/data")
    def vault_data(request: Request, limit_: int = Query(100, alias="limit", ge=1, le=500), offset: int = Query(0, ge=0),
                   user: dict = Depends(vault_user)):
        audit(user["username"], "vault_view_data", f"limit={limit_} offset={offset}", client_ip(request))
        scans = [dict(r) for r in db.all("SELECT id, install_id, scheme, host, path, risk_score, verdict, ml_probability, sources, reasons, created_at "
                                         "FROM scans ORDER BY id DESC LIMIT ? OFFSET ?", (limit_, offset))]
        return {"scans": scans, "total_scans": db.one("SELECT COUNT(*) n FROM scans")["n"],
                "installs": [dict(r) for r in db.all("SELECT id, created_at, last_seen FROM installs ORDER BY id DESC LIMIT 200")],
                "users": [dict(r) for r in db.all("SELECT id, username, role, active, created_at FROM users ORDER BY id")],
                "collected_fields": ["scheme", "host", "path (no query values)", "risk score", "verdict", "reasons", "timestamp", "anonymous install id"],
                "never_collected": ["passwords", "cookies", "authentication tokens", "page contents", "form field values", "query-string values", "screenshots"]}

    @app.get("/api/v1/admin/audit")
    def vault_audit(request: Request, user: dict = Depends(vault_user)):
        return {"entries": [dict(r) for r in db.all("SELECT ts, actor, action, detail, ip FROM audit_log ORDER BY id DESC LIMIT 300")]}

    @app.get("/api/v1/admin/security-check")
    def security_check(request: Request, user: dict = Depends(vault_user)):
        audit(user["username"], "vault_security_check", "", client_ip(request))
        leaked_q = db.one("SELECT COUNT(*) n FROM scans WHERE path LIKE '%?%' OR path LIKE '%#%'")["n"]
        admin_row = db.one("SELECT password_hash FROM users WHERE role='admin' LIMIT 1")
        checks = [
            ("Running in production mode", s.is_production, "Set PHISHGUARD_ENV=production."),
            ("JWT signing secret is persistent and >= 32 chars", not s.ephemeral_jwt, "Set JWT_SECRET so sessions survive restarts."),
            ("Master key is configured and >= 16 chars", len(s.admin_master_key) >= 16, "Set a long random ADMIN_MASTER_KEY."),
            ("Admin password stored as scrypt hash", bool(admin_row and admin_row["password_hash"].startswith("scrypt$")), "Reset the admin password."),
            ("No query strings/fragments stored in scan history", leaked_q == 0, f"{leaked_q} rows contain '?' or '#'. Purge them."),
            ("Google Safe Browsing enabled", bool(s.safe_browsing_key), "Optional: add GOOGLE_SAFE_BROWSING_API_KEY for live feed checks."),
            ("URLhaus enabled", bool(s.urlhaus_auth_key), "Optional: add URLHAUS_AUTH_KEY."),
            ("Wildcard CORS not used", "*" not in s.cors_origins, "Remove '*' from CORS_ORIGINS."),
            ("Data retention limit set", 0 < s.retention_days <= 365, "Set RETENTION_DAYS (e.g. 90)."),
            ("ML model file present", Path(MODEL_PATH).exists(), "Run python -m ml.train."),
        ]
        return {"checks": [{"name": n, "passed": bool(ok), "fix": None if ok else fix} for n, ok, fix in checks],
                "score": round(100 * sum(1 for _, ok, _ in checks if ok) / len(checks))}

    @app.post("/api/v1/admin/users")
    def vault_create_user(body: NewUser, request: Request, user: dict = Depends(vault_user)):
        problems = password_problems(body.password)
        if problems:
            raise HTTPException(422, "Password needs: " + ", ".join(problems) + ".")
        if db.one("SELECT 1 FROM users WHERE username=?", (body.username,)):
            raise HTTPException(409, "Username already exists.")
        db.run("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)", (body.username, hash_password(body.password), body.role))
        audit(user["username"], "user_created", f"{body.username} ({body.role})", client_ip(request))
        return {"ok": True}

    @app.post("/api/v1/admin/purge")
    def vault_purge(body: Purge, request: Request, user: dict = Depends(vault_user)):
        with db.tx() as c:
            n = c.execute("DELETE FROM scans WHERE created_at < strftime('%Y-%m-%dT%H:%M:%fZ','now',?)", (f"-{body.older_than_days} days",)).rowcount
        audit(user["username"], "data_purged", f"older than {body.older_than_days} days: {n} rows", client_ip(request))
        return {"deleted": n}

    if DASHBOARD_DIR.exists():
        app.mount("/dashboard", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")
    return app


app = create_app()
