import json
import httpx
import pytest

from .conftest import ADMIN_PW, MASTER, clean_handler
from .samples import SAFE_URLS, PHISHING_PATTERN_URLS, SUSPICIOUS_PATTERN_URLS, INVALID_URLS


def scan(client, headers, url, **kw):
    return client.post("/api/v1/scan", json={"url": url, **kw}, headers=headers)


# ---------------- classification ----------------
@pytest.mark.parametrize("url", SAFE_URLS)
def test_safe_urls_are_safe(client, install_headers, url):
    r = scan(client, install_headers, url)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["verdict"] == "safe", (url, d["risk_score"], d["reasons"])
    assert 0 <= d["risk_score"] <= 29


@pytest.mark.parametrize("url", PHISHING_PATTERN_URLS)
def test_phishing_patterns_are_flagged(client, install_headers, url):
    d = scan(client, install_headers, url).json()
    assert d["verdict"] == "phishing", (url, d["risk_score"])
    assert d["risk_score"] >= 70
    assert d["reasons"], "every verdict must be explained"


@pytest.mark.parametrize("url", SUSPICIOUS_PATTERN_URLS)
def test_suspicious_patterns_not_safe(client, install_headers, url):
    d = scan(client, install_headers, url).json()
    assert d["verdict"] in ("suspicious", "phishing"), (url, d["risk_score"])


def test_score_range_and_shape(client, install_headers):
    d = scan(client, install_headers, "https://www.google.com/").json()
    for k in ("risk_score", "verdict", "reasons", "sources", "ml_probability", "confirmed_threat"):
        assert k in d
    assert isinstance(d["risk_score"], int) and 0 <= d["risk_score"] <= 100


def test_lookalike_of_trusted_domain_does_not_get_trusted(client, install_headers):
    d = scan(client, install_headers, "https://paypal.com.account-verify.example-test.tk/login").json()
    assert d["verdict"] == "phishing"


# ---------------- invalid input ----------------
@pytest.mark.parametrize("url", INVALID_URLS)
def test_invalid_urls_rejected(client, install_headers, url):
    r = scan(client, install_headers, url)
    assert r.status_code == 422, (url, r.status_code)
    assert "detail" in r.json()


def test_unknown_fields_rejected(client, install_headers):
    r = client.post("/api/v1/scan", json={"url": "https://a.com/", "cookies": "x"}, headers=install_headers)
    assert r.status_code == 422


def test_signals_cannot_carry_extra_data(client, install_headers):
    r = client.post("/api/v1/scan", json={"url": "https://a.com/", "signals": {"has_password_field": True, "password_value": "hunter2"}}, headers=install_headers)
    assert r.status_code == 422


def test_page_signals_raise_score(client, install_headers):
    url = "http://login-portal.example-test.org/"
    base = scan(client, install_headers, url).json()["risk_score"]
    boosted = scan(client, install_headers, url, signals={"has_password_field": True, "password_form_cross_origin": True}).json()
    assert boosted["risk_score"] > base
    assert any("different website" in r["text"] for r in boosted["reasons"])


# ---------------- threat intel + API failures ----------------
def test_safe_browsing_hit_forces_phishing(make_app):
    def h(req):
        if "safebrowsing" in req.url.host:
            return httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})
        return clean_handler(req)
    c, _ = make_app(h)
    with c:
        tok = c.post("/api/v1/extension/register").json()["install_token"]
        d = c.post("/api/v1/scan", json={"url": "https://innocent-looking.example.org/"}, headers={"X-Install-Token": tok}).json()
    assert d["verdict"] == "phishing" and d["confirmed_threat"] and d["risk_score"] >= 95
    assert "Safe Browsing" in d["reasons"][0]["text"]


def test_urlhaus_hit_forces_phishing(make_app):
    def h(req):
        if "urlhaus" in req.url.host:
            return httpx.Response(200, json={"query_status": "ok", "url_status": "online", "threat": "malware_download"})
        return clean_handler(req)
    c, _ = make_app(h)
    with c:
        tok = c.post("/api/v1/extension/register").json()["install_token"]
        d = c.post("/api/v1/scan", json={"url": "https://innocent-looking.example.org/x.exe"}, headers={"X-Install-Token": tok}).json()
    assert d["verdict"] == "phishing" and d["sources"]["urlhaus"]["flagged"]


@pytest.mark.parametrize("failure", ["http500", "timeout", "badjson", "connect"])
def test_api_failures_degrade_gracefully(make_app, failure):
    def h(req):
        if failure == "http500":
            return httpx.Response(500, text="boom")
        if failure == "timeout":
            raise httpx.ReadTimeout("slow", request=req)
        if failure == "connect":
            raise httpx.ConnectError("down", request=req)
        return httpx.Response(200, content=b"<html>not json")
    c, _ = make_app(h)
    with c:
        tok = c.post("/api/v1/extension/register").json()["install_token"]
        r = c.post("/api/v1/scan", json={"url": "https://www.google.com/"}, headers={"X-Install-Token": tok})
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["sources"]["safe_browsing"]["status"] == "unavailable"
        assert d["sources"]["urlhaus"]["status"] == "unavailable"
        assert d["verdict"] == "safe"  # ML + rules still work
        bad = c.post("/api/v1/scan", json={"url": "http://paypa1-secure-login.example-test.tk/signin"}, headers={"X-Install-Token": tok}).json()
        assert bad["verdict"] == "phishing"


def test_works_without_api_keys(make_app):
    c, _ = make_app(sb_key="", uh_key="")
    with c:
        tok = c.post("/api/v1/extension/register").json()["install_token"]
        d = c.post("/api/v1/scan", json={"url": "https://www.google.com/"}, headers={"X-Install-Token": tok}).json()
    assert d["sources"]["safe_browsing"]["status"] == "disabled" and d["verdict"] == "safe"


def test_api_key_never_in_response(client, install_headers):
    assert "test-sb-key" not in scan(client, install_headers, "https://www.google.com/").text


# ---------------- privacy ----------------
def test_query_values_never_stored(client, install_headers, admin_headers):
    scan(client, install_headers, "https://example.org/reset?token=SUPERSECRET123&session=abc#frag")
    unlock = client.post("/api/v1/admin/unlock", json={"master_key": MASTER}, headers=admin_headers).json()
    data = client.get("/api/v1/admin/data", headers={**admin_headers, "X-Vault-Token": unlock["vault_token"]})
    assert "SUPERSECRET123" not in data.text and "session=abc" not in data.text and "frag" not in data.text


# ---------------- auth & access control ----------------
def test_scan_requires_credentials(client):
    assert client.post("/api/v1/scan", json={"url": "https://a.com/"}).status_code == 401
    assert client.post("/api/v1/scan", json={"url": "https://a.com/"}, headers={"X-Install-Token": "bogus"}).status_code == 401


@pytest.mark.parametrize("path", ["/api/v1/stats", "/api/v1/history", "/api/v1/reports/threats", "/api/v1/me", "/api/v1/model",
                                  "/api/v1/admin/data", "/api/v1/admin/audit", "/api/v1/admin/security-check"])
def test_dashboard_endpoints_protected(client, path):
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"Authorization": "Bearer not.a.jwt"}).status_code == 401


def test_login_flow_and_bad_password(client):
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PW})
    assert r.status_code == 200 and r.json()["role"] == "admin"


def test_login_lockout(client):
    for _ in range(5):
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "nope"})
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PW})
    assert r.status_code == 429


def test_rate_limit_scan(make_app):
    c, _ = make_app(scan_limit=3)
    with c:
        tok = c.post("/api/v1/extension/register").json()["install_token"]
        codes = [c.post("/api/v1/scan", json={"url": "https://a.com/"}, headers={"X-Install-Token": tok}).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and 429 in codes[3:]


def test_install_token_stored_hashed(client, tmp_path):
    tok = client.post("/api/v1/extension/register").json()["install_token"]
    db = client.app.state.db
    assert db.one("SELECT 1 FROM installs WHERE token_hash=?", (tok,)) is None


def test_change_password_rules(client, admin_headers):
    r = client.post("/api/v1/auth/change-password", json={"current_password": ADMIN_PW, "new_password": "short"}, headers=admin_headers)
    assert r.status_code == 422
    r = client.post("/api/v1/auth/change-password", json={"current_password": ADMIN_PW, "new_password": "BrandNewStrongPw9"}, headers=admin_headers)
    assert r.status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": "BrandNewStrongPw9"}).status_code == 200


# ---------------- admin vault ----------------
def test_vault_requires_master_key(client, admin_headers):
    assert client.get("/api/v1/admin/data", headers=admin_headers).status_code == 403
    assert client.post("/api/v1/admin/unlock", json={"master_key": "wrong"}, headers=admin_headers).status_code == 403
    ok = client.post("/api/v1/admin/unlock", json={"master_key": MASTER}, headers=admin_headers)
    assert ok.status_code == 200
    h = {**admin_headers, "X-Vault-Token": ok.json()["vault_token"]}
    assert client.get("/api/v1/admin/data", headers=h).status_code == 200
    sc = client.get("/api/v1/admin/security-check", headers=h).json()
    assert sc["checks"] and 0 <= sc["score"] <= 100
    audit = client.get("/api/v1/admin/audit", headers=h).json()["entries"]
    assert any(e["action"] == "vault_unlock" for e in audit) and any(e["action"] == "vault_unlock_failed" for e in audit)


def test_analyst_cannot_use_vault(client, admin_headers):
    ok = client.post("/api/v1/admin/unlock", json={"master_key": MASTER}, headers=admin_headers).json()
    vh = {**admin_headers, "X-Vault-Token": ok["vault_token"]}
    assert client.post("/api/v1/admin/users", json={"username": "ann", "password": "AnalystPassw0rdX", "role": "analyst"}, headers=vh).status_code == 200
    tok = client.post("/api/v1/auth/login", json={"username": "ann", "password": "AnalystPassw0rdX"}).json()["access_token"]
    ah = {"Authorization": "Bearer " + tok}
    assert client.get("/api/v1/stats", headers=ah).status_code == 200
    assert client.post("/api/v1/admin/unlock", json={"master_key": MASTER}, headers=ah).status_code == 403
    assert client.get("/api/v1/admin/data", headers={**ah, "X-Vault-Token": ok["vault_token"]}).status_code == 403


def test_vault_lockout_after_failures(client, admin_headers):
    for _ in range(5):
        client.post("/api/v1/admin/unlock", json={"master_key": "bad"}, headers=admin_headers)
    assert client.post("/api/v1/admin/unlock", json={"master_key": MASTER}, headers=admin_headers).status_code == 429


def test_vault_disabled_without_master_key(make_app):
    c, s = make_app()
    s.admin_master_key = ""
    with c:
        h = {"Authorization": "Bearer " + c.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PW}).json()["access_token"]}
        assert c.post("/api/v1/admin/unlock", json={"master_key": "anything"}, headers=h).status_code == 503


# ---------------- dashboard data ----------------
def test_stats_history_reports(client, install_headers, admin_headers):
    for u in SAFE_URLS[:3] + PHISHING_PATTERN_URLS[:2]:
        scan(client, install_headers, u)
    st = client.get("/api/v1/stats", headers=admin_headers).json()
    assert st["total"] == 5 and st["safe"] == 3 and st["phishing"] == 2 and sum(st["risk_distribution"]) == 5
    h = client.get("/api/v1/history?verdict=phishing", headers=admin_headers).json()
    assert h["total"] == 2 and all(i["verdict"] == "phishing" for i in h["items"])
    assert client.get("/api/v1/history?search=%25%27%3B--", headers=admin_headers).status_code == 200  # injection-safe
    rep = client.get("/api/v1/reports/threats", headers=admin_headers).json()
    assert len(rep["top_phishing_hosts"]) == 2 and rep["top_reasons"]


def test_security_headers(client):
    r = client.get("/health")
    assert r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff" and "script-src 'self'" in r.headers["content-security-policy"]


def test_oversized_body_rejected(client, install_headers):
    r = client.post("/api/v1/scan", content=b"x" * 40000, headers={**install_headers, "Content-Type": "application/json"})
    assert r.status_code == 413
