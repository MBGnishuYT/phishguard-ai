import os, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "import.db"))

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.app.config import Settings
from backend.app.intel import ThreatIntel
from backend.app.main import create_app

ADMIN_PW = "Sup3rSecretAdminPw"
MASTER = "master-key-for-tests-0123456789"


def make_settings(tmp_path, **kw) -> Settings:
    s = Settings()
    s.database_path = str(tmp_path / "t.db")
    s.jwt_secret = "j" * 48
    s.ephemeral_jwt = False
    s.admin_username, s.admin_password, s.admin_master_key = "admin", ADMIN_PW, MASTER
    s.safe_browsing_key = kw.get("sb_key", "test-sb-key")
    s.urlhaus_auth_key = kw.get("uh_key", "test-uh-key")
    s.enable_network_checks = kw.get("network", True)
    s.rate_limit_scan_per_min = kw.get("scan_limit", 1000)
    s.rate_limit_auth_per_min = kw.get("auth_limit", 1000)
    return s


def mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def clean_handler(request: httpx.Request) -> httpx.Response:
    if "safebrowsing" in request.url.host:
        return httpx.Response(200, json={})
    if "urlhaus" in request.url.host:
        return httpx.Response(200, json={"query_status": "no_results"})
    return httpx.Response(404)


@pytest.fixture
def make_app(tmp_path):
    def _make(handler=clean_handler, **kw):
        s = make_settings(tmp_path, **kw)
        app = create_app(s, ThreatIntel(s, mock_client(handler)))
        return TestClient(app), s
    return _make


@pytest.fixture
def client(make_app):
    with make_app()[0] as c:
        yield c


@pytest.fixture
def install_headers(client):
    tok = client.post("/api/v1/extension/register").json()["install_token"]
    return {"X-Install-Token": tok}


@pytest.fixture
def admin_headers(client):
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PW})
    return {"Authorization": "Bearer " + r.json()["access_token"]}
