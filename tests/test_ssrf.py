import socket
import pytest
from backend.app import ssrf
from backend.app.ssrf import UrlRejected, validate_fetch_target, validate_url_syntax, redact_query


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/", "http://192.168.1.1/admin",
    "http://172.16.0.9/", "http://[::1]/", "http://0x7f000001/", "http://2130706433/", "http://0177.0.0.1/", "http://[::ffff:127.0.0.1]/",
    "http://user:pw@example.com/", "http://example.com:22/", "http://example.com:5432/", "http://service.internal/", "http://printer.local/",
    "http://0.0.0.0/", "http://100.64.0.1/", "ftp://example.com/", "file:///etc/passwd", "gopher://example.com/",
])
def test_private_and_dangerous_targets_blocked(url):
    with pytest.raises(UrlRejected):
        validate_fetch_target(url)


def test_dns_resolving_to_private_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", p))])
    with pytest.raises(UrlRejected):
        validate_fetch_target("http://innocent.example.com/")


def test_mixed_dns_answers_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p)),
                                                                   (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", p))])
    with pytest.raises(UrlRejected):
        validate_fetch_target("http://rebind.example.com/")


def test_public_ip_allowed_and_pinned(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))])
    parts, ip, port = validate_fetch_target("https://example.com/a")
    assert ip == "93.184.216.34" and port == 443


class FakeSock:
    def __init__(self, response: bytes):
        self.response, self.sent = response, b""
    def settimeout(self, t): pass
    def sendall(self, b): self.sent += b
    def recv(self, n):
        r, self.response = self.response[:n], self.response[n:]
        return r
    def close(self): pass


def test_redirect_to_private_address_is_blocked(monkeypatch):
    table = {"good.example": "93.184.216.34", "evil.example": "127.0.0.1"}
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (table[h], p))])
    connected = []
    def fake_conn(addr, timeout=None):
        connected.append(addr)
        return FakeSock(b"HTTP/1.1 302 Found\r\nLocation: http://evil.example/steal\r\n\r\n")
    monkeypatch.setattr(socket, "create_connection", fake_conn)
    out = ssrf.trace_redirects("http://good.example/")
    assert out["error"].startswith("blocked")
    assert connected == [("93.184.216.34", 80)], "must connect only to the pinned public IP, never to 127.0.0.1"


def test_redirect_chain_followed_and_limited(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))])
    monkeypatch.setattr(socket, "create_connection", lambda a, timeout=None: FakeSock(b"HTTP/1.1 301 Moved\r\nLocation: /loop\r\n\r\n"))
    out = ssrf.trace_redirects("http://loop.example/")
    assert out["error"] == "too many redirects"


def test_query_redaction():
    assert redact_query("token=abc&session=xyz") == "token=&session="
    assert "abc" not in redact_query("a=abc&b=<script>")
    assert validate_url_syntax("https://a.com/p?x=1")["host"] == "a.com"
