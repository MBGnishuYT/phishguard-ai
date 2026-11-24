"""URL validation and SSRF-safe network probing.

Threat model: the backend is asked to look at attacker-supplied URLs (redirect chain, TLS info).
An attacker could submit http://169.254.169.254/ (cloud metadata), http://localhost:5432, a DNS name
that resolves to a private address, or a redirect to one of those. Defences:

1. Only http/https, no embedded credentials, ports limited to 80/443/8080/8443.
2. The hostname is resolved by *us*; every returned address must be globally routable.
3. We connect to the validated IP address directly (DNS pinning), so a second, different DNS answer
   (DNS rebinding) cannot redirect the connection.
4. Redirects are never followed automatically; each hop is re-validated from step 1.
5. Only response headers are read (never the body), with short timeouts and hard size caps.
6. No cookies or authorization headers are ever sent.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit, urljoin

ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_URL_LENGTH = 2048
BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".intranet", ".corp", ".home", ".arpa")
_CTRL = re.compile(r"[\x00-\x20\x7f]")


class UrlRejected(ValueError):
    """Raised with a user-safe reason when a URL fails validation."""


def validate_url_syntax(raw: str) -> dict:
    """Validate a URL for *analysis* (no network access). Returns normalised parts."""
    if not isinstance(raw, str) or not raw.strip():
        raise UrlRejected("URL is empty.")
    raw = raw.strip()
    if len(raw) > MAX_URL_LENGTH:
        raise UrlRejected(f"URL is longer than {MAX_URL_LENGTH} characters.")
    if _CTRL.search(raw):
        raise UrlRejected("URL contains spaces or control characters.")
    if "://" not in raw:
        raise UrlRejected("URL must include a scheme such as https://.")
    try:
        sp = urlsplit(raw)
        port = sp.port
    except ValueError:
        raise UrlRejected("URL is malformed.")
    if sp.scheme.lower() not in ("http", "https"):
        raise UrlRejected("Only http and https URLs can be scanned.")
    if not sp.hostname:
        raise UrlRejected("URL has no host name.")
    host = sp.hostname.lower().rstrip(".")
    if len(host) > 253 or any(len(l) > 63 for l in host.split(".")):
        raise UrlRejected("Host name is too long.")
    return {"scheme": sp.scheme.lower(), "host": host, "port": port, "path": sp.path or "/",
            "has_userinfo": "@" in sp.netloc, "query": sp.query}


def redact_query(query: str) -> str:
    """Keep parameter *names* (useful for detection) but drop all values (may hold tokens/PII)."""
    if not query:
        return ""
    names = [k for k, _ in parse_qsl(query, keep_blank_values=True)][:20]
    return "&".join(f"{re.sub(r'[^A-Za-z0-9_.-]', '', n)[:30]}=" for n in names)


def storable_url(parts: dict) -> str:
    """The only form of a URL that is analysed/stored: scheme://host[:port]/path?names-only."""
    host = parts["host"]
    port = f":{parts['port']}" if parts.get("port") else ""
    q = redact_query(parts.get("query", ""))
    return f"{parts['scheme']}://{host}{port}{parts['path'][:300]}" + (f"?{q}" if q else "")


def resolve_public(host: str, port: int) -> str:
    """Resolve host and ensure *every* answer is public. Returns the pinned IP string."""
    h = host.strip("[]").lower()
    if h == "localhost" or h.endswith(BLOCKED_SUFFIXES) or "." not in h and ":" not in h:
        raise UrlRejected("Host is not a public internet address.")
    try:
        infos = socket.getaddrinfo(h, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise UrlRejected("Host name could not be resolved.")
    if not infos:
        raise UrlRejected("Host name could not be resolved.")
    pinned = None
    for fam, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0].split("%")[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global or ip.is_multicast:
            raise UrlRejected("Host resolves to a private or reserved address; refusing to connect.")
        pinned = pinned or str(ip)
    return pinned


def validate_fetch_target(raw: str) -> tuple[dict, str, int]:
    """Full SSRF validation for anything we may connect to. Returns (parts, pinned_ip, port)."""
    parts = validate_url_syntax(raw)
    if parts["has_userinfo"]:
        raise UrlRejected("URLs with embedded credentials are not fetched.")
    port = parts["port"] or (443 if parts["scheme"] == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise UrlRejected("Port is not allowed.")
    return parts, resolve_public(parts["host"], port), port


def _read_headers(sock) -> tuple[int, dict]:
    buf = b""
    deadline = time.monotonic() + 5
    while b"\r\n\r\n" not in buf and len(buf) < 16384 and time.monotonic() < deadline:
        chunk = sock.recv(2048)
        if not chunk:
            break
        buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0] if lines else "")
    if not m:
        raise OSError("Not an HTTP response")
    headers = {}
    for ln in lines[1:60]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()[:2048]
    return int(m.group(1)), headers


def probe_once(raw_url: str, timeout: float = 4.0) -> dict:
    """One pinned-IP HEAD request. Returns status, location header and TLS details. Never reads a body."""
    parts, ip, port = validate_fetch_target(raw_url)
    host = parts["host"]
    tls: dict | None = None
    result: dict = {"host": host, "status": None, "location": None, "tls": None}
    raw = socket.create_connection((ip, port), timeout=timeout)
    raw.settimeout(timeout)
    sock = raw
    try:
        if parts["scheme"] == "https":
            ctx = ssl.create_default_context()
            try:
                sock = ctx.wrap_socket(raw, server_hostname=host)
                tls = _tls_info(sock, verified=True)
            except ssl.SSLError as exc:
                raw.close()
                tls = {"valid": False, "error": (getattr(exc, "verify_message", None) or str(exc))[:160]}
                raw = socket.create_connection((ip, port), timeout=timeout)
                raw.settimeout(timeout)
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                sock = ctx2.wrap_socket(raw, server_hostname=host)
                tls["protocol"] = sock.version()
        path = re.sub(r"[^\x21-\x7e]", "", parts["path"]) or "/"
        req = (f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: PhishGuard-Scanner/1.0\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n")
        sock.sendall(req.encode())
        status, headers = _read_headers(sock)
        result["status"] = status
        loc = headers.get("location")
        if loc and 300 <= status < 400:
            result["location"] = urljoin(raw_url, loc)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    result["tls"] = tls
    return result


def _tls_info(sock: ssl.SSLSocket, verified: bool) -> dict:
    cert = sock.getpeercert() or {}
    fmt = "%b %d %H:%M:%S %Y %Z"
    info: dict = {"valid": verified, "protocol": sock.version(), "error": None}
    try:
        not_after = datetime.strptime(cert["notAfter"], fmt).replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(cert["notBefore"], fmt).replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        info["days_until_expiry"] = (not_after - now).days
        info["cert_age_days"] = (now - not_before).days
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        info["issuer"] = issuer.get("organizationName") or issuer.get("commonName") or "unknown"
    except (KeyError, ValueError):
        pass
    return info


def trace_redirects(url: str, max_hops: int = 5) -> dict:
    """Follow redirects manually with SSRF validation at every hop."""
    chain: list[dict] = []
    current = url
    tls_first = None
    error = None
    for hop in range(max_hops + 1):
        try:
            r = probe_once(current)
        except UrlRejected as exc:
            error = f"blocked: {exc}"
            break
        except (OSError, ssl.SSLError) as exc:
            error = f"connection failed: {type(exc).__name__}"
            break
        if hop == 0:
            tls_first = r["tls"]
        chain.append({"url": storable_url(validate_url_syntax(current)), "status": r["status"]})
        if r["location"]:
            current = r["location"]
            if hop == max_hops:
                error = "too many redirects"
        else:
            break
    hosts = [validate_url_syntax(c["url"])["host"] for c in chain]
    return {"chain": chain, "hosts": hosts, "tls": tls_first, "error": error,
            "final_url": chain[-1]["url"] if chain else None}
