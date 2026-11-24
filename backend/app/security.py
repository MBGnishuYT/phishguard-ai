"""Password hashing (scrypt), JWT helpers, rate limiting and brute-force lockout."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import threading
import time
from collections import defaultdict, deque

import jwt

from .db import Database

# ---- passwords -------------------------------------------------------------
_N, _R, _P = 2 ** 14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return "scrypt$%d$%d$%d$%s$%s" % (_N, _R, _P, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except Exception:
        return False


def password_problems(pw: str) -> list[str]:
    out = []
    if len(pw) < 12:
        out.append("at least 12 characters")
    if pw.lower() == pw or pw.upper() == pw:
        out.append("both upper and lower case letters")
    if not any(c.isdigit() for c in pw):
        out.append("a digit")
    return out


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(hashlib.sha256(a.encode()).digest(), hashlib.sha256(b.encode()).digest())


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


# ---- JWT -------------------------------------------------------------------
def make_jwt(secret: str, sub: str, role: str, minutes: int, scope: str = "dashboard") -> str:
    now = int(time.time())
    return jwt.encode({"sub": sub, "role": role, "scope": scope, "iat": now, "exp": now + minutes * 60,
                       "jti": secrets.token_hex(8)}, secret, algorithm="HS256")


def decode_jwt(secret: str, token: str) -> dict | None:
    try:
        return jwt.decode(token, secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError:
        return None


# ---- rate limiting (in-memory sliding window) ----------------------------------
class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: int = 60) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False, max(1, int(window - (now - q[0])))
            q.append(now)
            if len(self._hits) > 20000:  # bound memory
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] > window][:5000]:
                    self._hits.pop(k, None)
            return True, 0


# ---- brute-force lockout ---------------------------------------------------------
MAX_FAILURES = 5
LOCK_SECONDS = 15 * 60


class Lockout:
    def __init__(self, db: Database):
        self.db = db

    def locked_for(self, key: str) -> int:
        row = self.db.one("SELECT locked_until FROM login_attempts WHERE key=?", (key,))
        if row and row["locked_until"] > time.time():
            return int(row["locked_until"] - time.time())
        return 0

    def fail(self, key: str) -> None:
        row = self.db.one("SELECT failures FROM login_attempts WHERE key=?", (key,))
        failures = (row["failures"] if row else 0) + 1
        locked = time.time() + LOCK_SECONDS if failures >= MAX_FAILURES else 0
        self.db.run("INSERT INTO login_attempts(key,failures,locked_until) VALUES(?,?,?) "
                    "ON CONFLICT(key) DO UPDATE SET failures=excluded.failures, locked_until=excluded.locked_until",
                    (key, 0 if locked else failures, locked))

    def reset(self, key: str) -> None:
        self.db.run("DELETE FROM login_attempts WHERE key=?", (key,))
