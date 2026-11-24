"""All configuration comes from environment variables (see .env.example). No secrets live in code."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_dotenv() -> None:
    env = ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    env: str = field(default_factory=lambda: os.getenv("PHISHGUARD_ENV", "development"))
    database_path: str = field(default_factory=lambda: os.getenv("DATABASE_PATH", str(ROOT / "database" / "phishguard.db")))
    # JWT signing key. If missing we generate an ephemeral one (sessions reset on restart) and warn.
    jwt_secret: str = field(default_factory=lambda: os.getenv("JWT_SECRET", ""))
    jwt_minutes: int = field(default_factory=lambda: int(os.getenv("JWT_EXPIRE_MINUTES", "60")))
    admin_username: str = field(default_factory=lambda: os.getenv("ADMIN_USERNAME", "admin"))
    admin_password: str = field(default_factory=lambda: os.getenv("ADMIN_PASSWORD", ""))
    # Second factor for the Admin Vault. Only a hash is kept in memory; compare in constant time.
    admin_master_key: str = field(default_factory=lambda: os.getenv("ADMIN_MASTER_KEY", ""))
    vault_minutes: int = field(default_factory=lambda: int(os.getenv("VAULT_SESSION_MINUTES", "10")))
    safe_browsing_key: str = field(default_factory=lambda: os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", ""))
    urlhaus_auth_key: str = field(default_factory=lambda: os.getenv("URLHAUS_AUTH_KEY", ""))
    enable_network_checks: bool = field(default_factory=lambda: _bool("ENABLE_NETWORK_CHECKS", True))
    cors_origins: list[str] = field(default_factory=lambda: [o for o in os.getenv("CORS_ORIGINS", "").split(",") if o])
    rate_limit_scan_per_min: int = field(default_factory=lambda: int(os.getenv("RATE_LIMIT_SCAN_PER_MIN", "120")))
    rate_limit_auth_per_min: int = field(default_factory=lambda: int(os.getenv("RATE_LIMIT_AUTH_PER_MIN", "10")))
    retention_days: int = field(default_factory=lambda: int(os.getenv("RETENTION_DAYS", "90")))
    trust_proxy: bool = field(default_factory=lambda: _bool("TRUST_PROXY_HEADERS", False))

    def __post_init__(self) -> None:
        self.ephemeral_jwt = False
        if len(self.jwt_secret) < 32:
            self.jwt_secret = secrets.token_urlsafe(48)
            self.ephemeral_jwt = True

    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"


def get_settings() -> Settings:
    return Settings()
