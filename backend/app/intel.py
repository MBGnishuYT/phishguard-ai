"""Threat-intelligence lookups. Every lookup returns a status dict and NEVER raises.

status values:
  ok           - lookup succeeded (see `flagged`)
  disabled     - not configured (no API key) or network checks switched off
  unavailable  - the service failed, timed out or returned an unexpected answer
Nothing is ever fabricated: if a service cannot be reached the result says so.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from .config import Settings

log = logging.getLogger("phishguard.intel")

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
RDAP_URL = "https://rdap.org/domain/"


class ThreatIntel:
    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        self.s = settings
        self.client = client or httpx.Client(timeout=httpx.Timeout(4.0, connect=3.0), follow_redirects=False,
                                             headers={"User-Agent": "PhishGuard-AI/1.0"})

    # -- Google Safe Browsing (Lookup API v4). Free key from Google Cloud Console. --
    def safe_browsing(self, url: str) -> dict:
        if not self.s.enable_network_checks:
            return {"status": "disabled", "flagged": False, "detail": "Network checks are turned off."}
        if not self.s.safe_browsing_key:
            return {"status": "disabled", "flagged": False, "detail": "No GOOGLE_SAFE_BROWSING_API_KEY configured."}
        body = {"client": {"clientId": "phishguard-ai", "clientVersion": "1.0"},
                "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                                "POTENTIALLY_HARMFUL_APPLICATION"],
                               "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                               "threatEntries": [{"url": url}]}}
        try:
            # key goes in a header, not the query string, so it never appears in URL logs
            r = self.client.post(SAFE_BROWSING_URL, json=body, headers={"x-goog-api-key": self.s.safe_browsing_key})
            if r.status_code != 200:
                return {"status": "unavailable", "flagged": False, "detail": f"Safe Browsing returned HTTP {r.status_code}."}
            matches = r.json().get("matches", [])
            if matches:
                kinds = sorted({m.get("threatType", "UNKNOWN") for m in matches})
                return {"status": "ok", "flagged": True, "detail": "Listed by Google Safe Browsing: " + ", ".join(kinds)}
            return {"status": "ok", "flagged": False, "detail": "Not listed by Google Safe Browsing."}
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("safe browsing failed: %s", type(exc).__name__)
            return {"status": "unavailable", "flagged": False, "detail": "Google Safe Browsing could not be reached."}

    # -- URLhaus (abuse.ch). Requires a free Auth-Key from https://auth.abuse.ch/ --
    def urlhaus(self, url: str) -> dict:
        if not self.s.enable_network_checks:
            return {"status": "disabled", "flagged": False, "detail": "Network checks are turned off."}
        if not self.s.urlhaus_auth_key:
            return {"status": "disabled", "flagged": False, "detail": "No URLHAUS_AUTH_KEY configured."}
        try:
            r = self.client.post(URLHAUS_URL, data={"url": url}, headers={"Auth-Key": self.s.urlhaus_auth_key})
            if r.status_code != 200:
                return {"status": "unavailable", "flagged": False, "detail": f"URLhaus returned HTTP {r.status_code}."}
            data = r.json()
            qs = data.get("query_status")
            if qs == "ok":
                if data.get("url_status") == "online" or data.get("threat"):
                    return {"status": "ok", "flagged": True,
                            "detail": f"Listed in URLhaus ({data.get('threat', 'malware')}, status {data.get('url_status')})."}
                return {"status": "ok", "flagged": True, "detail": "Previously listed in URLhaus (now offline)."}
            if qs in ("no_results", "invalid_url"):
                return {"status": "ok", "flagged": False, "detail": "Not listed in URLhaus."}
            return {"status": "unavailable", "flagged": False, "detail": f"URLhaus answered '{qs}'."}
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("urlhaus failed: %s", type(exc).__name__)
            return {"status": "unavailable", "flagged": False, "detail": "URLhaus could not be reached."}

    # -- Domain reputation: age from RDAP (public registration data, no key required) --
    def domain_age(self, registered_domain: str) -> dict:
        if not self.s.enable_network_checks:
            return {"status": "disabled", "age_days": None, "detail": "Network checks are turned off."}
        try:
            r = self.client.get(RDAP_URL + registered_domain, follow_redirects=True, timeout=5.0)
            if r.status_code != 200:
                return {"status": "unavailable", "age_days": None, "detail": f"RDAP returned HTTP {r.status_code}."}
            for ev in r.json().get("events", []):
                if ev.get("eventAction") == "registration":
                    created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    days = (datetime.now(timezone.utc) - created).days
                    return {"status": "ok", "age_days": days, "detail": f"Domain registered {days} days ago."}
            return {"status": "unavailable", "age_days": None, "detail": "No registration date published."}
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            log.warning("rdap failed: %s", type(exc).__name__)
            return {"status": "unavailable", "age_days": None, "detail": "Domain registration data could not be fetched."}
