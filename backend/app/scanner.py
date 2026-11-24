"""Combine every evidence source into one explainable verdict.

Score bands: 0-29 safe, 30-69 suspicious, 70-100 phishing.
Confirmed listings (Safe Browsing / URLhaus) force the phishing band.
"""
from __future__ import annotations

from ml.features import BRANDS, SHORTENERS, split_host, is_ip
from ml.predict import get_detector

from .intel import ThreatIntel
from .ssrf import storable_url, trace_redirects, validate_url_syntax, UrlRejected

SAFE_MAX, SUSPICIOUS_MAX = 29, 69

# Registered domains that are genuinely well known. A match on the *registered domain* (not a substring)
# keeps look-alike hosts such as paypal.com.evil.tk from benefiting.
TRUSTED = set(BRANDS.values()) | {
    "google.com", "youtube.com", "wikipedia.org", "github.com", "stackoverflow.com", "mozilla.org",
    "python.org", "cloudflare.com", "reddit.com", "nytimes.com", "bbc.co.uk", "bbc.com", "nasa.gov",
    "gov.uk", "usa.gov", "europa.eu", "mit.edu", "harvard.edu", "stanford.edu", "zoom.us", "slack.com",
    "microsoftonline.com", "live.com", "amazonaws.com", "gstatic.com", "googleapis.com", "npmjs.com", "pypi.org",
}


def verdict_for(score: int) -> str:
    return "safe" if score <= SAFE_MAX else "suspicious" if score <= SUSPICIOUS_MAX else "phishing"


def registered_domain(host: str) -> str:
    _, dom, suf = split_host(host)
    return f"{dom}.{suf}" if suf else dom


class Scanner:
    def __init__(self, intel: ThreatIntel, settings):
        self.intel = intel
        self.settings = settings

    def scan(self, url: str, deep: bool = False, signals: dict | None = None) -> dict:
        parts = validate_url_syntax(url)  # raises UrlRejected
        clean = storable_url(parts)
        host = parts["host"]
        reasons: list[dict] = []
        sources: dict = {}

        # 1. ML model on the URL string
        det = get_detector().predict(clean)
        prob = det["probability"]
        score = prob * 100.0
        for c in det["contributions"]:
            reasons.append({"source": "ml", "severity": "high" if c["impact"] > .15 else "medium", "text": c["reason"]})
        sources["ml"] = {"status": "ok", "probability": round(prob, 4), "model_version": det["model_version"]}

        # 2. Rule-based indicators (deterministic, independent of the model)
        rules_boost = 0
        ip_host = is_ip(host)
        if ip_host:
            rules_boost += 15
        if parts["has_userinfo"]:
            rules_boost += 20
            reasons.append({"source": "rules", "severity": "high", "text": "The URL embeds a username/@ section that can disguise the real host."})
        if det["features"]["typosquat_distance"] <= 2 and det["features"]["typosquat_distance"] != 5:
            rules_boost += 15
        sources["rules"] = {"status": "ok", "boost": rules_boost}
        score = min(100.0, score + rules_boost)

        # 3. Trusted registered domain lowers the model's false-positive risk
        reg = registered_domain(host) if not ip_host else host
        trusted = reg in TRUSTED
        if trusted and not parts["has_userinfo"]:
            score = min(score, 12.0)
            reasons.append({"source": "reputation", "severity": "info", "text": f"{reg} is a well-known domain."})
        sources["reputation"] = {"status": "ok", "trusted_domain": trusted}
        if host in SHORTENERS:  # destination is hidden, so never report it as plainly safe
            score = max(score, 35.0)
            reasons.append({"source": "rules", "severity": "medium", "text": "This is a shortened link; the real destination is hidden until you open it."})

        # 4. Threat feeds (never block on failure; report unavailable honestly)
        confirmed = False
        sb = self.intel.safe_browsing(clean)
        uh = self.intel.urlhaus(clean)
        sources["safe_browsing"], sources["urlhaus"] = sb, uh
        for name, res in (("Google Safe Browsing", sb), ("URLhaus", uh)):
            if res.get("flagged"):
                confirmed = True
                reasons.insert(0, {"source": name.lower().replace(" ", "_"), "severity": "critical", "text": res["detail"]})

        # 5. Optional deep checks: domain age, TLS, redirects (all SSRF-safe)
        if deep and not ip_host and not trusted:
            age = self.intel.domain_age(reg)
            sources["domain_age"] = age
            if age["status"] == "ok" and age["age_days"] is not None:
                if age["age_days"] < 30:
                    score += 20
                    reasons.append({"source": "domain_age", "severity": "high", "text": f"The domain was registered only {age['age_days']} days ago."})
                elif age["age_days"] < 180:
                    score += 8
                    reasons.append({"source": "domain_age", "severity": "medium", "text": f"The domain is fairly new ({age['age_days']} days old)."})
        if deep and self.settings.enable_network_checks:
            tr = trace_redirects(storable_url(parts))
            sources["redirects"] = {"status": "ok" if not tr["error"] or tr["chain"] else "unavailable",
                                    "chain": tr["chain"], "error": tr["error"]}
            if tr["error"] and not tr["chain"]:
                sources["redirects"]["status"] = "unavailable"
            sources["tls"] = tr["tls"] or {"status": "unavailable"}
            regs = [registered_domain(h) for h in tr["hosts"] if not is_ip(h)]
            if len(set(regs)) > 1 and regs[-1] != regs[0] and len(tr["hosts"]) >= 2:
                hops = len(tr["hosts"]) - 1
                bump = 10 if hops <= 2 else 20
                score += bump
                reasons.append({"source": "redirects", "severity": "medium",
                                "text": f"The link redirects through {hops} hop(s) to a different domain ({tr['hosts'][-1]})."})
            if tr["error"] == "too many redirects":
                score += 15
                reasons.append({"source": "redirects", "severity": "high", "text": "The link bounces through an unusually long redirect chain."})
            tls = tr["tls"]
            if parts["scheme"] == "https" and tls and tls.get("valid") is False:
                score += 20
                reasons.append({"source": "tls", "severity": "high", "text": f"The HTTPS certificate is not valid ({tls.get('error', 'verification failed')})."})
            elif tls and tls.get("cert_age_days") is not None and tls["cert_age_days"] < 3 and not trusted:
                score += 5
                reasons.append({"source": "tls", "severity": "low", "text": "The TLS certificate was issued in the last few days."})
        else:
            sources["tls"] = {"status": "disabled", "detail": "Deep scan is off."}
            sources["redirects"] = {"status": "disabled", "detail": "Deep scan is off."}

        # 6. In-page signals reported by the extension (booleans only, never field contents)
        if signals:
            s_boost = 0
            if signals.get("has_password_field") and not trusted:
                s_boost += 8
                reasons.append({"source": "page", "severity": "low", "text": "The page asks for a password."})
                if signals.get("password_form_cross_origin"):
                    s_boost += 25
                    reasons.append({"source": "page", "severity": "high", "text": "The login form sends data to a different website than the one you are on."})
                if parts["scheme"] != "https" or signals.get("password_form_insecure"):
                    s_boost += 15
                    reasons.append({"source": "page", "severity": "high", "text": "The login form is not protected by HTTPS."})
            if signals.get("mismatched_links", 0) >= 2:
                s_boost += 10
                reasons.append({"source": "page", "severity": "medium", "text": "Links on the page show one address but lead to another."})
            if signals.get("hidden_iframes", 0) >= 1 and not trusted:
                s_boost += 8
                reasons.append({"source": "page", "severity": "medium", "text": "The page contains hidden frames."})
            sources["page_signals"] = {"status": "ok", "boost": s_boost}
            score += s_boost

        if confirmed:
            score = max(score, 95.0)
        final = int(round(max(0.0, min(100.0, score))))
        verdict = verdict_for(final)
        if verdict == "safe" and not reasons:
            reasons.append({"source": "ml", "severity": "info", "text": "No phishing indicators were found in the address."})
        return {"url": clean, "host": host, "scheme": parts["scheme"], "path": parts["path"][:300], "risk_score": final,
                "verdict": verdict, "confirmed_threat": confirmed, "ml_probability": round(prob, 4),
                "reasons": reasons[:10], "sources": sources, "deep": deep}
