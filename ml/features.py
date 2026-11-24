"""URL feature extraction shared by training and the live API.

Only the URL string itself is analysed here (no network access), so the same
function produces identical features at training time and at prediction time.
"""
from __future__ import annotations

import ipaddress
import math
import re
from urllib.parse import urlsplit

# Brands most commonly impersonated. Used for typosquatting / brand-abuse checks.
BRANDS = {
    "paypal": "paypal.com", "google": "google.com", "microsoft": "microsoft.com",
    "apple": "apple.com", "amazon": "amazon.com", "facebook": "facebook.com",
    "instagram": "instagram.com", "netflix": "netflix.com", "linkedin": "linkedin.com",
    "dropbox": "dropbox.com", "github": "github.com", "twitter": "twitter.com",
    "whatsapp": "whatsapp.com", "outlook": "outlook.com", "office365": "office.com",
    "chase": "chase.com", "wellsfargo": "wellsfargo.com", "bankofamerica": "bankofamerica.com",
    "citibank": "citi.com", "coinbase": "coinbase.com", "binance": "binance.com",
    "steam": "steampowered.com", "adobe": "adobe.com", "dhl": "dhl.com",
    "fedex": "fedex.com", "icloud": "icloud.com", "yahoo": "yahoo.com", "hdfc": "hdfcbank.com",
    "sbi": "sbi.co.in", "icici": "icicibank.com",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure", "account", "update",
    "confirm", "banking", "password", "passwd", "credential", "wallet", "suspend", "suspended",
    "unlock", "recover", "billing", "invoice", "payment", "support", "alert", "security",
    "authenticate", "validate", "webscr", "ebayisapi", "limited", "restore", "reward", "prize",
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "work", "zip", "mov",
    "country", "kim", "loan", "men", "party", "review", "science", "stream", "support",
    "download", "racing", "win", "bid", "cyou", "icu", "rest", "monster", "buzz",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

# Small set of multi-part public suffixes so that "bbc.co.uk" is split correctly.
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "net.in",
    "org.in", "co.jp", "com.br", "com.cn", "co.za", "com.mx", "co.nz", "com.sg", "com.tr",
}

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length", "num_dots", "num_hyphens_host",
    "num_digits_host", "digit_ratio_url", "num_subdomains", "has_ip_host", "has_at_symbol",
    "uses_https", "has_port", "has_punycode", "suspicious_keyword_count", "keyword_in_host",
    "suspicious_tld", "is_shortener", "host_entropy", "brand_in_subdomain", "brand_in_path",
    "typosquat_distance", "path_depth", "num_special_chars", "double_slash_in_path",
    "hex_encoding_count", "long_host_token", "domain_has_digit_letter_mix",
]


# Other registered domains genuinely owned by the brands above, and country suffixes where the
# brand label alone is normal (google.co.in, amazon.de, ...). These must never count as typosquats.
EXTRA_LEGIT_DOMAINS = {
    "github.io", "githubusercontent.com", "live.com", "microsoftonline.com", "googleusercontent.com",
    "gstatic.com", "googleapis.com", "amazonaws.com", "amazon.co.uk", "icloud.com", "office.com",
    "paypal.me", "fb.com", "youtu.be", "x.com",
}
BRAND_COUNTRY_SUFFIXES = {"co.uk", "co.in", "in", "de", "fr", "co.jp", "jp", "com.au", "ca", "com.br", "es", "it", "nl", "com.mx", "co.za", "com.sg", "com.tr", "ch", "se"}


def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def split_host(host: str) -> tuple[str, str, str]:
    """Return (subdomain, registered_domain_label, suffix) for a hostname."""
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) < 2:
        return "", host, ""
    last2 = ".".join(parts[-2:])
    if last2 in MULTI_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[:-3]), parts[-3], last2
    return ".".join(parts[:-2]), parts[-2], parts[-1]


def is_ip(host: str) -> bool:
    """True for IPv4/IPv6 literals and for decimal/hex/octal-looking numeric hosts."""
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Obfuscated forms such as 2130706433, 0x7f000001 or 0177.0.0.1
    return bool(re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", host, re.I))


def entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})


def typosquat_match(host: str) -> tuple[str | None, int]:
    """Closest impersonated brand and edit distance.

    Returns (None, 99) for the genuine brand domain or when nothing is close.
    Distance 0 means the brand label appears on a domain the brand does not own
    after de-obfuscation (e.g. paypa1.com -> paypal).
    """
    sub, domain, suffix = split_host(host)
    registered = f"{domain}.{suffix}" if suffix else domain
    if registered in BRANDS.values() or registered in EXTRA_LEGIT_DOMAINS:
        return None, 99
    if domain in BRANDS and suffix in BRAND_COUNTRY_SUFFIXES:
        return None, 99
    best: tuple[str | None, int] = (None, 99)
    candidates = {domain, domain.translate(_HOMOGLYPHS), domain.replace("-", "")}
    for cand in candidates:
        for brand in BRANDS:
            if len(brand) < 4:
                if cand == brand:
                    return brand, 0
                continue
            d = levenshtein(cand, brand)
            if d < best[1] and d <= 2 and d <= max(1, len(brand) // 4):
                best = (brand, d)
    return best


def extract_parts(url: str) -> dict:
    url = normalize_url(url)
    sp = urlsplit(url)
    host = (sp.hostname or "").lower()
    try:
        port = sp.port
    except ValueError:
        port = None
    return {"url": url, "scheme": sp.scheme, "host": host, "port": port, "path": sp.path or "",
            "query": sp.query or "", "netloc": sp.netloc}


def extract_features(url: str) -> dict[str, float]:
    p = extract_parts(url)
    host, path, query, full = p["host"], p["path"], p["query"], p["url"]
    ip_host = is_ip(host)
    sub, domain, suffix = split_host(host) if not ip_host else ("", host, "")
    lower_all = (host + path + query).lower()
    kw_count = sum(1 for k in SUSPICIOUS_KEYWORDS if k in lower_all)
    kw_host = sum(1 for k in SUSPICIOUS_KEYWORDS if k in host)
    brand_sub = brand_path = 0
    if not ip_host:
        registered = f"{domain}.{suffix}"
        for brand, legit in BRANDS.items():
            if registered == legit or registered.endswith("." + legit):
                continue
            if brand in sub or (brand in domain and domain != brand):
                brand_sub = 1
            if brand in path.lower():
                brand_path = 1
    brand, dist = typosquat_match(host) if not ip_host else (None, 99)
    labels = host.split(".")
    specials = sum(full.count(c) for c in "!$%^*()+={}[]|;:'<>,~`")
    feats = {
        "url_length": len(full), "host_length": len(host), "path_length": len(path),
        "query_length": len(query), "num_dots": host.count("."), "num_hyphens_host": host.count("-"),
        "num_digits_host": sum(c.isdigit() for c in host),
        "digit_ratio_url": sum(c.isdigit() for c in full) / max(1, len(full)),
        "num_subdomains": len([s for s in sub.split(".") if s]) if sub else 0,
        "has_ip_host": int(ip_host), "has_at_symbol": int("@" in p["netloc"]),
        "uses_https": int(p["scheme"] == "https"), "has_port": int(p["port"] not in (None, 80, 443)),
        "has_punycode": int(any(l.startswith("xn--") for l in labels)),
        "suspicious_keyword_count": kw_count, "keyword_in_host": kw_host,
        "suspicious_tld": int(suffix.split(".")[-1] in SUSPICIOUS_TLDS), "is_shortener": int(host in SHORTENERS),
        "host_entropy": entropy(host), "brand_in_subdomain": brand_sub, "brand_in_path": brand_path,
        "typosquat_distance": dist if brand else 5,
        "path_depth": len([s for s in path.split("/") if s]), "num_special_chars": specials,
        "double_slash_in_path": int("//" in path), "hex_encoding_count": len(re.findall(r"%[0-9a-fA-F]{2}", full)),
        "long_host_token": int(any(len(l) > 20 for l in labels)),
        "domain_has_digit_letter_mix": int(bool(re.search(r"[a-z]\d|\d[a-z]", domain)) and not ip_host),
    }
    return {k: float(feats[k]) for k in FEATURE_NAMES}


def feature_vector(url: str) -> list[float]:
    f = extract_features(url)
    return [f[n] for n in FEATURE_NAMES]
