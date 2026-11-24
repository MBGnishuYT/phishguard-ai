"""Training data for PhishGuard.

IMPORTANT - read before trusting the metrics:
The bundled dataset is *synthetic*. It is generated locally from original
templates (no third-party data is copied, so there are no licensing issues).
It mimics well-known phishing URL patterns (brand-in-subdomain, typosquatting,
IP hosts, risky TLDs, credential keywords) and legitimate URL shapes, but real
attackers are more varied. Scores measured on it are therefore optimistic.

For production, retrain on real feeds:
    python -m ml.train --phish-csv openphish_or_urlhaus.csv --legit-csv tranco.csv
(see docs/DEPLOYMENT.md for where to get them and their licences).
"""
from __future__ import annotations

import csv
import random
import string
from pathlib import Path

from .features import BRANDS, SUSPICIOUS_TLDS

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "github.com", "stackoverflow.com", "amazon.com",
    "microsoft.com", "apple.com", "paypal.com", "netflix.com", "linkedin.com", "reddit.com",
    "nytimes.com", "bbc.co.uk", "cnn.com", "mozilla.org", "python.org", "nasa.gov", "who.int",
    "harvard.edu", "mit.edu", "stanford.edu", "dropbox.com", "adobe.com", "cloudflare.com",
    "wordpress.org", "medium.com", "twitter.com", "facebook.com", "instagram.com", "whatsapp.com",
    "zoom.us", "slack.com", "spotify.com", "ebay.com", "etsy.com", "walmart.com", "target.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "coinbase.com", "binance.com", "steampowered.com",
    "fedex.com", "dhl.com", "hdfcbank.com", "icicibank.com", "sbi.co.in", "irctc.co.in", "flipkart.com",
    "gov.uk", "usa.gov", "europa.eu", "ox.ac.uk", "imdb.com", "bing.com", "yahoo.com", "duckduckgo.com",
    "docs.python.org", "developer.mozilla.org", "arxiv.org", "nature.com", "bbc.com", "reuters.com",
    "theguardian.com", "weather.com", "booking.com", "airbnb.com", "tripadvisor.com", "quora.com",
    "office.com", "outlook.com", "icloud.com", "twitch.tv", "gitlab.com", "npmjs.com", "pypi.org",
]
LEGIT_SUBS = ["www", "", "", "", "accounts", "mail", "docs", "support", "login", "m", "en", "blog", "help", "shop", "api"]
LEGIT_PATHS = [
    "", "/", "/index.html", "/about", "/contact", "/news/world", "/search?q=weather", "/products/item/12345",
    "/login", "/signin", "/account/settings", "/help/article/security", "/support", "/docs/getting-started",
    "/wiki/Machine_learning", "/blog/2024/05/new-features", "/pricing", "/careers", "/privacy", "/terms",
    "/watch?v=dQw4w9WgXcQ", "/user/profile", "/cart", "/checkout", "/en-us/download", "/store/apps",
]
WORDS = ["secure", "login", "verify", "account", "update", "signin", "billing", "support", "alert", "confirm",
         "wallet", "service", "online", "portal", "helpdesk", "recovery", "unlock", "customer", "access"]
RISKY_TLDS = sorted(SUSPICIOUS_TLDS)
CHEAP_TLDS = ["com", "net", "org", "info", "co", "online", "site", "xyz", "top", "click", "tk", "ml", "ga", "cf"]
BRAND_LIST = sorted(BRANDS)


def _rand_label(rng: random.Random, lo=5, hi=12) -> str:
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(rng.randint(lo, hi)))


def _typo(brand: str, rng: random.Random) -> str:
    kind = rng.choice(["swap", "homoglyph", "drop", "double", "hyphen", "insert"])
    b = list(brand)
    i = rng.randrange(len(b))
    if kind == "swap" and len(b) > 3:
        i = rng.randrange(len(b) - 1)
        b[i], b[i + 1] = b[i + 1], b[i]
    elif kind == "homoglyph":
        m = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}
        idx = [k for k, c in enumerate(b) if c in m]
        if idx:
            k = rng.choice(idx)
            b[k] = m[b[k]]
    elif kind == "drop" and len(b) > 4:
        del b[i]
    elif kind == "double":
        b.insert(i, b[i])
    elif kind == "hyphen":
        b.insert(rng.randrange(1, len(b)), "-")
    else:
        b.insert(i, rng.choice(string.ascii_lowercase))
    return "".join(b)


def gen_legit(rng: random.Random) -> str:
    dom = rng.choice(LEGIT_DOMAINS)
    sub = rng.choice(LEGIT_SUBS)
    host = f"{sub}.{dom}" if sub and not dom.startswith("www.") else dom
    scheme = "https" if rng.random() < 0.96 else "http"
    return f"{scheme}://{host}{rng.choice(LEGIT_PATHS)}"


def gen_phish(rng: random.Random) -> str:
    kind = rng.choice(["brand_sub", "typo", "ip", "keywords", "at", "risky_tld", "punycode", "long", "brand_path", "numeric_mix"])
    brand = rng.choice(BRAND_LIST)
    word = rng.choice(WORDS)
    tld = rng.choice(CHEAP_TLDS)
    scheme = "http" if rng.random() < 0.6 else "https"
    path = rng.choice(["/login", "/signin.php", "/verify/account", "/update", "/secure/login.html", "/webscr?cmd=_login",
                       "/auth/confirm?id=" + _rand_label(rng), "/", "/index.php", "/account/unlock"])
    if kind == "brand_sub":
        host = f"{brand}.{word}.{_rand_label(rng)}.{rng.choice(RISKY_TLDS + ['com'])}"
        if rng.random() < .5:
            host = f"{word}-{brand}.com.{_rand_label(rng)}.{tld}"
    elif kind == "typo":
        host = f"{_typo(brand, rng)}.{rng.choice(['com', 'net', 'co', 'org'] + RISKY_TLDS[:6])}"
        if rng.random() < .4:
            host = "www." + host
    elif kind == "ip":
        host = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        path = f"/{brand}/{word}" + rng.choice(["", ".php", "/index.html"])
    elif kind == "keywords":
        host = f"{word}-{rng.choice(WORDS)}-{brand}.{tld}"
    elif kind == "at":
        host = f"{brand}.com@{_rand_label(rng)}.{tld}"
        return f"{scheme}://{host}{path}"
    elif kind == "risky_tld":
        host = f"{brand}{word}.{rng.choice(RISKY_TLDS)}"
    elif kind == "punycode":
        host = f"xn--{_rand_label(rng, 6, 10)}-{rng.choice(['9ua', 'k1a', 'dma'])}.{brand}.{tld}"
    elif kind == "long":
        host = f"{word}.{brand}.{rng.choice(WORDS)}.{_rand_label(rng, 18, 26)}.{tld}"
        path += "/" + _rand_label(rng, 20, 40)
    elif kind == "brand_path":
        host = f"{_rand_label(rng)}.{rng.choice(CHEAP_TLDS)}"
        path = f"/{brand}/{word}/login.php"
    else:
        host = f"{brand}{rng.randint(10, 9999)}-{word}.{tld}"
    port = rng.choice(["", "", "", ":8080", ":8443"])
    return f"{scheme}://{host}{port}{path}"


def generate_synthetic(n_per_class: int = 4000, seed: int = 1337) -> list[tuple[str, int]]:
    rng = random.Random(seed)
    rows: list[tuple[str, int]] = []
    seen: set[str] = set()
    for label, gen in ((0, gen_legit), (1, gen_phish)):
        count, tries = 0, 0
        while count < n_per_class and tries < n_per_class * 20:
            tries += 1
            u = gen(rng)
            if u in seen:
                continue
            seen.add(u)
            rows.append((u, label))
            count += 1
    rng.shuffle(rows)
    return rows


def load_csv(path: str | Path, label: int, url_column: str = "url", limit: int | None = None) -> list[tuple[str, int]]:
    """Load URLs from a CSV (header with `url`, or one URL per line / Tranco `rank,domain` format)."""
    rows: list[tuple[str, int]] = []
    with open(path, newline="", encoding="utf-8", errors="ignore") as fh:
        sample = fh.read(2048)
        fh.seek(0)
        has_header = url_column in sample.splitlines()[0].lower().split(",") if sample else False
        reader = csv.reader(fh)
        idx = 0
        if has_header:
            header = [h.strip().lower() for h in next(reader)]
            idx = header.index(url_column)
        for r in reader:
            if not r or r[0].startswith("#"):
                continue
            val = (r[idx] if len(r) > idx else r[-1]).strip()
            if not val:
                continue
            rows.append((val, label))
            if limit and len(rows) >= limit:
                break
    return rows


def write_csv(rows: list[tuple[str, int]], path: str | Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label"])
        w.writerows(rows)
