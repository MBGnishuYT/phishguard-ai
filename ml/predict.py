"""Load the trained model and produce a probability plus human-readable reasons."""
from __future__ import annotations

import threading
from pathlib import Path

import joblib
import numpy as np

from .features import FEATURE_NAMES, extract_features

MODEL_PATH = Path(__file__).parent / "model" / "phishguard_rf.joblib"

# Human-readable explanation for each feature when it pushes the score upward.
REASONS = {
    "has_ip_host": "The address uses a raw IP address instead of a domain name.",
    "has_at_symbol": "The URL contains '@', a trick used to hide the real destination.",
    "brand_in_subdomain": "A well-known brand name appears in the subdomain or domain of a site that does not belong to that brand.",
    "brand_in_path": "A well-known brand name appears in the URL path of a site that does not belong to that brand.",
    "typosquat_distance": "The domain is a near-copy (typosquat) of a well-known brand.",
    "suspicious_keyword_count": "The URL contains several credential/account keywords (login, verify, secure, ...).",
    "keyword_in_host": "The domain name itself contains credential/account keywords.",
    "suspicious_tld": "The domain ends in a top-level domain frequently abused for phishing.",
    "num_subdomains": "The address has an unusually deep chain of subdomains.",
    "num_hyphens_host": "The domain contains many hyphens, common in throwaway phishing domains.",
    "has_punycode": "The domain uses punycode (xn--), which can disguise look-alike characters.",
    "url_length": "The URL is unusually long.", "host_length": "The domain name is unusually long.",
    "host_entropy": "The domain looks randomly generated.", "num_digits_host": "The domain contains many digits.",
    "uses_https": "The page is not served over HTTPS.", "has_port": "The URL uses a non-standard port.",
    "is_shortener": "The link uses a URL shortener that hides the final destination.",
    "long_host_token": "The domain contains an unusually long label.",
    "num_dots": "The domain contains many dots.", "hex_encoding_count": "The URL contains many percent-encoded characters.",
    "domain_has_digit_letter_mix": "The domain mixes digits and letters in a way typical of look-alike domains.",
    "path_length": "The URL path is unusually long.", "path_depth": "The URL path is unusually deep.",
    "digit_ratio_url": "A large share of the URL consists of digits.", "double_slash_in_path": "The URL path contains a '//' redirect-style pattern.",
    "query_length": "The query string is unusually long.", "num_special_chars": "The URL contains unusual special characters.",
}


class Detector:
    def __init__(self, path: Path = MODEL_PATH):
        bundle = joblib.load(path)
        self.model = bundle["model"]
        self.baseline = np.array(bundle["baseline"], dtype=float)
        self.version = bundle.get("version", "unknown")
        self.names = bundle["feature_names"]
        assert self.names == FEATURE_NAMES, "Model was trained with a different feature set - retrain it."

    def predict(self, url: str, top_k: int = 5) -> dict:
        feats = extract_features(url)
        x = np.array([feats[n] for n in self.names], dtype=float)
        p = float(self.model.predict_proba(x.reshape(1, -1))[0, 1])
        # Occlusion explanation: how much does the phishing probability drop if one feature
        # is replaced by its typical value on legitimate URLs?
        variants = np.tile(x, (len(x), 1))
        for i in range(len(x)):
            variants[i, i] = self.baseline[i]
        drops = p - self.model.predict_proba(variants)[:, 1]
        order = np.argsort(-drops)
        contributions = []
        for i in order[:top_k]:
            if drops[i] <= 0.01:
                break
            name = self.names[i]
            contributions.append({"feature": name, "value": round(float(x[i]), 3),
                                  "impact": round(float(drops[i]), 3),
                                  "reason": REASONS.get(name, name.replace("_", " "))})
        return {"probability": p, "contributions": contributions, "model_version": self.version, "features": feats}


_lock = threading.Lock()
_detector: Detector | None = None


def get_detector() -> Detector:
    global _detector
    with _lock:
        if _detector is None:
            if not MODEL_PATH.exists():
                from .train import main as train_main  # first run: train automatically
                import sys
                argv, sys.argv = sys.argv, [sys.argv[0]]
                try:
                    train_main()
                finally:
                    sys.argv = argv
            _detector = Detector()
        return _detector
