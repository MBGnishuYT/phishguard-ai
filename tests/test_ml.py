import json
from pathlib import Path

import pytest

from ml.features import FEATURE_NAMES, extract_features, split_host, typosquat_match, is_ip, feature_vector
from ml.predict import get_detector
from ml.dataset import generate_synthetic


def test_feature_vector_is_stable_and_complete():
    f = extract_features("https://www.example.com/a?b=1")
    assert list(f) == FEATURE_NAMES and len(feature_vector("http://a.com")) == len(FEATURE_NAMES)


@pytest.mark.parametrize("url,key,expected", [
    ("http://192.0.2.1/login", "has_ip_host", 1), ("http://0x7f000001/", "has_ip_host", 1), ("https://example.com", "has_ip_host", 0),
    ("http://netflix.com@198.51.100.1/", "has_at_symbol", 1), ("https://a.b.c.example.com/", "num_subdomains", 3),
    ("http://x.tk/", "suspicious_tld", 1), ("https://x.com/", "uses_https", 1), ("http://x.com/", "uses_https", 0),
    ("https://paypal.com.evil.tk/", "brand_in_subdomain", 1), ("https://www.paypal.com/", "brand_in_subdomain", 0),
    ("https://xn--pypal-4ve.com/", "has_punycode", 1), ("http://bit.ly/x", "is_shortener", 1),
])
def test_individual_features(url, key, expected):
    assert extract_features(url)[key] == expected


def test_typosquat_detection():
    for typo in ["paypa1.com", "gooogle.com", "micros0ft.com", "faceb00k.com"]:
        brand, d = typosquat_match(typo)
        assert brand is not None and d <= 2, typo
    for ok in ["paypal.com", "google.com", "bbc.co.uk", "example.com", "github.io"]:
        assert typosquat_match(ok)[0] is None, ok


def test_split_host_handles_multi_part_suffix():
    assert split_host("www.bbc.co.uk") == ("www", "bbc", "co.uk")
    assert split_host("a.b.example.com") == ("a.b", "example", "com")
    assert not is_ip("example.com") and is_ip("::1")


def test_extractor_never_crashes_on_odd_input():
    for u in ["http://", "http://[::1]/", "http://a:99999/", "http://%zz/", "x" * 5000, "http://ex ample.com", "//", "http://a..b/"]:
        assert len(feature_vector(u)) == len(FEATURE_NAMES)


def test_model_metrics_file_meets_quality_bar():
    m = json.loads((Path(__file__).resolve().parents[1] / "ml" / "model" / "metrics.json").read_text())
    assert m["f1"] >= 0.95 and m["roc_auc"] >= 0.97 and m["false_positive_rate"] <= 0.03
    assert "caveat" in m and m["confusion_matrix"]["tp"] > 0


def test_explanations_name_the_real_cause():
    d = get_detector()
    r = d.predict("http://paypal.account-verify.example-test.tk/login")
    assert r["probability"] > 0.9
    feats = {c["feature"] for c in r["contributions"]}
    assert feats & {"brand_in_subdomain", "suspicious_tld", "suspicious_keyword_count", "keyword_in_host"}, feats
    assert all(c["reason"] and c["impact"] > 0 for c in r["contributions"])
    assert d.predict("https://www.wikipedia.org/")["probability"] < 0.2


def test_dataset_generation_is_deterministic_and_balanced():
    a, b = generate_synthetic(200, seed=5), generate_synthetic(200, seed=5)
    assert a == b and sum(l for _, l in a) == 200 and len(a) == 400
    assert len({u for u, _ in a}) == 400
