"""Hand-written sample URLs used by the tests.

These are NOT taken from live phishing feeds. They are original, non-resolving strings that reproduce
the *patterns* seen in real campaigns (brand in subdomain, typosquats, IP hosts, risky TLDs), so they are
safe to store, share and commit. The domains use reserved/unregistered names.
"""
SAFE_URLS = [
    "https://www.google.com/", "https://github.com/anthropics", "https://en.wikipedia.org/wiki/Phishing",
    "https://www.bbc.co.uk/news", "https://stackoverflow.com/questions/12345", "https://docs.python.org/3/library/ssl.html",
    "https://www.amazon.com/gp/cart", "https://accounts.google.com/signin", "https://login.microsoftonline.com/",
    "https://www.nasa.gov/missions", "https://news.ycombinator.com/", "https://www.mozilla.org/en-US/firefox/",
    "https://www.paypal.com/signin", "https://mail.google.com/mail/u/0/", "https://www.python.org/downloads/",
]
PHISHING_PATTERN_URLS = [
    "http://paypa1-secure-login.example-test.tk/signin",
    "http://192.0.2.45/paypal/verify/account.php",
    "https://secure-paypal.com.verify-account-update.xyz/webscr?cmd=_login",
    "http://microsoft.account-verify.example-test.top/login",
    "http://www.g00gle.com.session-confirm.example-test.click/signin",
    "http://amaz0n-billing-update.example-test.ml/ap/signin",
    "http://netflix.com@198.51.100.7/login",
    "https://apple-id-locked-verify.example-test.cf/unlock",
    "http://login-microsoft-office365.example-test.gq/",
    "http://facebook.com.security-alert.example-test.tk:8080/checkpoint",
]
SUSPICIOUS_PATTERN_URLS = [
    "http://203.0.113.9/",
    "http://xn--pypal-4ve.example-test.com/login",
    "https://account-verify.example-test.work/",
    "http://bit.ly/3xYzAbC",
]
INVALID_URLS = ["", "   ", "not a url", "ftp://example.com/file", "javascript:alert(1)", "file:///etc/passwd", "http://",
                "https://exa mple.com/", "http://" + "a" * 300 + ".com/", "https://example.com/" + "x" * 3000, "data:text/html,<h1>x</h1>"]
