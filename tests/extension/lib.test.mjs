import test from "node:test";
import assert from "node:assert/strict";
import * as L from "../../extension/lib.js";

test("verdict thresholds", () => {
  assert.equal(L.verdictFromScore(0), "safe"); assert.equal(L.verdictFromScore(29), "safe");
  assert.equal(L.verdictFromScore(30), "suspicious"); assert.equal(L.verdictFromScore(69), "suspicious");
  assert.equal(L.verdictFromScore(70), "phishing"); assert.equal(L.verdictFromScore(100), "phishing");
  assert.equal(L.verdictFromScore(NaN), "suspicious");
});
test("only http(s) is scannable; invalid input handled", () => {
  for (const u of ["https://a.com", "http://a.com/x"]) assert.ok(L.isScannable(u));
  for (const u of ["chrome://settings", "file:///etc/passwd", "javascript:alert(1)", "about:blank", "", "not a url", "chrome-extension://x/y.html"]) assert.equal(L.isScannable(u), false, u);
});
test("private hosts are never sent to the server", () => {
  for (const h of ["localhost", "127.0.0.1", "10.1.2.3", "192.168.0.5", "172.20.1.1", "169.254.169.254", "intranet", "printer.local", "db.internal", "::1"]) assert.ok(L.isPrivateHost(h), h);
  for (const h of ["example.com", "8.8.8.8", "172.32.0.1", "www.google.com"]) assert.equal(L.isPrivateHost(h), false, h);
});
test("redactUrl strips query values, fragment and credentials", () => {
  const r = L.redactUrl("https://user:pw@example.com:8443/a/b?token=SECRET&sid=1#frag");
  assert.equal(r, "https://example.com:8443/a/b?token=&sid=");
  assert.ok(!/SECRET|pw|frag|user/.test(r));
});
test("whitelist matching covers subdomains but not look-alikes", () => {
  const w = ["example.com"];
  assert.ok(L.isWhitelisted("example.com", w)); assert.ok(L.isWhitelisted("login.example.com", w));
  assert.equal(L.isWhitelisted("evilexample.com", w), false); assert.equal(L.isWhitelisted("example.com.evil.tk", w), false);
});
test("whitelist input normalisation", () => {
  assert.equal(L.normalizeWhitelistEntry("https://www.Example.com/path"), "example.com");
  assert.equal(L.normalizeWhitelistEntry("  bank.example.org "), "bank.example.org");
  for (const bad of ["", "   ", "nodots", "a b.com", "http://"]) assert.equal(L.normalizeWhitelistEntry(bad), null, bad);
});
test("offline heuristic flags phishing patterns and passes normal sites", () => {
  for (const u of ["http://paypal.secure-login.example.tk/signin", "http://netflix.com@203.0.113.5/x", "http://paypa1-login.example.xyz/verify/account"])
    assert.equal(L.localHeuristic(u).verdict, "phishing", u);
  assert.notEqual(L.localHeuristic("http://192.0.2.4/login").verdict, "safe"); // raw IP + login form path
  for (const u of ["https://www.google.com/", "https://github.com/login", "https://www.paypal.com/signin", "https://en.wikipedia.org/wiki/Phishing"])
    assert.equal(L.localHeuristic(u).verdict, "safe", u);
});
test("badge mapping", () => { assert.equal(L.badgeFor("phishing").text, "X"); assert.equal(L.badgeFor("off").text, "OFF"); });
