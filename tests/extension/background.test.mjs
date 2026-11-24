import test, { beforeEach } from "node:test";
import assert from "node:assert/strict";
import { installChrome, send, navigate, jsonResponse } from "./chrome-mock.mjs";

const env = installChrome();
const { chrome, calls } = env;
await import("../../extension/background.js");

const API = "http://127.0.0.1:8000";
let fetchLog, scanHandler;
function resetAll(settings = {}) {
  chrome.storage.local._reset(); chrome.storage.session._reset();
  calls.tabsUpdate.length = calls.notifications.length = calls.badge.length = 0;
  fetchLog = [];
  scanHandler = (body) => jsonResponse(200, { host: new URL(body.url).hostname, url: body.url, risk_score: 5, verdict: "safe", reasons: [{ severity: "info", text: "fine" }], sources: {}, confirmed_threat: false });
  globalThis.fetch = async (url, opts = {}) => {
    const body = opts.body ? JSON.parse(opts.body) : null;
    fetchLog.push({ url, opts, body });
    if (url.endsWith("/extension/register")) return jsonResponse(200, { install_token: "tok-" + fetchLog.length });
    if (url.endsWith("/scan")) return scanHandler(body, opts);
    return jsonResponse(404, {});
  };
  return chrome.storage.local.set({ settings: { enabled: true, apiBase: API, deepScan: false, notifications: true, shareScans: true, pageAnalysis: false, ...settings }, whitelist: [], history: [] });
}
beforeEach(() => resetAll());
const phishing = (body) => jsonResponse(200, { host: new URL(body.url).hostname, url: body.url, risk_score: 97, verdict: "phishing", confirmed_threat: true, reasons: [{ severity: "critical", text: "Listed by Google Safe Browsing: SOCIAL_ENGINEERING" }], sources: {} });

test("safe site: scanned, badge OK, no warning, no notification, history saved", async () => {
  await navigate(chrome, "https://safe1.example.org/page");
  assert.equal(fetchLog.filter((f) => f.url.endsWith("/scan")).length, 1);
  assert.equal(calls.tabsUpdate.length, 0); assert.equal(calls.notifications.length, 0);
  assert.ok(calls.badge.some((b) => b.text === "OK"));
  const { history } = await chrome.storage.local.get("history");
  assert.equal(history.length, 1); assert.equal(history[0].verdict, "safe");
});

test("phishing site: warning page shown with explanation and desktop alert", async () => {
  scanHandler = phishing;
  await navigate(chrome, "https://evil1.example.tk/login?session=SECRET");
  assert.equal(calls.tabsUpdate.length, 1);
  assert.match(calls.tabsUpdate[0].url, /^chrome-extension:\/\/test-extension-id\/warning\.html\?id=[0-9a-f-]{36}$/);
  assert.equal(calls.notifications.length, 1);
  assert.match(calls.notifications[0].title, /blocked a dangerous site/);
  const id = calls.tabsUpdate[0].url.split("id=")[1];
  const warn = (await chrome.storage.session.get(`warn:${id}`))[`warn:${id}`];
  assert.equal(warn.score, 97); assert.ok(warn.reasons[0].text.includes("Safe Browsing"));
  assert.ok(calls.badge.some((b) => b.text === "X"));
});

test("query values and fragments never leave the browser", async () => {
  await navigate(chrome, "https://safe2.example.org/reset?token=SECRET123&sid=abc#frag");
  const scan = fetchLog.find((f) => f.url.endsWith("/scan"));
  assert.ok(!JSON.stringify(scan.body).match(/SECRET123|abc|frag/)); assert.equal(scan.opts.credentials, "omit");
  assert.equal(scan.body.url, "https://safe2.example.org/reset?token=&sid=");
  assert.ok(!("cookie" in (scan.opts.headers || {})));
});

test("suspicious site: alert but no block", async () => {
  scanHandler = (b) => jsonResponse(200, { host: "s.example.org", url: b.url, risk_score: 45, verdict: "suspicious", reasons: [{ severity: "medium", text: "New domain" }], sources: {} });
  await navigate(chrome, "https://sus1.example.org/");
  assert.equal(calls.tabsUpdate.length, 0); assert.equal(calls.notifications.length, 1);
  assert.match(calls.notifications[0].title, /suspicious/);
});

test("protection OFF: nothing is scanned", async () => {
  await resetAll({ enabled: false });
  await navigate(chrome, "https://off1.example.org/");
  assert.equal(fetchLog.length, 0); assert.ok(calls.badge.some((b) => b.text === "OFF"));
});

test("whitelisted site is never sent to the server", async () => {
  await send(chrome, { type: "trustHost", host: "https://www.Trusted-Bank.example.org/x" });
  scanHandler = phishing;
  await navigate(chrome, "https://login.trusted-bank.example.org/");
  assert.equal(fetchLog.filter((f) => f.url.endsWith("/scan")).length, 0); assert.equal(calls.tabsUpdate.length, 0);
  await send(chrome, { type: "untrustHost", host: "trusted-bank.example.org" });
  await navigate(chrome, "https://login.trusted-bank.example.org/");
  assert.equal(calls.tabsUpdate.length, 1);
});

test("private/intranet and non-web URLs are not scanned", async () => {
  for (const u of ["http://localhost:3000/", "http://192.168.1.10/admin", "http://wiki.internal/", "chrome://settings", "file:///tmp/x.html", "about:blank"]) await navigate(chrome, u);
  assert.equal(fetchLog.length, 0);
});

test("backend down: offline heuristic still blocks obvious phishing and passes normal sites", async () => {
  globalThis.fetch = async () => { throw new TypeError("Failed to fetch"); };
  await navigate(chrome, "http://paypal.secure-login.offline-test.tk/signin");
  assert.equal(calls.tabsUpdate.length, 1);
  const id = calls.tabsUpdate[0].url.split("id=")[1];
  assert.equal((await chrome.storage.session.get(`warn:${id}`))[`warn:${id}`].offline, true);
  calls.tabsUpdate.length = 0;
  await navigate(chrome, "https://www.wikipedia.org/");
  assert.equal(calls.tabsUpdate.length, 0);
});

test("backend HTTP 500 and 429 fall back instead of crashing", async () => {
  for (const code of [500, 429]) {
    globalThis.fetch = async (u) => u.endsWith("/register") ? jsonResponse(200, { install_token: "t" }) : jsonResponse(code, { detail: "nope" });
    await navigate(chrome, `https://err${code}.example.org/`);
    const st = await send(chrome, { type: "getTabState" });
    assert.equal(st.result.offline, true, String(code));
  }
});

test("stale install token (401) triggers one re-registration and retry", async () => {
  let first = true;
  scanHandler = (b) => { if (first) { first = false; return jsonResponse(401, { detail: "Unknown installation" }); } return jsonResponse(200, { host: "x", url: b.url, risk_score: 3, verdict: "safe", reasons: [], sources: {} }); };
  await navigate(chrome, "https://retry1.example.org/");
  assert.equal(fetchLog.filter((f) => f.url.endsWith("/register")).length, 2);
  const st = await send(chrome, { type: "getTabState" }); assert.equal(st.result.verdict, "safe");
});

test("results are cached for repeat visits", async () => {
  await navigate(chrome, "https://cache1.example.org/a"); await navigate(chrome, "https://cache1.example.org/a");
  assert.equal(fetchLog.filter((f) => f.url.endsWith("/scan")).length, 1);
});

test("share-scans OFF tells the server not to record", async () => {
  await resetAll({ shareScans: false });
  await navigate(chrome, "https://norecord.example.org/");
  assert.equal(fetchLog.find((f) => f.url.endsWith("/scan")).body.record, false);
});

test("'continue anyway' is explicit, time-limited and does not loop", async () => {
  scanHandler = phishing;
  await navigate(chrome, "https://proceed1.example.tk/");
  const id = calls.tabsUpdate[0].url.split("id=")[1];
  calls.tabsUpdate.length = 0;
  const r = await send(chrome, { type: "allowOnce", id }, { id: chrome.runtime.id, tab: { id: 1 } });
  assert.ok(r.ok); assert.equal(calls.tabsUpdate[0].url, "https://proceed1.example.tk/");
  calls.tabsUpdate.length = 0; fetchLog.length = 0;
  await navigate(chrome, "https://proceed1.example.tk/");
  assert.equal(calls.tabsUpdate.length, 0, "must not bounce back to the warning");
});

test("messages from other senders cannot unlock sites or inject signals", async () => {
  scanHandler = phishing;
  await navigate(chrome, "https://proceed2.example.tk/");
  const id = calls.tabsUpdate[0].url.split("id=")[1]; calls.tabsUpdate.length = 0;
  const bad = await send(chrome, { type: "allowOnce", id }, { id: "some-other-extension", tab: { id: 1 } });
  assert.equal(bad.ok, false); assert.equal(calls.tabsUpdate.length, 0);
  assert.equal((await send(chrome, { type: "signals", signals: { has_password_field: true } }, { id: "other" })).ok, false);
});

test("page signals are validated/clamped before being sent", async () => {
  await send(chrome, { type: "signals", signals: { has_password_field: 1, password_value: "hunter2", mismatched_links: 99999, hidden_iframes: -5, evil: "x" } },
    { id: chrome.runtime.id, tab: { id: 7, url: "https://signals1.example.org/login" }, url: "https://signals1.example.org/login" });
  const body = fetchLog.find((f) => f.url.endsWith("/scan")).body;
  assert.deepEqual(body.signals, { has_password_field: true, password_form_cross_origin: false, password_form_insecure: false, mismatched_links: 500, hidden_iframes: 0 });
  assert.ok(!JSON.stringify(body).includes("hunter2"));
});

test("page-signal rescan can escalate a page to a block", async () => {
  scanHandler = (b) => b.signals && b.signals.password_form_cross_origin ? jsonResponse(200, { host: "h", url: b.url, risk_score: 88, verdict: "phishing", reasons: [{ severity: "high", text: "The login form sends data to a different website." }], sources: {} }) : jsonResponse(200, { host: "h", url: b.url, risk_score: 20, verdict: "safe", reasons: [], sources: {} });
  await navigate(chrome, "https://escalate1.example.org/login");
  assert.equal(calls.tabsUpdate.length, 0);
  await send(chrome, { type: "signals", signals: { has_password_field: true, password_form_cross_origin: true } }, { id: chrome.runtime.id, tab: { id: 1, url: "https://escalate1.example.org/login" }, url: "https://escalate1.example.org/login" });
  assert.equal(calls.tabsUpdate.length, 1);
});

test("popup state, history clearing and connection test messages", async () => {
  await navigate(chrome, "https://popup1.example.org/");
  const st = await send(chrome, { type: "getTabState", tabId: 1, url: "https://popup1.example.org/" });
  assert.equal(st.result.verdict, "safe"); assert.equal(st.history.length, 1);
  await send(chrome, { type: "clearHistory" });
  assert.equal((await send(chrome, { type: "getTabState", tabId: 1 })).history.length, 0);
  globalThis.fetch = async (u) => u.endsWith("/health") ? jsonResponse(200, { status: "ok", model_loaded: true }) : jsonResponse(404, {});
  assert.equal((await send(chrome, { type: "testConnection", apiBase: "https://phish.example.com" })).ok, true);
  assert.equal((await send(chrome, { type: "testConnection", apiBase: "ftp://x" })).ok, false);
  globalThis.fetch = async () => { throw new TypeError("down"); };
  assert.equal((await send(chrome, { type: "testConnection", apiBase: "https://phish.example.com" })).ok, false);
});
