// End-to-end: real extension service-worker code <-> real running FastAPI server <-> real dashboard JS (in jsdom).
// Run with:  PG_E2E_URL=http://127.0.0.1:8000 PG_ADMIN_PW=... PG_MASTER=... node --test e2e.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { JSDOM } from "jsdom";
import { installChrome, send, navigate } from "./chrome-mock.mjs";

const BASE = process.env.PG_E2E_URL, PW = process.env.PG_ADMIN_PW, MASTER = process.env.PG_MASTER;
const skip = !BASE;
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test("extension -> live backend -> dashboard", { skip }, async (t) => {
  const { chrome, calls } = installChrome();
  await chrome.storage.local.set({ settings: { enabled: true, apiBase: BASE, deepScan: false, notifications: true, shareScans: true, pageAnalysis: false }, whitelist: [], history: [] });
  await import("../../extension/background.js");

  await t.test("safe sites pass, phishing patterns are blocked with reasons", async () => {
    for (const u of ["https://www.google.com/search?q=cats", "https://github.com/anthropics", "https://en.wikipedia.org/wiki/Phishing"]) await navigate(chrome, u);
    await wait(400);
    assert.equal(calls.tabsUpdate.length, 0, "safe sites must not be blocked");
    for (const u of ["http://paypa1-secure-login.example-test.tk/signin", "http://192.0.2.45/paypal/verify/account.php", "https://secure-paypal.com.verify-account-update.xyz/webscr?cmd=_login"]) await navigate(chrome, u, 2);
    await wait(600);
    assert.equal(calls.tabsUpdate.length, 3, "each phishing pattern is redirected to the warning page");
    assert.equal(calls.notifications.length, 3);
    const id = calls.tabsUpdate[0].url.split("id=")[1];
    const w = (await chrome.storage.session.get(`warn:${id}`))[`warn:${id}`];
    assert.ok(w.score >= 70 && w.reasons.length > 0 && w.offline === false, JSON.stringify(w));
  });

  await t.test("page-signal escalation works through the real API", async () => {
    await navigate(chrome, "http://login-portal.example-test.org/", 3); await wait(300);
    const before = calls.tabsUpdate.length;
    await send(chrome, { type: "signals", signals: { has_password_field: true, password_form_cross_origin: true, password_form_insecure: true } },
      { id: chrome.runtime.id, tab: { id: 3, url: "http://login-portal.example-test.org/" }, url: "http://login-portal.example-test.org/" });
    const st = await send(chrome, { type: "getTabState", tabId: 3 });
    assert.ok(["suspicious", "phishing"].includes(st.result.verdict), JSON.stringify(st.result));
    assert.ok(st.result.risk_score >= 50); void before;
  });

  await t.test("deep scan request works against the live server (network may be unavailable in sandbox)", async () => {
    const r = await send(chrome, { type: "rescan", deep: true });
    assert.ok(r.result && Number.isInteger(r.result.risk_score));
  });

  let dom;
  await t.test("dashboard JS: login, overview shows the scans, vault needs master key", async () => {
    const html = fs.readFileSync(new URL("../../dashboard/index.html", import.meta.url), "utf8");
    dom = new JSDOM(html, { url: BASE + "/dashboard/", runScripts: "outside-only", pretendToBeVisual: true });
    const w = dom.window;
    w.fetch = (u, o) => fetch(new URL(u, BASE), o);
    w.eval(fs.readFileSync(new URL("../../dashboard/app.js", import.meta.url), "utf8"));
    const d = w.document;
    assert.equal(d.getElementById("login").hidden, false);
    d.getElementById("u").value = "admin"; d.getElementById("p").value = "WRONG-password-1";
    d.getElementById("loginForm").dispatchEvent(new w.Event("submit", { cancelable: true })); await wait(500);
    assert.match(d.getElementById("loginErr").textContent, /Incorrect/);
    d.getElementById("p").value = PW;
    d.getElementById("loginForm").dispatchEvent(new w.Event("submit", { cancelable: true })); await wait(1200);
    assert.equal(d.getElementById("app").hidden, false);
    const text = d.getElementById("main").textContent;
    assert.match(text, /Websites scanned/); assert.match(text, /Phishing detected/);
    const nums = [...d.querySelectorAll(".tile .n")].map((e) => Number(e.textContent));
    assert.ok(nums[0] >= 7, "total scans recorded by the extension: " + nums);
    assert.ok(nums[3] >= 3, "phishing count: " + nums);
    assert.ok(d.querySelector("svg.chart rect"), "charts render");
    assert.equal(d.getElementById("vaultNav").hidden, false);
    // vault locked until master key supplied
    d.querySelector('[data-view="vault"]').click(); await wait(300);
    assert.match(d.getElementById("main").textContent, /Enter the master key/);
    const input = d.querySelector("#main input[type=password]"); input.value = "wrong-key";
    [...d.querySelectorAll("#main button")].find((b) => b.textContent === "Unlock vault").click(); await wait(500);
    assert.match(d.getElementById("main").textContent, /incorrect/i);
    input.value = MASTER;
    [...d.querySelectorAll("#main button")].find((b) => b.textContent === "Unlock vault").click(); await wait(1200);
    const vt = d.getElementById("main").textContent;
    assert.match(vt, /Security check/); assert.match(vt, /All collected scans/); assert.match(vt, /Audit log/);
    assert.ok(!vt.includes("session=") && !vt.includes("cmd=_login=") , "no query values in vault");
    for (const view of ["history", "reports", "model", "settings"]) { d.querySelector(`[data-view="${view}"]`).click(); await wait(500); assert.ok(d.getElementById("main").textContent.length > 40, view); assert.ok(!d.querySelector(".banner:not(.x)") || !/Request failed|Failed|undefined/.test(d.getElementById("main").textContent), view + ": " + d.getElementById("main").textContent.slice(0, 200)); }
  });
});
