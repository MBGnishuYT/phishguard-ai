import test from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";
import { createRequire } from "node:module";
import fs from "node:fs";
import vm from "node:vm";

const src = fs.readFileSync(new URL("../../extension/content.js", import.meta.url), "utf8");
function load() { const m = { exports: {} }; vm.runInNewContext(src, { module: m, URL, console }); return m.exports; }
const { computeSignals } = load();
const run = (html, url) => { const d = new JSDOM(html, { url }); return JSON.parse(JSON.stringify(computeSignals(d.window.document, d.window.location))); };

test("benign page produces no signals", () => {
  const s = run("<p>hello</p><a href='https://example.com/a'>Read more</a>", "https://example.com/");
  assert.deepEqual(s, { has_password_field: false, password_form_cross_origin: false, password_form_insecure: false, mismatched_links: 0, hidden_iframes: 0 });
});
test("login form posting to another site is flagged", () => {
  const s = run("<form action='https://collector.example.net/x'><input type=password></form>", "https://bank.example.com/login");
  assert.ok(s.has_password_field && s.password_form_cross_origin);
});
test("same-site login form is not cross-origin", () => {
  const s = run("<form action='/session'><input type=password></form>", "https://example.com/login");
  assert.ok(s.has_password_field); assert.equal(s.password_form_cross_origin, false); assert.equal(s.password_form_insecure, false);
});
test("password form posting over http is flagged insecure", () => {
  const s = run("<form action='http://example.com/p'><input type=password></form>", "https://example.com/");
  assert.ok(s.password_form_insecure);
});
test("misleading link text vs href counted", () => {
  const s = run("<a href='http://evil.example.tk/a'>www.paypal.com</a><a href='http://evil.example.tk/b'>https://www.google.com/account</a><a href='https://x.com'>x.com</a>", "https://example.org/");
  assert.equal(s.mismatched_links, 2);
});
test("hidden iframes counted", () => {
  const s = run("<iframe src='https://a.example' width=0 height=0></iframe><iframe style='display: none' src='https://b.example'></iframe><iframe width=500 height=300></iframe>", "https://example.org/");
  assert.equal(s.hidden_iframes, 2);
});
test("signals never contain field values or text", () => {
  const s = run("<form><input type=password value='hunter2'></form>", "https://example.org/");
  assert.ok(!JSON.stringify(s).includes("hunter2"));
  assert.deepEqual(Object.keys(s).sort(), ["has_password_field", "hidden_iframes", "mismatched_links", "password_form_cross_origin", "password_form_insecure"]);
});
