import {
  DEFAULTS, badgeFor, hostOf, isPrivateHost, isScannable, isWhitelisted, localHeuristic,
  normalizeWhitelistEntry, redactUrl, trimHistory, verdictFromScore,
} from "./lib.js";

const CACHE_MS = 10 * 60 * 1000;
const NOTIFY_COOLDOWN_MS = 5 * 60 * 1000;
const FETCH_TIMEOUT_MS = 7000;
const tabResults = new Map(); // tabId -> last result (also persisted to session storage)
const notified = new Map();   // host -> timestamp

// ------------------------------------------------------------------ storage helpers
async function getSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return { ...DEFAULTS, ...(settings || {}) };
}
async function getWhitelist() {
  const { whitelist } = await chrome.storage.local.get("whitelist");
  return whitelist || [];
}
async function getToken(apiBase) {
  const { installToken, installApi } = await chrome.storage.local.get(["installToken", "installApi"]);
  if (installToken && installApi === apiBase) return installToken;
  const r = await fetchJson(`${apiBase}/api/v1/extension/register`, { method: "POST" });
  await chrome.storage.local.set({ installToken: r.install_token, installApi: apiBase });
  return r.install_token;
}

async function fetchJson(url, opts = {}, timeout = FETCH_TIMEOUT_MS) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const resp = await fetch(url, {
      ...opts, signal: ctrl.signal, credentials: "omit", cache: "no-store",
      headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const err = new Error(body.detail || `HTTP ${resp.status}`);
      err.status = resp.status;
      throw err;
    }
    return body;
  } finally {
    clearTimeout(t);
  }
}

// ------------------------------------------------------------------ scanning
async function scanUrl(url, { deep = false, signals = null, force = false } = {}) {
  const settings = await getSettings();
  const host = hostOf(url);
  const clean = redactUrl(url); // query values/fragments are stripped before anything is sent
  const cacheKey = `${clean}|${deep}|${signals ? JSON.stringify(signals) : ""}`;
  if (!force) {
    const { scanCache } = await chrome.storage.session.get("scanCache");
    const hit = scanCache && scanCache[cacheKey];
    if (hit && Date.now() - hit.at < CACHE_MS) return hit.result;
  }
  let result;
  try {
    let token = await getToken(settings.apiBase);
    const body = JSON.stringify({ url: clean, deep: deep || settings.deepScan, record: settings.shareScans, ...(signals ? { signals } : {}) });
    try {
      result = await fetchJson(`${settings.apiBase}/api/v1/scan`, { method: "POST", body, headers: { "X-Install-Token": token } });
    } catch (e) {
      if (e.status === 401) { // token no longer known to the server: register again once
        await chrome.storage.local.remove(["installToken", "installApi"]);
        token = await getToken(settings.apiBase);
        result = await fetchJson(`${settings.apiBase}/api/v1/scan`, { method: "POST", body, headers: { "X-Install-Token": token } });
      } else throw e;
    }
    result.offline = false;
  } catch (e) {
    const local = localHeuristic(url);
    result = { ...local, host, url: clean, sources: {}, backend_error: e.name === "AbortError" ? "Backend timed out." : String(e.message || e) };
  }
  result.scanned_at = Date.now();
  const { scanCache } = await chrome.storage.session.get("scanCache");
  const next = { ...(scanCache || {}), [cacheKey]: { at: Date.now(), result } };
  const keys = Object.keys(next);
  if (keys.length > 200) for (const k of keys.slice(0, keys.length - 200)) delete next[k];
  await chrome.storage.session.set({ scanCache: next });
  return result;
}

async function addHistory(result) {
  const { history } = await chrome.storage.local.get("history");
  const entry = { t: Date.now(), host: result.host, url: result.url, score: result.risk_score, verdict: result.verdict, offline: !!result.offline };
  const list = [entry, ...(history || [])];
  await chrome.storage.local.set({ history: trimHistory(list, 500) });
}

// ------------------------------------------------------------------ UI feedback
async function setBadge(tabId, verdict) {
  const b = badgeFor(verdict);
  try {
    await chrome.action.setBadgeText({ tabId, text: b.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
  } catch { /* tab may have closed */ }
}

async function notify(result) {
  const settings = await getSettings();
  if (!settings.notifications || result.verdict === "safe") return;
  const last = notified.get(result.host) || 0;
  if (Date.now() - last < NOTIFY_COOLDOWN_MS) return;
  notified.set(result.host, Date.now());
  const top = (result.reasons || []).find((r) => r.severity !== "info");
  const danger = result.verdict === "phishing";
  chrome.notifications.create(`pg-${Date.now()}`, {
    type: "basic", iconUrl: "icons/icon128.png", priority: danger ? 2 : 1,
    title: danger ? "PhishGuard blocked a dangerous site" : "PhishGuard: this site looks suspicious",
    message: `${result.host} - risk ${result.risk_score}/100. ${top ? top.text : ""}`.slice(0, 250),
  });
}

async function showWarning(tabId, result, originalUrl) {
  const id = crypto.randomUUID();
  await chrome.storage.session.set({ [`warn:${id}`]: { url: originalUrl, host: result.host, score: result.risk_score, reasons: result.reasons || [], offline: !!result.offline, confirmed: !!result.confirmed_threat } });
  await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`warning.html?id=${id}`) });
}

// ------------------------------------------------------------------ navigation handling
async function handleNavigation(tabId, url, { signals = null, rescan = false } = {}) {
  const settings = await getSettings();
  if (!settings.enabled) { await setBadge(tabId, "off"); return null; }
  if (!isScannable(url)) { await chrome.action.setBadgeText({ tabId, text: "" }); return null; }
  const host = hostOf(url);
  if (isPrivateHost(host)) { await chrome.action.setBadgeText({ tabId, text: "" }); return null; }
  if (isWhitelisted(host, await getWhitelist())) {
    const r = { host, url: redactUrl(url), risk_score: 0, verdict: "safe", reasons: [{ severity: "info", text: "You added this site to your trusted list." }], whitelisted: true, sources: {} };
    tabResults.set(tabId, r);
    await chrome.storage.session.set({ [`tab:${tabId}`]: r });
    await setBadge(tabId, "safe");
    return r;
  }
  const { allowed } = await chrome.storage.session.get("allowed");
  if (allowed && allowed[host] && allowed[host] > Date.now()) {
    const r = { host, url: redactUrl(url), risk_score: 0, verdict: "suspicious", reasons: [{ severity: "info", text: "You chose to continue to this site for now." }], tempAllowed: true, sources: {} };
    await chrome.storage.session.set({ [`tab:${tabId}`]: r });
    await setBadge(tabId, "suspicious");
    return r;
  }
  const result = await scanUrl(url, { signals, force: rescan });
  result.verdict = result.verdict || verdictFromScore(result.risk_score);
  tabResults.set(tabId, result);
  await chrome.storage.session.set({ [`tab:${tabId}`]: result });
  await setBadge(tabId, result.verdict);
  if (!signals) await addHistory(result);
  if (result.verdict === "phishing") {
    await notify(result);
    await showWarning(tabId, result, url);
  } else if (result.verdict === "suspicious") {
    await notify(result);
  }
  return result;
}

chrome.webNavigation.onBeforeNavigate.addListener((d) => {
  if (d.frameId === 0) handleNavigation(d.tabId, d.url).catch((e) => console.warn("PhishGuard scan failed", e));
});
chrome.webNavigation.onHistoryStateUpdated.addListener((d) => {
  if (d.frameId === 0) handleNavigation(d.tabId, d.url).catch(() => {});
});
chrome.tabs.onRemoved.addListener((tabId) => { tabResults.delete(tabId); chrome.storage.session.remove(`tab:${tabId}`); });

// ------------------------------------------------------------------ messages (popup, options, warning page, content script)
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg && msg.type) {
      case "signals": { // from content script; only validated booleans/counters are forwarded
        if (!sender.tab || !sender.url || sender.id !== chrome.runtime.id) return sendResponse({ ok: false });
        const s = msg.signals || {};
        const signals = {
          has_password_field: !!s.has_password_field, password_form_cross_origin: !!s.password_form_cross_origin,
          password_form_insecure: !!s.password_form_insecure,
          mismatched_links: Math.max(0, Math.min(500, Number(s.mismatched_links) | 0)),
          hidden_iframes: Math.max(0, Math.min(100, Number(s.hidden_iframes) | 0)),
        };
        const r = await handleNavigation(sender.tab.id, sender.tab.url || sender.url, { signals });
        return sendResponse({ ok: true, verdict: r && r.verdict });
      }
      case "getTabState": {
        const tab = msg.tabId != null ? { id: msg.tabId, url: msg.url } : (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
        const settings = await getSettings();
        const stored = tab ? (await chrome.storage.session.get(`tab:${tab.id}`))[`tab:${tab.id}`] : null;
        const { history } = await chrome.storage.local.get("history");
        return sendResponse({ settings, result: stored || null, tab: tab ? { id: tab.id, url: tab.url ? redactUrl(tab.url) : null, scannable: isScannable(tab.url || "") } : null, history: (history || []).slice(0, 8), whitelist: await getWhitelist() });
      }
      case "rescan": {
        const tab = (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
        if (!tab || !isScannable(tab.url || "")) return sendResponse({ error: "Open a web page first." });
        const r = await scanUrl(tab.url, { deep: !!msg.deep, force: true });
        await chrome.storage.session.set({ [`tab:${tab.id}`]: r });
        await setBadge(tab.id, r.verdict);
        return sendResponse({ result: r });
      }
      case "setEnabled": {
        const s = await getSettings();
        await chrome.storage.local.set({ settings: { ...s, enabled: !!msg.enabled } });
        if (!msg.enabled) await chrome.action.setBadgeText({ text: "OFF" });
        else await chrome.action.setBadgeText({ text: "" });
        return sendResponse({ ok: true });
      }
      case "trustHost": {
        const entry = normalizeWhitelistEntry(msg.host);
        if (!entry) return sendResponse({ error: "That is not a valid site name." });
        const list = await getWhitelist();
        if (!list.includes(entry)) await chrome.storage.local.set({ whitelist: [...list, entry].sort() });
        return sendResponse({ ok: true, entry });
      }
      case "untrustHost": {
        const list = (await getWhitelist()).filter((h) => h !== msg.host);
        await chrome.storage.local.set({ whitelist: list });
        return sendResponse({ ok: true });
      }
      case "allowOnce": { // from warning page: user explicitly continues to the flagged site
        if (sender.id !== chrome.runtime.id || !sender.tab) return sendResponse({ ok: false });
        const w = (await chrome.storage.session.get(`warn:${msg.id}`))[`warn:${msg.id}`];
        if (!w) return sendResponse({ error: "Warning expired." });
        const { allowed } = await chrome.storage.session.get("allowed");
        await chrome.storage.session.set({ allowed: { ...(allowed || {}), [hostOf(w.url)]: Date.now() + 15 * 60 * 1000 } });
        await chrome.tabs.update(sender.tab.id, { url: w.url });
        return sendResponse({ ok: true });
      }
      case "leave": {
        if (sender.id !== chrome.runtime.id || !sender.tab) return sendResponse({ ok: false });
        await chrome.tabs.update(sender.tab.id, { url: "chrome://newtab/" });
        return sendResponse({ ok: true });
      }
      case "testConnection": {
        try {
          const base = String(msg.apiBase || "").replace(/\/+$/, "");
          const u = new URL(base);
          if (!["http:", "https:"].includes(u.protocol)) throw new Error("Use an http(s) address.");
          const h = await fetchJson(`${base}/health`);
          return sendResponse({ ok: true, health: h });
        } catch (e) {
          return sendResponse({ ok: false, error: e.name === "AbortError" ? "Timed out." : String(e.message || e) });
        }
      }
      case "applyPageAnalysis": return sendResponse(await applyPageAnalysis(!!msg.enabled));
      case "clearHistory": await chrome.storage.local.set({ history: [] }); return sendResponse({ ok: true });
      default: return sendResponse({ error: "unknown message" });
    }
  })().catch((e) => sendResponse({ error: String(e.message || e) }));
  return true; // async response
});

// ------------------------------------------------------------------ optional page analysis (content script registered only with user consent)
async function applyPageAnalysis(enabled) {
  const id = "phishguard-page-analysis";
  try {
    const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [id] });
    if (enabled) {
      const granted = await chrome.permissions.contains({ origins: ["http://*/*", "https://*/*"] });
      if (!granted) return { ok: false, error: "Permission to analyse pages was not granted." };
      if (!existing.length) await chrome.scripting.registerContentScripts([{ id, js: ["content.js"], matches: ["http://*/*", "https://*/*"], runAt: "document_idle", persistAcrossSessions: true }]);
    } else {
      if (existing.length) await chrome.scripting.unregisterContentScripts({ ids: [id] });
      await chrome.permissions.remove({ origins: ["http://*/*", "https://*/*"] }).catch(() => {});
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: String(e.message || e) };
  }
}

chrome.runtime.onInstalled.addListener(async (details) => {
  const { settings } = await chrome.storage.local.get("settings");
  if (!settings) await chrome.storage.local.set({ settings: DEFAULTS, whitelist: [], history: [] });
  if (details.reason === "install") chrome.runtime.openOptionsPage();
});
