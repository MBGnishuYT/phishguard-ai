// Minimal in-memory fake of the chrome.* APIs used by the extension (for Node tests).
function area() {
  let data = {};
  return {
    async get(keys) {
      if (keys == null) return { ...data };
      const ks = Array.isArray(keys) ? keys : typeof keys === "string" ? [keys] : Object.keys(keys);
      const out = {}; for (const k of ks) if (k in data) out[k] = structuredClone(data[k]); return out;
    },
    async set(obj) { for (const [k, v] of Object.entries(obj)) data[k] = structuredClone(v); },
    async remove(keys) { for (const k of [].concat(keys)) delete data[k]; },
    _reset() { data = {}; }, _dump: () => data,
  };
}
function event() { const l = []; return { addListener: (f) => l.push(f), _l: l }; }

export function installChrome() {
  const calls = { tabsUpdate: [], notifications: [], badge: [], fetches: [] };
  const chrome = {
    runtime: { id: "test-extension-id", getURL: (p) => `chrome-extension://test-extension-id/${p}`, onMessage: event(), onInstalled: event(), openOptionsPage() {} },
    storage: { local: area(), session: area() },
    webNavigation: { onBeforeNavigate: event(), onHistoryStateUpdated: event() },
    tabs: { onRemoved: event(), async update(id, props) { calls.tabsUpdate.push({ id, ...props }); }, async query() { return [{ id: 1, url: "https://example.org/" }]; }, async remove() {} , create() {} },
    notifications: { create(id, opts) { calls.notifications.push({ id, ...opts }); } },
    action: { async setBadgeText(o) { calls.badge.push(o); }, async setBadgeBackgroundColor() {} },
    scripting: { async getRegisteredContentScripts() { return []; }, async registerContentScripts() {}, async unregisterContentScripts() {} },
    permissions: { async contains() { return true; }, async remove() {}, async request() { return true; } },
  };
  globalThis.chrome = chrome;
  return { chrome, calls };
}

export function send(chrome, msg, sender = { id: chrome.runtime.id, tab: { id: 1, url: "https://example.org/" }, url: "https://example.org/" }) {
  return new Promise((resolve) => { for (const l of chrome.runtime.onMessage._l) l(msg, sender, resolve); });
}
export async function navigate(chrome, url, tabId = 1) {
  for (const l of chrome.webNavigation.onBeforeNavigate._l) l({ frameId: 0, tabId, url });
  await new Promise((r) => setTimeout(r, 60)); // listeners are fire-and-forget
}
export function jsonResponse(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}
