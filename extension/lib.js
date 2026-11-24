// Pure helper functions (no chrome.* APIs) so they can be unit-tested in Node.

export const DEFAULTS = {
  enabled: true,
  apiBase: "http://127.0.0.1:8000",
  deepScan: false,
  notifications: true,
  shareScans: true,
  pageAnalysis: false,
};

export const SAFE_MAX = 29;
export const SUSPICIOUS_MAX = 69;

export function verdictFromScore(score) {
  if (!Number.isFinite(score)) return "suspicious";
  return score <= SAFE_MAX ? "safe" : score <= SUSPICIOUS_MAX ? "suspicious" : "phishing";
}

export function isScannable(url) {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

export function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase().replace(/\.$/, ""); } catch { return ""; }
}

// Intranet / localhost / private-range hosts are never sent to the server (privacy).
export function isPrivateHost(host) {
  if (!host) return true;
  if (host === "localhost" || !host.includes(".") && !host.includes(":")) return true;
  if (/\.(local|localhost|internal|lan|intranet|corp|home|arpa)$/.test(host)) return true;
  const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
           (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  return host === "::1" || host.startsWith("[::1") || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80");
}

// scheme://host[:port]/path?name=&name=  -- query VALUES and fragments never leave the browser.
export function redactUrl(url) {
  const u = new URL(url);
  const names = [...u.searchParams.keys()].slice(0, 20).map((k) => k.replace(/[^A-Za-z0-9_.-]/g, "").slice(0, 30));
  const q = names.length ? "?" + names.map((n) => n + "=").join("&") : "";
  return `${u.protocol}//${u.hostname}${u.port ? ":" + u.port : ""}${u.pathname.slice(0, 300)}${q}`;
}

export function isWhitelisted(host, list) {
  host = (host || "").toLowerCase();
  return (list || []).some((w) => host === w || host.endsWith("." + w));
}

export function normalizeWhitelistEntry(input) {
  let v = String(input || "").trim().toLowerCase();
  if (!v) return null;
  try { v = new URL(v.includes("://") ? v : "http://" + v).hostname; } catch { return null; }
  v = v.replace(/^www\./, "");
  return /^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(v) || /^\d+\.\d+\.\d+\.\d+$/.test(v) ? v : null;
}

const KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm", "banking", "password", "wallet", "suspend", "unlock", "billing", "webscr"];
const RISKY_TLDS = new Set(["tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "work", "zip", "country", "loan", "icu", "cyou", "rest", "buzz"]);
const BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram", "netflix", "linkedin", "dropbox", "github", "whatsapp", "outlook", "chase", "coinbase", "binance", "icloud", "yahoo"];

// Offline fallback used ONLY when the backend cannot be reached. Intentionally simple and clearly labelled.
export function localHeuristic(url) {
  const reasons = [];
  let score = 0;
  let u;
  try { u = new URL(url); } catch { return { risk_score: 50, verdict: "suspicious", reasons: [{ severity: "medium", text: "The address could not be parsed." }], offline: true }; }
  const host = u.hostname.toLowerCase();
  const labels = host.split(".");
  const tld = labels[labels.length - 1];
  const reg = labels.slice(-2).join(".");
  const add = (n, sev, text) => { score += n; reasons.push({ severity: sev, text }); };
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) add(35, "high", "The address uses a raw IP address instead of a domain name.");
  if (u.username || u.href.split("//")[1].split("/")[0].includes("@")) add(35, "high", "The URL contains '@', which can hide the real destination.");
  if (RISKY_TLDS.has(tld)) add(20, "medium", "The domain ends in a top-level domain often abused for phishing.");
  if (host.includes("xn--")) add(20, "medium", "The domain uses punycode, which can disguise look-alike characters.");
  const deob = host.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s"); // paypa1 -> paypal
  const brand = BRANDS.find((b) => deob.includes(b) && !(reg === b + ".com" || reg === b + ".net"));
  if (brand) add(35, "high", `The domain mentions "${brand}" but does not belong to it.`);
  const kws = KEYWORDS.filter((k) => (host + u.pathname).toLowerCase().includes(k)).length;
  if (kws >= 2) add(15, "medium", "The address contains several account/login keywords.");
  if ((host.match(/-/g) || []).length >= 3) add(10, "low", "The domain contains many hyphens.");
  if (labels.length >= 5) add(10, "low", "The address has many subdomains.");
  if (u.protocol === "http:") add(8, "low", "The page is not served over HTTPS.");
  score = Math.max(0, Math.min(100, score));
  if (!reasons.length) reasons.push({ severity: "info", text: "No indicators found by the offline check (backend unreachable)." });
  return { risk_score: score, verdict: verdictFromScore(score), reasons, offline: true };
}

export function badgeFor(verdict) {
  return { safe: { text: "OK", color: "#2f9e6e" }, suspicious: { text: "!", color: "#d99a1f" }, phishing: { text: "X", color: "#d6453d" }, off: { text: "OFF", color: "#6b7785" } }[verdict] || { text: "", color: "#6b7785" };
}

export function trimHistory(list, max = 500) {
  return list.length > max ? list.slice(0, max) : list;
}
