// PhishGuard page analysis ("screen watch"). Runs only if the user enabled it in Options.
// It inspects page STRUCTURE locally (forms, links, frames) and reports a few booleans/counters.
// It never reads or sends: password/field values, cookies, storage, page text, or screenshots.
(function () {
  "use strict";

  function regDomain(host) {
    const p = (host || "").toLowerCase().split(".");
    return p.length <= 2 ? p.join(".") : p.slice(-2).join(".");
  }

  function computeSignals(doc, loc) {
    const pageHost = regDomain(loc.hostname);
    const out = { has_password_field: false, password_form_cross_origin: false, password_form_insecure: false, mismatched_links: 0, hidden_iframes: 0 };

    const pwInputs = doc.querySelectorAll('input[type="password"]');
    out.has_password_field = pwInputs.length > 0;
    for (const input of pwInputs) {
      const form = input.form;
      if (!form) continue;
      let action;
      try { action = new URL(form.getAttribute("action") || loc.href, loc.href); } catch { continue; }
      if (regDomain(action.hostname) !== pageHost) out.password_form_cross_origin = true;
      if (action.protocol === "http:") out.password_form_insecure = true; // password sent without encryption
    }

    const looksLikeUrl = /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/\S*)?$/i;
    let mismatched = 0;
    const anchors = doc.querySelectorAll("a[href]");
    for (let i = 0; i < anchors.length && i < 400; i++) {
      const a = anchors[i];
      const text = (a.textContent || "").trim();
      if (text.length > 80 || !looksLikeUrl.test(text)) continue;
      try {
        const shown = new URL(/^https?:/i.test(text) ? text : "http://" + text);
        const real = new URL(a.getAttribute("href"), loc.href);
        if (/^https?:$/.test(real.protocol) && regDomain(shown.hostname) !== regDomain(real.hostname)) mismatched++;
      } catch { /* ignore */ }
    }
    out.mismatched_links = mismatched;

    let hidden = 0;
    for (const f of doc.querySelectorAll("iframe")) {
      const w = parseInt(f.getAttribute("width") || "", 10), h = parseInt(f.getAttribute("height") || "", 10);
      const st = (f.getAttribute("style") || "").replace(/\s+/g, "").toLowerCase();
      if ((w <= 1 && h <= 1) || st.includes("display:none") || st.includes("visibility:hidden")) hidden++;
    }
    out.hidden_iframes = hidden;
    return out;
  }

  if (typeof module !== "undefined" && module.exports) { module.exports = { computeSignals, regDomain }; }
  if (typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.sendMessage || typeof document === "undefined") return;
  if (window.top !== window) return;

  let sent = 0, timer = null, lastKey = "";
  function report() {
    const s = computeSignals(document, location);
    const interesting = s.has_password_field || s.mismatched_links >= 2 || s.hidden_iframes > 0;
    const key = JSON.stringify(s);
    if (!interesting || key === lastKey || sent >= 3) return;
    lastKey = key; sent++;
    chrome.runtime.sendMessage({ type: "signals", signals: s }).catch(() => {});
  }
  report();
  // Single-page apps often add login forms later: re-check (debounced, at most 3 reports per page).
  new MutationObserver(() => { clearTimeout(timer); timer = setTimeout(report, 1500); }).observe(document.documentElement, { childList: true, subtree: true });
})();
