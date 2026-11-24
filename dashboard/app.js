// PhishGuard dashboard. All server data is rendered with textContent (never innerHTML) to prevent XSS.
const API = "/api/v1";
const $ = (s, r = document) => r.querySelector(s);
const SESSION = { token: sessionStorage.getItem("pg_token"), user: null, vault: null, vaultExp: 0 };

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
const svgNS = "http://www.w3.org/2000/svg";
function s(tag, attrs = {}, ...kids) {
  const el = document.createElementNS(svgNS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  for (const kid of kids) if (kid != null) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
function toast(msg) { const t = $("#toast"); t.textContent = msg; t.classList.add("show"); setTimeout(() => t.classList.remove("show"), 3200); }
const chip = (v, text) => h("span", { class: "chip " + v }, text ?? v);
const fmtTime = (iso) => { const d = new Date(iso); return isNaN(d) ? iso : d.toLocaleString(); };

async function api(path, { method = "GET", body, vault = false } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (SESSION.token) headers.Authorization = "Bearer " + SESSION.token;
  if (vault && SESSION.vault) headers["X-Vault-Token"] = SESSION.vault;
  const r = await fetch(API + path, { method, headers, body: body ? JSON.stringify(body) : undefined, credentials: "omit" });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) { logout(); throw new Error("Your session expired. Please sign in again."); }
  if (!r.ok) {
    if (vault && r.status === 403 && /locked/i.test(data.detail || "")) { SESSION.vault = null; }
    throw new Error(typeof data.detail === "string" ? data.detail : "Request failed (" + r.status + ")");
  }
  return data;
}

// ------------------------------------------------------------------ auth
function logout() {
  sessionStorage.removeItem("pg_token"); SESSION.token = null; SESSION.user = null; SESSION.vault = null;
  $("#app").hidden = true; $("#login").hidden = false;
}
$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault(); $("#loginErr").textContent = "";
  try {
    const r = await fetch(API + "/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "omit",
      body: JSON.stringify({ username: $("#u").value, password: $("#p").value }) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.detail || "Sign-in failed.");
    SESSION.token = d.access_token; sessionStorage.setItem("pg_token", d.access_token); $("#p").value = "";
    await start();
  } catch (err) { $("#loginErr").textContent = err.message; }
});
$("#logout").addEventListener("click", logout);

// ------------------------------------------------------------------ charts (hand-drawn SVG, no external libraries)
function histogram(buckets) {
  const W = 520, H = 200, pad = 26, max = Math.max(1, ...buckets), bw = (W - pad * 2) / 10;
  const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Risk score distribution" });
  buckets.forEach((n, i) => {
    const bh = (n / max) * (H - pad * 2), x = pad + i * bw + 3, y = H - pad - bh;
    const band = i < 3 ? "var(--safe)" : i < 7 ? "var(--warn)" : "var(--danger)";
    svg.append(s("rect", { x, y, width: bw - 6, height: Math.max(bh, n ? 2 : 0), fill: band, rx: 2 }, s("title", {}, `${i * 10}-${i * 10 + 9}: ${n} scans`)));
    svg.append(s("text", { x: x + (bw - 6) / 2, y: H - 8, "text-anchor": "middle" }, i * 10));
    if (n) svg.append(s("text", { x: x + (bw - 6) / 2, y: y - 4, "text-anchor": "middle" }, n));
  });
  svg.append(s("line", { x1: pad, x2: W - pad, y1: H - pad, y2: H - pad, stroke: "var(--line)" }));
  return svg;
}
function dailyChart(daily) {
  const dates = [...new Set(daily.map((d) => d.date))].sort();
  const W = 520, H = 200, pad = 26;
  const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Scans per day" });
  if (!dates.length) { svg.append(s("text", { x: W / 2, y: H / 2, "text-anchor": "middle" }, "No scans in this period yet")); return svg; }
  const by = {}; for (const d of daily) (by[d.date] ||= { safe: 0, suspicious: 0, phishing: 0 })[d.verdict] = d.count;
  const max = Math.max(1, ...dates.map((d) => by[d].safe + by[d].suspicious + by[d].phishing)), bw = (W - pad * 2) / dates.length;
  dates.forEach((d, i) => {
    let y = H - pad; const x = pad + i * bw + 2;
    for (const [k, col] of [["safe", "var(--safe)"], ["suspicious", "var(--warn)"], ["phishing", "var(--danger)"]]) {
      const bh = (by[d][k] / max) * (H - pad * 2); y -= bh;
      if (bh > 0) svg.append(s("rect", { x, y, width: Math.max(bw - 4, 3), height: bh, fill: col }, s("title", {}, `${d} ${k}: ${by[d][k]}`)));
    }
    if (dates.length <= 14 || i % 2 === 0) svg.append(s("text", { x: x + (bw - 4) / 2, y: H - 8, "text-anchor": "middle" }, d.slice(5)));
  });
  svg.append(s("line", { x1: pad, x2: W - pad, y1: H - pad, y2: H - pad, stroke: "var(--line)" }));
  return svg;
}

// ------------------------------------------------------------------ views
const views = {
  async overview(root) {
    const st = await api("/stats");
    const pct = (n) => (st.total ? (n / st.total) * 100 : 0);
    root.append(h("h2", {}, "Overview"),
      h("div", { class: "tiles" },
        tile("Websites scanned", st.total), tile("Safe", st.safe, "safe"), tile("Suspicious", st.suspicious, "suspicious"),
        tile("Phishing detected", st.phishing, "phishing"), tile("Active installs (7d)", st.active_installs)));
    const split = h("div", { class: "split", role: "img", "aria-label": "Share of safe, suspicious and phishing scans" });
    for (const k of ["safe", "suspicious", "phishing"]) { const i = h("i", { class: "band-" + k, title: `${k}: ${st[k]}` }); i.style.width = pct(st[k]) + "%"; split.append(i); }
    root.append(split,
      h("div", { class: "grid2" },
        h("div", { class: "card" }, h("h3", {}, "Risk score distribution"), histogram(st.risk_distribution), h("p", { class: "muted" }, "Green 0-29 safe, amber 30-69 suspicious, red 70-100 phishing.")),
        h("div", { class: "card" }, h("h3", {}, "Scans per day (last 14 days)"), dailyChart(st.daily))));
    if (!st.total) root.append(h("div", { class: "card" }, h("h3", {}, "No scans yet"), h("p", { class: "muted" }, "Install the Chrome extension, point it at this server in its settings, and open a website. Results appear here within seconds.")));
  },

  async history(root) {
    let offset = 0; const limit = 25;
    const verdict = h("select", { "aria-label": "Verdict filter" }, ...[["", "All verdicts"], ["safe", "Safe"], ["suspicious", "Suspicious"], ["phishing", "Phishing"]].map(([v, t]) => h("option", { value: v }, t)));
    const search = h("input", { type: "search", placeholder: "Search by site name", "aria-label": "Search host", maxlength: 100 });
    const body = h("div", {});
    async function load() {
      const q = new URLSearchParams({ limit, offset }); if (verdict.value) q.set("verdict", verdict.value); if (search.value.trim()) q.set("search", search.value.trim());
      const d = await api("/history?" + q);
      const tbody = h("tbody", {});
      for (const it of d.items) {
        const detail = h("tr", { hidden: true }, h("td", { colspan: 5 }, it.reasons.length ? h("ul", { class: "reasons" }, it.reasons.map((r) => h("li", {}, r.text))) : "No details."));
        tbody.append(h("tr", { class: "clickable", tabindex: 0, onclick: () => (detail.hidden = !detail.hidden), onkeydown: (e) => { if (e.key === "Enter") detail.hidden = !detail.hidden; } },
          h("td", {}, fmtTime(it.created_at)), h("td", { class: "host" }, it.host, h("span", { class: "muted" }, it.path.length > 1 ? it.path.slice(0, 60) : "")), h("td", {}, it.risk_score), h("td", {}, chip(it.verdict)), h("td", { class: "muted" }, "details")), detail);
      }
      body.replaceChildren(h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Site", "Risk", "Verdict", ""].map((x) => h("th", {}, x)))), tbody),
        d.items.length ? null : h("p", { class: "muted" }, "No scans match."),
        h("div", { class: "pager" }, h("button", { disabled: offset === 0, onclick: () => { offset = Math.max(0, offset - limit); load(); } }, "Previous"),
          h("span", { class: "muted" }, `${Math.min(offset + 1, d.total)}-${Math.min(offset + limit, d.total)} of ${d.total}`),
          h("button", { disabled: offset + limit >= d.total, onclick: () => { offset += limit; load(); } }, "Next")));
    }
    verdict.addEventListener("change", () => { offset = 0; load(); });
    let t; search.addEventListener("input", () => { clearTimeout(t); t = setTimeout(() => { offset = 0; load(); }, 300); });
    root.append(h("h2", {}, "Scan history"), h("div", { class: "toolbar" }, verdict, search), body);
    await load();
  },

  async reports(root) {
    const rep = await api("/reports/threats");
    const result = h("div", {});
    const url = h("input", { type: "url", placeholder: "https://example.com/login", maxlength: 2048, "aria-label": "URL to check" });
    const deep = h("input", { type: "checkbox", id: "deepchk" });
    const go = h("button", { class: "primary", onclick: async () => {
      go.disabled = true; result.replaceChildren(h("p", { class: "muted" }, "Scanning..."));
      try {
        const r = await api("/scan", { method: "POST", body: { url: url.value.trim(), deep: deep.checked, record: false } });
        result.replaceChildren(h("p", {}, chip(r.verdict), " risk score ", h("b", {}, r.risk_score), r.confirmed_threat ? " - confirmed by a threat feed" : ""),
          h("ul", { class: "reasons" }, r.reasons.map((x) => h("li", {}, x.text))),
          h("p", { class: "muted" }, "Sources: " + Object.entries(r.sources).map(([k, v]) => `${k}: ${v.status || "ok"}`).join(", ")));
      } catch (e) { result.replaceChildren(h("p", { class: "error" }, e.message)); }
      go.disabled = false;
    } }, "Check URL");
    root.append(h("h2", {}, "Threat reports"),
      h("div", { class: "card" }, h("h3", {}, "Check a link"), h("div", { class: "toolbar" }, url, go), h("label", {}, deep, " Deep scan (domain age, TLS, redirects)"), result),
      h("div", { class: "grid2" },
        h("div", { class: "card" }, h("h3", {}, "Most-seen phishing sites"), rep.top_phishing_hosts.length ?
          h("table", {}, h("thead", {}, h("tr", {}, ["Site", "Hits", "Max risk", "Last seen"].map((x) => h("th", {}, x)))),
            h("tbody", {}, rep.top_phishing_hosts.map((r) => h("tr", {}, h("td", { class: "host" }, r.host), h("td", {}, r.n), h("td", {}, r.max_score), h("td", {}, fmtTime(r.last_seen)))))) : h("p", { class: "muted" }, "No phishing sites detected yet.")),
        h("div", { class: "card" }, h("h3", {}, "Top reasons sites were flagged"), rep.top_reasons.length ?
          h("ol", { class: "reasons" }, rep.top_reasons.map((r) => h("li", {}, `${r.reason} `, h("span", { class: "muted" }, `(${r.count})`)))) : h("p", { class: "muted" }, "Nothing flagged yet."))));
  },

  async model(root) {
    const m = await api("/model");
    if (m.detail) { root.append(h("h2", {}, "Detection model"), h("p", { class: "muted" }, m.detail)); return; }
    const cm = m.confusion_matrix, maxImp = Math.max(...Object.values(m.feature_importance));
    root.append(h("h2", {}, "Detection model"), h("div", { class: "banner" }, m.caveat),
      h("div", { class: "grid2" },
        h("div", { class: "card" }, h("h3", {}, "Performance on held-out data"), h("dl", { class: "kv" },
          ...[["Data source", m.data_source], ["Samples", `${m.samples} (${m.test_samples} test)`], ["Accuracy", m.accuracy], ["Precision", m.precision], ["Recall", m.recall], ["F1 score", m.f1], ["ROC AUC", m.roc_auc],
            ["False positive rate", m.false_positive_rate], ["False negative rate", m.false_negative_rate], ["5-fold CV F1", `${m.cv_f1_mean} +/- ${m.cv_f1_std}`]].flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]))),
        h("div", { class: "card" }, h("h3", {}, "Confusion matrix"), h("table", {}, h("thead", {}, h("tr", {}, ["", "Predicted legit", "Predicted phishing"].map((x) => h("th", {}, x)))),
          h("tbody", {}, h("tr", {}, h("td", {}, "Actually legit"), h("td", {}, cm.tn), h("td", {}, cm.fp)), h("tr", {}, h("td", {}, "Actually phishing"), h("td", {}, cm.fn), h("td", {}, cm.tp)))),
          h("h3", { class: "top" }, "What the model looks at"), ...Object.entries(m.feature_importance).slice(0, 10).map(([k, v]) => {
            const i = h("i", {}); i.style.width = (v / maxImp) * 100 + "%";
            return h("div", {}, h("div", { class: "muted" }, `${k.replaceAll("_", " ")} (${(v * 100).toFixed(1)}%)`), h("div", { class: "bar" }, i));
          }))));
  },

  async settings(root) {
    const me = await api("/me");
    const cur = h("input", { type: "password", autocomplete: "current-password", maxlength: 256 }), nw = h("input", { type: "password", autocomplete: "new-password", maxlength: 256 }), msg = h("p", { class: "error", role: "alert" });
    root.append(h("h2", {}, "Settings"),
      h("div", { class: "card" }, h("h3", {}, "Account"), h("dl", { class: "kv" }, h("dt", {}, "Signed in as"), h("dd", {}, me.username), h("dt", {}, "Role"), h("dd", {}, me.role), h("dt", {}, "Data retention"), h("dd", {}, `${me.retention_days} days (older scans are deleted automatically)`))),
      h("div", { class: "card" }, h("h3", {}, "Change password"), h("label", {}, "Current password"), cur, h("label", {}, "New password (12+ characters, upper and lower case, a digit)"), nw,
        h("p", {}, h("button", { class: "primary", onclick: async () => {
          msg.textContent = "";
          try { await api("/auth/change-password", { method: "POST", body: { current_password: cur.value, new_password: nw.value } }); cur.value = nw.value = ""; toast("Password changed."); } catch (e) { msg.textContent = e.message; }
        } }, "Change password")), msg),
      h("div", { class: "card" }, h("h3", {}, "What PhishGuard stores"),
        h("p", { class: "muted" }, "Site name and path (query values removed), risk score, verdict, the reasons, a timestamp and an anonymous install ID. It never stores passwords, cookies, authentication tokens, page contents, what you type, or screenshots.")));
  },

  async vault(root) {
    root.append(h("h2", {}, "Admin vault"));
    if (!SESSION.vault) {
      const key = h("input", { type: "password", autocomplete: "off", maxlength: 256, "aria-label": "Master key" }), err = h("p", { class: "error", role: "alert" });
      root.append(h("div", { class: "card" }, h("h3", {}, "Enter the master key"),
        h("p", { class: "muted" }, "The vault shows every record the system has collected, the audit trail and a security check. Access needs an admin account plus the server's master key, and every access is logged."),
        key, h("p", {}, h("button", { class: "primary", onclick: async () => {
          err.textContent = "";
          try { const r = await api("/admin/unlock", { method: "POST", body: { master_key: key.value } }); key.value = ""; SESSION.vault = r.vault_token; SESSION.vaultExp = Date.now() + r.expires_in * 1000; show("vault"); } catch (e) { err.textContent = e.message; }
        } }, "Unlock vault")), err));
      return;
    }
    const [data, audit, sec] = await Promise.all([api("/admin/data?limit=100", { vault: true }), api("/admin/audit", { vault: true }), api("/admin/security-check", { vault: true })]);
    const mins = Math.max(0, Math.round((SESSION.vaultExp - Date.now()) / 60000));
    const newU = h("input", { placeholder: "username", maxlength: 64 }), newP = h("input", { type: "password", placeholder: "password (12+ chars)", autocomplete: "new-password", maxlength: 256 }), newR = h("select", {}, h("option", { value: "analyst" }, "Analyst (read-only dashboard)"), h("option", { value: "admin" }, "Admin"));
    const days = h("input", { type: "number", min: 0, max: 3650, value: 90, "aria-label": "Delete scans older than (days)" });
    root.append(h("div", { class: "banner" }, `Vault unlocked - closes automatically in about ${mins} min. Every view is written to the audit log.`),
      h("div", { class: "card" }, h("h3", {}, `Security check - score ${sec.score}/100`),
        sec.checks.map((c) => h("div", { class: "check " + (c.passed ? "ok" : "fail") }, h("b", {}, c.passed ? "Pass" : "Fix"), h("div", {}, c.name, c.fix ? h("div", { class: "muted" }, c.fix) : null)))),
      h("div", { class: "grid2" },
        h("div", { class: "card" }, h("h3", {}, "What is collected"), h("ul", { class: "reasons" }, data.collected_fields.map((x) => h("li", {}, x))), h("h3", { class: "top" }, "Never collected"), h("ul", { class: "reasons" }, data.never_collected.map((x) => h("li", {}, x)))),
        h("div", { class: "card" }, h("h3", {}, "Accounts"), h("table", {}, h("thead", {}, h("tr", {}, ["User", "Role", "Active"].map((x) => h("th", {}, x)))), h("tbody", {}, data.users.map((u) => h("tr", {}, h("td", {}, u.username), h("td", {}, u.role), h("td", {}, u.active ? "yes" : "no"))))),
          h("h3", { class: "top" }, "Add account"), newU, newP, newR,
          h("p", {}, h("button", { onclick: async () => { try { await api("/admin/users", { method: "POST", body: { username: newU.value, password: newP.value, role: newR.value }, vault: true }); toast("Account created."); show("vault"); } catch (e) { toast(e.message); } } }, "Create account")))),
      h("div", { class: "card" }, h("h3", {}, `All collected scans (latest 100 of ${data.total_scans})`),
        h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, ["ID", "Time", "Install", "URL (no query values)", "Risk", "Verdict"].map((x) => h("th", {}, x)))),
          h("tbody", {}, data.scans.map((r) => h("tr", {}, h("td", {}, r.id), h("td", {}, fmtTime(r.created_at)), h("td", {}, r.install_id ?? "dashboard"), h("td", { class: "host" }, `${r.scheme}://${r.host}${r.path}`), h("td", {}, r.risk_score), h("td", {}, chip(r.verdict)))))))),
      h("div", { class: "card" }, h("h3", {}, "Audit log"), h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Actor", "Action", "Detail", "IP"].map((x) => h("th", {}, x)))),
        h("tbody", {}, audit.entries.map((e) => h("tr", {}, h("td", {}, fmtTime(e.ts)), h("td", {}, e.actor), h("td", {}, e.action), h("td", {}, e.detail), h("td", {}, e.ip))))))),
      h("div", { class: "card" }, h("h3", {}, "Data retention"), h("p", { class: "muted" }, "Permanently delete scan records older than this many days."), days,
        h("p", {}, h("button", { class: "danger", onclick: async () => { if (!confirm(`Delete all scans older than ${days.value} days? This cannot be undone.`)) return; try { const r = await api("/admin/purge", { method: "POST", body: { older_than_days: Number(days.value) }, vault: true }); toast(`${r.deleted} records deleted.`); show("vault"); } catch (e) { toast(e.message); } } }, "Delete old records"))),
      h("p", {}, h("button", { onclick: () => { SESSION.vault = null; show("vault"); } }, "Lock vault now")));
  },
};
function tile(label, n, cls = "") { return h("div", { class: "tile " + cls }, h("div", { class: "n" }, n), h("div", { class: "l" }, label)); }

// ------------------------------------------------------------------ shell
async function show(view) {
  const root = $("#main"); root.replaceChildren();
  document.querySelectorAll(".side button[data-view]").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  try { await views[view](root); } catch (e) { root.append(h("div", { class: "banner" }, e.message)); }
  root.focus({ preventScroll: true });
}
document.querySelectorAll(".side button[data-view]").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));

async function start() {
  try {
    SESSION.user = await api("/me");
  } catch { return; }
  $("#login").hidden = true; $("#app").hidden = false;
  $("#whoami").textContent = `${SESSION.user.username} (${SESSION.user.role})`;
  $("#vaultNav").hidden = SESSION.user.role !== "admin";
  show("overview");
}
if (SESSION.token) start(); else $("#login").hidden = false;
