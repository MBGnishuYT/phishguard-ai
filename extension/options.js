const $ = (id) => document.getElementById(id);
const send = (m) => chrome.runtime.sendMessage(m);
const ALL = { origins: ["http://*/*", "https://*/*"] };
let settings;

async function save(patch) {
  const { settings: cur } = await chrome.storage.local.get("settings");
  settings = { ...(cur || {}), ...patch };
  await chrome.storage.local.set({ settings });
}

async function load() {
  const s = await send({ type: "getTabState", tabId: -1 });
  settings = s.settings;
  for (const k of ["enabled", "notifications", "deepScan", "shareScans"]) $(k).checked = !!settings[k];
  $("pageAnalysis").checked = !!settings.pageAnalysis;
  $("apiBase").value = settings.apiBase;
  renderTrust(s.whitelist);
  const { history } = await chrome.storage.local.get("history");
  $("hist").replaceChildren();
  for (const h of (history || []).slice(0, 50)) {
    const li = document.createElement("li");
    const a = document.createElement("span"); a.textContent = `${new Date(h.t).toLocaleString()}  ${h.host}${h.offline ? " (offline check)" : ""}`;
    const b = document.createElement("span"); b.className = "chip " + h.verdict; b.textContent = `${h.verdict} ${h.score}`;
    li.append(a, b); $("hist").append(li);
  }
  if (!(history || []).length) { const li = document.createElement("li"); li.className = "muted"; li.textContent = "No scans yet."; $("hist").append(li); }
}

function renderTrust(list) {
  $("trustList").replaceChildren();
  if (!list.length) { const li = document.createElement("li"); li.className = "muted"; li.textContent = "No trusted sites yet."; $("trustList").append(li); return; }
  for (const h of list) {
    const li = document.createElement("li"); const a = document.createElement("span"); a.textContent = h;
    const b = document.createElement("button"); b.textContent = "Remove"; b.addEventListener("click", async () => { await send({ type: "untrustHost", host: h }); load(); });
    li.append(a, b); $("trustList").append(li);
  }
}

for (const k of ["notifications", "deepScan", "shareScans"]) $(k).addEventListener("change", (e) => save({ [k]: e.target.checked }));
$("enabled").addEventListener("change", (e) => send({ type: "setEnabled", enabled: e.target.checked }));

$("pageAnalysis").addEventListener("change", async (e) => {
  const want = e.target.checked;
  if (want) {
    const ok = await chrome.permissions.request(ALL); // must run inside this click handler (user gesture)
    if (!ok) { e.target.checked = false; return; }
  }
  const r = await send({ type: "applyPageAnalysis", enabled: want });
  if (!r.ok) { e.target.checked = false; alert(r.error || "Could not change page analysis."); return; }
  await save({ pageAnalysis: want });
});

$("saveApi").addEventListener("click", async () => {
  const status = $("apiStatus"); status.textContent = "Testing…";
  let base;
  try { const u = new URL($("apiBase").value.trim()); base = u.origin; } catch { status.textContent = "Enter a full address such as https://your-app.onrender.com"; return; }
  const granted = await chrome.permissions.request({ origins: [base + "/*"] }); // user gesture
  if (!granted) { status.textContent = "Permission to contact that server was not granted."; return; }
  const r = await send({ type: "testConnection", apiBase: base });
  if (!r.ok) { status.textContent = "Could not connect: " + r.error; return; }
  await save({ apiBase: base }); await chrome.storage.local.remove(["installToken", "installApi"]);
  status.textContent = r.health.model_loaded ? "Connected. Model loaded." : "Connected, but the server has no ML model loaded.";
});

$("addTrust").addEventListener("click", async () => {
  const r = await send({ type: "trustHost", host: $("newTrust").value });
  if (r.error) alert(r.error); else { $("newTrust").value = ""; load(); }
});
$("clearHist").addEventListener("click", async () => { await send({ type: "clearHistory" }); load(); });
load();
