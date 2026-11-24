const $ = (id) => document.getElementById(id);
const send = (m) => chrome.runtime.sendMessage(m);
const LABELS = { safe: "Looks safe", suspicious: "Be careful", phishing: "Dangerous - likely phishing" };
let state = null;

function render(result, tab, settings) {
  $("enabled").checked = settings.enabled;
  const g = $("gauge"); g.className = "gauge";
  $("reasons").replaceChildren();
  $("notice").hidden = true;
  if (!settings.enabled) { $("score").textContent = "OFF"; $("label").textContent = "Protection is off"; $("host").textContent = "Turn it on to scan pages."; return; }
  if (!tab || !tab.scannable) { $("score").textContent = "–"; $("label").textContent = "Nothing to scan here"; $("host").textContent = "Open a website (http/https) to see its safety rating."; $("rescan").disabled = true; $("trust").disabled = true; return; }
  if (!result) { $("score").textContent = "–"; $("label").textContent = "No scan yet"; $("host").textContent = tab.url || ""; return; }
  g.classList.add(result.verdict);
  $("score").textContent = result.risk_score;
  $("label").textContent = LABELS[result.verdict] || result.verdict;
  $("host").textContent = result.host + (result.whitelisted ? " (trusted by you)" : "");
  for (const r of (result.reasons || []).slice(0, 5)) { const li = document.createElement("li"); li.className = r.severity; li.textContent = r.text; $("reasons").append(li); }
  if (result.offline) { $("notice").hidden = false; $("notice").textContent = "Backend unreachable - showing a basic offline check only. " + (result.backend_error || ""); }
}

function renderRecent(items) {
  $("recent").replaceChildren();
  if (!items.length) { const li = document.createElement("li"); li.className = "muted"; li.textContent = "No scans yet."; $("recent").append(li); return; }
  for (const h of items) {
    const li = document.createElement("li"); const a = document.createElement("span"); a.textContent = h.host;
    const b = document.createElement("span"); b.className = "chip " + h.verdict; b.textContent = h.score;
    li.append(a, b); $("recent").append(li);
  }
}

async function load() {
  state = await send({ type: "getTabState" });
  render(state.result, state.tab, state.settings); renderRecent(state.history);
}

$("enabled").addEventListener("change", async (e) => { await send({ type: "setEnabled", enabled: e.target.checked }); load(); });
$("rescan").addEventListener("click", async () => {
  $("rescan").disabled = true; $("rescan").textContent = "Scanning…";
  const r = await send({ type: "rescan", deep: true });
  $("rescan").disabled = false; $("rescan").textContent = "Deep scan this page";
  if (r.error) { $("notice").hidden = false; $("notice").textContent = r.error; } else load();
});
$("trust").addEventListener("click", async () => {
  if (!state || !state.result) return;
  if (!confirm(`Always trust ${state.result.host}? PhishGuard will stop scanning it.`)) return;
  const r = await send({ type: "trustHost", host: state.result.host });
  if (r.error) alert(r.error); else load();
});
$("options").addEventListener("click", (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); });
$("dash").addEventListener("click", async (e) => { e.preventDefault(); const { settings } = await chrome.storage.local.get("settings"); chrome.tabs.create({ url: ((settings && settings.apiBase) || "http://127.0.0.1:8000") + "/dashboard/" }); });
load();
