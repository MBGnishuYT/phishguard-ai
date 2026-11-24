const $ = (id) => document.getElementById(id);
const id = new URLSearchParams(location.search).get("id") || "";
const valid = /^[0-9a-f-]{36}$/.test(id);

async function init() {
  const data = valid ? (await chrome.storage.session.get(`warn:${id}`))[`warn:${id}`] : null;
  if (!data) { $("host").textContent = "this site"; $("proceed").hidden = true; $("trust").hidden = true; $("score").textContent = "–"; return; }
  $("host").textContent = data.host;
  $("score").textContent = data.score;
  $("confirmed").hidden = !data.confirmed;
  $("offline").hidden = !data.offline;
  for (const r of data.reasons.filter((x) => x.severity !== "info").slice(0, 6)) {
    const li = document.createElement("li"); li.className = r.severity; li.textContent = r.text; $("reasons").append(li);
  }
}
$("leave").addEventListener("click", () => chrome.runtime.sendMessage({ type: "leave" }));
$("ack").addEventListener("change", (e) => { $("proceed").disabled = !e.target.checked; });
$("proceed").addEventListener("click", () => chrome.runtime.sendMessage({ type: "allowOnce", id }));
$("trust").addEventListener("click", async () => {
  const data = (await chrome.storage.session.get(`warn:${id}`))[`warn:${id}`];
  if (!data) return;
  if (!confirm(`Trust ${data.host} permanently? Only do this if you are sure it is legitimate.`)) return;
  await chrome.runtime.sendMessage({ type: "trustHost", host: data.host });
  await chrome.runtime.sendMessage({ type: "allowOnce", id });
});
init();
