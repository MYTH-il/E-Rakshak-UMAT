"use strict";

const state = { session: null, cases: [], pollTimer: null, activeTab: "overview" };
const app = document.querySelector("#app");

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = String(text);
  return element;
}

function append(parent, ...children) {
  children.filter(Boolean).forEach((child) => parent.append(child));
  return parent;
}

function link(label, href, className = "") {
  const element = node("a", className, label);
  element.href = href;
  if (href.startsWith("/")) element.addEventListener("click", navigateEvent);
  return element;
}

function button(label, className = "btn") {
  const element = node("button", className, label);
  element.type = "button";
  return element;
}

function formatDate(value) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function formatBytes(value) {
  if (!Number.isFinite(Number(value))) return "—";
  const units = ["B", "KiB", "MiB", "GiB"];
  let size = Number(value);
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
  return `${size.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

function human(value) {
  return String(value || "unknown").replaceAll("_", " ");
}

function csrfToken() {
  const pair = document.cookie.split("; ").find((item) => item.startsWith("umat_csrf="));
  return pair ? decodeURIComponent(pair.split("=").slice(1).join("=")) : "";
}

async function api(path, options = {}) {
  const request = { credentials: "same-origin", ...options };
  request.headers = new Headers(options.headers || {});
  if (request.body && !(request.body instanceof FormData) && typeof request.body !== "string") {
    request.headers.set("Content-Type", "application/json");
    request.body = JSON.stringify(request.body);
  }
  if (request.method && !["GET", "HEAD"].includes(request.method.toUpperCase())) {
    request.headers.set("X-CSRF-Token", csrfToken());
  }
  const response = await fetch(path, request);
  if (response.status === 401 && !path.endsWith("/login")) {
    state.session = null;
    go("/login");
    throw new Error("Your session has expired.");
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try { message = (await response.json()).detail || message; } catch (_) { /* response was not JSON */ }
    throw new Error(message);
  }
  if (response.status === 204) return null;
  return response.json();
}

function toast(message, error = false) {
  const existing = document.querySelector(".toast");
  if (existing) existing.remove();
  const item = node("div", `toast${error ? " notice-error" : ""}`, message);
  document.body.append(item);
  window.setTimeout(() => item.remove(), 4500);
}

function go(path) {
  history.pushState({}, "", path);
  renderRoute();
}

function navigateEvent(event) {
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  go(event.currentTarget.getAttribute("href"));
}

function badge(value) {
  return node("span", `badge badge-${String(value || "unknown").toLowerCase()}`, human(value));
}

function navItem(label, href, active) {
  return link(label, href, `nav-link${active ? " active" : ""}`);
}

function shell(title, content) {
  const path = location.pathname;
  const root = node("div", "shell");
  const sidebar = node("aside", "sidebar");
  sidebar.id = "sidebar";
  const brand = link("", "/cases", "brand");
  append(brand, node("span", "brand-mark", "U"));
  const brandCopy = node("span");
  append(brandCopy, node("strong", "", "UMAT"), node("small", "", "Analysis console"));
  brand.append(brandCopy);
  sidebar.append(brand, node("div", "nav-label", "Workspace"));
  sidebar.append(
    navItem("Case queue", "/cases", path === "/cases" || path.startsWith("/cases/")),
    navItem("New analysis", "/submit", path === "/submit")
  );
  if (state.session.roles.includes("administrator")) {
    sidebar.append(node("div", "nav-label", "Administration"));
    sidebar.append(navItem("Windows profiles", "/admin/windows", path === "/admin/windows"));
  }
  const foot = node("div", "sidebar-foot");
  const user = node("div", "user-chip");
  append(user, node("strong", "", state.session.username), node("small", "", state.session.roles.join(" · ")));
  const logout = button("Sign out", "btn btn-ghost btn-small");
  logout.addEventListener("click", async () => {
    try { await api("/api/v1/auth/logout", { method: "POST" }); } finally { state.session = null; go("/login"); }
  });
  append(user, logout); foot.append(user); sidebar.append(foot);

  const column = node("div", "main-column");
  const topbar = node("header", "topbar");
  const menu = button("Menu", "btn btn-ghost mobile-menu");
  menu.addEventListener("click", () => sidebar.classList.toggle("open"));
  append(topbar, append(node("div", "top-actions"), menu, node("h1", "", title)), link("New analysis", "/submit", "btn btn-primary"));
  const main = node("main", "content"); main.id = "main"; main.append(content);
  column.append(topbar, main); root.append(sidebar, column);
  app.replaceChildren(root);
}

function pageHead(eyebrow, title, description, action) {
  const head = node("div", "page-head");
  const copy = node("div");
  append(copy, node("div", "eyebrow", eyebrow), node("h2", "", title), node("p", "", description));
  append(head, copy, action);
  return head;
}

async function renderLogin() {
  if (state.session) { go("/cases"); return; }
  const page = node("main", "login-page");
  const wrapper = node("div", "login-card");
  const identity = node("div", "login-brand");
  append(identity, node("span", "brand-mark", "U"), node("h1", "", "UMAT"), node("p", "", "Unified malware analysis and triage"));
  const card = node("section", "card card-body");
  const form = node("form");
  const username = field("Username", "text", "username", true);
  const password = field("Password", "password", "password", true);
  const error = node("div");
  const submit = button("Authenticate", "btn btn-primary"); submit.type = "submit";
  append(form, username.wrap, password.wrap, error, submit);
  form.addEventListener("submit", async (event) => {
    event.preventDefault(); error.replaceChildren(); submit.disabled = true;
    try {
      state.session = await api("/api/v1/auth/login", { method: "POST", body: { username: username.input.value, password: password.input.value } });
      go("/cases");
    } catch (failure) {
      error.append(node("div", "notice notice-error", failure.message));
    } finally { submit.disabled = false; }
  });
  card.append(form); wrapper.append(identity, card); page.append(wrapper); app.replaceChildren(page);
}

function field(label, type, name, required = false) {
  const wrap = node("div", "field");
  const labelNode = node("label", "", label); labelNode.htmlFor = `field-${name}`;
  const input = node("input"); input.type = type; input.name = name; input.id = `field-${name}`; input.required = required;
  append(wrap, labelNode, input);
  return { wrap, input };
}

async function renderCases() {
  const content = node("div");
  content.append(pageHead("Investigation workspace", "Case queue", "Track submissions, analysis progress, and finalized verdicts.", null));
  try { state.cases = await api("/api/v1/cases"); } catch (failure) { content.append(node("div", "notice notice-error", failure.message)); shell("Case queue", content); return; }
  const terminal = state.cases.filter((item) => item.latest_status === "terminal").length;
  const suspicious = state.cases.filter((item) => ["malicious", "suspicious"].includes(item.latest_verdict)).length;
  const stats = node("div", "grid grid-3");
  [[state.cases.length, "Accessible cases"], [state.cases.length - terminal, "Active analyses"], [suspicious, "Require review"]].forEach(([value, label]) => {
    const card = node("div", "card metric"); append(card, node("small", "", label), node("strong", "", value)); stats.append(card);
  });
  content.append(stats, node("h3", "section-title", "Recent cases"));
  const list = node("div", "case-list");
  if (!state.cases.length) list.append(node("div", "card empty", "No cases yet. Start a new analysis to populate the queue."));
  state.cases.forEach((item) => {
    const row = link("", `/cases/${item.case_id}`, "card case-row");
    const identity = node("div");
    append(identity, node("h3", "", item.title || "Untitled case"), node("div", "mono muted", item.reference || item.case_id));
    append(row, identity, node("div", "", human(item.latest_platform || "pending")), node("div", "muted", formatDate(item.created_at)), badge(item.latest_verdict || item.latest_status || "pending"));
    list.append(row);
  });
  content.append(list); shell("Case queue", content);
}

async function renderSubmit() {
  const content = node("div");
  content.append(pageHead("Secure intake", "Start an analysis", "Upload one sample. APK structure determines Android routing; all other accepted content routes to Windows/CAPE.", null));
  const card = node("section", "card card-body form-card");
  const form = node("form");
  const grid = node("div", "field-grid");
  const title = field("Case title", "text", "title"); title.input.maxLength = 256;
  const reference = field("Reference", "text", "reference"); reference.input.maxLength = 128;
  const file = field("Sample file", "file", "file", true); file.wrap.classList.add("full");
  const profileWrap = node("div", "field full");
  const profileLabel = node("label", "", "Windows analysis profile (ignored for valid APKs)");
  const profiles = node("select"); profiles.name = "windows_profile_id";
  profiles.append(node("option", "", "Use active default profile")); profiles.firstChild.value = "";
  try {
    const items = await api("/api/v1/windows/profiles");
    items.forEach((item) => { const option = node("option", "", `${item.display_name} · ${item.windows_version} · ${item.analysis_profile}`); option.value = item.id; profiles.append(option); });
  } catch (_) { /* profile selection can remain default */ }
  append(profileWrap, profileLabel, profiles);
  append(grid, title.wrap, reference.wrap, file.wrap, profileWrap);
  const note = node("div", "notice", "Files are streamed into quarantine, hashed, structurally routed, and stored under generated content-addressed keys. Filenames never become storage paths.");
  const submit = button("Create case and analyze", "btn btn-primary"); submit.type = "submit";
  append(form, grid, note, append(node("div", "form-actions"), submit));
  form.addEventListener("submit", async (event) => {
    event.preventDefault(); submit.disabled = true; submit.textContent = "Uploading…";
    const data = new FormData(); data.append("file", file.input.files[0]);
    if (title.input.value) data.append("title", title.input.value);
    if (reference.input.value) data.append("reference", reference.input.value);
    if (profiles.value) data.append("windows_profile_id", profiles.value);
    try {
      const result = await api("/api/v1/cases", { method: "POST", body: data });
      if (result.duplicate_cases.length) toast("Duplicate content found. Confirmation is required before analysis starts.");
      go(`/cases/${result.case_id}`);
    } catch (failure) { toast(failure.message, true); } finally { submit.disabled = false; submit.textContent = "Create case and analyze"; }
  });
  card.append(form); content.append(card); shell("New analysis", content);
}

function latestRun(caseData) {
  return [...caseData.analysis_runs].sort((a, b) => String(b.id).localeCompare(String(a.id)))[0] || null;
}

async function renderCase(caseId, preserveTab = false) {
  if (!preserveTab) state.activeTab = "overview";
  const content = node("div");
  let caseData;
  try { caseData = await api(`/api/v1/cases/${caseId}`); } catch (failure) { content.append(node("div", "notice notice-error", failure.message)); shell("Case", content); return; }
  const run = latestRun(caseData);
  const report = caseData.report;
  content.append(pageHead("Case investigation", caseData.title || "Untitled case", `${caseData.reference || caseData.case_id} · received ${formatDate(caseData.created_at)}`, null));
  if (run && run.status === "awaiting_confirmation") {
    const warning = node("div", "notice notice-warn");
    const confirm = button("Confirm new analysis", "btn btn-primary btn-small");
    confirm.addEventListener("click", async () => { try { await api(`/api/v1/analysis-runs/${run.id}/confirm`, { method: "POST" }); toast("Analysis confirmed and queued."); renderCase(caseId, true); } catch (failure) { toast(failure.message, true); } });
    append(warning, node("strong", "", "Duplicate sample detected. "), node("span", "", "No analysis stage will start until you confirm this run. "), confirm);
    content.append(warning);
  }
  const hero = node("section", "card verdict-hero");
  const heroCopy = node("div");
  append(heroCopy, node("div", "eyebrow", report ? "Unified verdict" : "Analysis status"), node("h2", "", report ? human(report.verdict) : human(run?.status || "pending")), node("p", "muted", report?.headline || "Evidence is being collected and normalized. The report will appear after aggregation."));
  const actions = node("div", "actions-row");
  if (report) ["pdf", "json", "csv"].forEach((format) => { const exportButton = button(`Export ${format.toUpperCase()}`, "btn btn-small"); exportButton.addEventListener("click", () => exportReport(caseId, format)); actions.append(exportButton); });
  if (run && !["terminal", "cancelling"].includes(run.status)) { const cancel = button("Cancel run", "btn btn-danger btn-small"); cancel.addEventListener("click", async () => { try { await api(`/api/v1/analysis-runs/${run.id}/cancel`, { method: "POST" }); toast("Cancellation requested."); renderCase(caseId, true); } catch (failure) { toast(failure.message, true); } }); actions.append(cancel); }
  heroCopy.append(actions); append(hero, heroCopy, node("div", "verdict-orb", report ? report.verdict.slice(0, 1).toUpperCase() : "…")); content.append(hero);

  const tabs = node("div", "tabs");
  const availableTabs = [["overview", "L1 Overview"], ["progress", "Run progress"], ["evidence", report?.technical ? "L3 Evidence" : "Evidence"]];
  if (report?.technical) availableTabs.splice(1, 0, ["findings", "L2 Findings"]);
  availableTabs.forEach(([key, label]) => { const tab = button(label, `tab${state.activeTab === key ? " active" : ""}`); tab.addEventListener("click", () => { state.activeTab = key; renderCase(caseId, true); }); tabs.append(tab); });
  content.append(tabs);
  if (state.activeTab === "overview") renderOverview(content, report, run);
  else if (state.activeTab === "findings") renderFindings(content, report);
  else if (state.activeTab === "evidence") renderEvidence(content, report);
  else renderProgress(content, caseData.analysis_runs);
  shell("Case report", content);
  schedulePoll(caseId, caseData.analysis_runs);
}

function renderOverview(content, report, run) {
  if (!report) { content.append(node("div", "card empty", `Current run state: ${human(run?.status || "pending")}. This page refreshes automatically while work is active.`)); return; }
  const grid = node("div", "grid grid-2");
  grid.append(listCard("Information accessed", report.information_accessed, (item) => [human(item.data_type), `${human(item.evidence_level)} · ${human(item.confidence)}`]));
  grid.append(listCard("Destinations and protocols", report.destinations, (item) => [item.value, `${item.protocol || "unknown"}${item.port ? ` · port ${item.port}` : ""}`]));
  content.append(grid);
  content.append(node("h3", "section-title", "Important provenance"), listCard(null, report.provenance, (item) => [item.statement, [human(item.item_type), item.destination].filter(Boolean).join(" · ")]));
  content.append(node("h3", "section-title", "Analysis limitations"));
  if (report.caveats.length) content.append(listCard(null, report.caveats.map((value) => ({ value })), (item) => [human(item.value), "Caveat included in officer report"]));
  else content.append(node("div", "notice", "No material analysis limitations were recorded."));
  if (report.tested_profile) content.append(node("h3", "section-title", "Tested OS profile"), listCard(null, [report.tested_profile], (item) => [item.name || item.windows_version || "Windows profile", `${item.windows_version || ""} · ${item.vcpus || "?"} vCPU · ${item.ram_mb ? formatBytes(item.ram_mb * 1024 * 1024) : "RAM unknown"}`]));
}

function listCard(title, items, mapper) {
  const card = node("section", "card card-body");
  if (title) card.append(node("h3", "card-title", title));
  const list = node("ul", "data-list");
  if (!items?.length) list.append(node("li", "empty", "No reportable evidence in this section."));
  (items || []).forEach((item) => { const [primary, secondary] = mapper(item); const row = node("li", "data-item"); const copy = node("div"); append(copy, node("strong", "", primary), secondary ? node("small", "", secondary) : null); row.append(copy); list.append(row); });
  card.append(list); return card;
}

function renderFindings(content, report) {
  const technical = report?.technical;
  if (!technical) { content.append(node("div", "notice notice-error", "Technical findings require analyst access.")); return; }
  content.append(node("h3", "section-title", "Normalized findings"));
  content.append(table(["Finding", "Source", "Confidence", "Evidence", "MITRE ATT&CK"], technical.findings, (item) => [item.summary, `${item.source} · ${human(item.kind)}`, human(item.confidence), human(item.evidence_level), (item.mitre_technique_ids || []).join(", ") || "—"]));
  content.append(node("h3", "section-title", "Indicators of compromise"));
  content.append(table(["Type", "Value", "Confidence", "Source", "Traffic"], technical.iocs, (item) => [item.type, item.value, human(item.confidence), item.source, item.seen_in_traffic ? "Observed" : "Static"]));
  content.append(node("h3", "section-title", "Unified timeline"));
  content.append(table(["Time", "Actor", "Event", "MITRE"], technical.timeline, (item) => [formatDate(item.occurred_at), item.actor, item.description, item.mitre_technique_id || "—"]));
}

function table(headers, rows, mapper) {
  const wrap = node("div", "table-wrap"); const element = node("table"); const head = node("thead"); const headRow = node("tr"); headers.forEach((item) => headRow.append(node("th", "", item))); head.append(headRow); const body = node("tbody");
  if (!rows?.length) { const row = node("tr"); const cell = node("td", "empty", "No records available."); cell.colSpan = headers.length; row.append(cell); body.append(row); }
  (rows || []).forEach((item) => { const row = node("tr"); mapper(item).forEach((value) => row.append(node("td", "", value ?? "—"))); body.append(row); });
  element.append(head, body); wrap.append(element); return wrap;
}

function renderEvidence(content, report) {
  if (!report) { content.append(node("div", "card empty", "Evidence will be listed after report aggregation.")); return; }
  const integrity = report.integrity || {};
  const stats = node("div", "grid grid-3");
  [[integrity.validated_bundle_count || 0, "Validated bundles"], [integrity.registered_artifact_count || 0, "Registered artifacts"], [(integrity.bundle_hashes || []).length, "Bundle digests"]].forEach(([value, label]) => { const card = node("div", "card metric"); append(card, node("small", "", label), node("strong", "", value)); stats.append(card); });
  content.append(stats, node("h3", "section-title", "Authorized artifacts"));
  const list = node("div", "case-list");
  if (!report.artifacts.length) list.append(node("div", "card empty", "No artifacts are authorized for your role."));
  report.artifacts.forEach((item) => { const row = node("div", "card case-row"); const identity = node("div"); append(identity, node("h3", "", human(item.kind)), node("div", "mono muted", item.sha256)); const download = link("Download", item.download_path, "btn btn-small"); download.removeEventListener("click", navigateEvent); append(row, identity, node("div", "", formatBytes(item.size_bytes)), badge(item.access_tier), download); list.append(row); });
  content.append(list);
}

function renderProgress(content, runs) {
  [...runs].reverse().forEach((run, index) => {
    const title = node("h3", "section-title", `${index ? "Earlier" : "Current"} ${human(run.platform)} run`); content.append(title);
    const card = node("section", "card card-body"); const head = node("div", "actions-row"); append(head, badge(run.status), run.result ? badge(run.result) : null, node("span", "mono muted", run.id)); card.append(head);
    const track = node("div", "stage-track stage-track-spaced");
    const order = ["platform_analysis", "c2_analysis", "platform_adaptation", "c2_adaptation", "case_aggregation", "report_generation"];
    order.forEach((kind) => { const stageData = run.stages.find((item) => item.stage_type === kind); const stage = node("div", "stage"); append(stage, node("strong", "", human(kind)), node("span", `badge-${stageData?.state || "waiting"}`, human(stageData?.state || "waiting"))); track.append(stage); });
    card.append(track); content.append(card);
  });
}

async function exportReport(caseId, format) {
  try { const result = await api(`/api/v1/cases/${caseId}/exports/${format}`, { method: "POST" }); toast(`${format.toUpperCase()} export created and integrity-registered.`); window.location.assign(result.download_path); } catch (failure) { toast(failure.message, true); }
}

function schedulePoll(caseId, runs) {
  if (state.pollTimer) window.clearTimeout(state.pollTimer);
  if (!runs.some((run) => run.status !== "terminal")) return;
  const prior = Number(sessionStorage.getItem(`poll-${caseId}`) || 2000);
  const delay = Math.min(prior, 30000);
  sessionStorage.setItem(`poll-${caseId}`, String(Math.min(delay * 2, 30000)));
  state.pollTimer = window.setTimeout(() => renderCase(caseId, true), delay);
}

async function renderWindowsAdmin() {
  if (!state.session.roles.includes("administrator")) { go("/cases"); return; }
  const content = node("div");
  content.append(pageHead("CAPE orchestration", "Windows VM profiles", "Create and retire CAPE-managed VM/user profiles. Existing run snapshots remain reproducible after retirement.", null));
  const create = node("section", "card card-body"); create.append(node("h3", "card-title", "Provision profile"));
  const form = node("form"); const grid = node("div", "field-grid");
  const definitions = [["Machine name", "name", "text", ""], ["Display name", "display_name", "text", ""], ["Windows version", "windows_version", "text", "Windows 10 22H2"], ["CAPE template", "cape_template", "text", "win10-hardened"], ["vCPUs", "vcpus", "number", "4"], ["RAM (MiB)", "ram_mb", "number", "8192"], ["Disk (GiB)", "disk_gb", "number", "160"], ["Guest username", "username", "text", "officer"]];
  const controls = {};
  definitions.forEach(([label, name, type, value]) => { const item = field(label, type, name, true); item.input.value = value; controls[name] = item.input; grid.append(item.wrap); });
  const profileField = node("div", "field"); const profileLabel = node("label", "", "Analysis profile"); const profile = node("select"); ["standard", "deep_static", "tls_intercept", "full_memory", "full_investigation"].forEach((value) => { const option = node("option", "", human(value)); option.value = value; profile.append(option); }); append(profileField, profileLabel, profile); grid.append(profileField);
  const submit = button("Queue provisioning", "btn btn-primary"); submit.type = "submit"; append(form, grid, append(node("div", "form-actions"), submit)); create.append(form); content.append(create, node("h3", "section-title", "Managed profiles"));
  const list = node("div", "case-list"); content.append(list); shell("Windows profiles", content);
  async function load() { const items = await api("/api/v1/windows/profiles?include_inactive=true"); list.replaceChildren(); items.forEach((item) => { const row = node("div", "card case-row"); const copy = node("div"); append(copy, node("h3", "", item.display_name), node("div", "mono muted", `${item.name} · ${item.windows_version} · ${item.vcpus} vCPU · ${item.ram_mb} MiB · ${item.disk_gb} GiB`)); const remove = button("Retire", "btn btn-danger btn-small"); remove.disabled = ["deleting", "deleted", "provisioning"].includes(item.state); remove.addEventListener("click", async () => { try { await api(`/api/v1/windows/profiles/${item.id}`, { method: "DELETE" }); toast("Profile deletion queued through CAPE."); load(); } catch (failure) { toast(failure.message, true); } }); append(row, copy, node("div", "", human(item.analysis_profile)), badge(item.state), remove); list.append(row); }); }
  form.addEventListener("submit", async (event) => { event.preventDefault(); const body = { name: controls.name.value, display_name: controls.display_name.value, windows_version: controls.windows_version.value, architecture: "x64", vcpus: Number(controls.vcpus.value), ram_mb: Number(controls.ram_mb.value), disk_gb: Number(controls.disk_gb.value), user_profile: { username: controls.username.value, locale: "en-US", timezone: "UTC", installed_software: [] }, analysis_profile: profile.value, cape_template: controls.cape_template.value, is_default: false }; try { await api("/api/v1/windows/profiles", { method: "POST", body }); toast("Profile provisioning queued."); form.reset(); load(); } catch (failure) { toast(failure.message, true); } });
  try { await load(); } catch (failure) { list.append(node("div", "notice notice-error", failure.message)); }
}

async function renderRoute() {
  if (state.pollTimer) { window.clearTimeout(state.pollTimer); state.pollTimer = null; }
  if (!state.session && location.pathname !== "/login") {
    try { state.session = await api("/api/v1/auth/session"); } catch (_) { if (location.pathname !== "/login") history.replaceState({}, "", "/login"); }
  }
  const path = location.pathname;
  if (path === "/login") return renderLogin();
  if (!state.session) return renderLogin();
  if (path === "/" || path === "/cases") return renderCases();
  if (path === "/submit") return renderSubmit();
  if (path === "/admin/windows") return renderWindowsAdmin();
  const match = path.match(/^\/cases\/([0-9a-f-]+)$/i);
  if (match) return renderCase(match[1]);
  go("/cases");
}

window.addEventListener("popstate", renderRoute);
renderRoute();
