"use strict";

// Officer-facing caveat text. Mirrors contracts/vocabularies/caveats.json
// (descriptions). tests/unit/test_web_ui.py asserts the two stay in sync —
// an officer must never be shown a bare machine code.
const CAVEAT_TEXT = {
  analysis_timed_out: "The analysis ran out of time before finishing. Behaviour that occurs later than the time allowed would not have been seen.",
  android_api_monitoring_failed: "Monitoring of the app's activity on the device did not work, so its behaviour was only partly recorded.",
  android_dynamic_stop_failed: "The device did not shut down cleanly after the test, so the final part of the recording may be incomplete.",
  c2_analysis_failed: "The examination of network traffic failed, even though the rest of the analysis completed. Any servers contacted are not reported here.",
  c2_workflow_skipped: "Network-traffic analysis was not run for this sample, so no report is made about which servers it contacted. This was a choice made when the analysis was started, not a failure.",
  c2_network_only: "Only network traffic was available for this analysis. We can report which servers were contacted, but not which specific information was taken from the device.",
  cape_package_unsupported: "No suitable method was available to run this particular file type, so it could not be fully tested.",
  clock_uncertainty: "The clocks used to time events did not agree closely enough, which reduces confidence in the order and timing of what happened.",
  delayed_behavior_possible: "This file may be built to stay inactive for a period, or to act only under conditions not present during the test. A quiet result may not reflect its behaviour on a real device.",
  guest_profile_out_of_support: "The test system used a version of Windows that is no longer supported, which may not match the device under investigation.",
  host_network_correlation_unavailable: "We could not reliably link what the file read on the computer to what it sent over the network, so no claim is made about which specific information left the device.",
  host_telemetry_degraded: "Some monitoring on the test computer did not run, so certain activity may have happened without being recorded. Absence of a finding is not proof it did not occur.",
  network_capture_incomplete: "The recording of network traffic was incomplete, so some connections may be missing from this report.",
  network_responses_simulated: "The internet connection was faked during analysis. We can see where this file tried to send information, but not whether it succeeded. Seeing no theft here does not mean the file is safe.",
  static_analysis_only: "The file was examined but never run. Findings describe what it appears able to do, not what it was observed doing.",
  static_tool_unavailable: "One of the file-inspection tools did not run, so part of the examination of the file itself is missing.",
  stimulation_incomplete: "The app was not fully exercised during the test, so features that only activate through further use may not have been triggered.",
  tls_pinning: "The file used encryption we could not read. We can see who it contacted and how often, but not the contents of what was sent."
};

const state = {
  session: null, cases: [], pollTimer: null, activeTab: "overview",
  caseFilter: { query: "", status: "", platform: "", verdict: "" },
  activeRunId: null
};

// --- role helpers ---------------------------------------------------------
// The API already filters responses by role; the UI must additionally avoid
// showing controls a role cannot use, so an officer is never presented an
// action that will fail.
function hasRole(role) { return Boolean(state.session && state.session.roles.includes(role)); }
function isAdmin() { return hasRole("administrator"); }
function isAnalyst() { return hasRole("analyst") || isAdmin(); }
function canSubmit() { return isAnalyst() || hasRole("officer"); }
function canControlRuns() { return isAnalyst(); }
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
    sidebar.append(navItem("Android profiles", "/admin/android", path === "/admin/android"));
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

function selectField(label, name, options, value) {
  const wrap = node("div", "field");
  const labelNode = node("label", "", label); labelNode.htmlFor = `filter-${name}`;
  const select = node("select"); select.name = name; select.id = `filter-${name}`;
  options.forEach(([text, val]) => { const option = node("option", "", text); option.value = val; select.append(option); });
  select.value = value || "";
  append(wrap, labelNode, select);
  return { wrap, select };
}

function matchesFilter(item) {
  const f = state.caseFilter;
  if (f.status && (item.latest_status || "") !== f.status) return false;
  if (f.platform && (item.latest_platform || "") !== f.platform) return false;
  if (f.verdict && (item.latest_verdict || "") !== f.verdict) return false;
  if (f.query) {
    const hay = [item.title, item.reference, item.case_id, item.latest_headline]
      .filter(Boolean).join(" ").toLowerCase();
    if (!hay.includes(f.query.toLowerCase())) return false;
  }
  return true;
}

async function renderCases() {
  const content = node("div");
  content.append(pageHead("Investigation workspace", "Case queue",
    "Search, filter and open cases. Each case can hold several analysis runs.", null));
  try { state.cases = await api("/api/v1/cases"); }
  catch (failure) { content.append(node("div", "notice notice-error", failure.message)); shell("Case queue", content); return; }

  const terminal = state.cases.filter((item) => item.latest_status === "terminal").length;
  const attention = state.cases.filter((item) => ["malicious", "suspicious"].includes(item.latest_verdict)).length;
  const stats = node("div", "grid grid-3");
  [[state.cases.length, "Accessible cases"], [state.cases.length - terminal, "Active analyses"], [attention, "Require review"]]
    .forEach(([value, label]) => { const card = node("div", "card metric"); append(card, node("small", "", label), node("strong", "", value)); stats.append(card); });
  content.append(stats);

  // --- filter bar --------------------------------------------------------
  const filters = node("section", "card card-body");
  const bar = node("div", "field-grid");
  const search = field("Search title, reference, ID or headline", "search", "case-search");
  search.input.value = state.caseFilter.query;
  search.wrap.classList.add("full");
  const uniq = (key) => [...new Set(state.cases.map((c) => c[key]).filter(Boolean))].sort();
  const statusSel = selectField("Status", "status", [["Any status", ""], ...uniq("latest_status").map((v) => [human(v), v])], state.caseFilter.status);
  const platformSel = selectField("Platform", "platform", [["Any platform", ""], ...uniq("latest_platform").map((v) => [human(v), v])], state.caseFilter.platform);
  const verdictSel = selectField("Verdict", "verdict", [["Any verdict", ""], ...uniq("latest_verdict").map((v) => [human(v), v])], state.caseFilter.verdict);
  append(bar, search.wrap, statusSel.wrap, platformSel.wrap, verdictSel.wrap);
  filters.append(bar);
  content.append(filters);

  const heading = node("h3", "section-title", "Cases");
  const list = node("div", "case-list");
  content.append(heading, list);

  function paint() {
    const rows = state.cases.filter(matchesFilter);
    heading.textContent = rows.length === state.cases.length
      ? `Cases (${rows.length})`
      : `Cases (${rows.length} of ${state.cases.length})`;
    list.replaceChildren();
    if (!state.cases.length) { list.append(node("div", "card empty", "No cases yet. Start a new analysis to populate the queue.")); return; }
    if (!rows.length) { list.append(node("div", "card empty", "No cases match the current filters.")); return; }
    rows.forEach((item) => {
      const row = link("", `/cases/${item.case_id}`, "card case-row");
      const identity = node("div");
      append(identity,
        node("h3", "", item.title || "Untitled case"),
        node("div", "mono muted", item.reference || item.case_id),
        item.latest_headline ? node("small", "muted", item.latest_headline) : null);
      append(row, identity,
        node("div", "", human(item.latest_platform || "pending")),
        node("div", "muted", formatDate(item.created_at)),
        badge(item.latest_status || "pending"),
        badge(item.latest_verdict || "pending"));
      list.append(row);
    });
  }
  search.input.addEventListener("input", () => { state.caseFilter.query = search.input.value; paint(); });
  [["status", statusSel], ["platform", platformSel], ["verdict", verdictSel]].forEach(([key, control]) => {
    control.select.addEventListener("change", () => { state.caseFilter[key] = control.select.value; paint(); });
  });
  paint();
  shell("Case queue", content);
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
  const androidProfileWrap = node("div", "field full");
  const androidProfileLabel = node("label", "", "Android analysis profile (ignored for non-APKs)");
  const androidProfiles = node("select"); androidProfiles.name = "android_profile_id";
  androidProfiles.append(node("option", "", "Use active default profile")); androidProfiles.firstChild.value = "";
  try {
    const items = await api("/api/v1/android/profiles");
    items.forEach((item) => { const option = node("option", "", `${item.display_name} · API ${item.api_level} · ${item.architecture} · ${item.ram_mb} MiB`); option.value = item.id; androidProfiles.append(option); });
  } catch (_) { /* profile selection can remain default */ }
  append(androidProfileWrap, androidProfileLabel, androidProfiles);
  const networkWrap = node("div", "field full"); const networkLabel = node("label", "", "Analysis network"); const networkMode = node("select"); networkMode.name = "network_mode";
  [["Isolated / simulated (recommended)", "isolated_simulated"], ["Real-world network egress (not containment-qualified)", "real_world_egress"]].forEach(([label, value]) => { const option = node("option", "", label); option.value = value; networkMode.append(option); }); append(networkWrap, networkLabel, networkMode);
  const c2Wrap = node("label", "field full checkbox-field"); const c2Enabled = node("input"); c2Enabled.type = "checkbox"; c2Enabled.name = "c2_analysis_enabled"; append(c2Wrap, c2Enabled, node("span", "", "Run C2 analyzer on captured traffic (guest remains governed by the selected network mode)"));
  append(grid, title.wrap, reference.wrap, file.wrap, profileWrap, androidProfileWrap, networkWrap, c2Wrap);
  const note = node("div", "notice", "Isolated/simulated networking is the malware-safe baseline. C2 analysis is optional and can inspect captured connection attempts without enabling Internet access. Real-world egress remains unqualified.");
  const submit = button("Create case and analyze", "btn btn-primary"); submit.type = "submit";
  append(form, grid, note, append(node("div", "form-actions"), submit));
  form.addEventListener("submit", async (event) => {
    event.preventDefault(); submit.disabled = true; submit.textContent = "Uploading…";
    const data = new FormData(); data.append("file", file.input.files[0]);
    if (title.input.value) data.append("title", title.input.value);
    if (reference.input.value) data.append("reference", reference.input.value);
    if (profiles.value) data.append("windows_profile_id", profiles.value);
    if (androidProfiles.value) data.append("android_profile_id", androidProfiles.value);
    data.append("network_mode", networkMode.value);
    data.append("c2_analysis_enabled", c2Enabled.checked ? "true" : "false");
    try {
      const result = await api("/api/v1/cases", { method: "POST", body: data });
      if (result.duplicate_cases.length) toast("Duplicate content found. Confirmation is required before analysis starts.");
      go(`/cases/${result.case_id}`);
    } catch (failure) { toast(failure.message, true); } finally { submit.disabled = false; submit.textContent = "Create case and analyze"; }
  });
  card.append(form); content.append(card); shell("New analysis", content);
}

// A finished run with no report is a failure, not progress. Saying "the report
// will appear after aggregation" under a terminal run sends the reader away to
// wait for something that is never coming.
function statusExplanation(run) {
  if (!run) return "No analysis run exists for this case yet.";
  if (run.status === "terminal") {
    const failed = (run.stages || []).filter((item) => item.state === "failed");
    if (failed.length) {
      const first = failed[0];
      return `This run finished without producing a report. The ${human(first.stage_type)} stage failed`
        + (first.failure_code ? ` (${first.failure_code})` : "")
        + ". Open Run progress for the full diagnostics.";
    }
    if (run.result === "cancelled") return "This run was cancelled before a report was produced.";
    return "This run finished without producing a report. Open Run progress to see how far it got.";
  }
  if (run.status === "awaiting_confirmation") return "This run is waiting for confirmation before any analysis starts.";
  if (run.status === "cancelling") return "Cancellation has been requested; the run is stopping.";
  return "Evidence is being collected and normalized. The report will appear after aggregation.";
}

function latestRun(caseData) {
  return caseData.analysis_runs?.[caseData.analysis_runs.length - 1] || null;
}

function activeRun(caseData) {
  if (state.activeRunId) {
    const match = caseData.analysis_runs?.find((run) => run.id === state.activeRunId);
    if (match) return match;
  }
  return latestRun(caseData);
}

// A case may hold several runs — reruns, other profiles, other samples. The
// officer must be able to tell which run produced the report they are reading.
function runSelector(caseData, run, onPick) {
  const runs = caseData.analysis_runs || [];
  if (runs.length < 2) return null;
  const wrap = node("section", "card card-body");
  append(wrap, node("h3", "card-title", `Analysis runs (${runs.length})`),
    node("p", "muted", "This case contains more than one run. Select which run's report to display."));
  const listing = node("div", "case-list");
  runs.forEach((item, index) => {
    const isActive = item.id === run?.id;
    const row = node("div", `card case-row${isActive ? " active" : ""}`);
    const copy = node("div");
    const profile = item.windows_profile?.display_name || item.android_profile?.display_name || "default profile";
    append(copy,
      node("h3", "", `Run ${index + 1} · ${human(item.platform)}`),
      node("div", "mono muted", `${profile} · ${human(item.network_mode)} · C2 ${item.c2_analysis_enabled ? "on" : "off"}`),
      node("div", "mono muted", item.id));
    const pick = button(isActive ? "Showing" : "Show report", "btn btn-small");
    pick.disabled = isActive;
    pick.addEventListener("click", () => onPick(item.id));
    append(row, copy, badge(item.status), item.result ? badge(item.result) : null, pick);
    listing.append(row);
  });
  wrap.append(listing);
  return wrap;
}

// Re-run an existing sample without creating a duplicate case.
function rerunCard(caseData, run) {
  if (!canControlRuns()) return null;
  const submissions = caseData.submissions || [];
  if (!submissions.length) return null;
  const card = node("section", "card card-body");
  append(card, node("h3", "card-title", "Run this sample again"),
    node("p", "muted", "Creates an additional run on this case rather than a duplicate case."));
  const form = node("form");
  const grid = node("div", "field-grid");

  const sampleWrap = node("div", "field full");
  const sampleLabel = node("label", "", "Sample");
  const sample = node("select"); sample.name = "submission_id";
  submissions.forEach((item) => {
    const option = node("option", "", `${item.original_filename} · ${item.sample_sha256.slice(0, 16)}`);
    option.value = item.id; sample.append(option);
  });
  append(sampleWrap, sampleLabel, sample);

  const networkWrap = node("div", "field");
  const networkLabel = node("label", "", "Analysis network");
  const network = node("select"); network.name = "network_mode";
  [["Isolated / simulated (recommended)", "isolated_simulated"],
   ["Real-world egress (not containment-qualified)", "real_world_egress"]]
    .forEach(([label, value]) => { const option = node("option", "", label); option.value = value; network.append(option); });
  network.value = run?.network_mode || "isolated_simulated";
  append(networkWrap, networkLabel, network);

  const c2Wrap = node("label", "field checkbox-field");
  const c2 = node("input"); c2.type = "checkbox"; c2.name = "c2_analysis_enabled";
  c2.checked = Boolean(run?.c2_analysis_enabled);
  append(c2Wrap, c2, node("span", "", "Run the C2 network analyzer"));

  append(grid, sampleWrap, networkWrap, c2Wrap);
  const submit = button("Queue additional run", "btn btn-primary"); submit.type = "submit";
  append(form, grid, append(node("div", "form-actions"), submit));
  form.addEventListener("submit", async (event) => {
    event.preventDefault(); submit.disabled = true;
    try {
      const body = {
        submission_id: sample.value,
        network_mode: network.value,
        c2_analysis_enabled: c2.checked
      };
      if (run?.windows_profile?.id) body.windows_profile_id = run.windows_profile.id;
      if (run?.android_profile?.id) body.android_profile_id = run.android_profile.id;
      const result = await api(`/api/v1/cases/${caseData.case_id}/analysis-runs`, { method: "POST", body });
      toast("Additional run queued.");
      state.activeRunId = result.analysis_run_id;
      renderCase(caseData.case_id, true);
    } catch (failure) { toast(failure.message, true); }
    finally { submit.disabled = false; }
  });
  card.append(form);
  return card;
}

async function renderCase(caseId, preserveTab = false) {
  if (!preserveTab) state.activeTab = "overview";
  const content = node("div");
  let caseData;
  try { caseData = await api(`/api/v1/cases/${caseId}`); }
  catch (failure) { content.append(node("div", "notice notice-error", failure.message)); shell("Case", content); return; }
  const run = activeRun(caseData);

  // The case response carries the latest report; for any other run, fetch that
  // run's snapshot so the displayed verdict always matches the selected run.
  let report = caseData.report;
  if (run && state.activeRunId && run.id !== latestRun(caseData)?.id) {
    try { report = (await api(`/api/v1/cases/${caseId}/report?run_id=${run.id}`)).report; }
    catch (_) { report = null; }
  }

  content.append(pageHead("Case investigation", caseData.title || "Untitled case",
    `${caseData.reference || caseData.case_id} · received ${formatDate(caseData.created_at)}`, null));

  if (run && run.status === "awaiting_confirmation") {
    const warning = node("div", "notice notice-warn");
    const confirm = button("Confirm new analysis", "btn btn-primary btn-small");
    confirm.disabled = !canControlRuns();
    confirm.addEventListener("click", async () => {
      try { await api(`/api/v1/analysis-runs/${run.id}/confirm`, { method: "POST" }); toast("Analysis confirmed and queued."); renderCase(caseId, true); }
      catch (failure) { toast(failure.message, true); }
    });
    append(warning, node("strong", "", "Duplicate sample detected. "),
      node("span", "", canControlRuns()
        ? "No analysis stage will start until you confirm this run. "
        : "An analyst must confirm this run before analysis starts. "), confirm);
    content.append(warning);
  }

  const hero = node("section", "card verdict-hero");
  const heroCopy = node("div");
  append(heroCopy,
    node("div", "eyebrow", report ? "Unified verdict" : "Analysis status"),
    node("h2", "", report ? human(report.verdict) : human(run?.status || "pending")),
    node("p", "muted", report?.headline || statusExplanation(run)));
  const actions = node("div", "actions-row");
  if (report) ["pdf", "json", "csv"].forEach((format) => {
    const exportButton = button(`Export ${format.toUpperCase()}`, "btn btn-small");
    exportButton.addEventListener("click", () => exportReport(caseId, format));
    actions.append(exportButton);
  });
  if (run && !["terminal", "cancelling"].includes(run.status) && canControlRuns()) {
    const cancel = button("Cancel run", "btn btn-danger btn-small");
    cancel.addEventListener("click", async () => {
      try { await api(`/api/v1/analysis-runs/${run.id}/cancel`, { method: "POST" }); toast("Cancellation requested."); renderCase(caseId, true); }
      catch (failure) { toast(failure.message, true); }
    });
    actions.append(cancel);
  }
  heroCopy.append(actions);
  append(hero, heroCopy, node("div", "verdict-orb", report ? report.verdict.slice(0, 1).toUpperCase() : "…"));
  content.append(hero);

  const selector = runSelector(caseData, run, (id) => { state.activeRunId = id; renderCase(caseId, true); });
  if (selector) content.append(selector);

  const tabs = node("div", "tabs");
  const availableTabs = [["overview", "L1 Overview"], ["progress", "Run progress"], ["evidence", report?.technical ? "L3 Evidence" : "Evidence"]];
  if (report?.technical) availableTabs.splice(1, 0, ["findings", "L2 Findings"]);
  availableTabs.forEach(([key, label]) => {
    const tab = button(label, `tab${state.activeTab === key ? " active" : ""}`);
    tab.setAttribute("aria-selected", state.activeTab === key ? "true" : "false");
    tab.addEventListener("click", () => { state.activeTab = key; renderCase(caseId, true); });
    tabs.append(tab);
  });
  content.append(tabs);
  if (state.activeTab === "overview") renderOverview(content, report, run);
  else if (state.activeTab === "findings") renderFindings(content, report);
  else if (state.activeTab === "evidence") renderEvidence(content, report);
  else renderProgress(content, caseData.analysis_runs, caseId);

  if (state.activeTab === "overview") {
    const rerun = rerunCard(caseData, run);
    if (rerun) content.append(rerun);
  }
  shell("Case report", content);
  schedulePoll(caseId, caseData.analysis_runs);
}

function renderOverview(content, report, run) {
  if (!report) {
    const terminal = run?.status === "terminal";
    const card = node("div", `card ${terminal ? "notice notice-warn" : "empty"}`);
    append(card,
      node("strong", "", terminal ? "No report was produced" : `Current run state: ${human(run?.status || "pending")}`),
      node("p", "", statusExplanation(run)));
    if (terminal) {
      const jump = button("Open run progress", "btn btn-small");
      jump.addEventListener("click", () => { state.activeTab = "progress"; renderCase(run.id ? location.pathname.split("/").pop() : "", true); });
      card.append(jump);
    } else {
      card.append(node("small", "muted", "This page refreshes automatically while work is active."));
    }
    content.append(card);
    return;
  }
  const grid = node("div", "grid grid-2");
  grid.append(listCard("Information accessed", report.information_accessed, (item) => [human(item.data_type), `${human(item.evidence_level)} · ${human(item.confidence)}`]));
  grid.append(listCard("Destinations and protocols", report.destinations, (item) => [item.value, `${item.protocol || "unknown"}${item.port ? ` · port ${item.port}` : ""}`]));
  content.append(grid);
  content.append(node("h3", "section-title", "Important provenance"), listCard(null, report.provenance, (item) => [item.statement, [human(item.item_type), item.destination].filter(Boolean).join(" · ")]));
  content.append(node("h3", "section-title", "Analysis limitations"));
  if (report.caveats.length) content.append(listCard(null, report.caveats.map((value) => ({ value })), (item) => [CAVEAT_TEXT[item.value] || human(item.value), human(item.value)]));
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

// Diagnostics matter as much as progress: a stalled or failed run must say why
// and offer the action that resolves it, rather than showing a silent grey box.
function renderProgress(content, runs, caseId) {
  const ordered = [...runs].reverse();
  ordered.forEach((run, index) => {
    content.append(node("h3", "section-title", `${index ? "Earlier" : "Current"} ${human(run.platform)} run`));
    const card = node("section", "card card-body");
    const head = node("div", "actions-row");
    append(head, badge(run.status), run.result ? badge(run.result) : null,
      node("span", "mono muted", run.id));
    if (!["terminal", "cancelling"].includes(run.status) && canControlRuns() && caseId) {
      const cancel = button("Cancel", "btn btn-danger btn-small");
      cancel.addEventListener("click", async () => {
        try { await api(`/api/v1/analysis-runs/${run.id}/cancel`, { method: "POST" }); toast("Cancellation requested."); renderCase(caseId, true); }
        catch (failure) { toast(failure.message, true); }
      });
      head.append(cancel);
    }
    card.append(head);

    const policy = node("div", "mono muted",
      `network ${human(run.network_mode)} · C2 analyzer ${run.c2_analysis_enabled ? "enabled" : "disabled"}` +
      (run.windows_profile?.display_name ? ` · ${run.windows_profile.display_name}` : "") +
      (run.android_profile?.display_name ? ` · ${run.android_profile.display_name}` : ""));
    card.append(policy);

    const order = run.c2_analysis_enabled
      ? ["platform_analysis", "c2_analysis", "platform_adaptation", "c2_adaptation", "case_aggregation", "report_generation"]
      : ["platform_analysis", "platform_adaptation", "case_aggregation", "report_generation"];
    const track = node("div", "stage-track stage-track-spaced");
    order.forEach((kind) => {
      const stageData = run.stages.find((item) => item.stage_type === kind);
      const stage = node("div", "stage");
      append(stage, node("strong", "", human(kind)),
        node("span", `badge-${stageData?.state || "waiting"}`, human(stageData?.state || "waiting")));
      track.append(stage);
    });
    card.append(track);

    // Surface every failure reason the API gives us. A run that failed with no
    // visible cause is the single most common support question.
    const failures = run.stages.filter((item) => item.failure_code || item.failure_detail);
    if (failures.length) {
      card.append(node("h4", "card-title", "Diagnostics"));
      const table = node("div", "case-list");
      failures.forEach((item) => {
        const row = node("div", "card case-row");
        const copy = node("div");
        append(copy, node("h3", "", human(item.stage_type)),
          node("div", "mono muted", item.failure_code || "no code reported"),
          item.failure_detail ? node("small", "muted", item.failure_detail) : null);
        append(row, copy, badge(item.state));
        table.append(row);
      });
      card.append(table);
    }
    content.append(card);
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
  const definitions = [["Machine name", "name", "text", ""], ["Display name", "display_name", "text", ""], ["Windows version", "windows_version", "text", "Windows 10 22H2"], ["CAPE template", "cape_template", "text", "win10-hardened"], ["vCPUs", "vcpus", "number", "4"], ["RAM (MiB)", "ram_mb", "number", "4096"], ["Disk (GiB)", "disk_gb", "number", "160"], ["Guest username", "username", "text", "officer"]];
  const controls = {};
  definitions.forEach(([label, name, type, value]) => { const item = field(label, type, name, true); item.input.value = value; controls[name] = item.input; grid.append(item.wrap); });
  const profileField = node("div", "field"); const profileLabel = node("label", "", "Analysis profile"); const profile = node("select"); ["standard", "deep_static", "tls_intercept", "full_memory", "full_investigation"].forEach((value) => { const option = node("option", "", human(value)); option.value = value; profile.append(option); }); append(profileField, profileLabel, profile); grid.append(profileField);
  const submit = button("Queue provisioning", "btn btn-primary"); submit.type = "submit"; append(form, grid, append(node("div", "form-actions"), submit)); create.append(form); content.append(create, node("h3", "section-title", "Managed profiles"));
  const list = node("div", "case-list"); content.append(list); shell("Windows profiles", content);
  async function load() { const items = await api("/api/v1/windows/profiles?include_inactive=true"); list.replaceChildren(); items.forEach((item) => { const row = node("div", "card case-row"); const copy = node("div"); append(copy, node("h3", "", item.display_name), node("div", "mono muted", `${item.name} · ${item.windows_version} · ${item.vcpus} vCPU · ${item.ram_mb} MiB · ${item.disk_gb} GiB`)); const remove = button("Retire", "btn btn-danger btn-small"); remove.disabled = ["deleting", "deleted", "provisioning"].includes(item.state); remove.addEventListener("click", async () => { try { await api(`/api/v1/windows/profiles/${item.id}`, { method: "DELETE" }); toast("Profile deletion queued through CAPE."); load(); } catch (failure) { toast(failure.message, true); } }); append(row, copy, node("div", "", human(item.analysis_profile)), badge(item.state), remove); list.append(row); }); }
  form.addEventListener("submit", async (event) => { event.preventDefault(); const body = { name: controls.name.value, display_name: controls.display_name.value, windows_version: controls.windows_version.value, architecture: "x64", vcpus: Number(controls.vcpus.value), ram_mb: Number(controls.ram_mb.value), disk_gb: Number(controls.disk_gb.value), user_profile: { username: controls.username.value, locale: "en-US", timezone: "UTC", installed_software: [] }, analysis_profile: profile.value, cape_template: controls.cape_template.value, is_default: false }; try { await api("/api/v1/windows/profiles", { method: "POST", body }); toast("Profile provisioning queued."); form.reset(); load(); } catch (failure) { toast(failure.message, true); } });
  try { await load(); } catch (failure) { list.append(node("div", "notice notice-error", failure.message)); }
}

async function renderAndroidAdmin() {
  if (!state.session.roles.includes("administrator")) { go("/cases"); return; }
  const content = node("div");
  content.append(pageHead("Android orchestration", "Android emulator profiles", "Manage qualified Android 11 AOSP x86_64 analysis baselines. ARM profiles are intentionally unsupported.", null));
  const create = node("section", "card card-body"); create.append(node("h3", "card-title", "Create candidate profile"));
  const form = node("form"); const grid = node("div", "field-grid");
  const name = field("Profile name", "text", "android_name", true);
  const display = field("Display name", "text", "android_display_name", true);
  const defaultWrap = node("div", "field"); const defaultLabel = node("label", "", "Make active default"); const isDefault = node("input"); isDefault.type = "checkbox"; append(defaultWrap, defaultLabel, isDefault);
  append(grid, name.wrap, display.wrap, defaultWrap);
  const runtimeField = node("div", "field"); const runtimeLabel = node("label", "", "Runtime"); const runtime = node("select"); [["ReDroid Android 11 x86_64", "redroid"], ["AOSP API 30 x86_64 AVD", "avd"]].forEach(([label, value]) => { const option = node("option", "", label); option.value = value; runtime.append(option); }); append(runtimeField, runtimeLabel, runtime); grid.append(runtimeField);
  const fixed = node("div", "notice", "Both runtimes are fixed to Android 11 / API 30, x86_64, 4 vCPU, 4096 MiB RAM, and controlled networking. CPU/ARM emulation cannot be enabled here.");
  const submit = button("Create profile", "btn btn-primary"); submit.type = "submit"; append(form, grid, fixed, append(node("div", "form-actions"), submit)); create.append(form);
  content.append(create, node("h3", "section-title", "Managed profiles"));
  const list = node("div", "case-list"); content.append(list); shell("Android profiles", content);
  async function load() {
    const items = await api("/api/v1/android/profiles?include_inactive=true"); list.replaceChildren();
    if (!items.length) list.append(node("div", "card empty", "No Android profiles configured."));
    items.forEach((item) => { const row = node("div", "card case-row"); const copy = node("div"); append(copy, node("h3", "", item.display_name), node("div", "mono muted", `${item.name} · Android ${item.android_version} / API ${item.api_level} · ${item.architecture} · ${item.vcpus} vCPU · ${item.ram_mb} MiB`), node("div", "mono muted", item.system_image)); const remove = button("Retire", "btn btn-danger btn-small"); remove.disabled = item.state !== "active" || item.is_default; remove.title = item.is_default ? "Select another default before retiring this profile" : "Retire profile"; remove.addEventListener("click", async () => { try { await api(`/api/v1/android/profiles/${item.id}`, { method: "DELETE" }); toast("Android profile retired; existing run snapshots are preserved."); load(); } catch (failure) { toast(failure.message, true); } }); const qualify = button("Qualify", "btn btn-small"); qualify.disabled = item.state !== "active" || item.qualification?.status === "qualified"; qualify.title = "Record a completed evidence run that qualifies this profile"; qualify.addEventListener("click", async () => { const runId = window.prompt("Evidence analysis run ID that qualifies this profile:"); if (!runId) return; try { await api(`/api/v1/android/profiles/${item.id}/qualify`, { method: "POST", body: { evidence_run_id: runId.trim() } }); toast("Profile qualified against the supplied evidence run."); load(); } catch (failure) { toast(failure.message, true); } }); append(row, copy, node("div", "", item.is_default ? "Default" : human(item.qualification?.status || "candidate")), badge(item.state), qualify, remove); list.append(row); });
  }
  form.addEventListener("submit", async (event) => { event.preventDefault(); const redroid = runtime.value === "redroid"; try { await api("/api/v1/android/profiles", { method: "POST", body: { name: name.input.value, display_name: display.input.value, system_image: redroid ? "docker.io/redroid/redroid@sha256:d1ca0815eb68139a43d25a835e374559e9d18f5d5cea1a4288d4657c0074fb8d" : "system-images;android-30;default;x86_64", emulator_version: redroid ? "redroid-11-d1ca0815" : "34.1.19", is_default: isDefault.checked } }); toast("Android candidate profile created."); form.reset(); load(); } catch (failure) { toast(failure.message, true); } });
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
  if (path === "/admin/android") return renderAndroidAdmin();
  const match = path.match(/^\/cases\/([0-9a-f-]+)$/i);
  if (match) return renderCase(match[1]);
  go("/cases");
}

window.addEventListener("popstate", renderRoute);
renderRoute();
