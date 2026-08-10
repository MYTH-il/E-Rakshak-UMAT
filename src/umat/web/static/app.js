"use strict";

import { configureApi, api } from "./api.js";
import { loadWorkers, updateAndroidProfile, updateWindowsProfile } from "./administration.js";
import { loadAndroidCommand, loadAndroidWorkflow, submitAndroidCommand } from "./android.js";
import { addCaseSubmission, queryRecentRuns, retryAnalysisRun, updateCaseMetadata } from "./cases.js";
import { createReportExport, loadRunReport } from "./reports.js";
import { configureRouter, go, navigateEvent, state } from "./state-router.js";

// Officer-facing caveat text. Mirrors contracts/vocabularies/caveats.json
// (descriptions). tests/unit/test_web_ui.py asserts the two stay in sync —
// an officer must never be shown a bare machine code.
const CAVEAT_TEXT = {
  analysis_timed_out: "The analysis ran out of time before finishing. Behaviour that occurs later than the time allowed would not have been seen.",
  android_api_monitoring_failed: "Monitoring of the app's activity on the device did not work, so its behaviour was only partly recorded.",
  android_dynamic_stop_failed: "The device did not shut down cleanly after the test, so the final part of the recording may be incomplete.",
  android_package_process_not_observed: "The application package was installed, but its process was not running when activation was checked. Runtime conclusions are incomplete.",
  android_runtime_behavior_not_observed: "The application ran, but no package-attributable API activity, data access, or destination was recorded. This is an inconclusive dynamic result, not a clean result.",
  android_network_checkpoint_invalid: "Saved Android proxy checkpoints could not be read. Direct PCAP evidence remains available, but tunneled HTTPS destinations may be missing.",
  explicit_activity_launch_failed: "An optional request to launch a specific activity failed. The application may still have launched through its normal entry point.",
  application_data_collection_failed: "The application ran, but its private files could not be archived at the end of the session.",
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

function toast(message, error = false) {
  const existing = document.querySelector(".toast");
  if (existing) existing.remove();
  const item = node("aside", `toast${error ? " notice-error" : ""}`, message);
  item.setAttribute("aria-label", error ? "Error notification" : "Notification");
  item.setAttribute("aria-live", error ? "assertive" : "polite");
  document.body.append(item);
  window.setTimeout(() => item.remove(), 4500);
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
  sidebar.append(navItem("Case queue", "/cases", path === "/cases" || path.startsWith("/cases/")));
  sidebar.append(navItem("Recent runs", "/runs", path === "/runs"));
  if (canSubmit()) sidebar.append(navItem("New analysis", "/submit", path === "/submit"));
  if (state.session.roles.includes("administrator")) {
    sidebar.append(node("div", "nav-label", "Administration"));
    sidebar.append(navItem("Windows profiles", "/admin/windows", path === "/admin/windows"));
    sidebar.append(navItem("Android profiles", "/admin/android", path === "/admin/android"));
    sidebar.append(navItem("Workers", "/admin/workers", path === "/admin/workers"));
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
  append(
    topbar,
    append(node("div", "top-actions"), menu, node("h1", "", title)),
    canSubmit() ? link("New analysis", "/submit", "btn btn-primary") : null,
  );
  const main = node("main", "content"); main.id = "main"; main.tabIndex = -1; main.append(content);
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
  const page = node("main", "login-page"); page.id = "main"; page.tabIndex = -1;
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
  profileLabel.htmlFor = "intake-windows-profile";
  const profiles = node("select"); profiles.name = "windows_profile_id"; profiles.id = "intake-windows-profile";
  profiles.append(node("option", "", "Use active default profile")); profiles.firstChild.value = "";
  try {
    const items = await api("/api/v1/windows/profiles");
    items.forEach((item) => { const option = node("option", "", `${item.display_name} · ${item.windows_version} · ${item.analysis_profile}`); option.value = item.id; profiles.append(option); });
  } catch (_) { /* profile selection can remain default */ }
  append(profileWrap, profileLabel, profiles);
  const androidProfileWrap = node("div", "field full");
  const androidProfileLabel = node("label", "", "Android analysis profile (ignored for non-APKs)");
  androidProfileLabel.htmlFor = "intake-android-profile";
  const androidProfiles = node("select"); androidProfiles.name = "android_profile_id"; androidProfiles.id = "intake-android-profile";
  androidProfiles.append(node("option", "", "Use active default profile")); androidProfiles.firstChild.value = "";
  try {
    const items = await api("/api/v1/android/profiles");
    items.forEach((item) => { const option = node("option", "", `${item.display_name} · API ${item.api_level} · ${item.architecture} · ${item.ram_mb} MiB`); option.value = item.id; androidProfiles.append(option); });
  } catch (_) { /* profile selection can remain default */ }
  append(androidProfileWrap, androidProfileLabel, androidProfiles);
  const networkWrap = node("div", "field full"); const networkLabel = node("label", "", "Analysis network"); networkLabel.htmlFor = "intake-network-mode"; const networkMode = node("select"); networkMode.name = "network_mode"; networkMode.id = "intake-network-mode";
  [["Isolated / simulated (recommended)", "isolated_simulated"], ["Real-world network egress (not containment-qualified)", "real_world_egress"]].forEach(([label, value]) => { const option = node("option", "", label); option.value = value; networkMode.append(option); }); append(networkWrap, networkLabel, networkMode);
  const c2Wrap = node("label", "field full checkbox-field"); const c2Enabled = node("input"); c2Enabled.type = "checkbox"; c2Enabled.name = "c2_analysis_enabled"; append(c2Wrap, c2Enabled, node("span", "", "Run C2 analyzer on captured traffic (guest remains governed by the selected network mode)"));
  const interactiveWrap = node("label", "field full checkbox-field"); const androidInteractive = node("input"); androidInteractive.type = "checkbox"; androidInteractive.name = "android_interactive"; androidInteractive.checked = true; append(interactiveWrap, androidInteractive, node("span", "", "Hold Android guests for an interactive analyst session (ignored for non-APKs; automatically finalized after 15 minutes)"));
  append(grid, title.wrap, reference.wrap, file.wrap, profileWrap, androidProfileWrap, networkWrap, c2Wrap, interactiveWrap);
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
    data.append("android_interactive", androidInteractive.checked ? "true" : "false");
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
  const sampleLabel = node("label", "", "Sample"); sampleLabel.htmlFor = "rerun-submission";
  const sample = node("select"); sample.name = "submission_id"; sample.id = "rerun-submission";
  submissions.forEach((item) => {
    const option = node("option", "", `${item.original_filename} · ${item.sample_sha256.slice(0, 16)}`);
    option.value = item.id; sample.append(option);
  });
  append(sampleWrap, sampleLabel, sample);

  const networkWrap = node("div", "field");
  const networkLabel = node("label", "", "Analysis network"); networkLabel.htmlFor = "rerun-network-mode";
  const network = node("select"); network.name = "network_mode"; network.id = "rerun-network-mode";
  [["Isolated / simulated (recommended)", "isolated_simulated"],
   ["Real-world egress (not containment-qualified)", "real_world_egress"]]
    .forEach(([label, value]) => { const option = node("option", "", label); option.value = value; network.append(option); });
  network.value = run?.network_mode || "isolated_simulated";
  append(networkWrap, networkLabel, network);

  const c2Wrap = node("label", "field checkbox-field");
  const c2 = node("input"); c2.type = "checkbox"; c2.name = "c2_analysis_enabled";
  c2.checked = Boolean(run?.c2_analysis_enabled);
  append(c2Wrap, c2, node("span", "", "Run the C2 network analyzer"));

  const interactiveWrap = node("label", "field checkbox-field");
  const interactive = node("input"); interactive.type = "checkbox"; interactive.name = "android_interactive";
  interactive.checked = Boolean(run?.android_interactive);
  append(interactiveWrap, interactive, node("span", "", "Request an interactive Android session"));

  append(grid, sampleWrap, networkWrap, c2Wrap, interactiveWrap);
  const submit = button("Queue additional run", "btn btn-primary"); submit.type = "submit";
  append(form, grid, append(node("div", "form-actions"), submit));
  form.addEventListener("submit", async (event) => {
    event.preventDefault(); submit.disabled = true;
    try {
      const body = {
        submission_id: sample.value,
        network_mode: network.value,
        c2_analysis_enabled: c2.checked,
        android_interactive: interactive.checked,
      };
      if (run?.windows_profile?.profile_id) body.windows_profile_id = run.windows_profile.profile_id;
      if (run?.android_profile?.profile_id) body.android_profile_id = run.android_profile.profile_id;
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

function caseOperationsCard(caseData, run) {
  if (!canSubmit()) return null;
  const card = node("section", "card card-body");
  card.append(node("h3", "card-title", "Case operations"));
  const metadata = node("form");
  const metadataGrid = node("div", "field-grid");
  const title = field("Case title", "text", "edit_case_title");
  const reference = field("Case reference", "text", "edit_case_reference");
  title.input.value = caseData.title || "";
  reference.input.value = caseData.reference || "";
  const save = button("Save case metadata", "btn btn-small"); save.type = "submit";
  append(metadataGrid, title.wrap, reference.wrap);
  append(metadata, metadataGrid, append(node("div", "form-actions"), save));
  metadata.addEventListener("submit", async (event) => {
    event.preventDefault(); save.disabled = true;
    try {
      await updateCaseMetadata(caseData.case_id, {
        title: title.input.value || null,
        reference: reference.input.value || null,
      });
      await renderCase(caseData.case_id, true);
      toast("Case metadata updated and audited.");
    } catch (failure) { toast(failure.message, true); }
    finally { save.disabled = false; }
  });

  const upload = node("form"); upload.enctype = "multipart/form-data";
  upload.append(node("h4", "card-title", "Add submission to this case"));
  const uploadGrid = node("div", "field-grid");
  const sample = field("Additional sample", "file", "additional_sample", true);
  const network = selectField("Analysis network", "additional_network", [
    ["Isolated / simulated (recommended)", "isolated_simulated"],
    ["Real-world egress (not containment-qualified)", "real_world_egress"],
  ], run?.network_mode || "isolated_simulated");
  const c2Wrap = node("label", "field checkbox-field");
  const c2 = node("input"); c2.type = "checkbox"; c2.checked = Boolean(run?.c2_analysis_enabled);
  append(c2Wrap, c2, node("span", "", "Run the C2 network analyzer"));
  const interactiveWrap = node("label", "field checkbox-field");
  const interactive = node("input"); interactive.type = "checkbox";
  append(interactiveWrap, interactive, node("span", "", "Request an interactive Android session when the file is an APK"));
  append(uploadGrid, sample.wrap, network.wrap, c2Wrap, interactiveWrap);
  const add = button("Add submission and analyze", "btn btn-primary"); add.type = "submit";
  append(upload, uploadGrid, append(node("div", "form-actions"), add));
  upload.addEventListener("submit", async (event) => {
    event.preventDefault(); add.disabled = true;
    const data = new FormData();
    data.append("file", sample.input.files[0]);
    data.append("network_mode", network.select.value);
    data.append("c2_analysis_enabled", c2.checked ? "true" : "false");
    data.append("android_interactive", interactive.checked ? "true" : "false");
    try {
      const result = await addCaseSubmission(caseData.case_id, data);
      state.activeRunId = result.analysis_run_id;
      await renderCase(caseData.case_id, true);
      toast(result.status === "awaiting_confirmation" ? "Submission added; duplicate confirmation required." : "Submission added and queued.");
    } catch (failure) { toast(failure.message, true); }
    finally { add.disabled = false; }
  });
  card.append(metadata, upload);
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
    try { report = (await loadRunReport(caseId, run.id)).report; }
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
  if (run?.platform === "android" && canControlRuns()) {
    actions.append(link("Open Android workflow", `/analysis/${run.id}/android`, "btn btn-small"));
  }
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
    tab.setAttribute("aria-pressed", state.activeTab === key ? "true" : "false");
    tab.addEventListener("click", () => { state.activeTab = key; renderCase(caseId, true); });
    tabs.append(tab);
  });
  content.append(tabs);
  if (state.activeTab === "overview") renderOverview(content, report, run);
  else if (state.activeTab === "findings") renderFindings(content, report);
  else if (state.activeTab === "evidence") renderEvidence(content, report);
  else renderProgress(content, caseData.analysis_runs, caseId);

  if (state.activeTab === "overview") {
    const operations = caseOperationsCard(caseData, run);
    if (operations) content.append(operations);
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
  grid.append(destinationsCard(report.destinations));
  content.append(grid);
  content.append(node("h3", "section-title", "Important provenance"), listCard(null, report.provenance, (item) => [item.statement, [human(item.item_type), item.destination].filter(Boolean).join(" · ")]));
  content.append(node("h3", "section-title", "Analysis limitations"));
  if (report.caveats.length) content.append(listCard(null, report.caveats.map((value) => ({ value })), (item) => [CAVEAT_TEXT[item.value] || human(item.value), human(item.value)]));
  else content.append(node("div", "notice", "No material analysis limitations were recorded."));
  if (report.tested_profile) content.append(node("h3", "section-title", "Tested OS profile"), listCard(null, [report.tested_profile], (item) => [item.name || item.windows_version || "Windows profile", `${item.windows_version || ""} · ${item.vcpus || "?"} vCPU · ${item.ram_mb ? formatBytes(item.ram_mb * 1024 * 1024) : "RAM unknown"}`]));
}

// "185.199.110.153 · tcp · port 443" tells an officer nothing. Country, network
// operator and an independent intel hit are what make a destination actionable.
function destinationDetail(item) {
  const parts = [];
  if (item.protocol) parts.push(item.protocol);
  if (item.port) parts.push(`port ${item.port}`);
  if (item.geo_country) parts.push(`server in ${item.geo_country}`);
  if (item.asn_org) parts.push(`operated by ${item.asn_org}`);
  else if (item.asn) parts.push(`network ${item.asn}`);
  if (item.observation_count > 1) parts.push(`${item.observation_count} connections`);
  return parts.join(" · ") || "no further detail recorded";
}

function destinationsCard(destinations) {
  const card = node("section", "card card-body");
  card.append(node("h3", "card-title", "Destinations contacted"));
  const list = node("ul", "data-list");
  if (!destinations?.length) list.append(node("li", "empty", "No outbound destinations were recorded."));
  (destinations || []).forEach((item) => {
    const row = node("li", `data-item${item.known_bad ? " data-item-alert" : ""}`);
    const copy = node("div");
    append(copy, node("strong", "", item.value), node("small", "", destinationDetail(item)));
    if (item.known_bad) {
      const reason = item.reputation_note
        ? `Known malicious: ${item.reputation_note}`
        : "Listed on threat intelligence as malicious.";
      append(copy, node("small", "alert-text", item.reputation_source
        ? `${reason} (source: ${item.reputation_source})`
        : reason));
    }
    row.append(copy);
    if (item.known_bad) row.append(badge("known bad"));
    list.append(row);
  });
  card.append(list);
  return card;
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
  content.append(table(["Finding", "Source", "Confidence", "Evidence", "Security mappings"], technical.findings, (item) => [item.summary, `${item.source} · ${human(item.kind)}`, human(item.confidence), human(item.evidence_level), (item.security_mappings || item.mitre_technique_ids || []).join(", ") || "—"]));
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
    if (run.status === "terminal" && ["partial", "inconclusive", "failed", "cancelled", "unsupported"].includes(run.result) && canControlRuns()) {
      const retry = button("Retry run", "btn btn-small");
      retry.addEventListener("click", async () => {
        const reason = window.prompt("Reason for retry (recorded in the audit log):");
        if (!reason) return;
        try {
          const result = await retryAnalysisRun(run.id, reason);
          state.activeRunId = result.analysis_run_id;
          toast("Retry queued as a new immutable run.");
          renderCase(caseId, true);
        } catch (failure) { toast(failure.message, true); }
      });
      head.append(retry);
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
  try { const result = await createReportExport(caseId, format); toast(`${format.toUpperCase()} export created and integrity-registered.`); window.location.assign(result.download_path); } catch (failure) { toast(failure.message, true); }
}

function schedulePoll(caseId, runs) {
  if (state.pollTimer) window.clearTimeout(state.pollTimer);
  if (!runs.some((run) => run.status !== "terminal")) return;
  const prior = Number(sessionStorage.getItem(`poll-${caseId}`) || 2000);
  const delay = Math.min(prior, 30000);
  sessionStorage.setItem(`poll-${caseId}`, String(Math.min(delay * 2, 30000)));
  state.pollTimer = window.setTimeout(() => renderCase(caseId, true), delay);
}

function valueItems(value) {
  if (Array.isArray(value)) return value;
  if (value && typeof value === "object") return Object.entries(value).map(([name, details]) => ({ name, details }));
  return [];
}

function componentNames(value) {
  if (Array.isArray(value)) return value.map((item) => typeof item === "string" ? item : item.name || item.value || JSON.stringify(item));
  if (value && typeof value === "object") return Object.keys(value);
  return [];
}

function compactJson(value) {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

async function renderAndroidWorkflow(runId, quiet = false) {
  if (state.androidLiveCleanup) { state.androidLiveCleanup(); state.androidLiveCleanup = null; }
  let workflow;
  try { workflow = await loadAndroidWorkflow(runId); }
  catch (failure) {
    if (!quiet) { const content = node("div"); content.append(node("div", "notice notice-error", failure.message)); shell("Android analysis", content); }
    return;
  }
  const run = workflow.run;
  const metadata = workflow.metadata || {};
  const staticReport = workflow.mobsf?.static || {};
  const dynamicReport = workflow.mobsf?.dynamic || {};
  const content = node("div");
  const back = link("Back to case", `/cases/${run.case_id}`, "btn btn-ghost btn-small");
  content.append(pageHead("Android analysis workflow", metadata.app_name || staticReport.app_name || "Android sample", "UMAT-controlled MobSF and ReDroid evidence. Static discovery, runtime observation, and C2 correlation remain explicitly separated.", back));

  const summary = node("section", "card workflow-summary");
  const copy = node("div");
  append(copy, node("div", "eyebrow", metadata.package_name || staticReport.package_name || "Package pending"), node("h2", "", metadata.app_name || staticReport.file_name || "Analysis in progress"), node("p", "mono muted", `Run ${run.id}`));
  const status = node("div", "actions-row"); append(status, badge(run.status), run.result ? badge(run.result) : null, badge(run.network_mode), badge(run.c2_analysis_enabled ? "c2 enabled" : "c2 disabled")); copy.append(status);
  const metrics = node("div", "workflow-metrics");
  [[metadata.api_level || run.profile?.api_level || "—", "API level"], [metadata.dynamic_completed ? "Complete" : "Pending", "Dynamic run"], [workflow.findings.length, "Findings"], [workflow.iocs.length, "Static IOCs"]].forEach(([value, label]) => { const item = node("div"); append(item, node("strong", "", value), node("small", "", label)); metrics.append(item); });
  append(summary, copy, metrics); content.append(summary);

  const track = node("div", "stage-track stage-track-spaced");
  ["platform_analysis", "c2_analysis", "platform_adaptation", "c2_adaptation", "case_aggregation", "report_generation"].filter((kind) => run.c2_analysis_enabled || !kind.startsWith("c2_")).forEach((kind) => { const stageData = run.stages.find((item) => item.stage_type === kind); const stage = node("div", "stage"); append(stage, node("strong", "", human(kind)), node("span", `badge-${stageData?.state || "waiting"}`, human(stageData?.state || "waiting"))); track.append(stage); });
  content.append(track);

  const tabs = node("div", "tabs");
  [["static", "Static analysis"], ["dynamic", "Dynamic analysis"], ["network", "Network & C2"], ["artifacts", "Evidence files"]].forEach(([key, label]) => { const tab = button(label, `tab${state.androidTab === key ? " active" : ""}`); tab.addEventListener("click", () => { state.androidTab = key; renderAndroidWorkflow(runId, true); }); tabs.append(tab); });
  content.append(tabs);
  if (state.androidTab === "static") renderAndroidStatic(content, workflow, staticReport);
  else if (state.androidTab === "dynamic") renderAndroidDynamic(content, workflow, dynamicReport);
  else if (state.androidTab === "network") renderAndroidNetwork(content, workflow);
  else renderAndroidArtifacts(content, workflow);
  shell("Android analysis", content);
  if (run.status !== "terminal" && workflow.interactive_session?.state !== "ready") state.pollTimer = window.setTimeout(() => renderAndroidWorkflow(runId, true), 3000);
}

function renderAndroidStatic(content, workflow, report) {
  const identity = node("div", "grid grid-4");
  [[report.package_name || report.package, "Package"], [report.version_name || "—", "Version"], [report.main_activity || "—", "Main activity"], [report.min_sdk || report.min_sdk_version || "—", "Minimum SDK"]].forEach(([value, label]) => { const card = node("div", "card metric"); append(card, node("small", "", label), node("strong", "mono", value)); identity.append(card); });
  content.append(identity, node("h3", "section-title", "Permissions and data access"));
  content.append(table(["Permission", "Status / details"], valueItems(report.permissions), (item) => [item.name || item.permission || compactJson(item), compactJson(item.details || item.status || item)]));
  content.append(node("h3", "section-title", "Normalized capabilities"));
  content.append(table(["Data type", "Evidence", "Confidence", "Source"], workflow.capabilities, (item) => [human(item.data_type), human(item.evidence_level), human(item.confidence), item.source]));
  const components = node("div", "grid grid-2");
  [["Activities", report.activities], ["Services", report.services], ["Receivers", report.receivers], ["Providers", report.providers]].forEach(([label, values]) => { const names = componentNames(values); components.append(listCard(`${label} (${names.length})`, names.slice(0, 100).map((name) => ({ name })), (item) => [item.name, null])); });
  content.append(node("h3", "section-title", "Application components"), components, node("h3", "section-title", "Security findings"));
  content.append(table(["Finding", "Phase", "Category", "Severity", "Evidence"], workflow.findings, (item) => [item.summary, item.phase, human(item.category), human(item.severity || "unrated"), human(item.evidence_level)]));
  content.append(node("h3", "section-title", "Static indicators"));
  content.append(table(["Type", "Value", "Confidence", "Traffic"], workflow.iocs, (item) => [item.type, item.value, human(item.confidence), item.seen_in_traffic ? "Observed" : "Not observed"]));
  const scanLogs = workflow.mobsf?.scan_logs;
  if (scanLogs) { content.append(node("h3", "section-title", "Static scan log")); content.append(table(["Stage", "Status"], valueItems(scanLogs), (item) => [item.name || human(item), compactJson(item.details || item)])); }
}

function renderAndroidDynamic(content, workflow, report) {
  const stimulation = workflow.metadata?.stimulation || {};
  const quality = stimulation.quality || workflow.metadata?.details?.dynamic_quality || {};
  const terminal = workflow.run.status === "terminal";
  const sessionEnded = ["ended", "expired", "cancelled"].includes(workflow.interactive_session?.state);
  const dynamicState = quality.runtime_behavior_observed ? "Validated" : workflow.metadata?.dynamic_completed ? "Insufficient evidence" : terminal ? "Unavailable" : "Pending";
  const actionState = stimulation.actions_attempted || stimulation.actions_total
    ? `${stimulation.actions_completed || 0}/${stimulation.actions_attempted || stimulation.actions_total}`
    : terminal ? "Not recorded" : "0/?";
  const coverageState = stimulation.complete ? "Complete" : terminal ? "Unavailable" : "Incomplete";
  const guestState = sessionEnded || terminal ? "Guest destroyed" : workflow.metadata?.guest_ip || "Starting";
  const status = node("div", "grid grid-4");
  [[dynamicState, "MobSF dynamic report"], [actionState, "Stimulation actions"], [coverageState, "Stimulation coverage"], [guestState, "Guest lifecycle"]].forEach(([value, label]) => { const card = node("div", "card metric"); append(card, node("small", "", label), node("strong", "", value)); status.append(card); });
  content.append(status);
  if (workflow.metadata?.dynamic_completed && !quality.runtime_behavior_observed) content.append(node("div", "notice notice-warn", "MobSF generated a report, but UMAT did not observe behavior attributable to the analyzed package. This run is incomplete evidence, not a clean result."));
  if (Object.keys(quality).length) content.append(table(["Dynamic validation check", "Result"], [
    ["Package process observed", quality.package_process_observed],
    ["Frida instrumentation started", quality.frida_instrumentation_started],
    ["API monitor events", quality.api_monitor_event_count || 0],
    ["Attributable destinations", (quality.attributable_domains || []).join(", ") || "None"],
    ["Populated runtime sections", (quality.populated_runtime_sections || []).join(", ") || "None"],
  ], (item) => [item[0], typeof item[1] === "boolean" ? (item[1] ? "Yes" : "No") : item[1]]));
  if (terminal && !workflow.metadata?.dynamic_completed) content.append(node("div", "notice notice-warn", "This run ended without a MobSF dynamic report. Static findings and surviving evidence remain available, but runtime behavior must not be interpreted as complete."));
  const session = workflow.interactive_session;
  if (session?.state === "ready") renderLiveAndroidSession(content, workflow);
  else if (workflow.inline_evidence.screenshot) { const screenCard = node("section", "card card-body android-screen-card"); append(screenCard, node("h3", "card-title", "Final guest screenshot")); const image = node("img", "android-screen"); image.src = workflow.inline_evidence.screenshot; image.alt = "Final captured Android guest screen"; screenCard.append(image); content.append(node("h3", "section-title", "Captured device"), screenCard); }
  const backgroundCommands = new Set(["screen", "logcat", "frida_logs"]);
  const analystCommands = (session?.commands || []).filter((item) => !backgroundCommands.has(item.type)).reverse();
  content.append(node("h3", "section-title", "Analyst operations and captured outcomes"));
  if (analystCommands.length) content.append(table(["Time", "Operation", "State", "Captured result"], analystCommands, (item) => [formatDate(item.completed_at || item.created_at), human(item.type), human(item.state), compactJson(item.result || {}).slice(0, 4000)]));
  else content.append(node("div", "notice", terminal ? "No analyst-triggered operations were recorded for this run." : "Analyst operations will appear here as they complete."));
  content.append(node("h3", "section-title", "Runtime observations"));
  const runtimeRows = [];
  Object.entries(report).forEach(([name, value]) => { if (["domains", "urls", "traffic", "http_tools", "screenshots"].includes(name) || Array.isArray(value)) runtimeRows.push({ name, value }); });
  content.append(table(["Section", "Captured data"], runtimeRows.slice(0, 100), (item) => [human(item.name), compactJson(item.value).slice(0, 4000)]));
  if (session?.state !== "ready") { const controls = node("div", "notice", session ? `Interactive session is ${human(session.state)}. Controls are unavailable after cleanup begins.` : "This run did not request an interactive session. The ReDroid guest was destroyed after evidence collection."); content.append(controls); }
  const links = node("div", "actions-row");
  if (workflow.inline_evidence.logcat) { const item = link("Open logcat", workflow.inline_evidence.logcat, "btn btn-small"); item.removeEventListener("click", navigateEvent); item.target = "_blank"; links.append(item); }
  if (workflow.inline_evidence["frida-logs"]) { const item = link("Open Frida logs", workflow.inline_evidence["frida-logs"], "btn btn-small"); item.removeEventListener("click", navigateEvent); item.target = "_blank"; links.append(item); }
  content.append(links);
}

async function androidCommand(runId, type, payload = {}, timeoutMs = 120000) {
  const created = await submitAndroidCommand(runId, { command_type: type, payload });
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await loadAndroidCommand(runId, created.command_id);
    if (["completed", "failed"].includes(value.state)) {
      if (value.state === "failed") throw new Error(value.result?.error || `${human(type)} failed`);
      return value.result || {};
    }
    await new Promise((resolve) => window.setTimeout(resolve, 350));
  }
  throw new Error(`${human(type)} timed out`);
}

function renderLiveAndroidSession(content, workflow) {
  const runId = workflow.run.id; const session = workflow.interactive_session;
  const toolbar = node("div", "android-dynamic-toolbar");
  const toolDefinitions = [
    ["Stop screen", "screen-toggle"], ["Remove root CA", "remove-ca"],
    ["Unset HTTP(S) proxy", "unset-proxy"], ["TLS/SSL security tester", "tls"],
    ["Exported activity tester", "exported"], ["Activity tester", "activities"],
    ["Get dependencies", "dependencies"], ["Take screenshot", "screenshot"],
    ["Logcat stream", "logcat-toggle"], ["Generate report", "finalize"],
  ];
  const workspace = node("div", "android-dynamic-workspace");
  const navigation = node("nav", "card android-dynamic-nav");
  navigation.append(node("h3", "", "Dynamic Analyzer"));
  const sections = [
    ["device", "Live device"], ["frida", "Frida instrumentation"],
    ["tls", "TLS/SSL tester"], ["proxy", "HTTPS proxy & CA"],
    ["activities", "Activity tester"], ["dependencies", "Runtime dependencies"],
    ["files", "Application files"], ["logs", "Live logs"],
  ];
  sections.forEach(([target, label]) => { const item = button(label, "android-dynamic-nav-item"); item.addEventListener("click", () => document.querySelector(`[data-android-section='${target}']`)?.scrollIntoView({ behavior: "smooth", block: "start" })); navigation.append(item); });
  const device = node("section", "card card-body android-device-panel");
  device.dataset.androidSection = "device";
  const deviceHead = node("div", "android-panel-head"); append(deviceHead, node("div", ""), node("h3", "card-title", "Live ReDroid device"), badge(session.state), node("span", "mono muted", `Expires ${formatDate(session.expires_at)}`)); device.append(deviceHead);
  const screenWrap = node("div", "android-live-screen-wrap"); const screen = node("img", "android-live-screen"); screen.alt = "Live Android guest screen"; screen.draggable = false; screenWrap.append(screen); device.append(screenWrap);
  const keys = node("div", "actions-row android-device-keys");
  [["Back", 4], ["Home", 3], ["Overview", 187], ["Power", 26]].forEach(([label, keycode]) => { const item = button(label, "btn btn-small"); item.addEventListener("click", () => perform("key", { keycode })); keys.append(item); });
  const textInput = node("input", "android-inline-input"); textInput.placeholder = "Type into focused field"; const sendText = button("Send text", "btn btn-small"); sendText.addEventListener("click", () => perform("text", { text: textInput.value })); append(keys, textInput, sendText); device.append(keys);
  const statusLine = node("div", "mono android-live-status", "Connecting to guest…"); device.append(statusLine);

  const tools = node("div", "android-analysis-column");
  function panel(section, title, description = "") { const value = node("section", "card card-body android-analysis-panel"); value.dataset.androidSection = section; append(value, node("h3", "card-title", title), description ? node("p", "muted", description) : null); tools.append(value); return value; }
  const live = panel("logs", "Live runtime output", "Logcat and Frida/API-monitor output remain visible throughout the session and update while the guest runs.");
  const liveTabs = node("div", "tabs android-console-tabs"); const logcatTab = button("Logcat", "tab active"); const fridaTab = button("Frida / API monitor", "tab"); liveTabs.append(logcatTab, fridaTab);
  const logcatOutput = node("pre", "android-command-output android-live-console", "Waiting for Logcat…"); const fridaOutput = node("pre", "android-command-output android-live-console hidden", "Waiting for Frida output…");
  function showConsole(which) { const logs = which === "logcat"; logcatTab.classList.toggle("active", logs); fridaTab.classList.toggle("active", !logs); logcatOutput.classList.toggle("hidden", !logs); fridaOutput.classList.toggle("hidden", logs); }
  logcatTab.addEventListener("click", () => showConsole("logcat")); fridaTab.addEventListener("click", () => showConsole("frida")); append(live, liveTabs, logcatOutput, fridaOutput);
  const operation = panel("operation", "Latest operation result", "Every analyst action reports its outcome here instead of silently updating a distant panel.");
  const operationTitle = node("strong", "mono", "No manual operation has run yet."); const operationOutput = node("pre", "android-command-output", "Select a tool to see its result."); append(operation, operationTitle, operationOutput);

  const frida = panel("frida", "Frida instrumentation", "Choose hooks, then attach them to the running malware process. Spawn is available when the application is not already running."); const hooks = node("div", "android-hook-grid"); const hookValues = {}; [["API monitor", "api_monitor"], ["SSL pinning bypass", "ssl_pinning_bypass"], ["Root detection bypass", "root_bypass"], ["Debugger check bypass", "debugger_check_bypass"], ["Clipboard monitor", "dump_clipboard"]].forEach(([label, value]) => { const wrap = node("label", "checkbox-field compact"); const input = node("input"); input.type = "checkbox"; input.checked = ["api_monitor", "ssl_pinning_bypass", "root_bypass", "debugger_check_bypass"].includes(value); hookValues[value] = input; append(wrap, input, node("span", "", label)); hooks.append(wrap); }); frida.append(node("h4", "", "Default hooks"), hooks); const auxiliary = node("div", "android-hook-grid"); const auxiliaryValues = {}; [["Enumerate loaded classes", "enum_class"], ["Enumerate methods", "enum_methods"], ["Search classes", "search_class"], ["Trace class", "trace_class"], ["Catch strings", "string_catch"], ["Compare strings", "string_compare"], ["Runtime dependencies", "get_dependencies"]].forEach(([label, value]) => { const wrap = node("label", "checkbox-field compact"); const input = node("input"); input.type = "checkbox"; auxiliaryValues[value] = input; append(wrap, input, node("span", "", label)); auxiliary.append(wrap); }); frida.append(node("h4", "", "Auxiliary hooks"), auxiliary); const className = node("input"); className.placeholder = "Class name (required for method enumeration)"; const classSearch = node("input"); classSearch.placeholder = "Class search pattern"; const classTrace = node("input"); classTrace.placeholder = "Class trace pattern"; append(frida, className, classSearch, classTrace); const editor = node("textarea", "frida-editor"); editor.rows = 8; editor.placeholder = "Java.perform(function () {\n  // optional analyst Frida code\n});"; frida.append(node("h4", "", "Custom Frida script"), editor); const fridaButtons = node("div", "actions-row"); [["Attach selected hooks", "session", "btn btn-primary"], ["Spawn with selected hooks", "spawn", "btn"], ["List processes", "ps", "btn"], ["Preview injected code", "get", "btn"]].forEach(([label, action, style]) => { const item = button(label, `${style} btn-small`); item.addEventListener("click", () => perform("frida", { action, default_hooks: Object.entries(hookValues).filter(([, input]) => input.checked).map(([value]) => value).join(","), auxiliary_hooks: Object.entries(auxiliaryValues).filter(([, input]) => input.checked).map(([value]) => value).join(","), class_name: className.value, class_search: classSearch.value, class_trace: classTrace.value, frida_code: editor.value }, true, 180000)); fridaButtons.append(item); }); frida.append(fridaButtons, node("small", "muted", "Hook selections, custom code, target PID, and MobSF result are retained in the analyst operation journal."));

  const tls = panel("tls", "TLS/SSL security tester", "Run MobSF TLS misconfiguration, pinning/certificate-transparency, and transport-security checks against the live app."); const tlsResult = node("pre", "android-command-output", "No TLS test has run yet."); const runTls = button("Run TLS/SSL tests", "btn btn-primary"); runTls.addEventListener("click", async () => { const result = await perform("tls_test", {}, false, 180000); if (result) tlsResult.textContent = JSON.stringify(result, null, 2); }); append(tls, runTls, tlsResult);

  const proxy = panel("proxy", "HTTPS proxy and trusted root CA", "Control MobSF interception explicitly. These controls affect only the disposable Android guest."); const proxyState = node("div", "android-state-strip"); const proxyBadge = badge("proxy unknown"); const caBadge = badge("CA unknown"); append(proxyState, proxyBadge, caBadge); const proxyActions = node("div", "actions-row"); [["Set HTTP(S) proxy", "proxy", { action: "set" }], ["Unset HTTP(S) proxy", "proxy", { action: "unset" }], ["Install MobSF root CA", "root_ca", { action: "install" }], ["Remove root CA", "root_ca", { action: "remove" }]].forEach(([label, type, payload]) => { const item = button(label, "btn btn-small"); item.addEventListener("click", async () => { const result = await perform(type, payload, true); if (result) (type === "proxy" ? proxyBadge : caBadge).textContent = `${human(type)} ${payload.action}`; }); proxyActions.append(item); }); append(proxy, proxyState, proxyActions);

  const activity = panel("activities", "Activity and deep-link tester"); const activityInput = node("input"); activityInput.placeholder = session.main_activity || "package/.Activity"; const launch = button("Start activity", "btn btn-small"); launch.addEventListener("click", () => perform("start_activity", { activity: activityInput.value || session.main_activity }, true)); const deepLink = node("input"); deepLink.placeholder = "Application deep link or custom URI scheme"; const launchLink = button("Open deep link", "btn btn-small"); launchLink.addEventListener("click", () => perform("deeplink", { url: deepLink.value }, true)); const activityButtons = node("div", "actions-row"); const activityResult = node("pre", "android-command-output", "No activity test has run yet."); [["Test exported activities", "exported"], ["Test all activities", "all_activities"]].forEach(([label, test]) => { const item = button(label, "btn btn-small"); item.addEventListener("click", async () => { const result = await perform("activity_test", { test }, false, 180000); activityResult.textContent = result ? resultText(result) : "Activity test failed; see the status message above."; }); activityButtons.append(item); }); append(activity, activityInput, launch, deepLink, launchLink, activityButtons, activityResult);
  const dependencies = panel("dependencies", "Runtime dependencies"); const dependencyResult = node("pre", "android-command-output", "No dependency scan has run yet."); const getDependencies = button("Get dependencies", "btn"); getDependencies.addEventListener("click", async () => { const result = await perform("dependencies", {}, false); if (result) dependencyResult.textContent = JSON.stringify(result, null, 2); }); append(dependencies, getDependencies, dependencyResult);
  const files = panel("files", "Application data browser"); const filePath = node("input"); filePath.value = `/data/data/${session.package_name || ""}`; const listFiles = button("List files", "btn btn-small"); listFiles.addEventListener("click", () => perform("list_files", { path: filePath.value }, true)); append(files, filePath, listFiles);
  const output = node("pre", "android-command-output", "Operation results appear here."); files.append(output);
  const sessionActions = node("div", "actions-row"); const extend = button("Extend 5 minutes", "btn"); extend.addEventListener("click", async () => { try { await api(`/api/v1/analysis-runs/${runId}/android-commands`, { method: "POST", body: { command_type: "extend", payload: {} } }); toast("Session extended within the 30-minute hard limit."); renderAndroidWorkflow(runId, true); } catch (failure) { toast(failure.message, true); } }); const finish = button("Finalize and generate report", "btn btn-danger"); finish.addEventListener("click", async () => { if (!window.confirm("Finalize this session and destroy the Android guest?")) return; await perform("finalize", {}, false); renderAndroidWorkflow(runId, true); }); append(sessionActions, extend, finish); tools.append(sessionActions);
  workspace.append(navigation, device, tools); content.append(toolbar, workspace);

  let busy = false; let screenTimer = null; let logTimer = null; let screenRunning = true; let logsRunning = true; let stopped = false;
  function resultText(result) { const clean = { ...result }; if (clean.image_base64) clean.screenshot = "Captured for the finalized analysis report"; delete clean.image_base64; return JSON.stringify(clean, null, 2); }
  async function perform(type, payload, showResult = false, timeout = 120000, quietFailure = false) {
    if (busy && quietFailure) return null;
    const waitDeadline = Date.now() + 5000;
    while (busy && Date.now() < waitDeadline) await new Promise((resolve) => window.setTimeout(resolve, 75));
    if (busy) { toast("The current Android operation is still finishing. Try again.", true); return null; }
    busy = true; statusLine.textContent = `Running ${human(type)}…`;
    try { const result = await androidCommand(runId, type, payload, timeout); if (result.image_base64) screen.src = `data:image/png;base64,${result.image_base64}`; if (type === "logcat" && result.logcat) logcatOutput.textContent = result.logcat; if (["frida", "frida_logs", "api_monitor"].includes(type)) fridaOutput.textContent = JSON.stringify(result, null, 2); if (showResult) { operationTitle.textContent = `${human(type)} completed`; operationOutput.textContent = resultText(result); operation.scrollIntoView({ behavior: "smooth", block: "nearest" }); } statusLine.textContent = `${human(type)} completed`; return result; }
    catch (failure) { statusLine.textContent = failure.message; if (!quietFailure) toast(failure.message, true); return null; }
    finally { busy = false; }
  }
  let pointerStart = null; screen.addEventListener("pointerdown", (event) => { pointerStart = { x: event.clientX, y: event.clientY, at: Date.now() }; screen.setPointerCapture(event.pointerId); }); screen.addEventListener("pointerup", async (event) => { if (!pointerStart) return; const rect = screen.getBoundingClientRect(); const scaleX = screen.naturalWidth / rect.width; const scaleY = screen.naturalHeight / rect.height; const start = { x: Math.round((pointerStart.x - rect.left) * scaleX), y: Math.round((pointerStart.y - rect.top) * scaleY) }; const end = { x: Math.round((event.clientX - rect.left) * scaleX), y: Math.round((event.clientY - rect.top) * scaleY) }; const distance = Math.hypot(end.x - start.x, end.y - start.y); const duration = Date.now() - pointerStart.at; pointerStart = null; if (distance > 30) await perform("swipe", { x1: start.x, y1: start.y, x2: end.x, y2: end.y, duration_ms: Math.max(100, duration) }); else await perform("tap", { x: end.x, y: end.y }); scheduleScreen(); });
  async function background(type) { if (busy || stopped) return; await perform(type, {}, false, 120000, true); }
  function scheduleScreen() { if (screenTimer) window.clearTimeout(screenTimer); if (!screenRunning || stopped || location.pathname !== `/analysis/${runId}/android` || state.androidTab !== "dynamic") return; screenTimer = window.setTimeout(async () => { await background("screen"); scheduleScreen(); }, 900); }
  function scheduleLogs() { if (logTimer) window.clearTimeout(logTimer); if (!logsRunning || stopped || location.pathname !== `/analysis/${runId}/android` || state.androidTab !== "dynamic") return; logTimer = window.setTimeout(async () => { await background("logcat"); if (!busy) await background("frida_logs"); scheduleLogs(); }, 2500); }
  toolDefinitions.forEach(([label, action]) => { const item = button(label, `btn btn-small${action === "finalize" ? " btn-danger" : ""}`); item.addEventListener("click", async () => { if (action === "screen-toggle") { screenRunning = !screenRunning; item.textContent = screenRunning ? "Stop screen" : "Start screen"; if (screenRunning) scheduleScreen(); } else if (action === "logcat-toggle") { logsRunning = !logsRunning; item.textContent = logsRunning ? "Stop logcat stream" : "Start logcat stream"; if (logsRunning) scheduleLogs(); } else if (action === "remove-ca") await perform("root_ca", { action: "remove" }, true); else if (action === "unset-proxy") await perform("proxy", { action: "unset" }, true); else if (action === "tls") document.querySelector("[data-android-section='tls']")?.scrollIntoView({ behavior: "smooth" }); else if (action === "exported") await perform("activity_test", { test: "exported" }, true, 180000); else if (action === "activities") await perform("activity_test", { test: "all_activities" }, true, 180000); else if (action === "dependencies") getDependencies.click(); else if (action === "screenshot") await perform("screenshot", {}, true); else if (action === "finalize") finish.click(); }); toolbar.append(item); });
  state.androidLiveCleanup = () => { stopped = true; if (screenTimer) window.clearTimeout(screenTimer); if (logTimer) window.clearTimeout(logTimer); };
  perform("screen").then(() => { scheduleScreen(); scheduleLogs(); });
}

function renderAndroidNetwork(content, workflow) {
  const mode = node("div", `notice${workflow.run.network_mode === "real_world_egress" ? " notice-warn" : ""}`, workflow.run.network_mode === "isolated_simulated" ? "This run used the isolated/simulated malware-safe baseline. C2 analysis inspected captured connection attempts without granting unrestricted Internet access." : "This run requested real-world egress. Treat all resulting destinations and responses as potentially hostile.");
  content.append(mode, node("h3", "section-title", "Observed network destinations"));
  if (workflow.network_observations.length) content.append(table(["Time", "Domain", "IP", "Port", "Protocol", "Evidence source"], workflow.network_observations, (item) => [formatDate(item.observed_at), item.destination_domain || "—", item.destination_ip || "—", item.destination_port || "—", item.protocol || "—", human(item.details?.source || "unknown")]));
  else content.append(node("div", "notice notice-warn", "No application destinations were normalized. A completed C2 stage with this state means it had no usable network events; it is not evidence that the sample made no connection attempts."));
  content.append(node("h3", "section-title", "C2 analyzer findings"));
  if (workflow.c2_findings.length) content.append(table(["Finding", "Kind", "Confidence", "Limitation"], workflow.c2_findings, (item) => [item.summary, human(item.kind), human(item.confidence), item.capped_by_caveat ? CAVEAT_TEXT[item.capped_by_caveat] || human(item.capped_by_caveat) : "—"]));
  else content.append(node("div", "notice", workflow.run.c2_analysis_enabled ? "C2 analysis completed without a qualifying finding. Static indicators below remain unconfirmed unless they were observed in runtime traffic." : "C2 analysis was disabled for this run."));
  content.append(node("h3", "section-title", "Static destinations (not necessarily contacted)"));
  content.append(table(["Type", "Value", "Confidence", "Observed"], workflow.iocs.filter((item) => ["domain", "ip", "url"].includes(item.type)), (item) => [item.type, item.value, human(item.confidence), item.seen_in_traffic ? "Yes" : "No"]));
}

function renderAndroidArtifacts(content, workflow) {
  content.append(node("div", "notice", "Downloads remain access-controlled, integrity-verified, and audit-logged by UMAT."));
  const list = node("div", "case-list");
  workflow.artifacts.forEach((item) => { const row = node("div", "card case-row"); const identity = node("div"); append(identity, node("h3", "", human(item.kind)), node("div", "mono muted", item.sha256)); const download = link("Download", item.download_path, "btn btn-small"); download.removeEventListener("click", navigateEvent); append(row, identity, node("div", "", formatBytes(item.size_bytes)), badge(item.access_tier), download); list.append(row); });
  if (!workflow.artifacts.length) list.append(node("div", "card empty", "No evidence files are currently available."));
  content.append(node("h3", "section-title", "Registered evidence"), list);
}

async function renderRecentRuns() {
  const content = node("div");
  content.append(pageHead("Analysis operations", "Recent runs", "Search and diagnose analysis work across cases without opening native backend consoles.", null));
  const filters = node("form", "card card-body");
  const grid = node("div", "field-grid");
  const search = field("Search case, reference, filename or SHA-256", "search", "run_search");
  const statusFilter = selectField("Run status", "run_status", [["All statuses", ""], ["Awaiting confirmation", "awaiting_confirmation"], ["Queued", "queued"], ["Running", "running"], ["Cancelling", "cancelling"], ["Terminal", "terminal"]], "");
  const platformFilter = selectField("Platform", "run_platform", [["All platforms", ""], ["Windows", "windows"], ["Android", "android"]], "");
  const apply = button("Apply filters", "btn btn-primary"); apply.type = "submit";
  append(grid, search.wrap, statusFilter.wrap, platformFilter.wrap);
  append(filters, grid, append(node("div", "form-actions"), apply));
  const summary = node("div", "muted");
  const list = node("div", "case-list");
  const pagination = node("div", "actions-row");
  content.append(filters, summary, list, pagination);
  shell("Recent runs", content);

  async function load(page = 1) {
    apply.disabled = true;
    try {
      const result = await queryRecentRuns({ q: search.input.value, status: statusFilter.select.value, platform: platformFilter.select.value, page, page_size: 10 });
      state.recentRunPage = result.page;
      summary.textContent = `${result.total} run${result.total === 1 ? "" : "s"} · page ${result.page} of ${result.pages || 1}`;
      list.replaceChildren(); pagination.replaceChildren();
      if (!result.items.length) list.append(node("div", "card empty", "No runs match these filters."));
      result.items.forEach((item) => {
        const row = node("section", "card card-body");
        const head = node("div", "case-row");
        const identity = node("div");
        append(identity, link(item.case_title || "Untitled case", `/cases/${item.case_id}`), node("div", "mono muted", `${item.case_reference || item.case_id} · ${item.filename}`), node("div", "mono muted", item.id));
        append(head, identity, badge(item.platform), badge(item.status), item.result ? badge(item.result) : null);
        const policy = node("div", "muted", `${human(item.network_mode)} · C2 ${item.c2_analysis_enabled ? "enabled" : "disabled"} · ${formatDate(item.updated_at)}`);
        const diagnostics = node("details"); diagnostics.append(node("summary", "", "Stage diagnostics"));
        const stages = node("div", "case-list");
        item.stages.forEach((stage) => {
          const stageRow = node("div", "case-row");
          append(stageRow, node("span", "", human(stage.stage_type)), badge(stage.state), node("span", "muted", `${stage.attempt_count} attempt${stage.attempt_count === 1 ? "" : "s"}`), stage.failure_detail ? node("span", "notice notice-error", stage.failure_detail) : null);
          stages.append(stageRow);
        });
        diagnostics.append(stages);
        const actions = node("div", "actions-row");
        actions.append(link("Open case", `/cases/${item.case_id}`, "btn btn-small"));
        if (item.retry_eligible && canControlRuns()) {
          const retry = button("Retry", "btn btn-small");
          retry.addEventListener("click", async () => {
            const reason = window.prompt("Reason for retry (recorded in the audit log):");
            if (!reason) return;
            try { await retryAnalysisRun(item.id, reason); toast("Retry queued."); load(result.page); }
            catch (failure) { toast(failure.message, true); }
          });
          actions.append(retry);
        }
        append(row, head, policy, diagnostics, actions); list.append(row);
      });
      const previous = button("Previous", "btn btn-small"); previous.disabled = result.page <= 1; previous.addEventListener("click", () => load(result.page - 1));
      const next = button("Next", "btn btn-small"); next.disabled = result.page >= result.pages; next.addEventListener("click", () => load(result.page + 1));
      append(pagination, previous, next);
    } catch (failure) { list.replaceChildren(node("div", "notice notice-error", failure.message)); }
    finally { apply.disabled = false; }
  }
  filters.addEventListener("submit", (event) => { event.preventDefault(); load(1); });
  await load(state.recentRunPage);
}

async function renderWorkersAdmin() {
  if (!isAdmin()) { go("/cases"); return; }
  const content = node("div");
  content.append(pageHead("Execution capacity", "Workers", "Runtime identity, compatibility, heartbeat, workload, and active leases from the control plane.", null));
  const list = node("div", "case-list"); content.append(list); shell("Workers", content);
  try {
    const inventory = await loadWorkers();
    if (!inventory.items.length) list.append(node("div", "card empty", "No workers are enrolled."));
    inventory.items.forEach((item) => {
      const card = node("section", "card card-body");
      const head = node("div", "case-row");
      const identity = node("div");
      append(identity, node("h3", "", item.name), node("div", "mono muted", item.runtime_identity || "Runtime identity not advertised"), node("small", "muted", `${item.executor_type} · last seen ${formatDate(item.last_seen_at)}`));
      append(head, identity, badge(item.status), badge(item.heartbeat_state), badge(item.compatibility.compatible ? "compatible" : "incompatible"), node("strong", "", `${item.active_workload} active`));
      const details = node("details"); details.append(node("summary", "", "Capabilities and leases"));
      details.append(node("pre", "code-block", compactJson({ supported_stage_types: item.supported_stage_types, capabilities: item.capabilities, compatibility: item.compatibility })));
      const leases = node("div", "case-list");
      item.active_leases.forEach((lease) => { const row = node("div", "case-row"); append(row, link(human(lease.stage_type), `/cases/${lease.case_id}`), badge(lease.platform), badge(lease.state), node("span", "muted", `heartbeat ${formatDate(lease.last_heartbeat_at)} · expires ${formatDate(lease.expires_at)}`)); leases.append(row); });
      if (!item.active_leases.length) leases.append(node("div", "muted", "No active leases."));
      details.append(leases); append(card, head, details); list.append(card);
    });
  } catch (failure) { list.append(node("div", "notice notice-error", failure.message)); }
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
  async function load() {
    const items = await api("/api/v1/windows/profiles?include_inactive=true"); list.replaceChildren();
    items.forEach((item) => {
      const row = node("div", "card case-row"); const copy = node("div");
      append(copy, node("h3", "", item.display_name), node("div", "mono muted", `${item.name} · ${item.windows_version} · ${item.vcpus} vCPU · ${item.ram_mb} MiB · ${item.disk_gb} GiB`), node("div", "mono muted", `${item.cape_machine_label || "not provisioned"} · ${item.cape_template}`));
      const edit = button("Edit", "btn btn-small"); edit.disabled = item.state !== "active";
      edit.addEventListener("click", async () => {
        const displayName = window.prompt("Profile display name:", item.display_name);
        if (!displayName) return;
        try { await updateWindowsProfile(item.id, { display_name: displayName }); toast("Windows profile metadata updated."); load(); }
        catch (failure) { toast(failure.message, true); }
      });
      const makeDefault = button(item.is_default ? "Default" : "Make default", "btn btn-small"); makeDefault.disabled = item.is_default || item.state !== "active";
      makeDefault.addEventListener("click", async () => { try { await updateWindowsProfile(item.id, { is_default: true }); toast("Default Windows profile changed."); load(); } catch (failure) { toast(failure.message, true); } });
      const remove = button("Retire", "btn btn-danger btn-small"); remove.disabled = ["deleting", "deleted", "provisioning"].includes(item.state);
      remove.addEventListener("click", async () => { try { await api(`/api/v1/windows/profiles/${item.id}`, { method: "DELETE" }); toast("Profile deletion queued through CAPE."); load(); } catch (failure) { toast(failure.message, true); } });
      append(row, copy, node("div", "", human(item.analysis_profile)), badge(item.state), edit, makeDefault, remove); list.append(row);
    });
  }
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
    items.forEach((item) => {
      const row = node("div", "card case-row"); const copy = node("div");
      append(copy, node("h3", "", item.display_name), node("div", "mono muted", `${item.name} · Android ${item.android_version} / API ${item.api_level} · ${item.architecture} · ${item.vcpus} vCPU · ${item.ram_mb} MiB`), node("div", "mono muted", item.system_image));
      const edit = button("Edit", "btn btn-small"); edit.disabled = item.state !== "active";
      edit.addEventListener("click", async () => { const displayName = window.prompt("Profile display name:", item.display_name); if (!displayName) return; try { await updateAndroidProfile(item.id, { display_name: displayName }); toast("Android profile updated."); load(); } catch (failure) { toast(failure.message, true); } });
      const makeDefault = button(item.is_default ? "Default" : "Make default", "btn btn-small"); makeDefault.disabled = item.is_default || item.state !== "active";
      makeDefault.addEventListener("click", async () => { try { await updateAndroidProfile(item.id, { is_default: true }); toast("Default Android profile changed."); load(); } catch (failure) { toast(failure.message, true); } });
      const remove = button("Retire", "btn btn-danger btn-small"); remove.disabled = item.state !== "active" || item.is_default; remove.title = item.is_default ? "Select another default before retiring this profile" : "Retire profile";
      remove.addEventListener("click", async () => { try { await api(`/api/v1/android/profiles/${item.id}`, { method: "DELETE" }); toast("Android profile retired; existing run snapshots are preserved."); load(); } catch (failure) { toast(failure.message, true); } });
      const qualify = button("Qualify", "btn btn-small"); qualify.disabled = item.state !== "active" || item.qualification?.status === "qualified"; qualify.title = "Record a completed evidence run that qualifies this profile";
      qualify.addEventListener("click", async () => { const runId = window.prompt("Evidence analysis run ID that qualifies this profile:"); if (!runId) return; try { await api(`/api/v1/android/profiles/${item.id}/qualify`, { method: "POST", body: { evidence_run_id: runId.trim() } }); toast("Profile qualified against the supplied evidence run."); load(); } catch (failure) { toast(failure.message, true); } });
      append(row, copy, node("div", "", item.is_default ? "Default" : human(item.qualification?.status || "candidate")), badge(item.state), edit, makeDefault, qualify, remove); list.append(row);
    });
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
  if (path === "/runs") return renderRecentRuns();
  if (path === "/submit") return renderSubmit();
  if (path === "/admin/workers") return renderWorkersAdmin();
  if (path === "/admin/windows") return renderWindowsAdmin();
  if (path === "/admin/android") return renderAndroidAdmin();
  const androidMatch = path.match(/^\/analysis\/([0-9a-f-]+)\/android$/i);
  if (androidMatch) return renderAndroidWorkflow(androidMatch[1]);
  const match = path.match(/^\/cases\/([0-9a-f-]+)$/i);
  if (match) return renderCase(match[1]);
  go("/cases");
}

configureApi({ onUnauthorized: () => { state.session = null; go("/login"); } });
configureRouter(renderRoute);
renderRoute();
