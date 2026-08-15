from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from umat.api.app import app
from umat.reporting.worker import app as report_worker_app


@pytest.mark.asyncio
async def test_web_shell_and_assets_are_local_and_hardened() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        page = await client.get("/login")
        assert page.status_code == 200
        assert "default-src 'self'" in page.headers["content-security-policy"]
        assert "https://" not in page.text
        css = await client.get("/assets/app.css")
        javascript = await client.get("/assets/app.js")
        assert css.status_code == javascript.status_code == 200
        assert css.headers["cache-control"] == "no-store"
        assert javascript.headers["cache-control"] == "no-store"
        assert "innerHTML" not in javascript.text
        assert "http://" not in javascript.text and "https://" not in javascript.text


def test_documented_report_worker_subcommand_exists() -> None:
    result = CliRunner().invoke(report_worker_app, ["run", "--help"])
    assert result.exit_code == 0
    assert "--once" in result.stdout


ROOT = Path(__file__).resolve().parents[2]


def test_every_caveat_has_officer_facing_text() -> None:
    """An officer must never be shown a bare machine code.

    contracts/vocabularies/caveats.json is the canonical wording; app.js
    mirrors it for rendering. This guards the two against drifting apart, and
    fails when a new caveat is added without an explanation.
    """
    vocabulary = json.loads((ROOT / "contracts/vocabularies/caveats.json").read_text())
    codes = set(vocabulary["values"])
    descriptions = vocabulary["descriptions"]

    assert set(descriptions) == codes, "caveats.json values and descriptions disagree"
    for code, text in descriptions.items():
        assert text.strip(), f"{code} has empty officer text"
        assert code not in text, f"{code} description merely restates the code"

    javascript = (ROOT / "src/umat/web/static/app.js").read_text()
    block = re.search(r"const CAVEAT_TEXT = \{(.*?)\n\};", javascript, re.S)
    assert block, "app.js is missing CAVEAT_TEXT"
    rendered = set(re.findall(r"^\s{2}([a-z0-9_]+):", block.group(1), re.M))
    assert rendered == codes, f"app.js CAVEAT_TEXT drifted from the vocabulary: {rendered ^ codes}"


def test_caveats_are_rendered_as_explanations_not_codes() -> None:
    javascript = (ROOT / "src/umat/web/static/app.js").read_text()
    assert "CAVEAT_TEXT[item.value]" in javascript, (
        "the officer view must render the explanation, not the de-underscored code"
    )


def test_windows_run_progress_exposes_live_console_action() -> None:
    javascript = (ROOT / "src/umat/web/static/app.js").read_text()
    assert 'button("Launch live console"' in javascript
    assert "windows-session/launch-viewer" in javascript
    assert 'item.platform === "windows"' in javascript


def test_large_evidence_collections_use_search_and_pagination() -> None:
    javascript = (ROOT / "src/umat/web/static/app.js").read_text()
    css = (ROOT / "src/umat/web/static/app.css").read_text()
    assert "function dataExplorer(" in javascript
    assert '"Search indicators"' in javascript
    assert '"Search destinations, IPs, domains or networks"' in javascript
    assert '"Search actions, files, paths, processes or PIDs"' in javascript
    assert "filtered.slice(start, start + pageSize)" in javascript
    assert ".explorer-pagination" in css
    assert "overflow-wrap: anywhere" in css


def test_android_runtime_observations_are_expanded_into_searchable_rows() -> None:
    javascript = (ROOT / "src/umat/web/static/app.js").read_text()
    assert 'import { runtimeObservationRows } from "./runtime-observations.js"' in javascript
    assert '["Section", "Observation", "Details"]' in javascript
    assert '"Search runtime observations"' in javascript
    assert 'compactJson(item.value).slice(0, 4000)' not in javascript


def test_obfuscated_android_component_names_are_contained_and_disclosed() -> None:
    javascript = (ROOT / "src/umat/web/static/app.js").read_text()
    css = (ROOT / "src/umat/web/static/app.css").read_text()
    assert "androidComponentItems, readableAndroidFinding" in javascript
    assert 'from "./android-components.js"' in javascript
    assert '"Obfuscated Unicode identifier"' in javascript
    assert 'node("details", "component-raw")' in javascript
    assert ".component-name" in css and "overflow-wrap: anywhere" in css
    assert ".component-raw code" in css and "unicode-bidi: plaintext" in css


def test_android_findings_and_scan_logs_render_as_individual_readable_rows() -> None:
    javascript = (ROOT / "src/umat/web/static/app.js").read_text()
    assert "readableAndroidFinding(item.summary)" in javascript
    assert '"Show raw finding"' in javascript
    assert "androidScanLogRows(scanLogs)" in javascript
    assert '["Time", "Stage", "Status", "Error"]' in javascript
    assert '"Search static scan events"' in javascript


def test_administrator_console_exposes_user_and_role_management() -> None:
    javascript = (ROOT / "src/umat/web/static/app.js").read_text()
    administration = (ROOT / "src/umat/web/static/administration.js").read_text()
    assert 'navItem("Users & roles", "/admin/users"' in javascript
    assert "async function renderUsersAdmin()" in javascript
    assert 'button("Create user"' in javascript
    assert 'button("Delete user"' in javascript
    assert "/api/v1/admin/users" in administration


def test_unified_timeline_displays_confidence() -> None:
    javascript = (ROOT / "src/umat/web/static/app.js").read_text()
    assert '["Time", "Actor", "Event", "Confidence", "MITRE"]' in javascript
    assert "human(item.confidence)" in javascript
    assert "CAPE's family parser returned no record" in javascript


def test_ioc_table_sorts_by_confidence_with_allowlisted_last() -> None:
    javascript = (ROOT / "src/umat/web/static/app.js").read_text()
    assert "confidenceRank(b.confidence) - confidenceRank(a.confidence)" in javascript
    assert "allowlisted: 0" in javascript


def test_new_ui_design_preserves_accessibility_and_worker_diagnostics() -> None:
    index = (ROOT / "src/umat/web/index.html").read_text()
    css = (ROOT / "src/umat/web/static/app.css").read_text()

    assert 'app.css?v=20260815.2' in index
    assert 'app.js?v=20260815.2' in index
    assert "--accent: #93aeea" in css
    assert "--bad: #e0968f" in css
    assert "--line-strong:" in css
    assert "outline: 2px solid var(--accent-hi)" in css
    assert ".rail {" in css
    assert ".verdict-block {" in css
    assert ".device-screen-wrap" in css
    assert ".code-block {" in css
    assert "white-space: pre-wrap" in css
    assert "overflow-wrap: anywhere" in css
    assert ".sev-high" in css and "color: var(--bad-hi)" in css
    assert ".sev-unrated" in css and "color: var(--text-faint)" in css


def test_new_ui_keeps_live_routes_and_rbac_instead_of_static_mockup_behavior() -> None:
    javascript = (ROOT / "src/umat/web/static/app.js").read_text()

    assert 'node("aside", "rail")' in javascript
    assert 'node("section", "card verdict-block")' in javascript
    assert 'node("div", "dynamic-workspace")' in javascript
    assert 'api("/api/v1/auth/login"' in javascript
    assert 'api("/api/v1/cases"' in javascript
    assert 'navItem("Users & roles", "/admin/users"' in javascript
    assert 'button("Open live Windows console"' in javascript
    assert 'renderLiveAndroidSession(content, workflow)' in javascript
