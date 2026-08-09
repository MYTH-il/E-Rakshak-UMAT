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
