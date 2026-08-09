from __future__ import annotations

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
