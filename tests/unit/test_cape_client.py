from __future__ import annotations

from pathlib import Path

import httpx

from umat.windows.cape import CapeClient, cape_package_for_sample


def test_profile_management_uses_separate_authenticated_gateway() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            201,
            json={
                "operation_id": "0198a04b-8a7a-7000-8000-000000000002",
                "machine_label": "umat-office-1234abcd",
            },
        )

    client = CapeClient(
        "http://cape.invalid",
        management_url="http://gateway.invalid",
        management_token="gateway-secret",  # noqa: S106 - non-secret test fixture
    )
    client.management = httpx.Client(
        base_url="http://gateway.invalid", transport=httpx.MockTransport(handler)
    )
    operation, label = client.create_machine({"profile_id": "profile-1"})
    assert (operation, label) == (
        "0198a04b-8a7a-7000-8000-000000000002",
        "umat-office-1234abcd",
    )
    assert requests[0].url == httpx.URL("http://gateway.invalid/api/v1/machines")


def test_cape_status_accepts_native_string_response() -> None:
    client = CapeClient("http://cape.invalid")
    client.client = httpx.Client(
        base_url="http://cape.invalid",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"error": False, "data": "reported"})
        ),
    )
    assert client.status(42) == {"status": "reported"}


def test_submit_never_uses_original_filename(tmp_path: Path) -> None:
    sample = tmp_path / "attacker-name.exe"
    sample.write_bytes(b"harmless fixture")

    def handler(request: httpx.Request) -> httpx.Response:
        assert b'attacker-name.exe' not in request.content
        assert b'name="file"; filename="sample.bin"' in request.content
        assert b'name="timeout"' in request.content
        assert b"180" in request.content
        assert b'name="enforce_timeout"' in request.content
        return httpx.Response(200, json={"data": {"task_ids": [7]}})

    client = CapeClient("http://cape.invalid")
    client.client = httpx.Client(
        base_url="http://cape.invalid", transport=httpx.MockTransport(handler)
    )
    assert client.submit(sample, {"analysis_profile": "standard"}) == 7


def test_cape_package_for_native_pe(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    image = bytearray(128)
    image[:2] = b"MZ"
    image[60:64] = (64).to_bytes(4, "little")
    image[64:68] = b"PE\0\0"
    sample.write_bytes(image)
    assert cape_package_for_sample(sample) == "exe"

    image[64 + 22 : 64 + 24] = (0x2000).to_bytes(2, "little")
    sample.write_bytes(image)
    assert cape_package_for_sample(sample) == "dll"

    sample.write_bytes(b"PK\x03\x04not-a-pe")
    assert cape_package_for_sample(sample) == ""
