from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import umat.geolocation as geolocation


class FakeReader:
    def __init__(self, path: Path) -> None:
        self.path = path

    def __enter__(self) -> FakeReader:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def city(self, _: str) -> SimpleNamespace:
        return SimpleNamespace(country=SimpleNamespace(iso_code="US"))

    def asn(self, _: str) -> SimpleNamespace:
        return SimpleNamespace(
            autonomous_system_number=15169,
            autonomous_system_organization="Google LLC",
        )


def test_lookup_ip_uses_local_city_and_asn_databases(
    tmp_path: Path, monkeypatch,
) -> None:
    city = tmp_path / "city.mmdb"
    asn = tmp_path / "asn.mmdb"
    city.write_bytes(b"city")
    asn.write_bytes(b"asn")
    monkeypatch.setattr(geolocation.geoip2.database, "Reader", FakeReader)

    assert geolocation.lookup_ip("8.8.8.8", str(city), str(asn)) == (
        "US",
        "AS15169",
        "Google LLC",
    )


def test_lookup_ip_skips_non_public_addresses() -> None:
    assert geolocation.lookup_ip("10.66.0.101") == (None, None, None)
    assert geolocation.lookup_ip("not-an-ip") == (None, None, None)
