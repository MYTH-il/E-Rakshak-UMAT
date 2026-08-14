from __future__ import annotations

import ipaddress
import os
from functools import lru_cache
from pathlib import Path

import geoip2.database
from geoip2.errors import AddressNotFoundError

DEFAULT_CITY_DB = Path("/srv/winstdt/c2-data/GeoLite2-City.mmdb")
DEFAULT_ASN_DB = Path("/srv/winstdt/c2-data/GeoLite2-ASN.mmdb")


@lru_cache(maxsize=4096)
def lookup_ip(
    value: str,
    city_database: str | None = None,
    asn_database: str | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Return country, ASN, and network owner from the local GeoLite2 data."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None, None, None
    if not address.is_global:
        return None, None, None

    city_path = Path(
        city_database or os.environ.get("UMAT_GEOLITE2_CITY_DB", str(DEFAULT_CITY_DB))
    )
    asn_path = Path(
        asn_database or os.environ.get("UMAT_GEOLITE2_ASN_DB", str(DEFAULT_ASN_DB))
    )
    country = asn = organization = None
    try:
        if city_path.is_file():
            with geoip2.database.Reader(city_path) as reader:
                country = reader.city(value).country.iso_code
        if asn_path.is_file():
            with geoip2.database.Reader(asn_path) as reader:
                result = reader.asn(value)
                if result.autonomous_system_number is not None:
                    asn = f"AS{result.autonomous_system_number}"
                organization = result.autonomous_system_organization
    except (AddressNotFoundError, OSError, ValueError):
        # Enrichment must never prevent an evidence report from being emitted.
        return country, asn, organization
    return country, asn, organization
