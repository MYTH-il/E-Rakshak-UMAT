from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
LOCK_ROOT = ROOT / "dependency-locks"
SHA256 = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    assert value["schema_version"] == "1.0", path
    return value  # type: ignore[no-any-return]


def test_inventory_references_complete_existing_locks() -> None:
    inventory = load(LOCK_ROOT / "third-party-inventory.json")
    expected_lock_files = {
        "dependency-locks/installer.json",
        "dependency-locks/umat-postgres.json",
        "dependency-locks/winstdt.json",
        "dependency-locks/android-erakshak.json",
        "dependency-locks/c2-exfil.json",
    }
    observed = {component["lock_file"] for component in inventory["components"]}
    assert observed == expected_lock_files
    for component in inventory["components"]:
        lock_path = ROOT / component["lock_file"]
        assert lock_path.is_file(), component["name"]
        locked = load(lock_path)
        if component["name"] == "CAPEv2":
            identity = locked["cape"]
        else:
            identity = locked
        if component["commit"] is not None:
            assert identity["commit"] == component["commit"]
            assert identity["repository"] == component["repository"]
        assert isinstance(component["redistribution_allowed"], bool)
        assert component["license_evidence"]
        assert component["runtime_status"]


def test_runtime_locks_have_complete_immutable_identities() -> None:
    android = load(LOCK_ROOT / "android-erakshak.json")
    c2 = load(LOCK_ROOT / "c2-exfil.json")
    postgres = load(LOCK_ROOT / "umat-postgres.json")
    winstdt = load(LOCK_ROOT / "winstdt.json")

    for source_lock in (android, c2, winstdt):
        assert COMMIT.fullmatch(source_lock["commit"])
        assert source_lock["repository"].startswith("https://github.com/")
    for digest in (
        android["tree_sha256"],
        android["patch_series_sha256"],
        android["container_image_digest"].removeprefix("sha256:"),
        c2["upstream_tree_sha256"],
        c2["effective_tree_sha256"],
        c2["patch_series_sha256"],
        postgres["image_digest"].removeprefix("sha256:"),
        winstdt["tree_sha256"],
        winstdt["deployment_patch_series"]["patch_series_sha256"],
    ):
        assert SHA256.fullmatch(digest), digest
    assert android["runtime_policy"]["default"] in android["runtime_policy"]["required"]
    assert set(android["runtime_policy"]["required"]).isdisjoint(
        android["runtime_policy"]["optional"]
    )
    assert "@sha256:" in android["tool_versions"]["redroid_image"]
    assert android["validation"]["runtime"] == android["runtime_policy"]["default"]
    assert android["validation"]["status"] == "qualified"
    assert c2["schema_reference"]["commit"] == c2["commit"]
    assert c2["schema_reference"]["repository"] == c2["repository"]
    assert SHA256.fullmatch(c2["schema_reference"]["sha256"])
    assert COMMIT.fullmatch(winstdt["cape"]["commit"])


def test_c2_promotion_records_every_upstream_change_and_observed_test_total() -> None:
    c2 = load(LOCK_ROOT / "c2-exfil.json")
    validation = c2["validation"]
    assert validation["upstream_tests_collected"] == (
        validation["upstream_tests_passed"] + validation["upstream_tests_skipped"]
    )
    assert validation["upstream_tests_deselected_missing_corpus"] == 0
    changes = {
        item["commit"]: item["functionality"]
        for item in validation["included_upstream_commits"]
    }
    assert set(changes) == {
        "ef0c32ce7b4ffa28de093aa296b0d70d76b2fbd8",
        "478f131de510ad580754f152d946086b3aeacf05",
    }
    combined = " ".join(changes.values()).lower()
    for behavior in ("shared hosting", "dns tunnel", "destination", "bounded-memory"):
        assert behavior in combined


def test_deployment_manifest_covers_every_runtime_lock() -> None:
    manifest = load(ROOT / "deployment/full-stack/manifest.json")
    components = manifest["components"]
    assert {"installer", "winstdt", "cape", "c2", "android", "umat_postgres"} == set(
        components
    )
    installer = load(LOCK_ROOT / "installer.json")
    assert components["installer"]["uv_version"] == installer["uv"]["version"]
    assert SHA256.fullmatch(installer["uv"]["sha256"])
