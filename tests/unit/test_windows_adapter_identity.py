import json
from types import SimpleNamespace
from uuid import UUID

import pytest

from umat.windows.adapter import WindowsAdaptationError, WindowsAdapter

RUN_ID = UUID("0198fd40-1111-7000-8000-000000000001")
EXECUTOR_ID = UUID("0198fd40-1111-7000-8000-000000000002")


def inputs(interactive: bool) -> tuple[dict, SimpleNamespace, SimpleNamespace, SimpleNamespace]:
    selected_profile = {
        "cape_machine_label": "win10-clean",
        "network_mode": "isolated_simulated",
        "c2_analysis_enabled": False,
        "android_interactive": False,
        "windows_interactive": interactive,
    }
    manifest = {
        "analysis_run_id": str(RUN_ID),
        "sample_sha256": "a" * 64,
        "signature": {"key_id": str(EXECUTOR_ID)},
        "selected_profile": selected_profile,
    }
    run = SimpleNamespace(
        id=RUN_ID,
        network_mode="isolated_simulated",
        c2_analysis_enabled=False,
        android_interactive=False,
        windows_interactive=interactive,
    )
    executor = SimpleNamespace(id=EXECUTOR_ID)
    configuration = SimpleNamespace(profile_snapshot={"cape_machine_label": "win10-clean"})
    return manifest, run, executor, configuration


@pytest.mark.parametrize("interactive", [False, True])
def test_profile_identity_accepts_automated_and_manual_execution_snapshots(
    interactive: bool,
) -> None:
    manifest, run, executor, configuration = inputs(interactive)
    WindowsAdapter._identity(manifest, run, "a" * 64, executor, configuration)  # type: ignore[arg-type]


def test_profile_identity_rejects_manual_mode_tampering() -> None:
    manifest, run, executor, configuration = inputs(True)
    manifest["selected_profile"]["windows_interactive"] = False
    with pytest.raises(WindowsAdaptationError, match="profile snapshot mismatch"):
        WindowsAdapter._identity(manifest, run, "a" * 64, executor, configuration)  # type: ignore[arg-type]


def test_capabilities_keep_distinct_file_names_and_paths(tmp_path) -> None:  # type: ignore[no-untyped-def]
    native = tmp_path / "native"
    behavior = native / "behavior"
    behavior.mkdir(parents=True)
    events = [
        {
            "data_type": "file_access",
            "object_name": "Login Data",
            "object_path": r"C:\Users\Analyst\Edge\Login Data",
            "access_operation": "FILE_READ_DATA",
            "process_path": r"C:\Temp\sample.exe",
        },
        {
            "data_type": "file_access",
            "object_name": "Cookies",
            "object_path": r"C:\Users\Analyst\Edge\Cookies",
            "access_operation": "FILE_READ_DATA",
            "process_path": r"C:\Temp\sample.exe",
        },
        {
            "data_type": "file_access",
            "object_name": "Cookies",
            "object_path": r"C:\Users\Analyst\Edge\Cookies",
            "access_operation": "FILE_READ_DATA",
            "process_path": r"C:\Temp\sample.exe",
        },
    ]
    (behavior / "access_events.json").write_text(json.dumps(events))
    db = SimpleNamespace(items=[], add=lambda item: db.items.append(item))
    WindowsAdapter._capabilities(db, UUID(int=1), RUN_ID, native)  # type: ignore[arg-type]
    assert [event["object_name"] for event in db.items[0].details["events"]] == [
        "Login Data",
        "Cookies",
        "Cookies",
    ]
