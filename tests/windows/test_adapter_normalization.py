from __future__ import annotations

from typing import Any
from uuid import uuid4

from umat.db.models import WindowsFinding
from umat.windows.adapter import WindowsAdapter


class RecordingSession:
    def __init__(self) -> None:
        self.rows: list[Any] = []

    def add(self, value: Any) -> None:
        self.rows.append(value)


def test_windows_adapter_imports_cape_attack_mappings() -> None:
    session = RecordingSession()
    WindowsAdapter._findings(  # noqa: SLF001
        session,  # type: ignore[arg-type]
        uuid4(),
        uuid4(),
        {
            "ttps": [
                {
                    "signature": "application_layer_protocol",
                    "ttps": ["T1071.001", "T1059"],
                    "mbcs": ["B0030"],
                }
            ]
        },
        {},
    )
    mappings = [
        item
        for item in session.rows
        if isinstance(item, WindowsFinding) and item.category == "attack_mapping"
    ]
    assert len(mappings) == 1
    assert mappings[0].details["mitre_technique_ids"] == ["T1059", "T1071.001"]
    assert mappings[0].details["source"] == "cape-evidence.json"
