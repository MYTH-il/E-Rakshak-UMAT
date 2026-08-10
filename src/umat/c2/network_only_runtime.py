"""PCAP-only entry point for the locked C2 runtime.

This file is deliberately dependency-free from the UMAT application so it can be
executed by the isolated runtime virtual environment. It invokes the locked runtime's
network analysis without fabricating a Windows handoff or enabling host correlation.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--sample-sha256", required=True)
    parser.add_argument("--static-prior", type=Path)
    args = parser.parse_args()

    from orchestrator import (  # type: ignore[import-not-found]
        build_network_events,
        emit_schema_rows,
    )

    network_events = build_network_events(str(args.pcap), handoff=None)
    rows = emit_schema_rows(network_events, [], args.sample_sha256, handoff=None)
    output = Path.cwd() / "output"
    output.mkdir(mode=0o700)
    (output / "network_events.json").write_text(json.dumps(network_events, indent=2))
    (output / "exfil_events.json").write_text(json.dumps(rows, indent=2))
    for name in ("attribution.json", "provenance.json", "timeline.json"):
        (output / name).write_text("[]\n")
    notes = {
        "notes": [
            "Android PCAP-only execution: host correlation was disabled and no Windows handoff was supplied."
        ]
    }
    (output / "analysis_notes.json").write_text(json.dumps(notes, indent=2))
    with (output / "iocs.csv").open("w", newline="") as target:
        writer = csv.DictWriter(
            target,
            fieldnames=["destination_domain", "destination_ip", "confidence_tier"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "destination_domain": row.get("destination_domain"),
                    "destination_ip": row.get("destination_ip"),
                    "confidence_tier": row.get("confidence_tier"),
                }
            )


if __name__ == "__main__":
    main()
