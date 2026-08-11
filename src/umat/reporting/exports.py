from __future__ import annotations

import csv
import hashlib
import io
import os
import tempfile
from pathlib import Path
from typing import Any
from uuid import UUID

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from umat.contracts.canonical import canonical_json
from umat.db.models import (
    AccessTier,
    AnalysisStage,
    Artifact,
    CaseReportSnapshot,
    ExportFormat,
    ReportExport,
    StageType,
)
from umat.reporting.aggregator import filter_report_for_roles
from umat.storage.local import LocalArtifactStore, StoredObject

FORMAT_VERSION = "1.0"


def _csv_safe(value: object) -> str:
    text = str(value if value is not None else "")
    return f"'{text}" if text.startswith(("=", "+", "-", "@")) else text


class ReportExporter:
    def __init__(self, artifact_store: LocalArtifactStore) -> None:
        self.artifact_store = artifact_store

    async def create(
        self,
        db: AsyncSession,
        snapshot: CaseReportSnapshot,
        export_format: ExportFormat,
        requested_by_user_id: UUID,
        roles: frozenset[str],
    ) -> ReportExport:
        if export_format == ExportFormat.JSON:
            content = canonical_json(filter_report_for_roles(snapshot.report_json, roles)) + b"\n"
            media_type, kind = "application/json", "report"
        elif export_format == ExportFormat.CSV:
            content = self._csv(snapshot.report_json)
            media_type, kind = "text/csv", "ioc_export"
        else:
            content = self._pdf(snapshot.report_json)
            media_type, kind = "application/pdf", "report"

        digest = hashlib.sha256(content).hexdigest()
        stored = self._store(content, digest)
        report_stage = await db.scalar(
            select(AnalysisStage).where(
                AnalysisStage.analysis_run_id == snapshot.analysis_run_id,
                AnalysisStage.stage_type == StageType.REPORT_GENERATION,
            )
        )
        artifact = Artifact(
            analysis_run_id=snapshot.analysis_run_id,
            stage_id=report_stage.id if report_stage else None,
            attempt_id=None,
            kind=kind,
            sha256=digest,
            size_bytes=len(content),
            media_type=media_type,
            object_key=stored.object_key,
            access_tier=AccessTier.OFFICER,
        )
        db.add(artifact)
        await db.flush()
        export = ReportExport(
            case_id=snapshot.case_id,
            analysis_run_id=snapshot.analysis_run_id,
            report_snapshot_id=snapshot.id,
            artifact_id=artifact.id,
            export_format=export_format,
            format_version=FORMAT_VERSION,
            sha256=digest,
            size_bytes=len(content),
            requested_by_user_id=requested_by_user_id,
        )
        db.add(export)
        await db.flush()
        return export

    def _store(self, content: bytes, digest: str) -> StoredObject:
        descriptor, raw_path = tempfile.mkstemp(
            prefix="report-", suffix=".part", dir=self.artifact_store.quarantine_root
        )
        path = Path(raw_path)
        try:
            with os.fdopen(descriptor, "wb") as destination:
                destination.write(content)
                destination.flush()
                os.fsync(destination.fileno())
            return self.artifact_store.store_file(path, digest, len(content))
        finally:
            path.unlink(missing_ok=True)

    @staticmethod
    def _csv(report: dict[str, Any]) -> bytes:
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["record_type", "type", "value", "confidence", "source", "summary"])
        technical = report.get("technical") or {}
        for item in technical.get("iocs", []):
            writer.writerow(
                [
                    "ioc",
                    _csv_safe(item.get("type")),
                    _csv_safe(item.get("value")),
                    _csv_safe(item.get("confidence")),
                    _csv_safe(item.get("source")),
                    "",
                ]
            )
        for item in technical.get("findings", []):
            writer.writerow(
                [
                    "finding",
                    _csv_safe(item.get("kind")),
                    "",
                    _csv_safe(item.get("confidence")),
                    _csv_safe(item.get("source")),
                    _csv_safe(item.get("summary")),
                ]
            )
        return output.getvalue().encode("utf-8")

    @staticmethod
    def _pdf(report: dict[str, Any]) -> bytes:
        output = io.BytesIO()
        document = canvas.Canvas(output, pagesize=A4, pageCompression=1)
        width, height = A4
        y = height - 52

        def line(text: object, *, size: int = 10, gap: int = 15) -> None:
            nonlocal y
            safe = str(text).encode("latin-1", "replace").decode("latin-1")
            words = safe.split()
            rows: list[str] = []
            current = ""
            for word in words:
                candidate = f"{current} {word}".strip()
                if document.stringWidth(candidate, "Helvetica", size) > width - 88 and current:
                    rows.append(current)
                    current = word
                else:
                    current = candidate
            rows.append(current)
            for row in rows:
                if y < 48:
                    document.showPage()
                    y = height - 52
                document.setFont("Helvetica", size)
                document.drawString(44, y, row)
                y -= gap

        document.setTitle("UMAT Officer Report")
        line("UMAT ANALYSIS REPORT", size=18, gap=26)
        line(
            f"Verdict: {str(report.get('verdict', 'inconclusive')).replace('_', ' ').upper()}",
            size=13,
            gap=22,
        )
        line(report.get("headline", ""), size=11, gap=20)
        line(f"Platform: {report.get('platform', 'unknown')}")
        line(f"Sample SHA-256: {report.get('sample_sha256', '')}")
        line(f"Generated: {report.get('generated_at', '')}", gap=22)
        line("INFORMATION ACCESSED", size=12, gap=19)
        capabilities = report.get("information_accessed", [])
        if not capabilities:
            line("No host data access was established by the available evidence.")
        for item in capabilities:
            line(f"- {item.get('summary', item.get('data_type', ''))}")
        y -= 7
        line("DESTINATIONS", size=12, gap=19)
        destinations = report.get("destinations", [])
        if not destinations:
            line("No reportable network destination was observed.")
        for item in destinations:
            line(
                f"- {item.get('value', '')}:{item.get('port') or '-'} ({item.get('protocol') or 'unknown'})"
            )
        y -= 7
        line("ANALYSIS LIMITATIONS", size=12, gap=19)
        caveats = report.get("caveats", [])
        if not caveats:
            line("No material analysis limitation was recorded.")
        for caveat in caveats:
            line(f"- {str(caveat).replace('_', ' ')}")
        line(
            "This report does not label a sample safe solely because no behavior was observed.",
            gap=18,
        )
        document.save()
        return output.getvalue()
