from __future__ import annotations

import csv
import hashlib
import io
import os
import tempfile
from pathlib import Path
from typing import Any
from uuid import UUID

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from umat.contracts.canonical import canonical_json
from umat.contracts.validator import ContractError, load_schema
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

FORMAT_VERSION = "2.0"

# A forensic report is read by people who were not present at the analysis and
# may be read years later in a proceeding. It therefore has to state its own
# scope, the conditions under which the evidence was produced, what it did not
# see, and how a reader can prove the document has not been altered. The prior
# one-page version stated a verdict and two flat lists, which is a summary, not
# evidence.
REPORT_TITLE = "MALWARE ANALYSIS REPORT"
ISSUING_AUTHORITY = "E-Rakshak · Unified Malware Analysis & Triage (UMAT)"
HANDLING = "OFFICIAL — FOR AUTHORISED RECIPIENTS"

# Rows shown inline before the reader is directed to the machine-readable
# export. A printed report is a summary of record, not a substitute for it, and
# a 1,450-row timeline in a PDF helps nobody.
_MAX_ROWS = 40

_VERDICT_TEXT = {
    "malicious": "MALICIOUS",
    "suspicious": "SUSPICIOUS",
    "no_malicious_activity_observed": "NO MALICIOUS ACTIVITY OBSERVED",
    "inconclusive": "INCONCLUSIVE",
    "failed": "ANALYSIS FAILED",
}
_VERDICT_COLOUR = {
    "malicious": colors.HexColor("#8B1A1A"),
    "suspicious": colors.HexColor("#8A5A00"),
    "no_malicious_activity_observed": colors.HexColor("#14532D"),
    "inconclusive": colors.HexColor("#3F3F46"),
    "failed": colors.HexColor("#3F3F46"),
}

# The interpretation rules the analysis actually applies. Stating them in the
# document means a reader can judge the findings by the same standard the tool
# used, rather than assuming a stricter or looser one.
_METHODOLOGY = [
    "A behavioural signal on its own is recorded as a candidate, never as a "
    "verdict. A destination or capability reaches 'confirmed' only when an "
    "independent source agrees: threat intelligence, an indicator extracted "
    "from the file itself, or a host action correlated in time.",
    "Confidence is reported on five levels: allowlisted, unconfirmed, weak, "
    "strong and confirmed. 'Allowlisted' means the destination was judged "
    "benign and is shown for completeness; it is not an indicator of "
    "compromise.",
    "Absence of evidence is not evidence of absence. Where the analysis "
    "environment limited what could be seen, the limitation is recorded in "
    "the Analysis Limitations section and the affected findings are capped.",
    "No sample is described as safe solely because no behaviour was observed.",
]


def _caveat_descriptions() -> dict[str, str]:
    """Plain-language explanations of each caveat code.

    Printing bare codes such as 'host_telemetry_degraded' tells a
    non-specialist reader nothing, and a limitation nobody understands is a
    limitation nobody applies. The vocabulary already carries officer-facing
    text; this reuses it rather than restating it in a second place.
    """
    try:
        document = load_schema("vocabularies/caveats.json")
    except (ContractError, OSError, ValueError):
        return {}
    descriptions = document.get("descriptions")
    return descriptions if isinstance(descriptions, dict) else {}


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
        # Every export is filtered to the requesting roles, not only JSON.
        #
        # CSV and PDF previously serialised the raw snapshot. filter_report_for_roles
        # removes the whole `technical` block for non-analysts and drops
        # analyst-tier artefacts, so an officer exporting CSV received the
        # technical findings and IOC tables their console deliberately withholds.
        # The old PDF happened to print only officer-tier sections, which
        # concealed the gap; the current one includes findings, indicators and
        # the artefact inventory, so the same leak would now be plainly visible
        # in a document intended for distribution.
        visible = filter_report_for_roles(snapshot.report_json, roles)
        if export_format == ExportFormat.JSON:
            content = canonical_json(visible) + b"\n"
            media_type, kind = "application/json", "report"
        elif export_format == ExportFormat.CSV:
            content = self._csv(visible)
            media_type, kind = "text/csv", "ioc_export"
        else:
            content = self._pdf(visible)
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
        """Flat export of the same record the PDF summarises.

        The first column has always been `record_type`, but only two types were
        ever written, so an analyst exporting CSV lost the destinations, the
        items accessed, the limitations and the artefact digests — everything a
        spreadsheet is actually convenient for. The remaining types are filled
        in here rather than adding a second export format.

        Row order is deliberate: sample, then what was taken, where it went,
        what was concluded, what limited the analysis, and finally the evidence
        digests. A reader scrolling top to bottom follows the same argument as
        the PDF.
        """
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["record_type", "type", "value", "confidence", "source", "summary"])
        technical = report.get("technical") or {}

        writer.writerow([
            "sample", "sha256", _csv_safe(report.get("sample_sha256")), "",
            _csv_safe(report.get("platform")), _csv_safe(report.get("headline")),
        ])
        writer.writerow([
            "verdict", _csv_safe(report.get("verdict")), "", "",
            _csv_safe(report.get("network_mode")),
            f"analysis run {_csv_safe(report.get('analysis_run_id'))}"
            f" generated {_csv_safe(report.get('generated_at'))}",
        ])
        for item in report.get("information_accessed") or []:
            objects = [o for o in (item.get("observed_objects") or []) if isinstance(o, dict)]
            if not objects:
                writer.writerow([
                    "information_accessed", _csv_safe(item.get("data_type")), "",
                    _csv_safe(item.get("confidence")),
                    _csv_safe(item.get("evidence_level")), _csv_safe(item.get("summary")),
                ])
                continue
            for entry in objects:
                writer.writerow([
                    "information_accessed", _csv_safe(item.get("data_type")),
                    _csv_safe(entry.get("path") or entry.get("name")),
                    _csv_safe(item.get("confidence")),
                    _csv_safe(entry.get("process") or item.get("evidence_level")),
                    _csv_safe(entry.get("operation")),
                ])
        for item in report.get("destinations") or []:
            owner = " ".join(
                str(value) for value in (item.get("geo_country"), item.get("asn_org")) if value
            )
            writer.writerow([
                "destination", _csv_safe(item.get("protocol")),
                _csv_safe(f"{item.get('value') or ''}:{item.get('port') or ''}".rstrip(":")),
                "known_bad" if item.get("known_bad") else "",
                _csv_safe(owner),
                _csv_safe(item.get("reputation_note")),
            ])
        for item in report.get("provenance") or []:
            writer.writerow([
                "provenance", _csv_safe(item.get("item_type")),
                _csv_safe(item.get("destination")), _csv_safe(item.get("confidence_tier")),
                "", _csv_safe(item.get("statement")),
            ])
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
        descriptions = _caveat_descriptions()
        for code in report.get("caveats") or []:
            writer.writerow([
                "limitation", _csv_safe(code), "", "", "",
                _csv_safe(descriptions.get(str(code), "")),
            ])
        integrity = report.get("integrity") or {}
        for index, digest in enumerate(integrity.get("bundle_hashes") or [], start=1):
            writer.writerow([
                "evidence_bundle", "sha256", _csv_safe(digest), "", "",
                f"evidence bundle {index}",
            ])
        for item in report.get("artifacts") or []:
            writer.writerow([
                "artifact", _csv_safe(item.get("kind")), _csv_safe(item.get("sha256")),
                "", _csv_safe(item.get("access_tier")),
                f"{_csv_safe(item.get('size_bytes'))} bytes",
            ])
        return output.getvalue().encode("utf-8")

    # ---- PDF: the document of record -------------------------------------
    #
    # Structured so a reader who was not present can establish, in order: what
    # this document is, what it examined, what was concluded, under what
    # conditions, what the evidence was, what could not be seen, and how to
    # prove the document is intact.

    @staticmethod
    def _styles() -> dict[str, ParagraphStyle]:
        base = getSampleStyleSheet()
        body = ParagraphStyle(
            "UmatBody", parent=base["BodyText"], fontName="Helvetica", fontSize=9,
            leading=12.5, alignment=TA_LEFT, spaceAfter=4,
        )
        return {
            "title": ParagraphStyle(
                "UmatTitle", parent=body, fontName="Helvetica-Bold", fontSize=19,
                leading=23, spaceAfter=2,
            ),
            "subtitle": ParagraphStyle(
                "UmatSubtitle", parent=body, fontSize=9.5, textColor=colors.HexColor("#52525B"),
                spaceAfter=10,
            ),
            "section": ParagraphStyle(
                "UmatSection", parent=body, fontName="Helvetica-Bold", fontSize=11.5,
                leading=15, spaceBefore=13, spaceAfter=5,
                textColor=colors.HexColor("#111827"),
            ),
            "body": body,
            "small": ParagraphStyle(
                "UmatSmall", parent=body, fontSize=7.8, leading=10.4,
                textColor=colors.HexColor("#3F3F46"),
            ),
            "cell": ParagraphStyle("UmatCell", parent=body, fontSize=7.8, leading=10, spaceAfter=0),
            # Sub-headings inside a section. A dedicated style rather than inline
            # <b> markup: para() escapes its input so that a filename or process
            # name containing angle brackets cannot inject formatting, which
            # means markup passed through it is printed literally.
            "label": ParagraphStyle(
                "UmatLabel", parent=body, fontName="Helvetica-Bold", fontSize=9,
                leading=12, spaceBefore=4, spaceAfter=3,
            ),
            "mono": ParagraphStyle(
                "UmatMono", parent=body, fontName="Courier", fontSize=7.6, leading=10,
                spaceAfter=0,
            ),
        }

    @staticmethod
    def _table(rows: list[list[Any]], widths: list[float], *, header: bool = True) -> Table:
        table = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
        style = [
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D4D4D8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        if header:
            style += [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E4E4E7")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 7.8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#FAFAFA")]),
            ]
        table.setStyle(TableStyle(style))
        return table

    @classmethod
    def _pdf(cls, report: dict[str, Any]) -> bytes:
        styles = cls._styles()
        cell, mono, body = styles["cell"], styles["mono"], styles["body"]

        def para(value: object, style: ParagraphStyle = cell) -> Paragraph:
            text = "" if value is None else str(value)
            escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            return Paragraph(escaped or "&mdash;", style)

        def humanise(value: object) -> str:
            return str(value or "").replace("_", " ").strip() or "—"

        run_id = str(report.get("analysis_run_id") or "—")
        sample = str(report.get("sample_sha256") or "—")
        verdict_key = str(report.get("verdict") or "inconclusive")
        generated = str(report.get("generated_at") or "")

        output = io.BytesIO()

        def decorate(canvas_obj: Any, doc: Any) -> None:
            canvas_obj.saveState()
            canvas_obj.setFont("Helvetica-Bold", 6.6)
            canvas_obj.setFillColor(colors.HexColor("#8B1A1A"))
            canvas_obj.drawString(18 * mm, A4[1] - 11 * mm, HANDLING)
            canvas_obj.setFont("Helvetica", 6.6)
            canvas_obj.setFillColor(colors.HexColor("#52525B"))
            canvas_obj.drawRightString(
                A4[0] - 18 * mm, A4[1] - 11 * mm, f"Analysis run {run_id}"
            )
            canvas_obj.setLineWidth(0.4)
            canvas_obj.setStrokeColor(colors.HexColor("#D4D4D8"))
            canvas_obj.line(18 * mm, A4[1] - 13 * mm, A4[0] - 18 * mm, A4[1] - 13 * mm)
            canvas_obj.line(18 * mm, 14 * mm, A4[0] - 18 * mm, 14 * mm)
            canvas_obj.setFont("Courier", 6.2)
            canvas_obj.drawString(18 * mm, 10.5 * mm, f"Sample SHA-256 {sample}")
            canvas_obj.setFont("Helvetica", 6.6)
            canvas_obj.drawRightString(A4[0] - 18 * mm, 10.5 * mm, f"Page {doc.page}")
            canvas_obj.restoreState()

        document = BaseDocTemplate(
            output, pagesize=A4, title="UMAT Malware Analysis Report",
            author=ISSUING_AUTHORITY, subject=f"Analysis run {run_id}",
            leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
            pageCompression=1,
        )
        frame = Frame(
            document.leftMargin, document.bottomMargin,
            document.width, document.height - 4 * mm, id="body",
        )
        document.addPageTemplates([PageTemplate(id="std", frames=[frame], onPage=decorate)])

        flow: list[Any] = []
        width = document.width

        # -- masthead ------------------------------------------------------
        flow.append(Paragraph(REPORT_TITLE, styles["title"]))
        flow.append(Paragraph(ISSUING_AUTHORITY, styles["subtitle"]))
        verdict_box = cls._table(
            [[Paragraph(
                f"<b>VERDICT: {_VERDICT_TEXT.get(verdict_key, verdict_key.upper())}</b>",
                ParagraphStyle("v", parent=body, fontSize=13, leading=17,
                               textColor=colors.white),
            )]],
            [width], header=False,
        )
        verdict_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1),
             _VERDICT_COLOUR.get(verdict_key, colors.HexColor("#3F3F46"))),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0, colors.white),
        ]))
        flow.append(verdict_box)
        flow.append(Spacer(1, 7))
        if report.get("headline"):
            flow.append(para(report["headline"], body))

        # -- 1. identification --------------------------------------------
        flow.append(Paragraph("1. Report and sample identification", styles["section"]))
        profile = report.get("tested_profile") or {}
        identification = [
            ["Field", "Value"],
            [para("Analysis run"), para(run_id, mono)],
            [para("Sample SHA-256"), para(sample, mono)],
            [para("Platform"), para(humanise(report.get("platform")))],
            [para("Report generated"), para(generated, mono)],
            [para("Report format version"), para(FORMAT_VERSION)],
            [para("Report schema version"), para(report.get("schema_version"))],
        ]
        flow.append(cls._table(identification, [width * 0.28, width * 0.72]))

        # -- 2. conditions -------------------------------------------------
        flow.append(Paragraph("2. Conditions of analysis", styles["section"]))
        flow.append(para(
            "Findings can only be interpreted against the conditions that produced "
            "them. The environment below determines what could and could not have "
            "been observed.", body))
        technical_block = report.get("technical") or {}
        tools = technical_block.get("tool_versions") or {}
        conditions = [
            ["Field", "Value"],
            [para("Network mode"),
             para(humanise(report.get("network_mode") or profile.get("network_mode")))],
            [para("C2/exfiltration analysis"),
             para("Enabled" if report.get("c2_analysis_enabled")
                  or profile.get("c2_analysis_enabled") else "Not enabled")],
        ]
        if profile.get("name") or profile.get("windows_version"):
            conditions.append([para("Guest profile"), para(
                " · ".join(str(v) for v in (profile.get("name"),
                                            profile.get("windows_version")) if v))])
        # tool_versions is a list of adapter records, not a name/version mapping.
        # Both shapes are accepted so a change on the producing side degrades to
        # a thinner row rather than failing the whole document.
        if isinstance(tools, dict):
            for name, version in sorted(tools.items())[:12]:
                conditions.append([para(f"Component · {humanise(name)}"), para(version, mono)])
        elif isinstance(tools, list):
            for record in tools[:12]:
                if not isinstance(record, dict):
                    continue
                conditions.append([
                    para(f"Analysis component · {humanise(record.get('adapter'))}"),
                    para(f"contract schema {record.get('schema_version') or '—'}", mono),
                ])
        attribution = [a for a in (technical_block.get("attribution") or [])
                       if isinstance(a, dict) and a.get("family")]
        for record in attribution[:5]:
            conditions.append([
                para("Family attribution"),
                para(f"{record.get('family')} "
                     f"({humanise(record.get('confidence'))}, "
                     f"basis: {humanise(record.get('basis'))})"),
            ])
        flow.append(cls._table(conditions, [width * 0.28, width * 0.72]))

        # -- 3. information accessed ---------------------------------------
        flow.append(Paragraph("3. Information accessed on the system", styles["section"]))
        accessed = report.get("information_accessed") or []
        if not accessed:
            flow.append(para(
                "No access to user or system information was established by the "
                "available evidence.", body))
        else:
            rows: list[list[Any]] = [["Type of information", "Evidence", "Confidence", "Items"]]
            for item in accessed:
                objects = [o for o in (item.get("observed_objects") or [])
                           if isinstance(o, dict) and (o.get("path") or o.get("name"))]
                rows.append([
                    para(humanise(item.get("data_type"))),
                    para(humanise(item.get("evidence_level"))),
                    para(humanise(item.get("confidence"))),
                    para(str(len(objects)) if objects else "—"),
                ])
            flow.append(cls._table(
                rows, [width * 0.34, width * 0.20, width * 0.20, width * 0.26]))
            for item in accessed:
                objects = [o for o in (item.get("observed_objects") or [])
                           if isinstance(o, dict) and (o.get("path") or o.get("name"))]
                if not objects:
                    continue
                flow.append(Spacer(1, 5))
                flow.append(para(
                    f"{humanise(item.get('data_type'))} — items accessed "
                    f"({len(objects)})", styles["label"]))
                detail: list[list[Any]] = [["Item", "Location", "Action", "Process"]]
                for entry in objects[:_MAX_ROWS]:
                    detail.append([
                        para(entry.get("name")
                             or str(entry.get("path") or "").replace("\\", "/").split("/")[-1]),
                        para(entry.get("path"), mono),
                        para(humanise(entry.get("operation"))),
                        para(entry.get("process")),
                    ])
                flow.append(cls._table(
                    detail, [width * 0.22, width * 0.44, width * 0.16, width * 0.18]))
                if len(objects) > _MAX_ROWS:
                    flow.append(para(
                        f"{len(objects) - _MAX_ROWS} further items are recorded in the "
                        f"machine-readable export.", styles["small"]))

        # -- 4. destinations -----------------------------------------------
        flow.append(Paragraph("4. Network destinations contacted", styles["section"]))
        destinations = report.get("destinations") or []
        if not destinations:
            flow.append(para("No network destination was observed.", body))
        else:
            rows = [["Destination", "Port", "Protocol", "Location / network owner",
                     "Assessment"]]
            for item in destinations[:_MAX_ROWS]:
                owner = " · ".join(str(v) for v in (item.get("geo_country"),
                                                    item.get("asn_org")) if v)
                if item.get("known_bad"):
                    assessment = "Known malicious"
                elif item.get("reputation_note"):
                    assessment = str(item["reputation_note"])
                else:
                    assessment = "No independent malicious reputation recorded"
                rows.append([
                    para(item.get("value") or item.get("domain") or item.get("ip"), mono),
                    para(item.get("port")),
                    para(humanise(item.get("protocol"))),
                    para(owner),
                    para(assessment),
                ])
            flow.append(cls._table(
                rows, [width * 0.28, width * 0.07, width * 0.11, width * 0.24, width * 0.30]))
            if len(destinations) > _MAX_ROWS:
                flow.append(para(
                    f"{len(destinations) - _MAX_ROWS} further destinations are recorded "
                    f"in the machine-readable export.", styles["small"]))

        # -- 5. attribution of items to destinations ------------------------
        flow.append(Paragraph(
            "5. Items linked to destinations", styles["section"]))
        provenance = report.get("provenance") or []
        if not provenance:
            flow.append(para(
                "No specific item could be linked to a specific destination. This "
                "requires host activity and network traffic to be matched on a shared "
                "clock; see Analysis Limitations.", body))
        else:
            rows = [["Statement", "Item", "Destination"]]
            for item in provenance[:_MAX_ROWS]:
                rows.append([
                    para(item.get("statement")),
                    para(humanise(item.get("item_type"))),
                    para(item.get("destination"), mono),
                ])
            flow.append(cls._table(rows, [width * 0.56, width * 0.16, width * 0.28]))

        # -- 6. findings ----------------------------------------------------
        # `technical` is absent entirely when the reader is not an analyst.
        # "No findings were recorded" would then be a false statement in a
        # document intended as evidence: findings exist, this reader is simply
        # not cleared for them. The two cases must read differently.
        technical = report.get("technical")
        technical_withheld = technical is None
        technical = technical or {}
        findings = technical.get("findings") or []
        flow.append(Paragraph(
            f"6. Detailed findings ({len(findings)})" if not technical_withheld
            else "6. Detailed findings", styles["section"]))
        if technical_withheld:
            flow.append(para(
                "Detailed technical findings are recorded for this analysis but are "
                "released to analyst and administrator roles only. Request an "
                "analyst-tier export to obtain them.", body))
        elif not findings:
            flow.append(para("No findings were recorded.", body))
        else:
            order = {"confirmed": 0, "strong": 1, "weak": 2, "unconfirmed": 3, "allowlisted": 4}
            ranked = sorted(findings, key=lambda f: order.get(str(f.get("confidence")), 5))
            rows = [["Finding", "Source", "Confidence", "Evidence", "Security mappings"]]
            for item in ranked[:_MAX_ROWS]:
                mappings = item.get("security_mappings") or item.get("mitre_technique_ids") or []
                rows.append([
                    para(item.get("summary") or humanise(item.get("kind"))),
                    para(humanise(item.get("source"))),
                    para(humanise(item.get("confidence"))),
                    para(humanise(item.get("evidence_level"))),
                    para(", ".join(str(m) for m in mappings)),
                ])
            flow.append(cls._table(
                rows, [width * 0.42, width * 0.11, width * 0.13, width * 0.13, width * 0.21]))
            if len(findings) > _MAX_ROWS:
                flow.append(para(
                    f"{len(findings) - _MAX_ROWS} further findings, ordered by "
                    f"confidence, are recorded in the machine-readable export.",
                    styles["small"]))

        # -- 7. indicators of compromise -------------------------------------
        iocs = technical.get("iocs") or []
        flow.append(Paragraph(
            f"7. Indicators of compromise ({len(iocs)})" if not technical_withheld
            else "7. Indicators of compromise", styles["section"]))
        if technical_withheld:
            flow.append(para(
                "Indicators of compromise are released to analyst and administrator "
                "roles only.", body))
        else:
            flow.append(para(
                "Indicators are provided for detection and intelligence sharing. Entries "
                "assessed as allowlisted are excluded: a destination judged benign is not "
                "an indicator of compromise.", body))
        if not iocs and not technical_withheld:
            flow.append(para("No indicators of compromise were extracted.", body))
        else:
            rows = [["Type", "Value", "Confidence", "Source", "Observed"]]
            for item in iocs[:_MAX_ROWS]:
                rows.append([
                    para(humanise(item.get("type"))),
                    para(item.get("value"), mono),
                    para(humanise(item.get("confidence"))),
                    para(humanise(item.get("source"))),
                    para("On the network" if item.get("seen_in_traffic") else "In the file only"),
                ])
            flow.append(cls._table(
                rows, [width * 0.11, width * 0.40, width * 0.14, width * 0.16, width * 0.19]))

        # -- 8. limitations ---------------------------------------------------
        flow.append(Paragraph("8. Analysis limitations", styles["section"]))
        caveats = report.get("caveats") or []
        descriptions = _caveat_descriptions()
        if not caveats:
            flow.append(para("No material analysis limitation was recorded.", body))
        else:
            rows = [["Limitation", "What this means for the findings"]]
            for code in caveats:
                rows.append([
                    para(humanise(code)),
                    para(descriptions.get(str(code))
                         or "No further explanation is recorded for this limitation."),
                ])
            flow.append(cls._table(rows, [width * 0.28, width * 0.72]))

        # -- 9. evidence integrity --------------------------------------------
        flow.append(PageBreak())
        flow.append(Paragraph("9. Evidence integrity and verification", styles["section"]))
        integrity = report.get("integrity") or {}
        artifacts = report.get("artifacts") or []
        flow.append(para(
            "Every item below is identified by its SHA-256 digest. Recomputing the "
            "digest of a retained item and comparing it with the value printed here "
            "establishes whether that item has changed since the analysis. The digest "
            "of this document is recorded against the case record on issue; a copy "
            "whose digest differs is not this document.", body))
        summary_rows = [
            ["Field", "Value"],
            [para("Sample SHA-256"), para(sample, mono)],
            [para("Evidence bundles validated"),
             para(integrity.get("validated_bundle_count"))],
            [para("Artefacts registered"), para(integrity.get("registered_artifact_count"))],
        ]
        for index, digest in enumerate(integrity.get("bundle_hashes") or [], start=1):
            summary_rows.append([para(f"Evidence bundle {index} SHA-256"), para(digest, mono)])
        flow.append(cls._table(summary_rows, [width * 0.28, width * 0.72]))
        if artifacts:
            flow.append(Spacer(1, 6))
            flow.append(para("Retained artefacts", styles["label"]))
            rows = [["Artefact", "SHA-256", "Size (bytes)", "Access tier"]]
            for item in artifacts[:_MAX_ROWS]:
                rows.append([
                    para(humanise(item.get("kind"))),
                    para(item.get("sha256"), mono),
                    para(item.get("size_bytes")),
                    para(humanise(item.get("access_tier"))),
                ])
            flow.append(cls._table(
                rows, [width * 0.20, width * 0.48, width * 0.16, width * 0.16]))

        # -- 10. methodology ---------------------------------------------------
        flow.append(Paragraph("10. Basis of assessment", styles["section"]))
        for statement in _METHODOLOGY:
            flow.append(para(f"• {statement}", body))

        # -- 11. attestation ----------------------------------------------------
        flow.append(Paragraph("11. Attestation", styles["section"]))
        flow.append(para(
            "This report was generated automatically by the UMAT analysis platform "
            "from the evidence identified in section 9. It records what was observed "
            "under the conditions stated in section 2 and the limitations in section "
            "8. It does not constitute an expert opinion; interpretation in a legal "
            "context remains a matter for a qualified examiner.", body))
        flow.append(Spacer(1, 16))
        signature = [
            [para("Reviewed by", body), para("Designation", body), para("Date", body)],
            [Spacer(1, 26), Spacer(1, 26), Spacer(1, 26)],
        ]
        flow.append(cls._table(signature, [width * 0.42, width * 0.32, width * 0.26]))

        document.build(flow)
        return output.getvalue()
