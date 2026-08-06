"""Turns a saved scan history record back into a downloadable report.

Markdown reuses scanner.py's own generate_markdown_report — reconstructing
Finding/ScanResult objects from the serialized dict gives byte-for-byte the
same report format the CLI's `--report` flag produces. The other formats are
built directly from the stored dict since there's no equivalent CLI output to
stay consistent with.

PDF/DOCX/XLSX depend on optional third-party libraries; each builder raises
ExportUnavailable when its library isn't installed so the UI can hide (or
explain) that format instead of returning a broken file.
"""
import csv
import datetime
import io
import json

from scanner import Finding, ScanResult, generate_markdown_report

CSV_FIELDS = [
    "severity", "category", "rule", "file", "line", "description",
    "impact", "improvement", "source", "ai_verdict", "ai_reason",
    "likely_test_fixture",
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class ExportUnavailable(RuntimeError):
    """Raised when a format's optional dependency isn't installed."""


def _is_dismissed(f: dict) -> bool:
    return f.get("ai_verdict") == "false_positive"


def _sorted_findings(record: dict, include_dismissed: bool = False) -> list:
    findings = record.get("findings", [])
    if not include_dismissed:
        findings = [f for f in findings if not _is_dismissed(f)]
    return sorted(findings, key=lambda f: (
        SEVERITY_ORDER.get((f.get("severity") or "").lower(), 9),
        f.get("file") or "",
        f.get("line") or 0,
    ))


def _scanned_at(record: dict) -> str:
    return datetime.datetime.fromtimestamp(
        record.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")


def _findings_to_dataclasses(findings: list) -> list:
    out = []
    for f in findings:
        out.append(Finding(
            rule=f.get("rule", ""),
            severity=f.get("severity", "low"),
            file=f.get("file", ""),
            line=f.get("line") or 0,
            display_line=f.get("evidence", ""),
            description=f.get("description", ""),
            source=f.get("source", "regex"),
            likely_test_fixture=bool(f.get("likely_test_fixture", False)),
            ai_verdict=f.get("ai_verdict"),
            ai_reason=f.get("ai_reason"),
            impact=f.get("impact", ""),
            improvement=f.get("improvement", ""),
        ))
    return out


def build_markdown(record: dict) -> str:
    result = ScanResult(
        findings=_findings_to_dataclasses(record.get("findings", [])),
        files_scanned=record.get("files_scanned", 0),
    )
    return generate_markdown_report(
        result,
        target=record.get("target", ""),
        used_ai=record.get("ai_used", False),
        risk_summary=record.get("ai_risk_summary"),
        recommendations=record.get("ai_recommendations"),
        ai_error=None,
        exit_code=record.get("exit_code") or 0,
        threshold=record.get("fail_on", "high"),
    )


def build_json(record: dict) -> str:
    return json.dumps(record, indent=2)


def build_csv(record: dict) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for f in record.get("findings", []):
        row = dict(f)
        row["category"] = f.get("category") or f.get("rule", "")
        writer.writerow(row)
    return buf.getvalue()


def build_sarif(record: dict) -> str:
    """SARIF 2.1.0 — the format GitHub code scanning, Azure DevOps and most
    security dashboards ingest, so findings can be uploaded rather than
    read by hand."""
    findings = _sorted_findings(record)
    rules = {}
    results = []
    sarif_level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}

    for f in findings:
        rule_id = f.get("rule") or "finding"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f.get("description") or rule_id},
                "fullDescription": {"text": f.get("impact") or f.get("description") or rule_id},
                "help": {"text": f.get("improvement") or ""},
                "properties": {
                    "category": f.get("category") or rule_id,
                    "security-severity": {
                        "critical": "9.5", "high": "7.5", "medium": "5.0", "low": "3.0"
                    }.get((f.get("severity") or "").lower(), "3.0"),
                },
            }
        results.append({
            "ruleId": rule_id,
            "level": sarif_level.get((f.get("severity") or "").lower(), "note"),
            "message": {"text": f.get("description") or rule_id},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(f.get("file") or "").replace("\\", "/")},
                    "region": {"startLine": max(1, int(f.get("line") or 1))},
                }
            }],
            "properties": {
                "severity": f.get("severity"),
                "source": f.get("source"),
                "ai_verdict": f.get("ai_verdict"),
                "ai_reason": f.get("ai_reason"),
            },
        })

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "security-scan",
                "informationUri": "https://github.com/",
                "rules": list(rules.values()),
            }},
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.datetime.fromtimestamp(
                    record.get("timestamp", 0),
                    tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }],
        }],
    }
    return json.dumps(doc, indent=2)


def build_xlsx(record: dict) -> bytes:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment
    except ImportError:
        raise ExportUnavailable("XLSX export needs the 'openpyxl' package (pip install openpyxl).")

    wb = Workbook()

    summary = wb.active
    summary.title = "Summary"
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in _sorted_findings(record):
        sev = (f.get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
    rows = [
        ("Target", record.get("target", "")),
        ("Scanned", _scanned_at(record)),
        ("Scan types", ", ".join(record.get("scan_types") or [])),
        ("Files scanned", record.get("files_scanned", 0)),
        ("AI verification", "on" if record.get("ai_used") else "off"),
        ("", ""),
        ("Critical", counts["critical"]),
        ("High", counts["high"]),
        ("Medium", counts["medium"]),
        ("Low", counts["low"]),
    ]
    for label, value in rows:
        summary.append([label, value])
    for cell in summary["A"]:
        cell.font = Font(bold=True)
    summary.column_dimensions["A"].width = 18
    summary.column_dimensions["B"].width = 70

    ws = wb.create_sheet("Findings")
    headers = ["Severity", "Category", "Rule", "File", "Line", "Description",
               "Impact", "Fix", "Source", "AI verdict", "AI reason"]
    ws.append(headers)
    header_fill = PatternFill("solid", start_color="1F2937")
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = header_fill

    sev_fill = {
        "critical": PatternFill("solid", start_color="FEE2E2"),
        "high": PatternFill("solid", start_color="FFEDD5"),
        "medium": PatternFill("solid", start_color="FEF3C7"),
        "low": PatternFill("solid", start_color="DBEAFE"),
    }
    for f in _sorted_findings(record, include_dismissed=True):
        ws.append([
            f.get("severity", ""), f.get("category") or f.get("rule", ""), f.get("rule", ""),
            f.get("file", ""), f.get("line") or "", f.get("description", ""),
            f.get("impact", ""), f.get("improvement", ""), f.get("source", ""),
            f.get("ai_verdict") or "", f.get("ai_reason") or "",
        ])
        fill = sev_fill.get((f.get("severity") or "").lower())
        if fill:
            ws.cell(row=ws.max_row, column=1).fill = fill

    for col, width in zip("ABCDEFGHIJK", (10, 22, 22, 46, 7, 46, 52, 52, 10, 15, 46)):
        ws.column_dimensions[col].width = width
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def build_docx(record: dict) -> bytes:
    try:
        from docx import Document
        from docx.shared import Pt, RGBColor
    except ImportError:
        raise ExportUnavailable("Word export needs the 'python-docx' package (pip install python-docx).")

    sev_color = {
        "critical": RGBColor(0xDC, 0x26, 0x26),
        "high": RGBColor(0xEA, 0x58, 0x0C),
        "medium": RGBColor(0xD9, 0x77, 0x06),
        "low": RGBColor(0x25, 0x63, 0xEB),
    }

    doc = Document()
    doc.add_heading("Security Scan Report", level=0)
    meta = doc.add_paragraph()
    meta.add_run("Target: ").bold = True
    meta.add_run(str(record.get("target", "")) + "\n")
    meta.add_run("Scanned: ").bold = True
    meta.add_run(_scanned_at(record) + "\n")
    meta.add_run("Scan types: ").bold = True
    meta.add_run(", ".join(record.get("scan_types") or []) + "\n")
    meta.add_run("Files scanned: ").bold = True
    meta.add_run(str(record.get("files_scanned", 0)) + "\n")
    meta.add_run("AI verification: ").bold = True
    meta.add_run("on" if record.get("ai_used") else "off")

    findings = _sorted_findings(record)
    counts = {}
    for f in findings:
        sev = (f.get("severity") or "").lower()
        counts[sev] = counts.get(sev, 0) + 1
    doc.add_heading("Summary", level=1)
    summary_line = ", ".join(
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if counts.get(s))
    doc.add_paragraph(summary_line or "No confirmed findings.")

    if record.get("ai_used") and record.get("ai_risk_summary"):
        doc.add_heading("AI risk summary", level=1)
        doc.add_paragraph(record["ai_risk_summary"])
        if record.get("ai_recommendations"):
            doc.add_heading("Recommended fixes", level=2)
            for rec in record["ai_recommendations"]:
                doc.add_paragraph(str(rec), style="List Bullet")

    doc.add_heading("Findings", level=1)
    if not findings:
        doc.add_paragraph("No confirmed findings.")
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        head = doc.add_paragraph()
        run = head.add_run("[" + sev.upper() + "] ")
        run.bold = True
        run.font.color.rgb = sev_color.get(sev, RGBColor(0, 0, 0))
        head.add_run(str(f.get("description") or f.get("rule") or "")).bold = True

        loc = doc.add_paragraph(
            str(f.get("file") or "") + (f":{f['line']}" if f.get("line") else ""))
        loc.runs[0].font.name = "Consolas"
        loc.runs[0].font.size = Pt(9)

        if f.get("evidence"):
            ev = doc.add_paragraph(str(f["evidence"]))
            ev.runs[0].font.name = "Consolas"
            ev.runs[0].font.size = Pt(9)
        for label, key in (("Impact", "impact"), ("Fix", "improvement"), ("AI note", "ai_reason")):
            if f.get(key):
                p = doc.add_paragraph()
                p.add_run(label + ": ").bold = True
                p.add_run(str(f[key]))

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def build_pdf(record: dict) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Preformatted, KeepTogether)
    except ImportError:
        raise ExportUnavailable("PDF export needs the 'reportlab' package (pip install reportlab).")

    from xml.sax.saxutils import escape

    sev_color = {
        "critical": colors.HexColor("#dc2626"),
        "high": colors.HexColor("#ea580c"),
        "medium": colors.HexColor("#d97706"),
        "low": colors.HexColor("#2563eb"),
    }

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
        title="security-scan report",
    )
    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9.5, leading=13)
    mono = ParagraphStyle("mono", parent=styles["Code"], fontSize=8, leading=11,
                           backColor=colors.HexColor("#f1f5f9"), borderPadding=4)
    story = []

    story.append(Paragraph("Security Scan Report", styles["Title"]))
    story.append(Paragraph(
        f"<b>Target:</b> {escape(str(record.get('target','')))}<br/>"
        f"<b>Scanned:</b> {_scanned_at(record)}<br/>"
        f"<b>Scan types:</b> {escape(', '.join(record.get('scan_types') or []))}<br/>"
        f"<b>Files scanned:</b> {record.get('files_scanned', 0)}<br/>"
        f"<b>AI verification:</b> {'on' if record.get('ai_used') else 'off'}", body))
    story.append(Spacer(1, 8))

    findings = _sorted_findings(record)
    counts = {}
    for f in findings:
        sev = (f.get("severity") or "").lower()
        counts[sev] = counts.get(sev, 0) + 1
    summary_line = ", ".join(
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if counts.get(s))
    story.append(Paragraph("<b>Summary:</b> " + escape(summary_line or "no confirmed findings"), body))
    story.append(Spacer(1, 10))

    if record.get("ai_used") and record.get("ai_risk_summary"):
        story.append(Paragraph("AI Risk Summary", styles["Heading2"]))
        story.append(Paragraph(escape(str(record["ai_risk_summary"])), body))
        if record.get("ai_recommendations"):
            story.append(Paragraph("Recommended fixes", styles["Heading3"]))
            for rec in record["ai_recommendations"]:
                story.append(Paragraph("• " + escape(str(rec)), body))
        story.append(Spacer(1, 10))

    story.append(Paragraph("Findings", styles["Heading2"]))
    if not findings:
        story.append(Paragraph("No confirmed findings.", body))

    for f in findings:
        sev = (f.get("severity") or "low").lower()
        block = [Paragraph(
            f'<font color="{sev_color.get(sev, colors.black).hexval()}"><b>[{escape(sev.upper())}]</b></font> '
            f'<b>{escape(str(f.get("description") or f.get("rule") or ""))}</b>', body)]
        loc = str(f.get("file") or "") + (f":{f['line']}" if f.get("line") else "")
        block.append(Paragraph(f'<font size="8" color="#64748b">{escape(loc)}</font>', body))
        if f.get("evidence"):
            # Preformatted takes a plain string and escapes it itself — the
            # evidence line is verbatim scanned content, so it must never be
            # interpolated into reportlab's mini-HTML markup.
            block.append(Preformatted(str(f["evidence"])[:400], mono))
        for label, key in (("Impact", "impact"), ("Fix", "improvement"), ("AI note", "ai_reason")):
            if f.get(key):
                block.append(Paragraph(f"<b>{label}:</b> " + escape(str(f[key])), body))
        block.append(Spacer(1, 9))
        story.append(KeepTogether(block))

    doc.build(story)
    return buf.getvalue()
