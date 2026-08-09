"""
Test suite for web/reports.py — report_model() and the PDF/DOCX/HTML/CSV/
SARIF export builders.

Covers:
  - report_model() derives correct scope/severity/category/file/dismissed
    tables from a raw scan record, matching scan_jobs.py's own dismissed-
    finding policy (AI verdict wins; otherwise test-fixture findings are
    set aside unless include_test_files is on)
  - PDF/DOCX/HTML builders don't crash on a normal record, an empty-findings
    record, or a record with only dismissed findings (skipped if the
    optional reportlab/python-docx/jinja2 packages aren't installed —
    these formats are opt-in dependencies, see requirements.txt)
  - CSV/JSON/SARIF builders (no optional dependencies) produce valid,
    parseable output
"""

import csv
import io
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "web"))

import reports  # noqa: E402


def _record(findings, **overrides):
    base = {
        "id": "test", "timestamp": time.time(), "name": "", "target": "https://example.com",
        "scan_types": ["web"], "files_scanned": 3, "skipped_files": [], "exit_code": 0,
        "fail_on": "high", "include_test_files": False, "ai_used": False,
        "ai_risk_summary": None, "ai_recommendations": None, "findings": findings,
    }
    base.update(overrides)
    return base


CRITICAL_AI_CONFIRMED = {
    "category": "arbitrary-command-execution", "rule": "dangerous-call", "severity": "critical",
    "file": "server.py", "line": 10, "evidence": "os.system(cmd)", "description": "eval used",
    "impact": "RCE", "improvement": "don't", "source": "ai", "likely_test_fixture": False,
    "ai_verdict": "true_positive", "ai_reason": "confirmed",
}
HIGH_REGEX = {
    "category": "xss", "rule": "reflected-xss", "severity": "high",
    "file": "app.js", "line": 5, "evidence": "innerHTML = x", "description": "xss sink",
    "impact": "script injection", "improvement": "escape it", "source": "regex",
    "likely_test_fixture": False,
}
DISMISSED_AI_FALSE_POSITIVE = {
    "category": "hardcoded-secret", "rule": "hardcoded-secret", "severity": "critical",
    "file": "tests/fixture.py", "line": 3, "evidence": "AKIA...", "description": "aws key",
    "impact": "n/a", "improvement": "n/a", "source": "regex", "likely_test_fixture": True,
    "ai_verdict": "false_positive", "ai_reason": "test fixture data",
}
DISMISSED_GUESS = {
    "category": "hardcoded-secret", "rule": "hardcoded-secret", "severity": "medium",
    "file": "tests/fixture.py", "line": 8, "evidence": "pw = 'x'", "description": "password",
    "impact": "n/a", "improvement": "n/a", "source": "regex", "likely_test_fixture": True,
}
TRUE_POSITIVE_IN_TEST_FILE = {
    "category": "hardcoded-secret", "rule": "hardcoded-secret", "severity": "high",
    "file": "tests/fixture.py", "line": 12, "evidence": "real looking key", "description": "secret",
    "impact": "n/a", "improvement": "n/a", "source": "regex", "likely_test_fixture": True,
    "ai_verdict": "true_positive",
}


# --------------------------------------------------------------- report_model

def test_scope_counts_and_dismissal_policy():
    record = _record([CRITICAL_AI_CONFIRMED, HIGH_REGEX, DISMISSED_AI_FALSE_POSITIVE,
                       DISMISSED_GUESS, TRUE_POSITIVE_IN_TEST_FILE])
    model = reports.report_model(record)

    # true_positive always counts as a real finding, even inside a test file
    assert len(model["findings"]) == 3
    assert model["scope"]["dismissed"] == 2
    assert model["scope"]["raw_detections"] == 5
    assert model["sev_counts"]["critical"] == 1
    assert model["sev_counts"]["high"] == 2


def test_include_test_files_overrides_guess_dismissal():
    record = _record([DISMISSED_GUESS], include_test_files=True)
    model = reports.report_model(record)
    # no explicit AI verdict + include_test_files=True -> counted, not dismissed
    assert len(model["findings"]) == 1
    assert model["scope"]["dismissed"] == 0


def test_ai_false_positive_always_dismissed_even_with_include_test_files():
    record = _record([DISMISSED_AI_FALSE_POSITIVE], include_test_files=True)
    model = reports.report_model(record)
    assert len(model["findings"]) == 0
    assert model["scope"]["dismissed"] == 1


def test_severity_rows_share_sums_to_100_or_zero():
    record = _record([CRITICAL_AI_CONFIRMED, HIGH_REGEX])
    model = reports.report_model(record)
    total_share = sum(r["share"] for r in model["severity_rows"])
    assert total_share == 100
    assert model["severity_rows"][0]["severity"] == "critical"  # fixed order


def test_severity_rows_share_is_zero_when_no_findings():
    model = reports.report_model(_record([]))
    assert all(r["share"] == 0 for r in model["severity_rows"])
    assert model["verdict"].startswith("No confirmed findings")


def test_category_and_file_rows_sorted_by_worst_severity():
    low = dict(HIGH_REGEX, severity="low", category="info-leak", file="b.js")
    record = _record([CRITICAL_AI_CONFIRMED, low])
    model = reports.report_model(record)
    assert model["category_rows"][0]["worst"] == "critical"
    assert model["file_rows"][0]["worst"] == "critical"


def test_dismissed_groups_carry_reason_text():
    record = _record([DISMISSED_AI_FALSE_POSITIVE, DISMISSED_GUESS])
    model = reports.report_model(record)
    assert len(model["dismissed_groups"]) == 1  # both in tests/fixture.py
    reasons = {r["reason"] for r in model["dismissed_groups"][0]["rows"]}
    assert "test fixture data" in reasons
    assert "test/fixture path heuristic, unreviewed" in reasons


def test_start_here_is_worst_finding():
    record = _record([HIGH_REGEX, CRITICAL_AI_CONFIRMED])
    model = reports.report_model(record)
    assert model["start_here"]["severity"] == "critical"


def test_verdict_reflects_worst_severity():
    assert "Critical" in reports.report_model(_record([CRITICAL_AI_CONFIRMED]))["verdict"]
    assert "High" in reports.report_model(_record([HIGH_REGEX]))["verdict"]
    assert "No confirmed" in reports.report_model(_record([]))["verdict"]


# ---------------------------------------------------------------- CSV / JSON

def test_build_csv_round_trips():
    record = _record([CRITICAL_AI_CONFIRMED, HIGH_REGEX])
    rows = list(csv.DictReader(io.StringIO(reports.build_csv(record))))
    assert len(rows) == 2
    assert {r["severity"] for r in rows} == {"critical", "high"}


def test_build_json_is_valid_json():
    record = _record([CRITICAL_AI_CONFIRMED])
    data = json.loads(reports.build_json(record))
    assert data["target"] == "https://example.com"
    assert len(data["findings"]) == 1


def test_build_sarif_is_valid_and_excludes_dismissed():
    record = _record([CRITICAL_AI_CONFIRMED, DISMISSED_AI_FALSE_POSITIVE])
    data = json.loads(reports.build_sarif(record))
    results = data["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "dangerous-call"


# --------------------------------------------------- optional-dependency exports

def test_build_pdf_normal_and_empty_records():
    reportlab = pytest.importorskip("reportlab")
    for record in (_record([CRITICAL_AI_CONFIRMED, HIGH_REGEX, DISMISSED_GUESS]), _record([])):
        pdf_bytes = reports.build_pdf(record)
        assert pdf_bytes[:4] == b"%PDF"
        assert len(pdf_bytes) > 500


def test_build_docx_normal_and_empty_records():
    pytest.importorskip("docx")
    for record in (_record([CRITICAL_AI_CONFIRMED, HIGH_REGEX, DISMISSED_GUESS]), _record([])):
        docx_bytes = reports.build_docx(record)
        # docx files are zip archives
        assert docx_bytes[:2] == b"PK"
        assert len(docx_bytes) > 500


def test_build_xlsx_normal_and_empty_records():
    pytest.importorskip("openpyxl")
    for record in (_record([CRITICAL_AI_CONFIRMED, HIGH_REGEX]), _record([])):
        xlsx_bytes = reports.build_xlsx(record)
        assert xlsx_bytes[:2] == b"PK"
        assert len(xlsx_bytes) > 500


def test_report_export_html_template_renders():
    jinja2 = pytest.importorskip("jinja2")
    from jinja2 import Environment, FileSystemLoader
    template_dir = Path(__file__).resolve().parent.parent / "web" / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    tpl = env.get_template("report_export.html")

    for record in (_record([CRITICAL_AI_CONFIRMED, HIGH_REGEX, DISMISSED_AI_FALSE_POSITIVE]),
                   _record([])):
        html = tpl.render(model=reports.report_model(record))
        assert "VULNERABILITY" in html
        assert "<script" not in html.lower()  # no unescaped script injection from findings

    # findings are numbered globally across severity groups, not per-group
    html = tpl.render(model=reports.report_model(_record([CRITICAL_AI_CONFIRMED, HIGH_REGEX])))
    assert "#1 &middot;" in html or "#1 ·" in html
    assert "#2 &middot;" in html or "#2 ·" in html
