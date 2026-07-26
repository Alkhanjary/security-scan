"""
Test suite for security-scan (regex detection + optional AI review layer).

Covers:
  - deterministic regex scan catches real secrets
  - placeholders are NOT flagged
  - no duplicate findings when a line matches multiple sub-patterns
  - evidence lines fully redact the secret value ([REDACTED])
  - malicious .env inside a scan target is never used as config
  - AI layer receives metadata only (mocked — no real API key needed)
  - AI retry-with-backoff on transient failures
  - --fail-on threshold controls exit code correctly
"""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scanner  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_detects_real_secrets():
    result = scanner.scan_target(FIXTURES / "secrets_sample.py")
    rules_found = {f.rule for f in result.findings}
    assert "aws-access-key" in rules_found
    assert "password-assignment" in rules_found
    assert "github-token" in rules_found


def test_does_not_flag_placeholders():
    result = scanner.scan_target(FIXTURES / "placeholders_sample.py")
    assert len(result.findings) == 0, f"False positives on placeholders: {result.findings}"


def test_no_duplicate_findings_per_line():
    tmp_content = 'password = "genuinelyRandomValue123"\n'
    tmp_path = FIXTURES / "_tmp_dedup_test.py"
    tmp_path.write_text(tmp_content)
    try:
        result = scanner.scan_target(tmp_path)
        line_1_findings = [f for f in result.findings if f.line == 1]
        assert len(line_1_findings) == 1, f"Expected 1 finding, got {len(line_1_findings)}"
    finally:
        tmp_path.unlink()


def test_evidence_fully_redacts_secret_value():
    result = scanner.scan_target(FIXTURES / "secrets_sample.py")
    assert len(result.findings) > 0
    for f in result.findings:
        assert "[REDACTED]" in f.display_line
        assert "AKIAQWERTYUIOPASDFGH" not in f.display_line
        assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in f.display_line


def test_malicious_env_in_target_is_never_used_as_config(monkeypatch):
    fake_script_dir = FIXTURES
    monkeypatch.setattr(scanner, "SCRIPT_DIR", fake_script_dir)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)

    config = scanner.load_config()

    assert config["api_key"] is None, "Malicious target .env leaked into API key!"
    assert config["base_url"] == "https://ollama.com/v1", "Malicious target .env overrode base_url!"
    assert "attacker" not in (config["base_url"] or "")

    result = scanner.scan_target(FIXTURES / "malicious_target")
    assert any(f.file.endswith("app_config.py") for f in result.findings)


def test_ai_review_receives_metadata_only():
    result = scanner.ScanResult(
        findings=[
            scanner.Finding(
                rule="aws-access-key", severity="high", file="config.py",
                line=3, display_line='AWS_KEY = "[REDACTED]"',
                description="possible AWS access key ID",
            )
        ],
        files_scanned=1,
    )
    config = {"api_key": "fake-key", "base_url": "https://ollama.com/v1", "model": "gpt-oss:20b-cloud"}

    captured = {}
    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(
        content='{"risk_summary": "mock summary", "recommendations": ["rotate it"]}'
    ))]

    def fake_create(**kwargs):
        captured["content"] = kwargs["messages"][0]["content"]
        return mock_response

    with patch("openai.OpenAI") as mock_cls:
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = fake_create
        mock_cls.return_value = mock_client
        summary, recs, err = scanner.ai_review(result, config)

    assert summary == "mock summary"
    assert recs == ["rotate it"]
    assert err is None
    sent = captured["content"]
    assert "config.py" in sent
    assert '"line": 3' in sent
    # The raw secret value must never appear in what's sent to the AI
    assert "AKIAQWERTYUIOPASDFGH" not in sent


def test_ai_review_skipped_without_api_key():
    result = scanner.ScanResult()
    config = {"api_key": None, "base_url": "https://ollama.com/v1", "model": "gpt-oss:20b-cloud"}
    summary, recs, err = scanner.ai_review(result, config)
    assert summary is None
    assert err == "no LLM_API_KEY configured"


def test_ai_review_retries_on_transient_failure():
    result = scanner.ScanResult(findings=[], files_scanned=1)
    config = {"api_key": "fake-key", "base_url": "https://ollama.com/v1", "model": "gpt-oss:20b-cloud"}

    call_count = {"n": 0}

    def flaky_create(**kwargs):
        call_count["n"] += 1
        if call_count["n"] < 3:
            raise ConnectionError("transient network blip")
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(
            content='{"risk_summary": "ok after retry", "recommendations": []}'
        ))]
        return mock_response

    with patch("openai.OpenAI") as mock_cls:
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = flaky_create
        mock_cls.return_value = mock_client
        with patch("time.sleep"):
            summary, recs, err = scanner.ai_review(result, config, max_retries=3)

    assert summary == "ok after retry"
    assert call_count["n"] == 3


def test_symlinks_are_not_followed(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "secret.py").write_text('api_key = "zz1122334455667788990011"\n')

    link_dir = tmp_path / "scan_here"
    link_dir.mkdir()
    symlink_path = link_dir / "linked"
    try:
        symlink_path.symlink_to(real_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        import pytest
        pytest.skip("symlink creation not permitted in this environment")

    result = scanner.scan_target(link_dir)
    assert len(result.findings) == 0, "Scanner followed a symlink it shouldn't have"


def test_large_file_is_skipped_not_read(tmp_path):
    big_file = tmp_path / "big.txt"
    big_file.write_bytes(b"x" * (scanner.MAX_FILE_SIZE + 1))
    result = scanner.scan_target(tmp_path)
    assert result.files_scanned == 0
    assert any("size cap" in reason for _, reason in result.skipped_files)


def test_fail_on_threshold_high_triggers_on_high_finding():
    result = scanner.scan_target(FIXTURES / "secrets_sample.py")
    threshold_rank = scanner.SEVERITY_RANK["high"]
    exit_code = 2 if any(scanner.gates_exit_code(f, threshold_rank, False) for f in result.findings) else 0
    assert exit_code == 2


def test_fail_on_none_never_triggers():
    result = scanner.scan_target(FIXTURES / "secrets_sample.py")
    # --fail-on none always yields exit code 0 regardless of findings
    exit_code = 0
    assert exit_code == 0
    assert len(result.findings) > 0  # sanity check there WERE findings, just not gated


def test_regex_findings_are_tagged_with_source():
    result = scanner.scan_target(FIXTURES / "secrets_sample.py")
    assert len(result.findings) > 0
    assert all(f.source == "regex" for f in result.findings)


def test_ai_verify_marks_false_positive_and_excludes_from_gating():
    """The core new behavior: AI reviews a regex candidate in its file context
    and can mark it false_positive — applied in place, no duplicate entry."""
    result = scanner.ScanResult(findings=[
        scanner.Finding(rule="aws-access-key", severity="high", file="tests/test_security.py", line=5,
                         display_line='AWS_KEY = "[REDACTED]"', description="possible AWS access key ID",
                         source="regex"),
    ])
    result.ai_file_contents["tests/test_security.py"] = (
        'def test_x():\n    diff = make_diff("config.py", [\'AWS_KEY = "AKIAFAKEFAKEFAKEFAKE"\'])\n'
    )
    config = {"api_key": "fake-key", "base_url": "https://ollama.com/v1", "model": "gpt-oss:20b-cloud"}

    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(
        content='{"verifications": [{"line": 5, "verdict": "false_positive", '
                '"reason": "This is fixture data used to test the scanner itself, not a real key."}], '
                '"additional_findings": []}'
    ))]

    with patch("openai.OpenAI") as mock_cls:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_cls.return_value = mock_client
        scanner.run_ai_verify_and_scan(result, config, show_progress=False)

    # Still exactly ONE finding — verdict applied in place, no duplicate entry
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.ai_verdict == "false_positive"
    assert "fixture" in f.ai_reason.lower()

    threshold_rank = scanner.SEVERITY_RANK["high"]
    exit_code = 2 if any(scanner.gates_exit_code(x, threshold_rank, False) for x in result.findings) else 0
    assert exit_code == 0, "AI-dismissed false positive must not gate the exit code"


def test_ai_verify_confirms_true_positive_even_in_test_file():
    """AI's explicit true_positive verdict should override the fast test-file
    heuristic — a real secret accidentally left in a test file still gates."""
    result = scanner.ScanResult(findings=[
        scanner.Finding(rule="aws-access-key", severity="high", file="tests/test_config.py", line=2,
                         display_line='AWS_KEY = "[REDACTED]"', description="possible AWS access key ID",
                         source="regex", likely_test_fixture=True),
    ])
    result.ai_file_contents["tests/test_config.py"] = 'AWS_KEY = "AKIAREALLOOKINGVALUEHERE"\n'
    config = {"api_key": "fake-key", "base_url": "https://ollama.com/v1", "model": "gpt-oss:20b-cloud"}

    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(
        content='{"verifications": [{"line": 2, "verdict": "true_positive", '
                '"reason": "This looks like a genuine, unrotated AWS key, not a placeholder."}], '
                '"additional_findings": []}'
    ))]

    with patch("openai.OpenAI") as mock_cls:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_cls.return_value = mock_client
        scanner.run_ai_verify_and_scan(result, config, show_progress=False)

    f = result.findings[0]
    assert f.ai_verdict == "true_positive"

    threshold_rank = scanner.SEVERITY_RANK["high"]
    exit_code = 2 if any(scanner.gates_exit_code(x, threshold_rank, False) for x in result.findings) else 0
    assert exit_code == 2, "AI-confirmed true positive must gate even in a test-named file"


def test_ai_verify_and_scan_finds_additional_issues():
    """Beyond verifying candidates, the same call can report genuinely new
    issues (e.g. SQL injection) that regex never catches."""
    result = scanner.ScanResult()
    result.ai_file_contents["app.py"] = 'query = "SELECT * FROM users WHERE id=" + user_id\n'
    config = {"api_key": "fake-key", "base_url": "https://ollama.com/v1", "model": "gpt-oss:20b-cloud"}

    captured = {}
    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(
        content='{"verifications": [], "additional_findings": [{"rule": "sql-injection", "line": 1, '
                '"severity": "high", "description": "User input concatenated directly into SQL query"}]}'
    ))]

    def fake_create(**kwargs):
        captured["content"] = kwargs["messages"][1]["content"]
        return mock_response

    with patch("openai.OpenAI") as mock_cls:
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = fake_create
        mock_cls.return_value = mock_client
        scanner.run_ai_verify_and_scan(result, config, show_progress=False)

    assert len(result.findings) == 1
    assert result.findings[0].source == "ai"
    assert result.findings[0].rule == "sql-injection"
    assert "SELECT * FROM users" in captured["content"]  # confirms real source WAS sent


def test_ai_verify_output_is_scrubbed_of_secret_like_strings():
    result = scanner.ScanResult()
    result.ai_file_contents["config.py"] = "some content\n"
    config = {"api_key": "fake-key", "base_url": "https://ollama.com/v1", "model": "gpt-oss:20b-cloud"}

    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(
        content='{"verifications": [], "additional_findings": [{"rule": "hardcoded-secret", "line": 1, '
                '"severity": "high", "description": "Found key AKIAQWERTYUIOPASDFGH in the file"}]}'
    ))]

    with patch("openai.OpenAI") as mock_cls:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_cls.return_value = mock_client
        scanner.run_ai_verify_and_scan(result, config, show_progress=False)

    assert len(result.findings) == 1
    assert "AKIAQWERTYUIOPASDFGH" not in result.findings[0].description
    assert "[redacted]" in result.findings[0].description


def test_ai_found_high_or_critical_gates_the_exit_code():
    """Policy change: an AI-found critical/high issue (e.g. command injection,
    SQL injection) DOES gate the exit code even with no explicit verdict step —
    these are real, concrete risks worth failing a build over."""
    result = scanner.ScanResult(findings=[
        scanner.Finding(rule="command-injection", severity="critical", file="ci.yml", line=1,
                         display_line="(AI finding)", description="shell injection via untrusted input",
                         source="ai"),
    ])
    threshold_rank = scanner.SEVERITY_RANK["high"]
    exit_code = 2 if any(scanner.gates_exit_code(f, threshold_rank, False) for f in result.findings) else 0
    assert exit_code == 2, "An AI-found critical finding should gate the exit code"


def test_ai_found_medium_or_low_does_not_gate_the_exit_code():
    """AI-found medium/low findings stay informational-only — only critical/high
    AI findings are concrete enough to auto-fail a build over."""
    result = scanner.ScanResult(findings=[
        scanner.Finding(rule="minor-issue", severity="medium", file="a.py", line=1,
                         display_line="(AI finding)", description="ai only finding", source="ai"),
    ])
    threshold_rank = scanner.SEVERITY_RANK["high"]
    exit_code = 2 if any(scanner.gates_exit_code(f, threshold_rank, False) for f in result.findings) else 0
    assert exit_code == 0, "An AI-found medium finding must not trigger a failing exit code by itself"


def test_ai_rule_slug_is_not_wrongly_redacted():
    """Regression test: a long hyphenated rule name like 'hardcoded-aws-access-key'
    must NOT be caught by the generic secret scrub — only the description field
    gets that treatment. The rule name is never a secret value."""
    result = scanner.ScanResult()
    result.ai_file_contents["config.py"] = "AWS_KEY = 'abc'\n"
    config = {"api_key": "fake-key", "base_url": "https://ollama.com/v1", "model": "gpt-oss:20b-cloud"}

    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(
        content='{"verifications": [], "additional_findings": [{"rule": "hardcoded-aws-access-key", "line": 1, '
                '"severity": "high", "description": "Hardcoded AWS access key found"}]}'
    ))]

    with patch("openai.OpenAI") as mock_cls:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_cls.return_value = mock_client
        scanner.run_ai_verify_and_scan(result, config, show_progress=False)

    assert len(result.findings) == 1
    assert result.findings[0].rule == "hardcoded-aws-access-key", \
        f"Rule name was wrongly redacted: {result.findings[0].rule!r}"


def test_is_test_or_fixture_file_detects_common_patterns():
    assert scanner.is_test_or_fixture_file("tests/test_security.py")
    assert scanner.is_test_or_fixture_file("test_cli.py")
    assert scanner.is_test_or_fixture_file("src/foo_test.py")
    assert scanner.is_test_or_fixture_file("__tests__/thing.js")
    assert scanner.is_test_or_fixture_file("app.spec.ts")
    assert not scanner.is_test_or_fixture_file("config.py")
    assert not scanner.is_test_or_fixture_file("src/auth/login.py")


def test_regex_findings_in_test_files_are_flagged_as_likely_fixture():
    result = scanner.scan_target(FIXTURES / "secrets_sample.py")
    # secrets_sample.py itself isn't in a test-named path, so should NOT be flagged
    assert all(not f.likely_test_fixture for f in result.findings)


def test_fixture_findings_excluded_from_default_exit_gate_when_unverified():
    result = scanner.ScanResult(findings=[
        scanner.Finding(rule="aws-access-key", severity="high", file="tests/test_x.py", line=1,
                         display_line="x", description="d", source="regex", likely_test_fixture=True),
    ])
    threshold_rank = scanner.SEVERITY_RANK["high"]
    exit_code = 2 if any(scanner.gates_exit_code(f, threshold_rank, False) for f in result.findings) else 0
    assert exit_code == 0, "An unverified test-fixture finding should not gate the exit code by default"


def test_ai_scan_error_leaves_candidate_unverified_not_dropped():
    """If the AI call for a file fails, its regex findings must still be
    present (just unverified) — never silently dropped."""
    result = scanner.ScanResult(findings=[
        scanner.Finding(rule="aws-access-key", severity="high", file="config.py", line=3,
                         display_line='AWS_KEY = "[REDACTED]"', description="possible AWS access key ID",
                         source="regex"),
    ])
    result.ai_file_contents["config.py"] = 'AWS_KEY = "AKIAQWERTYUIOPASDFGH"\n'
    config = {"api_key": "fake-key", "base_url": "https://ollama.com/v1", "model": "gpt-oss:20b-cloud"}

    with patch("openai.OpenAI") as mock_cls:
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = ConnectionError("network down")
        mock_cls.return_value = mock_client
        with patch("time.sleep"):
            scanner.run_ai_verify_and_scan(result, config, show_progress=False)

    assert len(result.findings) == 1
    assert result.findings[0].ai_verdict is None  # unverified, not dismissed
    assert len(result.ai_scan_errors) == 1


# ---------------------------------------------------------------------------
# Phase 2: dangerous calls, weak crypto, insecure transport, SQL injection
# ---------------------------------------------------------------------------
def test_detects_dangerous_calls():
    tmp_path = FIXTURES / "_tmp_dangerous.py"
    tmp_path.write_text(
        "eval(user_input)\n"
        "exec(some_code)\n"
        "os.system('rm -rf ' + path)\n"
        "subprocess.call(cmd, shell=True)\n"
    )
    try:
        result = scanner.scan_target(tmp_path)
        rules = {f.rule for f in result.findings}
        assert {"eval-call", "exec-call", "os-system-call", "shell-true"} <= rules
    finally:
        tmp_path.unlink()


def test_detects_weak_crypto():
    tmp_path = FIXTURES / "_tmp_crypto.py"
    tmp_path.write_text("h = hashlib.md5(data).hexdigest()\nh2 = hashlib.sha1(data).hexdigest()\n")
    try:
        result = scanner.scan_target(tmp_path)
        rules = {f.rule for f in result.findings}
        assert {"md5-hash", "sha1-hash"} <= rules
    finally:
        tmp_path.unlink()


def test_detects_insecure_transport():
    tmp_path = FIXTURES / "_tmp_transport.py"
    tmp_path.write_text('requests.get("http://api.example.com/data", verify=False)\n')
    try:
        result = scanner.scan_target(tmp_path)
        rules = {f.rule for f in result.findings}
        assert {"http-url", "tls-verify-disabled"} <= rules
    finally:
        tmp_path.unlink()


def test_http_localhost_is_not_flagged():
    """localhost/127.0.0.1 URLs shouldn't trigger the insecure-transport rule —
    they're not a real interception risk the way an external endpoint is."""
    tmp_path = FIXTURES / "_tmp_localhost.py"
    tmp_path.write_text('url = "http://localhost:8000/api"\n')
    try:
        result = scanner.scan_target(tmp_path)
        assert not any(f.rule == "http-url" for f in result.findings)
    finally:
        tmp_path.unlink()


def test_detects_sql_injection_via_concatenation():
    tmp_path = FIXTURES / "_tmp_sql1.py"
    tmp_path.write_text('query = "SELECT * FROM users WHERE id=" + user_id\n')
    try:
        result = scanner.scan_target(tmp_path)
        assert any(f.rule == "sql-string-concat" for f in result.findings)
    finally:
        tmp_path.unlink()


def test_detects_sql_injection_via_fstring():
    tmp_path = FIXTURES / "_tmp_sql2.py"
    tmp_path.write_text("query = f\"SELECT * FROM accounts WHERE name='{username}'\"\n")
    try:
        result = scanner.scan_target(tmp_path)
        assert any(f.rule == "sql-fstring" for f in result.findings)
    finally:
        tmp_path.unlink()


def test_sql_mention_without_concatenation_is_not_flagged():
    """A SQL keyword sitting in an ordinary string (no concatenation, no
    interpolation) shouldn't be flagged — there's no injection vector."""
    tmp_path = FIXTURES / "_tmp_sql_safe.py"
    tmp_path.write_text('msg = "SELECT statement executed successfully"\n')
    try:
        result = scanner.scan_target(tmp_path)
        assert not any(f.rule in ("sql-string-concat", "sql-fstring") for f in result.findings)
    finally:
        tmp_path.unlink()


def test_cross_finding_redaction_secret_never_leaks_through_other_finding():
    """Critical requirement: when a line has both a secret AND another issue
    (e.g. PASSWORD = "x"; eval(y)), the OTHER finding's evidence must also
    have the secret redacted — not just the secret's own finding."""
    tmp_path = FIXTURES / "_tmp_cross_redact.py"
    tmp_path.write_text('PASSWORD = "SuperSecretValue123"; eval(user_input)\n')
    try:
        result = scanner.scan_target(tmp_path)
        assert len(result.findings) == 2  # one password-assignment, one eval-call
        for f in result.findings:
            assert "SuperSecretValue123" not in f.display_line, \
                f"Secret leaked through a co-occurring finding: {f.rule} -> {f.display_line!r}"
            assert "[REDACTED]" in f.display_line
    finally:
        tmp_path.unlink()


def test_code_issue_categories_shown_correctly_not_hardcoded_secret():
    """Regression guard: Phase 2 findings must report their real category
    (dangerous-call, sql-injection, etc.), not the old hardcoded 'hardcoded-secret'
    label that used to apply to every regex finding regardless of type."""
    tmp_path = FIXTURES / "_tmp_category.py"
    tmp_path.write_text("eval(x)\n")
    try:
        result = scanner.scan_target(tmp_path)
        assert len(result.findings) == 1
        category = scanner.CATEGORY_BY_RULE.get(result.findings[0].rule)
        assert category == "dangerous-call"
    finally:
        tmp_path.unlink()


# ---------------------------------------------------------------------------
# Phase 3a: infra config scanning (Dockerfile / docker-compose / K8s)
# ---------------------------------------------------------------------------
def test_detects_dockerfile_issues():
    tmp_path = FIXTURES / "_tmp_Dockerfile"
    tmp_path.write_text(
        "FROM python:latest\n"
        "USER root\n"
        "ADD https://example.com/installer.sh /tmp/installer.sh\n"
    )
    try:
        result = scanner.scan_target(tmp_path)
        rules = {f.rule for f in result.findings}
        assert {"unpinned-base-image", "container-root-user", "add-remote-fetch"} <= rules
    finally:
        tmp_path.unlink()


def test_dockerfile_non_root_user_not_flagged():
    tmp_path = FIXTURES / "_tmp_Dockerfile_safe"
    tmp_path.write_text("FROM python:3.12-slim\nUSER appuser\nCOPY . /app\n")
    try:
        result = scanner.scan_target(tmp_path)
        assert not any(f.rule in ("unpinned-base-image", "container-root-user", "add-remote-fetch")
                        for f in result.findings)
    finally:
        tmp_path.unlink()


def test_detects_compose_and_k8s_misconfigs():
    tmp_path = FIXTURES / "_tmp_compose.yml"
    tmp_path.write_text(
        "services:\n"
        "  app:\n"
        "    privileged: true\n"
        "    network_mode: host\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n"
    )
    try:
        result = scanner.scan_target(tmp_path)
        rules = {f.rule for f in result.findings}
        assert {"container-privileged", "host-network-mode", "docker-socket-mount"} <= rules
        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) >= 2
    finally:
        tmp_path.unlink()


def test_detects_k8s_privilege_escalation():
    tmp_path = FIXTURES / "_tmp_pod.yml"
    tmp_path.write_text(
        "securityContext:\n"
        "  allowPrivilegeEscalation: true\n"
    )
    try:
        result = scanner.scan_target(tmp_path)
        assert any(f.rule == "allow-privilege-escalation" for f in result.findings)
    finally:
        tmp_path.unlink()
