#!/usr/bin/env python3
"""
security-scan
--------------
Deterministic regex-based secret detection (the source of truth for
findings — reliable, offline, gates CI via exit code) with an optional
AI layer on top that reviews the findings and writes a risk summary +
recommended fixes in plain language.

Design guarantees:
  - Config (.env) is loaded ONLY from this script's own directory —
    never from the scan target. A malicious .env inside a scanned repo
    cannot redirect LLM_BASE_URL or steal LLM_API_KEY.
  - The regex scan is what gates exit codes / CI. It never depends on
    the AI layer being available or correct.
  - The AI layer (--ai) is opt-in and receives METADATA ONLY: finding
    category, severity, file, line — never source snippets or secret
    values.
  - Every finding's evidence line has the secret value fully replaced
    with [REDACTED] before it is displayed, logged, or sent anywhere.
  - No symlinks followed. File-size and directory-depth caps enforced.
    A clean result means "no implemented rule matched" — never "secure".
"""

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
    _COLOR = True
except ImportError:
    _COLOR = False

    class _NoColor:
        def __getattr__(self, name):
            return ""
    Fore = _NoColor()
    Style = _NoColor()

SEV_COLOR = {"critical": Fore.MAGENTA + Style.BRIGHT, "high": Fore.RED, "medium": Fore.YELLOW, "low": Fore.CYAN}


def _c(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}" if _COLOR else text


# ---------------------------------------------------------------------------
# Config: loaded ONLY from this script's own directory, never the scan target.
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent


def load_config():
    env_path = SCRIPT_DIR / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=False)
    return {
        "api_key": os.environ.get("LLM_API_KEY"),
        "base_url": os.environ.get("LLM_BASE_URL", "https://ollama.com/v1"),
        "model": os.environ.get("LLM_MODEL", "gpt-oss:20b-cloud"),
    }


# ---------------------------------------------------------------------------
# Filesystem safety limits
# ---------------------------------------------------------------------------
MAX_FILE_SIZE = 2_000_000
MAX_DEPTH = 25
MAX_LINE_LENGTH = 2000
MAX_FINDINGS_PER_FILE = 50
MAX_FINDINGS_TOTAL = 1000

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".gz", ".tar", ".7z", ".rar", ".pdf", ".exe", ".dll", ".so", ".pyc",
    ".class", ".jar", ".mp3", ".mp4", ".mov", ".avi", ".lock",
}

# ---------------------------------------------------------------------------
# Secret detection patterns. Group 1 captures the secret value; that is the
# ONLY part ever inspected for placeholder detection or shown (redacted).
# ---------------------------------------------------------------------------
SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("slack-token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b")),
    ("github-token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36})\b")),
    ("stripe-key", re.compile(r"\b((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,64})\b")),
    ("google-api-key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("private-key-block", re.compile(r"(-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----)")),
    (
        "api-key-assignment",
        re.compile(r"(?i)\b(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{12,100})['\"]"),
    ),
    (
        "password-assignment",
        re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,100})['\"]"),
    ),
    (
        "secret-assignment",
        re.compile(r"(?i)\b(?:secret|token)\s*[:=]\s*['\"]([A-Za-z0-9_\-./+=]{12,100})['\"]"),
    ),
]

PLACEHOLDER_MARKERS = (
    "your-", "your_", "yourkey", "changeme", "change_me", "example",
    "xxxxx", "<", ">", "insert", "replace", "placeholder", "dummy",
    "test123", "fake", "sample", "todo", "0000000000",
)

SEVERITY = {
    "aws-access-key": "critical",
    "private-key-block": "critical",
    "github-token": "high",
    "stripe-key": "high",
    "slack-token": "high",
    "google-api-key": "high",
    "api-key-assignment": "high",
    "secret-assignment": "medium",
    "password-assignment": "medium",
}

DESCRIPTION = {
    "aws-access-key": "possible AWS access key ID",
    "private-key-block": "possible private key material",
    "github-token": "possible GitHub personal access token",
    "stripe-key": "possible Stripe API key",
    "slack-token": "possible Slack token",
    "google-api-key": "possible Google API key",
    "api-key-assignment": "possible hardcoded credential",
    "secret-assignment": "possible hardcoded secret or token",
    "password-assignment": "possible hardcoded password",
}

# What could actually go wrong if this specific finding is real, and the
# concrete fix for it. Shown under every finding in the report.
IMPACT = {
    "aws-access-key": "Full programmatic access to your AWS account within that key's permissions — an attacker could spin up resources, read/exfiltrate data from S3/databases, or rack up billing charges.",
    "private-key-block": "Whatever this key authenticates (SSH access, TLS termination, signing) is fully compromised — an attacker can impersonate this identity or decrypt traffic protected by it.",
    "github-token": "Access to whatever repos/orgs this token covers — an attacker could read private code, push malicious commits, or modify CI/CD configuration.",
    "stripe-key": "A live key can move real money and read customer payment data; a test key is lower risk but still leaks internal config details.",
    "slack-token": "Access to post as this bot/user, read channel history, and potentially exfiltrate internal conversations depending on scopes granted.",
    "google-api-key": "Depends on which Google APIs the key is scoped to — could range from map-tile abuse (billing impact) to access to Cloud/Workspace data.",
    "api-key-assignment": "Depends on the service this key belongs to, but at minimum it lets an attacker impersonate this application to that service.",
    "secret-assignment": "Depends on what the secret protects (session signing, encryption, webhook verification) — compromise typically allows forging or decrypting data.",
    "password-assignment": "Direct account/service takeover if this password is still active anywhere.",
}

IMPROVEMENT = {
    "aws-access-key": "Revoke this key in IAM immediately, issue a new one, and load it from an environment variable or AWS Secrets Manager instead of source.",
    "private-key-block": "Treat the key as burned — generate a new keypair, redistribute the public key, and revoke trust in the old one. Deleting the file alone does not undo exposure already in git history.",
    "github-token": "Revoke it under GitHub Settings > Developer settings > Personal access tokens, generate a new one, and store it as a repo/CI secret.",
    "stripe-key": "Roll the key from the Stripe dashboard now and load the new one from environment config.",
    "slack-token": "Revoke it in your Slack App settings and reissue; store bot/user tokens as environment variables, never in source.",
    "google-api-key": "Regenerate the key in Google Cloud Console and add API restrictions (HTTP referrer / IP allowlist) to the replacement.",
    "api-key-assignment": "Rotate this credential at its source service and load it from a .env file or secrets manager instead of hardcoding it.",
    "secret-assignment": "Rotate the value and move it to environment configuration; check whether it's reused anywhere else that also needs rotating.",
    "password-assignment": "Change this password at its source and load it from environment variables or a secrets manager, never from source code.",
}

GENERIC_REMEDIATION = [
    "Move flagged values into environment variables or a secrets manager",
    "Rotate every flagged credential now — they may already be in git history even after removal",
    "Add this scan as a pre-commit hook or CI check to catch this earlier",
]

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
CATEGORY = "hardcoded-secret"


def is_placeholder(secret_value: str) -> bool:
    """Checks ONLY the captured secret value — never the variable name or
    any trailing comment on the source line."""
    lowered = secret_value.lower()
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return True
    if len(set(secret_value)) <= 2:
        return True
    return False


_TEST_PATH_PARTS = {"test", "tests", "spec", "specs", "__tests__", "fixture", "fixtures", "mocks", "mock"}
_TEST_FILENAME_RE = re.compile(r"(^test_.*\.\w+$)|(.*_test\.\w+$)|(.*\.spec\.\w+$)|(.*\.test\.\w+$)", re.IGNORECASE)


def is_test_or_fixture_file(rel_path: str) -> bool:
    """A finding inside a test/fixture file is very often the scanner's own
    test data (fixture strings, mock diffs) rather than a real leaked
    secret. Such findings are still reported, but separated out and
    excluded from exit-code gating by default — this is a heuristic, not
    a guarantee, so real secrets accidentally left in test files are still
    visible, just not blocking a build on their own."""
    parts = [p.lower() for p in Path(rel_path).parts]
    if any(p in _TEST_PATH_PARTS for p in parts):
        return True
    filename = Path(rel_path).name
    return bool(_TEST_FILENAME_RE.match(filename))


@dataclass
class Finding:
    rule: str            # e.g. "aws-access-key"
    severity: str         # critical / high / medium / low
    file: str
    line: int
    display_line: str     # source line with the secret value replaced by [REDACTED] (regex findings only)
    description: str
    source: str = "regex"  # "regex" (from the deterministic scan) or "ai" (an issue only AI found)
    likely_test_fixture: bool = False
    ai_verdict: Optional[str] = None   # "true_positive" | "false_positive" | None (not AI-reviewed)
    ai_reason: Optional[str] = None    # AI's short justification for the verdict
    impact: str = ""       # what could actually go wrong if this is real
    improvement: str = ""  # concrete fix


@dataclass
class ScanResult:
    findings: list = field(default_factory=list)
    skipped_files: list = field(default_factory=list)
    files_scanned: int = 0
    scanned_file_names: list = field(default_factory=list)
    truncated: bool = False
    ai_file_contents: dict = field(default_factory=dict)   # rel_path -> text, for files within the AI size cap
    ai_scan_errors: list = field(default_factory=list)      # (rel_path, error) for files where the AI code scan itself failed

AI_MAX_FILE_SIZE = 300_000  # separate, smaller cap for what actually gets sent to the AI


def scan_target(target: Path, show_progress: bool = True) -> ScanResult:
    result = ScanResult()
    target = target.resolve()

    if target.is_file():
        _scan_file(target, target.parent, result)
        return result

    file_count = 0
    for root, dirs, files in os.walk(target, followlinks=False):
        root_path = Path(root)
        rel_depth = len(root_path.relative_to(target).parts)
        if rel_depth >= MAX_DEPTH:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in files:
            if len(result.findings) >= MAX_FINDINGS_TOTAL:
                result.truncated = True
                return result
            fpath = root_path / fname
            _scan_file(fpath, target, result)
            file_count += 1
            if show_progress:
                print(_c(f"[regex {file_count}] {fname}", Style.DIM), flush=True)

    if show_progress and file_count:
        print(_c(f"Regex scan done: {file_count} file(s).", Style.DIM), flush=True)

    return result


def _scan_file(fpath: Path, base: Path, result: ScanResult):
    rel_path = str(fpath.relative_to(base)) if fpath.is_relative_to(base) else str(fpath)

    if fpath.is_symlink():
        result.skipped_files.append((rel_path, "symlink (not followed)"))
        return
    if fpath.suffix.lower() in BINARY_EXTENSIONS:
        result.skipped_files.append((rel_path, "binary extension (skipped)"))
        return
    try:
        size = fpath.stat().st_size
    except OSError as e:
        result.skipped_files.append((rel_path, f"stat failed: {e}"))
        return
    if size > MAX_FILE_SIZE:
        result.skipped_files.append((rel_path, f"exceeds size cap ({size} bytes)"))
        return
    try:
        raw = fpath.read_bytes()
    except OSError as e:
        result.skipped_files.append((rel_path, f"read failed: {e}"))
        return
    if b"\x00" in raw[:8192]:
        result.skipped_files.append((rel_path, "binary content (skipped)"))
        return
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except Exception:
            result.skipped_files.append((rel_path, "undecodable content"))
            return

    result.files_scanned += 1
    result.scanned_file_names.append(rel_path)
    file_finding_count = 0

    if len(text.encode("utf-8", errors="ignore")) <= AI_MAX_FILE_SIZE:
        result.ai_file_contents[rel_path] = text

    for line_no, line in enumerate(text.splitlines(), 1):
        if len(line) > MAX_LINE_LENGTH:
            continue
        if file_finding_count >= MAX_FINDINGS_PER_FILE:
            result.skipped_files.append((rel_path, "per-file finding cap reached — remaining matches not reported"))
            break

        for rule, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            value = match.group(1)
            if is_placeholder(value):
                break
            display_line = line[:match.start(1)] + "[REDACTED]" + line[match.end(1):]
            result.findings.append(Finding(
                rule=rule,
                severity=SEVERITY.get(rule, "medium"),
                file=rel_path,
                line=line_no,
                display_line=display_line.strip(),
                description=DESCRIPTION.get(rule, "possible hardcoded secret"),
                likely_test_fixture=is_test_or_fixture_file(rel_path),
                impact=IMPACT.get(rule, "Could allow an attacker to impersonate this application or access whatever the credential protects."),
                improvement=IMPROVEMENT.get(rule, "Rotate this credential and move it to environment variables or a secrets manager."),
            ))
            file_finding_count += 1
            break

    if len(result.findings) >= MAX_FINDINGS_TOTAL:
        result.truncated = True


# ---------------------------------------------------------------------------
# AI code-scan layer — reads actual source (unlike ai_review below, which is
# metadata-only). This is what makes --ai send real code externally. Output
# is scrubbed defensively in case the model echoes a value despite the
# system-prompt instruction not to.
# ---------------------------------------------------------------------------
_SCRUB_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,72}"),
    re.compile(r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,64}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"[A-Za-z0-9_\-./+=]{20,}"),
]


def _scrub(text: str) -> str:
    if not text:
        return text
    for pattern in _SCRUB_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text


def _clean_rule_slug(rule: str) -> str:
    """Rule names are never secret values, so they don't need the generic
    long-string scrub (which would wrongly catch ordinary slugs like
    'hardcoded-aws-access-key'). Just normalize to safe kebab-case and cap
    length as a sanity bound."""
    rule = rule.strip().lower().replace(" ", "-")
    rule = re.sub(r"[^a-z0-9\-]", "", rule)
    return rule[:60] or "ai-finding"


AI_VERIFY_AND_SCAN_PROMPT = """You are a security code reviewer. You will be shown the content of ONE source
file, and a list of candidate findings an automated regex scanner already
flagged in this file (by line number).

Your job has two parts:

1. VERIFY each candidate finding. Look at the actual line AND its surrounding
   code context (not just whether the string LOOKS like a real secret).
   Decide: is this a real secret/credential that would cause harm if leaked
   (true_positive), or is it test/fixture data (false_positive)?

   Strong signals of false_positive, even when the value looks real:
   - The value is passed as a literal argument to a function whose name
     suggests test data or diff/patch construction (e.g. make_diff,
     build_fixture, mock_*, fake_*, sample_*)
   - The line appears inside an assert statement, or checks scanner/tool
     OUTPUT (e.g. `assert "X" not in secret["evidence"]`, checking redaction
     behavior) — this is the scanner testing ITSELF, not a real credential
   - The file's own purpose is testing a scanner, linter, or security tool
     (common in files like test_security.py, test_scanner.py) — in such
     files, secret-shaped strings are usually intentional test input, not
     real leaks
   - Surrounding code references words like "diff", "evidence", "redacted",
     "fixture", "mock", "sample", "expected"

   Only mark true_positive when the value appears to be an actual credential
   USED by the application (e.g. assigned to a config variable that the
   real code path reads), not test input being fed into or checked against
   a scanner/tool. Give a short reason either way — you must classify every
   candidate given to you, one verdict each.

2. SCAN for ADDITIONAL issues not already in the candidate list: dangerous
   calls (eval/exec/os.system), SQL injection via string concatenation, XSS
   sinks, insecure transport (verify=False, http://), weak crypto
   (MD5/SHA1), missing auth checks, or other hardcoded secrets the
   candidates missed.

CRITICAL RULE: Never include the actual secret/credential VALUE anywhere in
your response — describe type and location only.

Also: never quote source code lines verbatim in "reason" or "description" —
summarize in your own plain words. This avoids broken JSON when code lines
contain quote characters. Output strict, valid JSON: double-quoted keys and
strings only, no trailing commas.

Respond ONLY with JSON (no markdown fences, no preamble):
{
  "verifications": [
    {"line": <int>, "verdict": "true_positive"|"false_positive", "reason": "<short reason>"}
  ],
  "additional_findings": [
    {"rule": "<short-kebab-case-slug>", "line": <int>, "severity": "critical"|"high"|"medium"|"low",
     "description": "<1 sentence, plain language, never include secret values>",
     "impact": "<1 sentence: what could actually go wrong if this is real>",
     "fix": "<1 sentence: the concrete remediation step>"}
  ]
}

Use "critical" severity only for something that gives near-total system/account
compromise on its own (e.g. a live cloud provider key, a private key, full DB
admin credentials). Use "high" for other real secrets, "medium"/"low" for
lesser issues.

"verifications" must include exactly one entry per candidate finding you were given.
"additional_findings" may be an empty list if there's nothing new.
"""


def ai_verify_and_scan_file(rel_path: str, content: str, candidates: list, config: dict, max_retries: int = 3):
    """Sends one file's real content plus its regex candidate findings to the
    model in a single call. Returns (verifications: dict[line -> (verdict, reason)],
    additional_findings: list[Finding], error: str|None)."""
    try:
        from openai import OpenAI
    except ImportError:
        return {}, [], "'openai' package not installed"

    client = OpenAI(api_key=config["api_key"], base_url=config["base_url"])
    numbered = "\n".join(f"{i+1}: {line}" for i, line in enumerate(content.splitlines()))
    candidate_desc = "\n".join(
        f"- line {c.line}: {c.rule} ({c.description})" for c in candidates
    ) or "(none — just scan for additional issues)"
    user_prompt = (
        f"File: {rel_path}\n\nCandidate findings from the regex scanner:\n{candidate_desc}\n\n"
        f"Full file content:\n{numbered}"
    )

    delay = 1.0
    last_error = None
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=config["model"],
                messages=[
                    {"role": "system", "content": AI_VERIFY_AND_SCAN_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=6000,
            )
            text = response.choices[0].message.content.strip()
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            data = json.loads(text)

            verifications = {}
            for v in data.get("verifications", []):
                line = int(v.get("line", 0) or 0)
                verdict = str(v.get("verdict", "")).lower()
                if verdict not in ("true_positive", "false_positive"):
                    verdict = "true_positive"  # fail safe: unclear verdict is treated as real
                reason = _scrub(str(v.get("reason", "")))
                verifications[line] = (verdict, reason)

            additional = []
            for item in data.get("additional_findings", []):
                sev = str(item.get("severity", "medium")).lower()
                if sev not in ("critical", "high", "medium", "low"):
                    sev = "medium"
                additional.append(Finding(
                    rule=_clean_rule_slug(str(item.get("rule", "ai-finding"))),
                    severity=sev,
                    file=rel_path,
                    line=int(item.get("line", 0) or 0),
                    display_line="(AI finding — no local evidence line; see description)",
                    description=_scrub(str(item.get("description", ""))),
                    source="ai",
                    likely_test_fixture=is_test_or_fixture_file(rel_path),
                    impact=_scrub(str(item.get("impact", ""))) or "Could compromise the affected system depending on how this code path is used.",
                    improvement=_scrub(str(item.get("fix", ""))) or "Review and remediate this issue at its source.",
                ))
            return verifications, additional, None
        except Exception as e:
            last_error = e
            if attempt < max_retries - 1:
                time.sleep(delay)
                delay *= 2

    return {}, [], str(last_error)


def run_ai_verify_and_scan(result: ScanResult, config: dict, show_progress: bool = True):
    """For every file the regex scan covered, sends its content + that file's
    regex candidates to the AI in one call: verifies each candidate as true/
    false positive (applied in place onto the existing Finding — no
    duplicate entries), and appends any genuinely new findings the AI spots."""
    total = len(result.ai_file_contents)
    durations = []
    regex_by_file = {}
    for f in result.findings:
        regex_by_file.setdefault(f.file, []).append(f)

    for i, (rel_path, content) in enumerate(result.ai_file_contents.items(), 1):
        candidates = regex_by_file.get(rel_path, [])
        if show_progress:
            eta_str = ""
            if durations:
                avg = sum(durations) / len(durations)
                remaining = avg * (total - i + 1)
                eta_str = f"  (est. {_fmt_duration(remaining)} remaining)"
            note = f", verifying {len(candidates)} candidate(s)" if candidates else ""
            print(_c(f"[{i}/{total}] AI reviewing {rel_path}{note}...{eta_str}", Style.DIM), flush=True)

        t0 = time.time()
        verifications, additional, error = ai_verify_and_scan_file(rel_path, content, candidates, config)
        durations.append(time.time() - t0)

        if error:
            result.ai_scan_errors.append((rel_path, error))
            continue

        for c in candidates:
            if c.line in verifications:
                verdict, reason = verifications[c.line]
                c.ai_verdict = verdict
                c.ai_reason = reason

        result.findings.extend(additional)

    if show_progress and total:
        total_elapsed = sum(durations)
        print(_c(f"AI verify+scan done: {total} file(s) in {_fmt_duration(total_elapsed)}.", Style.DIM), flush=True)


def _fmt_duration(seconds: float) -> str:
    seconds = max(0, seconds)
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}m{secs:02d}s"




def ai_review(result: ScanResult, config: dict, max_retries: int = 3):
    """Returns (risk_summary: str|None, recommendations: list[str]|None, error: str|None)."""
    if not config.get("api_key"):
        return None, None, "no LLM_API_KEY configured"

    try:
        from openai import OpenAI
    except ImportError:
        return None, None, "'openai' package not installed"

    payload = {
        "total_findings": len(result.findings),
        "files_scanned": result.files_scanned,
        "findings": [
            {"rule": f.rule, "severity": f.severity, "file": f.file, "line": f.line, "description": f.description}
            for f in result.findings
        ],
    }
    prompt = (
        "You are reviewing metadata from a code security scan (hardcoded-secret "
        "detection). You are given ONLY finding types, severities, files, and "
        "lines — never source code or secret values. Respond ONLY with JSON:\n"
        '{"risk_summary": "<2-3 sentence plain-language risk assessment>", '
        '"recommendations": ["<action>", "<action>", ...]}\n'
        "Be concrete about what could go wrong given the finding types present, "
        "without inventing details you weren't given.\n\n"
        f"Scan metadata:\n{json.dumps(payload, indent=2)}"
    )

    client = OpenAI(api_key=config["api_key"], base_url=config["base_url"])
    delay = 1.0
    last_error = None
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=config["model"],
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500,
            )
            text = response.choices[0].message.content.strip()
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            data = json.loads(text)
            return data.get("risk_summary"), data.get("recommendations", []), None
        except Exception as e:
            last_error = e
            if attempt < max_retries - 1:
                time.sleep(delay)
                delay *= 2

    return None, None, str(last_error)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def _rule_line(width=62):
    return _c("-" * width, Style.DIM)


def print_report(result: ScanResult, target: str, used_ai: bool,
                  risk_summary: Optional[str], recommendations: Optional[list],
                  ai_error: Optional[str], exit_code: int, threshold: str, include_test_files: bool = False):
    from collections import Counter, defaultdict

    print()
    print(_c(f"security-scan report — {target}", Style.BRIGHT))
    print(_rule_line())

    def _dismissed(f: Finding) -> bool:
        if f.ai_verdict == "false_positive":
            return True
        if f.ai_verdict == "true_positive":
            return False
        return f.likely_test_fixture and not include_test_files

    main_findings = [f for f in result.findings if not _dismissed(f)]
    dismissed_findings = [f for f in result.findings if _dismissed(f)]

    files_with_findings = len({f.file for f in result.findings})
    print(f"{result.files_scanned} file(s) scanned — {files_with_findings} with finding(s), "
          f"{result.files_scanned - files_with_findings} clean")

    by_sev = Counter(f.severity for f in main_findings)
    sev_parts = [f"{_c(str(by_sev.get(s,0)), SEV_COLOR.get(s,''))} {s}" for s in ("critical","high","medium","low") if by_sev.get(s,0)]
    if sev_parts:
        print("  " + "   ".join(sev_parts) + (f"   ({len(dismissed_findings)} dismissed)" if dismissed_findings else ""))
    elif dismissed_findings:
        print(_c(f"  0 confirmed findings   ({len(dismissed_findings)} dismissed as false positives / unverified test data)", Style.DIM))
    print(_rule_line())

    def _sev_rank(f):
        return SEVERITY_RANK.get(f.severity, 0)

    if not main_findings:
        print(_c("No confirmed findings. This does not mean the code is secure — only", Style.DIM))
        print(_c("that nothing matched (or everything that matched was dismissed below).", Style.DIM))
    else:
        by_file = defaultdict(list)
        for f in main_findings:
            by_file[f.file].append(f)
        for flist in by_file.values():
            flist.sort(key=_sev_rank, reverse=True)
        files_by_worst = sorted(by_file.keys(), key=lambda fn: max(_sev_rank(f) for f in by_file[fn]), reverse=True)
        for fname in files_by_worst:
            worst = by_file[fname][0].severity
            print()
            print(_c(f"{fname}", Style.BRIGHT) + _c(f"  (worst: {worst})", SEV_COLOR.get(worst, "")))
            for f in by_file[fname]:
                tag = _c(f"[{f.severity.upper()}]", SEV_COLOR.get(f.severity, ""))
                label = f.rule if f.source == "ai" else CATEGORY
                confirm = _c(" ✓AI-confirmed", Fore.GREEN) if f.ai_verdict == "true_positive" else (_c(" (ai-found)", Fore.CYAN) if f.source == "ai" else "")
                print(f"  {tag} {label}{confirm}  —  line {f.line}")
                if f.source == "regex":
                    print(f"    {f.display_line}")
                print(f"    {_c('Impact:', Fore.YELLOW)} {f.impact}")
                print(f"    {_c('Fix:', Fore.GREEN)} {f.improvement}")

    total_main = len(main_findings)
    print()
    print(_rule_line())
    regex_count = sum(1 for f in main_findings if f.source == "regex")
    ai_count = sum(1 for f in main_findings if f.source == "ai")
    extra = f"  [{regex_count} regex, {ai_count} ai-found]" if used_ai else ""
    print(f"{total_main} finding(s) across {result.files_scanned} file(s){extra}")

    if dismissed_findings:
        print()
        print(_c(f"Dismissed ({len(dismissed_findings)}):", Style.DIM))
        by_file_dismissed = defaultdict(list)
        for f in dismissed_findings:
            by_file_dismissed[f.file].append(f)
        for flist in by_file_dismissed.values():
            flist.sort(key=lambda f: f.line)
        for fname in by_file_dismissed:
            for f in by_file_dismissed[fname]:
                if f.ai_verdict == "false_positive":
                    tag = _c("[AI-reviewed]", Fore.CYAN)
                    reason = f.ai_reason
                else:
                    tag = _c("[unreviewed guess]", Fore.YELLOW)
                    reason = "matched a test/fixture file path — not actually checked by AI"
                print(f"  {tag} {fname}:{f.line} — {reason}")

    if result.ai_scan_errors:
        print()
        print(_c(f"AI review failed for {len(result.ai_scan_errors)} file(s) — see --json output for details", Fore.YELLOW))

    if result.skipped_files:
        print(_c(f"{len(result.skipped_files)} file(s) skipped (not analyzed) — see --json output for details", Fore.YELLOW))

    if used_ai:
        print()
        print(_c("AI Risk Summary", Style.BRIGHT))
        if risk_summary:
            print(f"  {risk_summary}")
        else:
            print(_c(f"  unavailable ({ai_error})", Fore.YELLOW))

        print()
        print(_c("Recommended Fix", Style.BRIGHT))
        recs = recommendations if recommendations else (GENERIC_REMEDIATION if main_findings else [])
        for rec in recs:
            print(f"  - {rec}")

    print()
    reason = f"findings at or above configured threshold ({threshold})" if exit_code != 0 else "no findings at or above threshold"
    print(f"Exit code: {exit_code} ({reason})")


def save_json_report(result: ScanResult, risk_summary, recommendations, exit_code, path):
    data = {
        "files_scanned": result.files_scanned,
        "scanned_files": result.scanned_file_names,
        "skipped_files": [{"file": p, "reason": r} for p, r in result.skipped_files],
        "ai_scan_errors": [{"file": p, "error": e} for p, e in result.ai_scan_errors],
        "findings": [
            {
                "category": CATEGORY if f.source == "regex" else f.rule,
                "rule": f.rule,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "evidence": f.display_line,
                "description": f.description,
                "impact": f.impact,
                "improvement": f.improvement,
                "source": f.source,
                "likely_test_fixture": f.likely_test_fixture,
                "ai_verdict": f.ai_verdict,
                "ai_reason": f.ai_reason,
            }
            for f in result.findings
        ],
        "truncated": result.truncated,
        "ai_risk_summary": risk_summary,
        "ai_recommendations": recommendations,
        "exit_code": exit_code,
        "note": "Zero findings means no implemented rule matched; this is not a security guarantee. "
                "'ai_verdict' is 'true_positive'/'false_positive' when AI reviewed a regex finding, "
                "or null if unreviewed (--ai not used, or that file's AI call failed).",
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)


def gates_exit_code(f: Finding, threshold_rank: int, include_test_files: bool) -> bool:
    """Decides whether a single finding should cause a non-zero exit code.

    Policy:
      - Below the severity threshold: never gates.
      - AI explicitly reviewed and said false_positive: never gates.
      - AI explicitly reviewed and said true_positive: always gates (overrides the fixture heuristic).
      - AI-found (not a verified regex candidate) critical/high: gates — AI-only findings like
        command injection or SQL injection are real risks even though they're non-deterministic,
        and a critical/high one is worth failing a build over.
      - AI-found medium/low with no verdict: informational only, does not gate.
      - Regex finding with no AI verdict (either --ai unused, or that file's AI call failed):
        falls back to the fast test/fixture-path heuristic.
    """
    if SEVERITY_RANK[f.severity] < threshold_rank:
        return False
    if f.ai_verdict == "false_positive":
        return False
    if f.ai_verdict == "true_positive":
        return True
    if f.source == "ai" and SEVERITY_RANK[f.severity] >= SEVERITY_RANK["high"]:
        return True
    if f.source != "regex":
        return False
    return include_test_files or not f.likely_test_fixture


def main():
    parser = argparse.ArgumentParser(description="security-scan")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--ai", action="store_true",
                         help="Enable AI verification of regex findings (true/false positive) + scan for "
                              "additional issues + risk summary (sends real source to the LLM)")
    parser.add_argument("--json", dest="json_out", default=None, help="Write JSON report to this path")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="high",
                         help="Minimum severity that causes a non-zero exit code (default: high).")
    parser.add_argument("--include-test-files", action="store_true",
                         help="Include findings in test/fixture files in the exit-code gate too "
                              "(by default, only applies when AI hasn't explicitly confirmed them as real)")
    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"Error: target does not exist: {target}", file=sys.stderr)
        sys.exit(2)

    result = scan_target(target)

    risk_summary = recommendations = ai_error = None
    if args.ai:
        config = load_config()
        if not config.get("api_key"):
            print("[!] --ai requested but LLM_API_KEY not set in this script's own .env — skipping AI layers.",
                  file=sys.stderr)
        else:
            eligible = len(result.ai_file_contents)
            regex_count_pre = len(result.findings)
            print(_c(f"Starting AI verify+scan: {eligible} file(s) eligible, {regex_count_pre} regex "
                      f"candidate(s) to verify (each file is a separate API call, so this can take a "
                      f"while for large repos)...", Style.DIM), flush=True)
            run_ai_verify_and_scan(result, config)          # verifies regex candidates in place + adds new AI findings
            print(_c("Generating AI risk summary...", Style.DIM), flush=True)

            def _dismissed_for_summary(f: Finding) -> bool:
                if f.ai_verdict == "false_positive":
                    return True
                if f.ai_verdict == "true_positive":
                    return False
                return f.likely_test_fixture and not args.include_test_files

            summary_result = ScanResult(
                findings=[f for f in result.findings if not _dismissed_for_summary(f)],
                files_scanned=result.files_scanned,
            )
            risk_summary, recommendations, ai_error = ai_review(summary_result, config)  # metadata-only, confirmed findings only

    if args.fail_on == "none":
        exit_code = 0
    else:
        threshold_rank = SEVERITY_RANK[args.fail_on]

        def _gates(f: Finding) -> bool:
            if f.source != "regex" or SEVERITY_RANK[f.severity] < threshold_rank:
                return False
            if f.ai_verdict == "false_positive":
                return False  # AI explicitly reviewed this and says it's not real
            if f.ai_verdict == "true_positive":
                return True   # AI explicitly confirmed it — gate regardless of the fixture heuristic
            # No AI verdict (either --ai wasn't used, or this file's AI call failed):
            # fall back to the fast heuristic.
            return args.include_test_files or not f.likely_test_fixture

        exit_code = 2 if any(_gates(f) for f in result.findings) else 0

    print_report(result, str(target), args.ai, risk_summary, recommendations, ai_error, exit_code, args.fail_on,
                 include_test_files=args.include_test_files)

    if args.json_out:
        save_json_report(result, risk_summary, recommendations, exit_code, args.json_out)
        print(f"\n[*] JSON report written to {args.json_out}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
