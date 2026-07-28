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
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from dotenv import load_dotenv

# When this file is run directly (python scanner.py ...), its module name is
# "__main__", not "scanner". web_scan.py / network_scan.py do `from scanner
# import Finding, ...` — without this line, that import would re-execute this
# entire file as a second module (double the regex tables, wasted work). This
# makes "scanner" resolve to the already-loaded module instead.
sys.modules.setdefault("scanner", sys.modules[__name__])

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

# ---------------------------------------------------------------------------
# Phase 2: code-issue patterns beyond hardcoded secrets. These don't capture
# a "secret value" to redact — the whole matched line is safe to show as-is,
# EXCEPT it must still go through cross-finding redaction (see _scan_file):
# if the same line also contains a real secret, that secret gets redacted
# here too, not just in the secret's own finding.
# ---------------------------------------------------------------------------
CODE_PATTERNS = [
    ("eval-call", re.compile(r"\beval\s*\(")),
    ("exec-call", re.compile(r"\bexec\s*\(")),
    ("os-system-call", re.compile(r"\bos\.system\s*\(")),
    ("shell-true", re.compile(r"shell\s*=\s*True")),
    ("md5-hash", re.compile(r"\bhashlib\.md5\s*\(")),
    ("sha1-hash", re.compile(r"\bhashlib\.sha1\s*\(")),
    ("tls-verify-disabled", re.compile(r"verify\s*=\s*False")),
    ("http-url", re.compile(r"\bhttp://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[A-Za-z0-9][A-Za-z0-9.\-]*")),
    ("sql-string-concat", re.compile(
        r"""(?i)["'][^"'\n]*\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^"'\n]*["']\s*\+"""
    )),
    ("sql-fstring", re.compile(
        r"""(?i)f(['"])(?:(?!\1).)*?\b(?:SELECT|INSERT|UPDATE|DELETE)\b(?:(?!\1).)*?\{"""
    )),
    # --- Phase 3a: infra config (Dockerfile / docker-compose / K8s manifests) ---
    # No network access needed — same line-by-line text scanning as everything else.
    ("container-privileged", re.compile(r"(?i)\bprivileged:\s*true\b|--privileged\b")),
    ("container-root-user", re.compile(r"(?im)^\s*USER\s+root\b")),
    ("host-network-mode", re.compile(r"""(?i)network_mode:\s*["']?host["']?|hostNetwork:\s*true""")),
    ("add-remote-fetch", re.compile(r"(?im)^\s*ADD\s+https?://")),
    ("unpinned-base-image", re.compile(r"(?im)^\s*FROM\s+\S+:latest\b")),
    ("allow-privilege-escalation", re.compile(r"(?i)allowPrivilegeEscalation:\s*true")),
    ("docker-socket-mount", re.compile(r"/var/run/docker\.sock")),
    # --- Phase 2b: broader vulnerability classes ---
    ("pickle-loads", re.compile(r"\bpickle\.loads?\s*\(")),
    ("yaml-unsafe-load", re.compile(r"\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)")),
    ("weak-random-for-security", re.compile(r"\brandom\.(random|randint|choice|randrange)\s*\(")),
    ("debug-mode-enabled", re.compile(r"\bDEBUG\s*=\s*True\b|debug\s*=\s*True\b")),
    ("cors-wildcard", re.compile(r"""Access-Control-Allow-Origin['"]?\]?\s*[:=]\s*['"]?\*['"]?""")),
    ("csrf-disabled", re.compile(r"\bcsrf_exempt\b|CSRF_ENABLED\s*=\s*False|WTF_CSRF_ENABLED\s*=\s*False")),
    ("path-traversal-risk", re.compile(r"open\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\+")),
    # --- Phase 2c: XSS sinks, session cookies, JWT, open redirect ---
    ("xss-innerhtml", re.compile(r"\.innerHTML\s*=")),
    ("xss-dangerously-set-html", re.compile(r"dangerouslySetInnerHTML")),
    ("xss-jinja-safe-filter", re.compile(r"\{\{.*\|\s*safe\s*\}\}")),
    ("xss-document-write", re.compile(r"document\.write\s*\(")),
    ("insecure-cookie-flag", re.compile(r"SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False")),
    ("jwt-none-algorithm", re.compile(r"""algorithm\s*[:=]\s*['"]none['"]""")),
    ("jwt-verify-disabled", re.compile(r"jwt\.decode\([^)]*verify\s*=\s*False")),
    ("open-redirect-risk", re.compile(r"redirect\s*\(\s*request\.(args|GET|POST)\.get\(")),
    # --- Phase 2d: SSRF, XXE, weak TLS versions, temp files, shell via popen ---
    ("ssrf-risk", re.compile(r"requests\.(get|post|put|delete)\s*\(\s*request\.(args|GET|POST|form)\.get\(")),
    ("xxe-risk", re.compile(r"(etree\.parse|minidom\.parse|xml\.sax\.parse)\s*\(")),
    ("weak-tls-protocol", re.compile(r"ssl\.(PROTOCOL_SSLv2|PROTOCOL_SSLv3|PROTOCOL_TLSv1\b)")),
    ("insecure-temp-file", re.compile(r"tempfile\.mktemp\s*\(")),
    ("os-popen-call", re.compile(r"os\.popen\s*\(")),
    ("cloud-metadata-ssrf", re.compile(r"169\.254\.169\.254")),
    # --- Phase 2e: large batch, rounding out common vulnerability classes ---
    ("insecure-file-permissions", re.compile(r"os\.chmod\s*\([^)]*0o?7{2,3}\b")),
    ("nosql-injection", re.compile(r"""\$where['"]?\s*:\s*.*\+""")),
    ("ssti-risk", re.compile(r"render_template_string\s*\(\s*request\.")),
    ("ldap-injection-risk", re.compile(r"(?i)(?=.*ldap)search_s?\([^)]*\+")),
    ("weak-password-hashing", re.compile(r"(?i)hashlib\.(sha256|sha512)\s*\(\s*password")),
    ("hardcoded-iv-static", re.compile(r"""\biv\s*=\s*b?['"][^'"]{8,32}['"]""")),
    ("hardcoded-jwt-secret", re.compile(r"""jwt\.encode\([^)]*,\s*['"][^'"]{8,}['"]""")),
    ("sql-percent-format", re.compile(
        r"""(?i)['"][^'"\n]*\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^'"\n]*['"]\s*%\s*[(\w]"""
    )),
    ("sql-dot-format", re.compile(
        r"""(?i)['"][^'"\n]*\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^'"\n]*\{\}[^'"\n]*['"]\.format\("""
    )),
    ("yaml-full-load-unsafe", re.compile(r"\byaml\.full_load\s*\(")),
    ("weak-cipher-legacy", re.compile(r"(?i)\b(DES|RC4|ARC4)\.new\s*\(")),
    ("ecb-cipher-mode", re.compile(r"MODE_ECB")),
    ("flask-secret-key-hardcoded", re.compile(r"""(?i)(app\.secret_key|SECRET_KEY)\s*=\s*['"][^'"]{4,}['"]""")),
]

CATEGORY_BY_RULE = {
    "aws-access-key": "hardcoded-secret",
    "private-key-block": "hardcoded-secret",
    "github-token": "hardcoded-secret",
    "stripe-key": "hardcoded-secret",
    "slack-token": "hardcoded-secret",
    "google-api-key": "hardcoded-secret",
    "api-key-assignment": "hardcoded-secret",
    "secret-assignment": "hardcoded-secret",
    "password-assignment": "hardcoded-secret",
    "eval-call": "dangerous-call",
    "exec-call": "dangerous-call",
    "os-system-call": "dangerous-call",
    "shell-true": "dangerous-call",
    "md5-hash": "weak-crypto",
    "sha1-hash": "weak-crypto",
    "tls-verify-disabled": "insecure-transport",
    "http-url": "insecure-transport",
    "sql-string-concat": "sql-injection",
    "sql-fstring": "sql-injection",
    "container-privileged": "infra-misconfig",
    "container-root-user": "infra-misconfig",
    "host-network-mode": "infra-misconfig",
    "add-remote-fetch": "infra-misconfig",
    "unpinned-base-image": "infra-misconfig",
    "allow-privilege-escalation": "infra-misconfig",
    "docker-socket-mount": "infra-misconfig",
    "pickle-loads": "insecure-deserialization",
    "yaml-unsafe-load": "insecure-deserialization",
    "weak-random-for-security": "weak-crypto",
    "debug-mode-enabled": "debug-mode-exposed",
    "cors-wildcard": "insecure-transport",
    "csrf-disabled": "csrf-disabled",
    "path-traversal-risk": "path-traversal",
    "xss-innerhtml": "xss",
    "xss-dangerously-set-html": "xss",
    "xss-jinja-safe-filter": "xss",
    "xss-document-write": "xss",
    "insecure-cookie-flag": "insecure-cookie",
    "jwt-none-algorithm": "jwt-misconfig",
    "jwt-verify-disabled": "jwt-misconfig",
    "open-redirect-risk": "open-redirect",
    "ssrf-risk": "ssrf",
    "xxe-risk": "xxe",
    "weak-tls-protocol": "insecure-transport",
    "insecure-temp-file": "insecure-temp-file",
    "os-popen-call": "dangerous-call",
    "cloud-metadata-ssrf": "ssrf",
    "insecure-file-permissions": "insecure-file-permissions",
    "nosql-injection": "nosql-injection",
    "ssti-risk": "ssti",
    "ldap-injection-risk": "ldap-injection",
    "weak-password-hashing": "weak-crypto",
    "hardcoded-iv-static": "weak-crypto",
    "hardcoded-jwt-secret": "hardcoded-secret",
    "sql-percent-format": "sql-injection",
    "sql-dot-format": "sql-injection",
    "yaml-full-load-unsafe": "insecure-deserialization",
    "weak-cipher-legacy": "weak-crypto",
    "ecb-cipher-mode": "weak-crypto",
    "flask-secret-key-hardcoded": "hardcoded-secret",

    # --- web_scan.py rules ---
    "missing-hsts": "web-security-headers",
    "missing-csp": "web-security-headers",
    "missing-x-content-type-options": "web-security-headers",
    "missing-x-frame-options": "web-security-headers",
    "missing-referrer-policy": "web-security-headers",
    "missing-permissions-policy": "web-security-headers",
    "cookie-missing-secure": "web-security-headers",
    "cookie-missing-httponly": "web-security-headers",
    "server-header-disclosure": "web-security-headers",
    "no-https": "web-tls",
    "tls-cert-expired": "web-tls",
    "tls-cert-expiring-soon": "web-tls",
    "tls-outdated-protocol": "web-tls",
    "tls-handshake-failed": "web-tls",
    "reflected-xss": "web-xss",
    "sql-injection-error-based": "web-sql-injection",

    # --- network_scan.py rules ---
    "open-port": "network-exposure",
    "risky-service-exposed": "network-exposure",
    "outdated-service-banner": "network-exposure",
}

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
    "eval-call": "high",
    "exec-call": "high",
    "os-system-call": "high",
    "shell-true": "high",
    "md5-hash": "medium",
    "sha1-hash": "medium",
    "tls-verify-disabled": "high",
    "http-url": "low",
    "sql-string-concat": "high",
    "sql-fstring": "high",
    "container-privileged": "critical",
    "container-root-user": "high",
    "host-network-mode": "high",
    "add-remote-fetch": "medium",
    "unpinned-base-image": "medium",
    "allow-privilege-escalation": "high",
    "docker-socket-mount": "critical",
    "pickle-loads": "high",
    "yaml-unsafe-load": "high",
    "weak-random-for-security": "medium",
    "debug-mode-enabled": "medium",
    "cors-wildcard": "medium",
    "csrf-disabled": "high",
    "path-traversal-risk": "high",
    "xss-innerhtml": "high",
    "xss-dangerously-set-html": "high",
    "xss-jinja-safe-filter": "high",
    "xss-document-write": "medium",
    "insecure-cookie-flag": "medium",
    "jwt-none-algorithm": "critical",
    "jwt-verify-disabled": "critical",
    "open-redirect-risk": "medium",
    "ssrf-risk": "high",
    "xxe-risk": "high",
    "weak-tls-protocol": "high",
    "insecure-temp-file": "medium",
    "os-popen-call": "high",
    "cloud-metadata-ssrf": "critical",
    "insecure-file-permissions": "medium",
    "nosql-injection": "high",
    "ssti-risk": "critical",
    "ldap-injection-risk": "high",
    "weak-password-hashing": "high",
    "hardcoded-iv-static": "high",
    "hardcoded-jwt-secret": "critical",
    "sql-percent-format": "high",
    "sql-dot-format": "high",
    "yaml-full-load-unsafe": "high",
    "weak-cipher-legacy": "high",
    "ecb-cipher-mode": "high",
    "flask-secret-key-hardcoded": "critical",
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
    "eval-call": "use of eval() on potentially untrusted input",
    "exec-call": "use of exec() on potentially untrusted input",
    "os-system-call": "shell command execution via os.system()",
    "shell-true": "subprocess call with shell=True",
    "md5-hash": "MD5 used, a cryptographically broken hash",
    "sha1-hash": "SHA1 used, a cryptographically weak hash",
    "tls-verify-disabled": "TLS certificate verification disabled",
    "http-url": "plain HTTP URL (unencrypted transport)",
    "sql-string-concat": "SQL query built via string concatenation",
    "sql-fstring": "SQL query built via f-string interpolation",
    "container-privileged": "container running in privileged mode",
    "container-root-user": "container explicitly set to run as root",
    "host-network-mode": "container sharing the host's network namespace",
    "add-remote-fetch": "Dockerfile ADD fetching a remote URL directly",
    "unpinned-base-image": "base image pinned to :latest instead of a specific version",
    "allow-privilege-escalation": "Kubernetes pod allows privilege escalation",
    "docker-socket-mount": "Docker socket mounted into the container",
    "pickle-loads": "unpickling data with pickle.loads() (can execute arbitrary code)",
    "yaml-unsafe-load": "yaml.load() without SafeLoader (can execute arbitrary code)",
    "weak-random-for-security": "random module used where cryptographic randomness may be needed",
    "debug-mode-enabled": "debug mode left enabled",
    "cors-wildcard": "CORS configured to allow any origin (*)",
    "csrf-disabled": "CSRF protection disabled",
    "path-traversal-risk": "file path built via string concatenation with a variable",
    "xss-innerhtml": "unsanitized data assigned to innerHTML",
    "xss-dangerously-set-html": "React dangerouslySetInnerHTML with unsanitized data",
    "xss-jinja-safe-filter": "Jinja2 |safe filter disabling auto-escaping",
    "xss-document-write": "document.write() with potentially unsanitized data",
    "insecure-cookie-flag": "session cookie Secure/HttpOnly flag disabled",
    "jwt-none-algorithm": "JWT accepting the 'none' algorithm (no signature verification)",
    "jwt-verify-disabled": "JWT decoded with signature verification disabled",
    "open-redirect-risk": "redirect target taken directly from user-controlled input",
    "ssrf-risk": "outbound HTTP request built directly from user-controlled input",
    "xxe-risk": "XML parsed without disabling external entity resolution",
    "weak-tls-protocol": "deprecated/insecure SSL/TLS protocol version explicitly selected",
    "insecure-temp-file": "tempfile.mktemp() used (race-condition-prone, deprecated)",
    "os-popen-call": "shell command execution via os.popen()",
    "cloud-metadata-ssrf": "hardcoded reference to the cloud instance metadata IP (169.254.169.254)",
    "insecure-file-permissions": "file permissions set to world-writable (0o777)",
    "nosql-injection": "MongoDB $where query built via string concatenation",
    "ssti-risk": "server-side template rendered directly from user input",
    "ldap-injection-risk": "LDAP search filter built via string concatenation",
    "weak-password-hashing": "password hashed with a fast general-purpose hash instead of a proper KDF",
    "hardcoded-iv-static": "hardcoded/static initialization vector (IV) for encryption",
    "hardcoded-jwt-secret": "JWT signing secret hardcoded as a string literal",
    "sql-percent-format": "SQL query built via %-style string formatting",
    "sql-dot-format": "SQL query built via .format() string interpolation",
    "yaml-full-load-unsafe": "yaml.full_load() used (can still instantiate unsafe objects)",
    "weak-cipher-legacy": "legacy/broken cipher (DES, RC4) used",
    "ecb-cipher-mode": "ECB cipher mode used (does not hide data patterns)",
    "flask-secret-key-hardcoded": "Flask/app secret key hardcoded as a string literal",
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
    "eval-call": "If any part of the evaluated string is influenced by user/external input, this allows arbitrary code execution.",
    "exec-call": "If any part of the executed string is influenced by user/external input, this allows arbitrary code execution.",
    "os-system-call": "If any part of the command is influenced by user/external input, this allows arbitrary shell command execution.",
    "shell-true": "If the command or its arguments include user/external input, this allows shell injection (arbitrary command execution).",
    "md5-hash": "MD5 collisions are practical to generate — unsafe for password hashing, integrity checks, or anything security-sensitive.",
    "sha1-hash": "SHA1 collisions are practical to generate — unsafe for anything security-sensitive, including certificate/commit integrity.",
    "tls-verify-disabled": "Traffic can be intercepted or tampered with via a man-in-the-middle attack without detection.",
    "http-url": "Traffic sent to this URL is unencrypted and can be intercepted, read, or modified in transit.",
    "sql-string-concat": "If any concatenated value comes from user input, this allows SQL injection — full database read/write/delete access.",
    "sql-fstring": "If any interpolated value comes from user input, this allows SQL injection — full database read/write/delete access.",
    "container-privileged": "A privileged container has near-full access to the host — a container escape here means full host compromise, not just container compromise.",
    "container-root-user": "Any vulnerability in the containerized app (e.g. a code execution bug) runs as root inside the container, worsening the blast radius of an escape.",
    "host-network-mode": "The container can see and bind to the host's network interfaces directly, bypassing container network isolation — exposes host services and weakens network segmentation.",
    "add-remote-fetch": "The fetched content isn't pinned/verified — if the remote source is compromised or the connection is intercepted, malicious content gets baked into the image.",
    "unpinned-base-image": ":latest can silently change between builds, pulling in unreviewed code/dependencies and making builds non-reproducible — a supply-chain and stability risk.",
    "allow-privilege-escalation": "A process in the pod can gain more privileges than its parent (e.g. via setuid binaries), undermining the pod's security boundary.",
    "docker-socket-mount": "Access to the Docker socket is equivalent to root on the host — a compromised container with this mount can control or escape to the host entirely.",
    "pickle-loads": "Unpickling untrusted/attacker-influenced data can execute arbitrary code — pickle is not a data format, it's a code-execution mechanism.",
    "yaml-unsafe-load": "The default YAML loader can be tricked into instantiating arbitrary Python objects, leading to code execution from a malicious YAML file.",
    "weak-random-for-security": "If this value is used for a token, password, session ID, or anything security-sensitive, it's predictable — an attacker can guess or brute-force it far more easily than a real random value.",
    "debug-mode-enabled": "Debug mode typically exposes stack traces, source code, environment variables, and sometimes an interactive debugger/console to anyone who triggers an error.",
    "cors-wildcard": "Any website can make authenticated cross-origin requests to this endpoint, potentially reading responses that should be restricted to your own origin.",
    "csrf-disabled": "An attacker can trick a logged-in user's browser into submitting unwanted requests (state changes, purchases, account changes) without their consent.",
    "path-traversal-risk": "If the variable comes from user input and isn't validated, an attacker can use ../ sequences to read or write files outside the intended directory.",
    "xss-innerhtml": "If the assigned value includes user input, an attacker can inject and execute arbitrary HTML/JavaScript in the victim's browser session.",
    "xss-dangerously-set-html": "React normally escapes content automatically — this bypasses that protection, so unsanitized data here executes as real HTML/JS in the browser.",
    "xss-jinja-safe-filter": "Auto-escaping is Jinja2's main XSS defense — marking user-influenced content as |safe disables it for that content specifically.",
    "xss-document-write": "Content written this way isn't escaped — if it includes user-controlled data (e.g. from the URL), it can execute arbitrary script.",
    "insecure-cookie-flag": "Without Secure, the cookie can be sent over plain HTTP and intercepted; without HttpOnly, JavaScript (including injected XSS payloads) can read it.",
    "jwt-none-algorithm": "An attacker can forge a token with 'alg: none' and no signature at all, and the app will accept it as valid — complete authentication bypass.",
    "jwt-verify-disabled": "Any token, including one an attacker crafted with arbitrary claims, will be accepted as valid — complete authentication bypass.",
    "open-redirect-risk": "An attacker can craft a link to your trusted domain that redirects victims to a malicious site, often used in phishing.",
    "ssrf-risk": "An attacker can make the server issue requests to internal-only services, cloud metadata endpoints, or arbitrary external hosts on the server's behalf.",
    "xxe-risk": "A malicious XML document can read local files, make the server issue outbound requests (SSRF), or in some cases cause denial of service.",
    "weak-tls-protocol": "These protocol versions have known cryptographic weaknesses and are vulnerable to attacks like POODLE and BEAST — connections aren't genuinely secure.",
    "insecure-temp-file": "mktemp() creates a filename then returns it without creating the file atomically — a race condition lets an attacker create/symlink that path first.",
    "os-popen-call": "If any part of the command is influenced by user/external input, this allows arbitrary shell command execution.",
    "cloud-metadata-ssrf": "The cloud metadata endpoint can expose IAM credentials, instance secrets, and other sensitive configuration if reachable by an attacker.",
    "insecure-file-permissions": "Any local user or process can read, modify, or replace this file — a significant risk on shared or multi-tenant systems.",
    "nosql-injection": "If any concatenated value comes from user input, an attacker can inject operators to bypass query logic or extract unauthorized data.",
    "ssti-risk": "If the template engine evaluates the input as a template (not just a string), an attacker can achieve remote code execution.",
    "ldap-injection-risk": "An attacker can inject LDAP filter syntax to bypass authentication or extract directory data beyond what's intended.",
    "weak-password-hashing": "Fast hashes like SHA-256 are designed for speed, which makes brute-forcing/cracking leaked password hashes far easier than with a proper password KDF.",
    "hardcoded-iv-static": "Reusing the same IV across encryptions (especially with certain modes) can leak information about the plaintext or fully break confidentiality.",
    "hardcoded-jwt-secret": "Anyone with access to the source (or a leaked copy) can forge validly-signed tokens for any user — complete authentication bypass.",
    "sql-percent-format": "If any formatted value comes from user input, this allows SQL injection — full database read/write/delete access.",
    "sql-dot-format": "If any formatted value comes from user input, this allows SQL injection — full database read/write/delete access.",
    "yaml-full-load-unsafe": "full_load is safer than the bare default loader but can still construct some unsafe Python objects depending on the PyYAML version.",
    "weak-cipher-legacy": "DES and RC4 have known practical attacks and are considered broken — data encrypted with them should be treated as effectively unprotected.",
    "ecb-cipher-mode": "ECB encrypts identical plaintext blocks identically, so patterns in the original data remain visible in the ciphertext.",
    "flask-secret-key-hardcoded": "This key signs session cookies and other security tokens — anyone with it can forge valid sessions and impersonate any user.",
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
    "eval-call": "Avoid eval() entirely where possible; if dynamic evaluation is required, use a restricted parser (e.g. ast.literal_eval) instead.",
    "exec-call": "Avoid exec() entirely where possible; refactor to avoid dynamic code execution, or strictly validate/allowlist the input first.",
    "os-system-call": "Use subprocess.run() with an argument list (not shell=True) instead of os.system(), so arguments are never shell-interpreted.",
    "shell-true": "Pass the command as a list without shell=True, or if a shell is genuinely required, strictly validate/escape every interpolated value.",
    "md5-hash": "Use SHA-256 or better for integrity checks; use bcrypt/scrypt/argon2 (never a raw hash) for password storage.",
    "sha1-hash": "Use SHA-256 or better for integrity/signing; use bcrypt/scrypt/argon2 (never a raw hash) for password storage.",
    "tls-verify-disabled": "Remove verify=False and fix the underlying certificate issue (e.g. install/trust the correct CA) instead of disabling verification.",
    "http-url": "Switch to https:// for this endpoint; if it's genuinely a local/internal-only address, confirm it's excluded from this check intentionally.",
    "sql-string-concat": "Use parameterized queries / prepared statements (e.g. cursor.execute(query, params)) instead of building SQL via string concatenation.",
    "sql-fstring": "Use parameterized queries / prepared statements (e.g. cursor.execute(query, params)) instead of interpolating values into SQL strings.",
    "container-privileged": "Remove --privileged / privileged: true; grant only the specific Linux capabilities the container actually needs instead.",
    "container-root-user": "Add a non-root USER directive (create a dedicated user in the Dockerfile) and drop root before the container's entrypoint runs.",
    "host-network-mode": "Remove host network mode unless there's a specific, documented reason; use standard container networking with explicit port mappings instead.",
    "add-remote-fetch": "Use COPY for local files, or RUN curl/wget with a checksum verification step, instead of ADD with a remote URL.",
    "unpinned-base-image": "Pin the base image to a specific version tag (or digest) so builds are reproducible and reviewed before the base image changes.",
    "allow-privilege-escalation": "Set allowPrivilegeEscalation: false in the pod's securityContext unless a specific workload genuinely requires it.",
    "docker-socket-mount": "Avoid mounting the Docker socket into containers; if container management is genuinely needed, use a proxy with restricted API access instead.",
    "pickle-loads": "Avoid pickle for untrusted data — use JSON or another safe, data-only serialization format instead.",
    "yaml-unsafe-load": "Use yaml.safe_load() (or yaml.load(f, Loader=yaml.SafeLoader)) instead — it only builds basic Python types, never arbitrary objects.",
    "weak-random-for-security": "Use the secrets module (e.g. secrets.token_hex(), secrets.choice()) for anything security-sensitive — random is fine for non-security randomness only.",
    "debug-mode-enabled": "Ensure debug mode is disabled in production, ideally driven by an environment variable that defaults to False.",
    "cors-wildcard": "Restrict Access-Control-Allow-Origin to a specific allowlist of trusted origins instead of using a wildcard, especially if credentials are involved.",
    "csrf-disabled": "Re-enable CSRF protection; if a specific endpoint genuinely needs an exemption, scope it narrowly and document why.",
    "path-traversal-risk": "Validate/sanitize the input (e.g. reject '..' segments) or resolve the path and confirm it's still within the intended base directory before opening it.",
    "xss-innerhtml": "Use .textContent for plain text, or sanitize with a library like DOMPurify before assigning to innerHTML if HTML rendering is genuinely needed.",
    "xss-dangerously-set-html": "Avoid dangerouslySetInnerHTML where possible; if needed, sanitize the content with DOMPurify first.",
    "xss-jinja-safe-filter": "Remove |safe unless the content is genuinely trusted/already sanitized — let Jinja2's default auto-escaping handle user-influenced content.",
    "xss-document-write": "Avoid document.write() with dynamic data; use safe DOM APIs (textContent, or a sanitizer) instead.",
    "insecure-cookie-flag": "Set SESSION_COOKIE_SECURE = True and SESSION_COOKIE_HTTPONLY = True (the framework defaults exist for a reason — don't override them to False).",
    "jwt-none-algorithm": "Explicitly specify and enforce the expected algorithm(s) (e.g. algorithms=['HS256']) when decoding — never accept 'none'.",
    "jwt-verify-disabled": "Remove verify=False and always verify the signature; if you need to inspect an unverified token for debugging, make that an explicit, clearly-labeled code path.",
    "open-redirect-risk": "Validate the redirect target against an allowlist of known-safe paths/domains before redirecting, rather than trusting it directly.",
    "ssrf-risk": "Validate/allowlist the target URL's host before requesting it, and block requests to internal IP ranges and the cloud metadata address.",
    "xxe-risk": "Use a library like defusedxml, or explicitly disable external entity resolution on the parser before parsing untrusted XML.",
    "weak-tls-protocol": "Use ssl.PROTOCOL_TLS_CLIENT (or TLS 1.2+) instead — let the library negotiate a modern, secure protocol version.",
    "insecure-temp-file": "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp(), which create the file atomically and avoid the race condition.",
    "os-popen-call": "Use subprocess.run() with an argument list (not shell=True) instead of os.popen(), so arguments are never shell-interpreted.",
    "cloud-metadata-ssrf": "Remove hardcoded access to this endpoint from application code; if genuinely needed, restrict it to trusted internal-only code paths with strict access controls.",
    "insecure-file-permissions": "Use the minimum permissions needed (e.g. 0o600 or 0o644) instead of world-writable 0o777.",
    "nosql-injection": "Use the query builder's parameterized/safe query methods instead of building query operators from raw string concatenation.",
    "ssti-risk": "Never pass user input directly as a template string; use render_template() with a fixed template file and pass user data only as variables.",
    "ldap-injection-risk": "Escape special LDAP filter characters in user input (or use a library that does this) before building the filter string.",
    "weak-password-hashing": "Use a dedicated password hashing library (bcrypt, scrypt, or argon2) instead of a raw cryptographic hash function.",
    "hardcoded-iv-static": "Generate a fresh random IV for every encryption operation (e.g. os.urandom(16)) — never reuse or hardcode it.",
    "hardcoded-jwt-secret": "Load the signing secret from an environment variable or secrets manager, and use a long, randomly generated value.",
    "sql-percent-format": "Use parameterized queries / prepared statements (e.g. cursor.execute(query, params)) instead of %-formatting SQL strings.",
    "sql-dot-format": "Use parameterized queries / prepared statements (e.g. cursor.execute(query, params)) instead of .format()-ing SQL strings.",
    "yaml-full-load-unsafe": "Use yaml.safe_load() instead, which is guaranteed to only construct basic Python types.",
    "weak-cipher-legacy": "Use a modern authenticated cipher like AES-GCM or ChaCha20-Poly1305 instead of DES or RC4.",
    "ecb-cipher-mode": "Use an authenticated mode like GCM, or at minimum CBC with a random IV, instead of ECB.",
    "flask-secret-key-hardcoded": "Load the secret key from an environment variable or secrets manager, and use a long, randomly generated value — never a hardcoded string.",
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
    ai_file_contents: dict = field(default_factory=dict)   # rel_path/url/host -> text, for units within the AI size cap
    ai_target_kind: dict = field(default_factory=dict)      # rel_path/url/host -> "code" | "web" | "network"
    ai_scan_errors: list = field(default_factory=list)      # (rel_path, error) for units where the AI scan itself failed

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

        # Determine once whether this line contains a real (non-placeholder)
        # secret, and compute the redacted version of the line. Every finding
        # on this line — the secret finding itself AND any code-issue finding
        # — uses this SAME redacted text, so a secret can never leak through
        # a co-occurring finding's evidence (e.g. PASSWORD = "x"; eval(y)).
        display_text = line
        secret_hit = None
        for rule, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            value = match.group(1)
            if is_placeholder(value):
                break
            display_text = line[:match.start(1)] + "[REDACTED]" + line[match.end(1):]
            secret_hit = rule
            break

        if secret_hit:
            result.findings.append(Finding(
                rule=secret_hit,
                severity=SEVERITY.get(secret_hit, "medium"),
                file=rel_path,
                line=line_no,
                display_line=display_text.strip(),
                description=DESCRIPTION.get(secret_hit, "possible hardcoded secret"),
                likely_test_fixture=is_test_or_fixture_file(rel_path),
                impact=IMPACT.get(secret_hit, "Could allow an attacker to impersonate this application or access whatever the credential protects."),
                improvement=IMPROVEMENT.get(secret_hit, "Rotate this credential and move it to environment variables or a secrets manager."),
            ))
            file_finding_count += 1

        for rule, pattern in CODE_PATTERNS:
            if file_finding_count >= MAX_FINDINGS_PER_FILE:
                break
            match = pattern.search(display_text)  # search the (possibly redacted) text, never the raw line
            if not match:
                continue
            result.findings.append(Finding(
                rule=rule,
                severity=SEVERITY.get(rule, "medium"),
                file=rel_path,
                line=line_no,
                display_line=display_text.strip(),
                description=DESCRIPTION.get(rule, "possible code security issue"),
                likely_test_fixture=is_test_or_fixture_file(rel_path),
                impact=IMPACT.get(rule, "Could introduce a security weakness depending on how this code path is used."),
                improvement=IMPROVEMENT.get(rule, "Review and remediate this pattern at its source."),
            ))
            file_finding_count += 1

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


_AI_VERIFY_AND_SCAN_INTRO = {
    "code": """You are a security code reviewer. You will be shown the content of ONE source
file, and a list of candidate findings an automated regex scanner already
flagged in this file (by line number).""",
    "web": """You are a web application security reviewer. You will be shown the collected
scan evidence for ONE web target (response headers, cookies, TLS/certificate
info, and any crawl/injection-test results), and a list of candidate findings
an automated scanner already flagged (each tagged with a reference line
number from the evidence text below, not a source file line).""",
    "network": """You are a network security reviewer. You will be shown the collected scan
evidence for ONE host (open ports, detected services, and any grabbed
banners), and a list of candidate findings an automated scanner already
flagged (each tagged with a reference line number from the evidence text
below, not a source file line).""",
}

_AI_VERIFY_STEP = {
    "code": """1. VERIFY each candidate finding. Look at the actual line AND its surrounding
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
   candidate given to you, one verdict each.""",
    "web": """1. VERIFY each candidate finding against the evidence given. Decide: is this
   a real, currently-present issue on this target (true_positive), or does
   the evidence actually contradict it — e.g. the header is present after
   all, the cookie IS flagged Secure, the "reflected" payload was actually
   escaped, the site errored out unrelated to the payload (false_positive)?

   Only mark true_positive when the evidence text itself supports the
   finding. Give a short reason either way — you must classify every
   candidate given to you, one verdict each.""",
    "network": """1. VERIFY each candidate finding against the evidence given. Decide: is this
   a real, currently-present issue — e.g. the port is genuinely open and the
   banner confirms a risky/outdated service (true_positive) — or does the
   evidence suggest it's likely a transient/misidentified result, such as a
   banner that doesn't actually match the assumed service (false_positive)?

   Only mark true_positive when the evidence text itself supports the
   finding. Give a short reason either way — you must classify every
   candidate given to you, one verdict each.""",
}

_AI_SCAN_STEP = {
    "code": """2. SCAN for ADDITIONAL issues not already in the candidate list: dangerous
   calls (eval/exec/os.system), SQL injection via string concatenation, XSS
   sinks, insecure transport (verify=False, http://), weak crypto
   (MD5/SHA1), missing auth checks, or other hardcoded secrets the
   candidates missed.""",
    "web": """2. SCAN for ADDITIONAL issues visible in this evidence but not already in the
   candidate list: other missing/misconfigured security headers, weak or
   permissive CORS, session cookie issues, TLS weaknesses, information
   disclosure in headers/banners, or injection signatures the candidates
   missed.""",
    "network": """2. SCAN for ADDITIONAL issues visible in this evidence but not already in the
   candidate list: other risky exposed services, banners suggesting
   outdated/unsupported software, or unusual port combinations that suggest
   a misconfiguration the candidates missed.""",
}

_AI_CRITICAL_RULE = {
    "code": "CRITICAL RULE: Never include the actual secret/credential VALUE anywhere in\nyour response — describe type and location only.\n\n",
    "web": "",
    "network": "",
}


def _build_ai_verify_and_scan_prompt(kind: str) -> str:
    intro = _AI_VERIFY_AND_SCAN_INTRO.get(kind, _AI_VERIFY_AND_SCAN_INTRO["code"])
    verify_step = _AI_VERIFY_STEP.get(kind, _AI_VERIFY_STEP["code"])
    scan_step = _AI_SCAN_STEP.get(kind, _AI_SCAN_STEP["code"])
    critical_rule = _AI_CRITICAL_RULE.get(kind, _AI_CRITICAL_RULE["code"])
    return f"""{intro}

Your job has two parts:

{verify_step}

   Never quote source lines verbatim in "reason" or "description" — summarize
   in your own plain words. This avoids broken JSON when lines contain quote
   characters. Output strict, valid JSON: double-quoted keys and strings
   only, no trailing commas.

{scan_step}

{critical_rule}Respond ONLY with JSON (no markdown fences, no preamble):
{{
  "verifications": [
    {{"line": <int>, "verdict": "true_positive"|"false_positive", "reason": "<short reason>"}}
  ],
  "additional_findings": [
    {{"rule": "<short-kebab-case-slug>", "line": <int>, "severity": "critical"|"high"|"medium"|"low",
     "description": "<1 sentence, plain language, never include secret values>",
     "impact": "<1 sentence: what could actually go wrong if this is real>",
     "fix": "<1 sentence: the concrete remediation step>"}}
  ]
}}

Use "critical" severity only for something that gives near-total system/account
compromise on its own (e.g. a live cloud provider key, a private key, full DB
admin credentials, complete auth bypass). Use "high" for other serious issues,
"medium"/"low" for lesser ones.

"verifications" must include exactly one entry per candidate finding you were given.
"additional_findings" may be an empty list if there's nothing new.
"""


# Kept for backwards compatibility with any external code importing this name directly.
AI_VERIFY_AND_SCAN_PROMPT = _build_ai_verify_and_scan_prompt("code")


def _candidate_ref(index: int, candidate, kind: str) -> int:
    """The integer each candidate is identified by in the AI exchange.

    For code, this is the real source line number (candidate.line), which is
    both meaningful to the model and already unique per candidate. For
    web/network, candidate.line is either always 0 (web — findings aren't
    line-addressable) or a port number (network — unique, but reused here as
    a stable id rather than a "line"). Web findings would collide on 0 if we
    used candidate.line directly, silently applying one verdict to every
    finding on the target, so web always gets a synthetic 1-based id instead.
    Network keeps its port number since ports are already unique per host."""
    if kind == "web":
        return index + 1
    return candidate.line


def ai_verify_and_scan_file(rel_path: str, content: str, candidates: list, config: dict,
                             max_retries: int = 3, kind: str = "code"):
    """Sends one unit's content (source file text for code, or a synthesized
    evidence dump for web/network targets) plus its regex candidate findings
    to the model in a single call. Returns (verifications: dict[ref ->
    (verdict, reason)], additional_findings: list[Finding], error: str|None).
    `ref` is the candidate's real line number for code, or the id produced by
    _candidate_ref for web/network — callers must use the same function to
    map verifications back onto candidates."""
    try:
        from openai import OpenAI
    except ImportError:
        return {}, [], "'openai' package not installed"

    client = OpenAI(api_key=config["api_key"], base_url=config["base_url"])
    system_prompt = _build_ai_verify_and_scan_prompt(kind)
    numbered = "\n".join(f"{i+1}: {line}" for i, line in enumerate(content.splitlines()))
    refs = [_candidate_ref(i, c, kind) for i, c in enumerate(candidates)]
    candidate_desc = "\n".join(
        f"- line {ref}: {c.rule} ({c.description})" for ref, c in zip(refs, candidates)
    ) or "(none — just scan for additional issues)"
    required_lines = ", ".join(str(ref) for ref in refs)
    required_note = (
        f"\n\nYou MUST include exactly one \"verifications\" entry for each of these line "
        f"numbers: [{required_lines}]. Do not skip any."
        if candidates else ""
    )
    label = "File" if kind == "code" else ("Web target" if kind == "web" else "Host")
    content_label = "Full file content" if kind == "code" else "Collected evidence"
    user_prompt = (
        f"{label}: {rel_path}\n\nCandidate findings from the automated scanner:\n{candidate_desc}{required_note}\n\n"
        f"{content_label}:\n{numbered}"
    )

    delay = 1.0
    last_error = None
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=config["model"],
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=8000,
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
                # For web/network, the AI's "line" refers to a position in the
                # synthesized evidence dump, not a real source line or port —
                # showing it as e.g. "https://x:8" would misleadingly look
                # like a port number, so it's suppressed for those kinds.
                finding_line = int(item.get("line", 0) or 0) if kind == "code" else 0
                additional.append(Finding(
                    rule=_clean_rule_slug(str(item.get("rule", "ai-finding"))),
                    severity=sev,
                    file=rel_path,
                    line=finding_line,
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
    """For every unit the scan(s) covered — source files (code), or the
    synthesized evidence dump for a web target / network host — sends its
    content + that unit's candidate findings to the AI in one call: verifies
    each candidate as true/false positive (applied in place onto the
    existing Finding — no duplicate entries), and appends any genuinely new
    findings the AI spots."""
    total = len(result.ai_file_contents)
    durations = []
    regex_by_file = {}
    for f in result.findings:
        regex_by_file.setdefault(f.file, []).append(f)

    for i, (rel_path, content) in enumerate(result.ai_file_contents.items(), 1):
        candidates = regex_by_file.get(rel_path, [])
        kind = result.ai_target_kind.get(rel_path, "code")
        if show_progress:
            eta_str = ""
            if durations:
                avg = sum(durations) / len(durations)
                remaining = avg * (total - i + 1)
                eta_str = f"  (est. {_fmt_duration(remaining)} remaining)"
            note = f", verifying {len(candidates)} candidate(s)" if candidates else ""
            print(_c(f"[{i}/{total}] AI reviewing {rel_path}{note}...{eta_str}", Style.DIM), flush=True)

        t0 = time.time()
        verifications, additional, error = ai_verify_and_scan_file(rel_path, content, candidates, config, kind=kind)
        durations.append(time.time() - t0)

        if error:
            result.ai_scan_errors.append((rel_path, error))
            continue

        for idx, c in enumerate(candidates):
            ref = _candidate_ref(idx, c, kind)
            if ref in verifications:
                verdict, reason = verifications[ref]
                c.ai_verdict = verdict
                c.ai_reason = reason
            else:
                # AI call for this unit succeeded, but the model didn't return a
                # verdict for this specific candidate — distinct from never
                # being reviewed at all (e.g. --ai not used, or the call failed).
                c.ai_reason = "AI reviewed this target but returned no verdict for this specific finding"

        result.findings.extend(additional)

    if show_progress and total:
        total_elapsed = sum(durations)
        print(_c(f"AI verify+scan done: {total} unit(s) in {_fmt_duration(total_elapsed)}.", Style.DIM), flush=True)


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
                max_tokens=2000,
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

    clean_count = result.files_scanned - len({f.file for f in main_findings}) - len({f.file for f in dismissed_findings if f.file not in {x.file for x in main_findings}})
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
        by_category = defaultdict(list)
        for f in main_findings:
            cat = CATEGORY_BY_RULE.get(f.rule, f.rule)
            by_category[cat].append(f)
        for flist in by_category.values():
            flist.sort(key=_sev_rank, reverse=True)
        categories_by_worst = sorted(
            by_category.keys(),
            key=lambda c: (max(_sev_rank(f) for f in by_category[c]), len(by_category[c])),
            reverse=True,
        )
        for cat in categories_by_worst:
            flist = by_category[cat]
            worst = flist[0].severity
            print()
            print(_c(f"=== {cat} ===", Style.BRIGHT) + _c(f"  ({len(flist)} finding(s), worst: {worst})", SEV_COLOR.get(worst, "")))
            for f in flist:
                tag = _c(f"[{f.severity.upper()}]", SEV_COLOR.get(f.severity, ""))
                confirm = _c(" ✓AI-confirmed", Fore.GREEN) if f.ai_verdict == "true_positive" else (_c(" (ai-found)", Fore.CYAN) if f.source == "ai" else "")
                loc = f"{f.file}:{f.line}" if f.line else f.file
                print(f"  {tag}{confirm}  —  {_c(loc, Style.BRIGHT)}")
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
        print(_c(f"Possible False Positives / Unverified ({len(dismissed_findings)})", Style.BRIGHT))
        print(_c("These were dismissed by AI review or a fast heuristic — not confirmed safe.", Style.DIM))
        print(_c("Treat this as our best guess, not certainty. Review before fully trusting it.", Style.DIM))

        def _sev_rank(f):
            return SEVERITY_RANK.get(f.severity, 0)

        cat_counts = Counter(CATEGORY_BY_RULE.get(f.rule, f.rule) for f in dismissed_findings)
        summary = ", ".join(f"{cat} ({n})" for cat, n in cat_counts.most_common())
        print(_c(f"By category: {summary}", Style.DIM))

        by_file = defaultdict(list)
        for f in dismissed_findings:
            by_file[f.file].append(f)
        for flist in by_file.values():
            flist.sort(key=lambda f: (-_sev_rank(f), f.line))
        files_by_worst = sorted(
            by_file.keys(),
            key=lambda fn: (max(_sev_rank(f) for f in by_file[fn]), len(by_file[fn])),
            reverse=True,
        )

        reason_max = 60
        for fname in files_by_worst:
            flist = by_file[fname]
            worst = flist[0].severity
            print()
            print(_c(f"{fname}", Style.BRIGHT) + _c(f"  ({len(flist)} dismissed, worst: {worst})", SEV_COLOR.get(worst, "")))
            for f in flist:
                if f.ai_verdict == "false_positive":
                    tag, tag_color = "AI", Fore.CYAN
                    reason = f.ai_reason or ""
                elif f.ai_reason:
                    tag, tag_color = "AI*", Fore.YELLOW
                    reason = f.ai_reason
                else:
                    tag, tag_color = "guess", Fore.YELLOW
                    reason = "test/fixture path heuristic, unreviewed"
                reason_shown = (reason[:reason_max - 3] + "...") if len(reason) > reason_max else reason
                cat = CATEGORY_BY_RULE.get(f.rule, f.rule)
                sev_plain = f"[{f.severity.upper()}]"
                sev_shown = _c(f"{sev_plain:<10}", SEV_COLOR.get(f.severity, ""))
                tag_shown = _c(f"{tag:<6}", tag_color)
                print(f"  L{f.line:<5} {sev_shown} {cat:<20} {tag_shown} {reason_shown}")

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


def generate_markdown_report(result: ScanResult, target: str, used_ai: bool,
                              risk_summary: Optional[str], recommendations: Optional[list],
                              ai_error: Optional[str], exit_code: int, threshold: str,
                              include_test_files: bool = False) -> str:
    from collections import Counter, defaultdict
    from datetime import datetime

    lines = []
    a = lines.append

    def _dismissed(f: Finding) -> bool:
        if f.ai_verdict == "false_positive":
            return True
        if f.ai_verdict == "true_positive":
            return False
        return f.likely_test_fixture and not include_test_files

    main_findings = [f for f in result.findings if not _dismissed(f)]
    dismissed_findings = [f for f in result.findings if _dismissed(f)]

    def _sev_rank(f):
        return SEVERITY_RANK.get(f.severity, 0)

    a("# Security Scan Report")
    a("")
    a(f"**Target:** `{target}`  ")
    a(f"**Scanned:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    files_with_findings = len({f.file for f in result.findings})
    a(f"**Files:** {result.files_scanned} scanned — {files_with_findings} with finding(s), "
      f"{result.files_scanned - files_with_findings} clean")
    a("")

    by_sev = Counter(f.severity for f in main_findings)
    sev_parts = [f"{by_sev.get(s,0)} {s}" for s in ("critical", "high", "medium", "low") if by_sev.get(s, 0)]
    summary_line = ", ".join(sev_parts) if sev_parts else "0 confirmed findings"
    if dismissed_findings:
        summary_line += f" ({len(dismissed_findings)} dismissed)"
    a(f"**Summary:** {summary_line}")
    a("")
    a("---")
    a("")

    a("## Findings")
    a("")
    if not main_findings:
        a("_No confirmed findings. This does not mean the code is secure — only that nothing "
          "matched (or everything that matched was dismissed below)._")
        a("")
    else:
        by_category = defaultdict(list)
        for f in main_findings:
            by_category[CATEGORY_BY_RULE.get(f.rule, f.rule)].append(f)
        for flist in by_category.values():
            flist.sort(key=_sev_rank, reverse=True)
        categories_by_worst = sorted(
            by_category.keys(),
            key=lambda c: (max(_sev_rank(f) for f in by_category[c]), len(by_category[c])),
            reverse=True,
        )
        for cat in categories_by_worst:
            flist = by_category[cat]
            worst = flist[0].severity
            a(f"### {cat} ({len(flist)} finding(s), worst: {worst})")
            a("")
            for f in flist:
                confirm = " ✓AI-confirmed" if f.ai_verdict == "true_positive" else (" (ai-found)" if f.source == "ai" else "")
                loc = f"{f.file}:{f.line}" if f.line else f.file
                a(f"**[{f.severity.upper()}]{confirm}** — `{loc}`")
                a("")
                if f.source == "regex":
                    a(f"```\n{f.display_line}\n```")
                a(f"- **Impact:** {f.impact}")
                a(f"- **Fix:** {f.improvement}")
                a("")

    total_main = len(main_findings)
    regex_count = sum(1 for f in main_findings if f.source == "regex")
    ai_count = sum(1 for f in main_findings if f.source == "ai")
    extra = f" ({regex_count} regex, {ai_count} ai-found)" if used_ai else ""
    a(f"**{total_main} finding(s)** across {result.files_scanned} file(s){extra}")
    a("")

    if dismissed_findings:
        a("---")
        a("")
        a(f"## Possible False Positives / Unverified ({len(dismissed_findings)})")
        a("")
        a("> These were dismissed by AI review or a fast heuristic — not confirmed safe. "
          "Treat this as our best guess, not certainty. Review before fully trusting it.")
        a("")
        cat_counts = Counter(CATEGORY_BY_RULE.get(f.rule, f.rule) for f in dismissed_findings)
        summary = ", ".join(f"{cat} ({n})" for cat, n in cat_counts.most_common())
        a(f"**By category:** {summary}")
        a("")

        by_file = defaultdict(list)
        for f in dismissed_findings:
            by_file[f.file].append(f)
        for flist in by_file.values():
            flist.sort(key=lambda f: (-_sev_rank(f), f.line))
        files_by_worst = sorted(
            by_file.keys(),
            key=lambda fn: (max(_sev_rank(f) for f in by_file[fn]), len(by_file[fn])),
            reverse=True,
        )
        for fname in files_by_worst:
            flist = by_file[fname]
            worst = flist[0].severity
            a(f"### `{fname}` ({len(flist)} dismissed, worst: {worst})")
            a("")
            a("| Line | Severity | Category | Status | Reason |")
            a("|---|---|---|---|---|")
            for f in flist:
                if f.ai_verdict == "false_positive":
                    tag, reason = "AI", (f.ai_reason or "")
                elif f.ai_reason:
                    tag, reason = "AI*", f.ai_reason
                else:
                    tag, reason = "guess", "test/fixture path heuristic, unreviewed"
                cat = CATEGORY_BY_RULE.get(f.rule, f.rule)
                reason_cell = reason.replace("|", "\\|")
                a(f"| {f.line} | {f.severity.upper()} | {cat} | {tag} | {reason_cell} |")
            a("")

    if result.ai_scan_errors:
        a(f"_AI review failed for {len(result.ai_scan_errors)} file(s) — see JSON report for details._")
        a("")
    if result.skipped_files:
        a(f"_{len(result.skipped_files)} file(s) skipped (not analyzed) — see JSON report for details._")
        a("")

    if used_ai:
        a("---")
        a("")
        a("## AI Risk Summary")
        a("")
        a(risk_summary if risk_summary else f"_unavailable ({ai_error})_")
        a("")
        a("## Recommended Fix")
        a("")
        recs = recommendations if recommendations else (GENERIC_REMEDIATION if main_findings else [])
        for rec in recs:
            a(f"- {rec}")
        a("")

    a("---")
    a("")
    reason = f"findings at or above configured threshold ({threshold})" if exit_code != 0 else "no findings at or above threshold"
    a(f"**Exit code:** `{exit_code}` ({reason})")

    return "\n".join(lines)


def save_json_report(result: ScanResult, risk_summary, recommendations, exit_code, path):
    data = {
        "files_scanned": result.files_scanned,
        "scanned_files": result.scanned_file_names,
        "skipped_files": [{"file": p, "reason": r} for p, r in result.skipped_files],
        "ai_scan_errors": [{"file": p, "error": e} for p, e in result.ai_scan_errors],
        "findings": [
            {
                "category": CATEGORY_BY_RULE.get(f.rule, f.rule),
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


SCAN_TYPES = ["code", "web", "network"]


def resolve_scan_types(scan_arg: str) -> list:
    if scan_arg.strip().lower() == "all":
        return list(SCAN_TYPES)
    requested = [s.strip().lower() for s in scan_arg.split(",") if s.strip()]
    invalid = [s for s in requested if s not in SCAN_TYPES]
    if invalid:
        print(f"Error: unknown scan type(s): {', '.join(invalid)}. "
              f"Valid options: {', '.join(SCAN_TYPES)}, or 'all'.", file=sys.stderr)
        sys.exit(2)
    return requested


def autodetect_target(args, scan_arg_was_default: bool):
    """Lets a single positional `target` work for any scan type without
    also having to repeat it via --url/--net-target: a bare 'security-scan
    <target>' fills in --url or --net-target for you when target is
    unambiguously a URL or an IP/CIDR. When the scan type wasn't already
    pinned down explicitly (no --code/--web/--network/--all and no
    non-default --scan), it also picks the scan type itself from what
    target looks like — so 'security-scan https://x' just works without
    needing --web too."""
    if not args.target or args.url or args.net_target:
        return

    if re.match(r"^https?://", args.target, re.IGNORECASE):
        args.url = args.target
        if scan_arg_was_default:
            args.scan = "web"
        args.target = None
        return

    if not Path(args.target).exists():
        try:
            import ipaddress
            ipaddress.ip_network(args.target, strict=False)
            args.net_target = args.target
            if scan_arg_was_default:
                args.scan = "network"
            args.target = None
        except ValueError:
            pass  # not an IP/CIDR either — fall through and let the normal
                   # code-scan path report "target does not exist"


def main():
    parser = argparse.ArgumentParser(
        description="security-scan — point it at a directory/file, a URL, or a host/CIDR "
                     "and it detects what kind of scan to run.",
    )
    parser.add_argument("target", nargs="?", default=None,
                         help="What to scan: a file/directory (code scan), a URL like "
                              "https://example.com (web scan), or a host/CIDR like 10.0.0.5 or "
                              "10.0.0.0/24 (network scan) — auto-detected from what you pass. "
                              "Omit entirely to scan the current directory. Use --scan/--url/"
                              "--net-target instead if you need explicit control or want to combine "
                              "scan types.")
    parser.add_argument("--code", action="store_true", help="Run the code scan.")
    parser.add_argument("--web", action="store_true", help="Run the web scan (needs a URL — pass it "
                                                             "as `target` or via --url).")
    parser.add_argument("--network", action="store_true",
                         help="Run the network scan. Needs a host/CIDR — pass it as `target` or via "
                              "--net-target, or just give --url/a URL target and it'll be resolved "
                              "to an IP for you automatically.")
    parser.add_argument("--all", action="store_true", help="Run all three: code, web, and network.")
    parser.add_argument("--scan", default="code",
                         help=f"Advanced form of --code/--web/--network/--all: 'all' for a full scan, or "
                              f"a comma-separated list of {', '.join(SCAN_TYPES)} "
                              f"(default: auto-detected from `target`).")
    parser.add_argument("--url", default=None,
                         help="Target URL for web scanning, e.g. https://example.com (required when "
                              "--scan includes 'web' and target isn't already a URL)")
    parser.add_argument("--net-target", default=None,
                         help="Host or CIDR subnet for network scanning, e.g. 10.0.0.5 or 10.0.0.0/24. "
                              "Optional if --url/target is a URL — its host is resolved to an IP and "
                              "used automatically; pass this to scan a different/specific IP instead.")
    parser.add_argument("--net-ports", default=None,
                         help="Comma/range port list for network scanning, e.g. 22,80,443 or 1-1024 "
                              "(default: a common-ports list)")
    parser.add_argument("--ai", action="store_true",
                         help="Enable AI verification of findings (true/false positive) + scan for "
                              "additional issues + risk summary, for every scan type selected (code, "
                              "web, network). Code sends real source to the LLM; web/network send only "
                              "collected scan evidence (headers, banners, etc.), never source code.")
    parser.add_argument("--json", dest="json_out", default=None, help="Write JSON report to this path")
    parser.add_argument("--report", dest="report_out", default=None,
                         help="Write a shareable Markdown report to this path")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="high",
                         help="Minimum severity that causes a non-zero exit code (default: high).")
    parser.add_argument("--include-test-files", action="store_true",
                         help="Include findings in test/fixture files in the exit-code gate too "
                              "(by default, only applies when AI hasn't explicitly confirmed them as real)")
    args = parser.parse_args()

    # --code/--web/--network/--all are the simple form of --scan: translate
    # them into the same args.scan string --scan already understands, so
    # everything downstream (including the auto-detect logic below) only
    # has to deal with one representation of "what to scan".
    flag_types = []
    if args.all:
        flag_types = list(SCAN_TYPES)
    else:
        if args.code:
            flag_types.append("code")
        if args.web:
            flag_types.append("web")
        if args.network:
            flag_types.append("network")
    scan_type_pinned = bool(flag_types) or args.scan != "code"
    if flag_types:
        args.scan = ",".join(flag_types)

    scan_types = resolve_scan_types(args.scan)

    # Simplest possible invocation: no target/url/net-target given at all,
    # but a code scan is (explicitly or by default) requested — scan the
    # current directory, same as `security-scan .`, so you never have to
    # type the dot for the common "scan what I'm standing in" case.
    if "code" in scan_types and not args.target and not args.url and not args.net_target:
        args.target = "."

    # A bare positional target (no --code/--web/--network/--all/--scan
    # pinning it down) fills in --url/--net-target for you and, when nothing
    # was pinned, also picks the scan type from what target looks like — so
    # `security-scan https://x` works without needing --web too.
    autodetect_target(args, scan_arg_was_default=not scan_type_pinned)
    scan_types = resolve_scan_types(args.scan)
    print(_c(f"Scan scope: {', '.join(scan_types)}", Style.BRIGHT), flush=True)

    if "code" in scan_types and not args.target:
        print("Error: a file/directory target is required when --scan includes 'code'.", file=sys.stderr)
        sys.exit(2)
    if "web" in scan_types and not args.url:
        print("Error: --url is required when --scan includes 'web'.", file=sys.stderr)
        sys.exit(2)

    # If you only typed a URL, --network can piggyback on it: resolve that
    # URL's host to an IP and use it as the network-scan target, so you
    # don't have to look up and type the IP yourself. --net-target (or a
    # bare IP/CIDR passed as `target`) always wins if you do give one.
    if "network" in scan_types and not args.net_target and args.url:
        hostname = urlparse(args.url).hostname
        try:
            resolved_ip = socket.gethostbyname(hostname)
            args.net_target = resolved_ip
            print(_c(f"[*] --network target not given — resolved {hostname} -> {resolved_ip} from --url",
                      Style.DIM), flush=True)
        except socket.gaierror as e:
            print(f"Error: could not resolve a network target — --net-target wasn't given and "
                  f"the host from --url ('{hostname}') failed to resolve: {e}", file=sys.stderr)
            sys.exit(2)

    if "network" in scan_types and not args.net_target:
        print("Error: --net-target is required when --scan includes 'network' (or pass --url so "
              "it can be resolved automatically).", file=sys.stderr)
        sys.exit(2)

    target = None
    if args.target:
        target = Path(args.target)
        if "code" in scan_types and not target.exists():
            print(f"Error: target does not exist: {target}", file=sys.stderr)
            sys.exit(2)

    # Each scan type produces its own ScanResult; merge them into one so the
    # existing print_report / generate_markdown_report / save_json_report
    # functions (which all take a single ScanResult) work unchanged.
    result = ScanResult()
    display_target_parts = []

    if "code" in scan_types:
        code_result = scan_target(target)
        result.findings.extend(code_result.findings)
        result.skipped_files.extend(code_result.skipped_files)
        result.files_scanned += code_result.files_scanned
        result.scanned_file_names.extend(code_result.scanned_file_names)
        result.truncated = result.truncated or code_result.truncated
        result.ai_file_contents.update(code_result.ai_file_contents)
        display_target_parts.append(str(target))

    if "web" in scan_types:
        from web_scan import scan_url
        print(_c(f"Starting web scan of {args.url} ...", Style.DIM), flush=True)
        web_result = scan_url(args.url, use_ai=args.ai)
        result.findings.extend(web_result.findings)
        result.files_scanned += web_result.files_scanned
        result.scanned_file_names.extend(web_result.scanned_file_names)
        result.ai_file_contents.update(web_result.ai_file_contents)
        result.ai_target_kind.update(web_result.ai_target_kind)
        display_target_parts.append(args.url)

    if "network" in scan_types:
        from network_scan import scan_network, _parse_ports
        print(_c(f"Starting network scan of {args.net_target} ...", Style.DIM), flush=True)
        net_result = scan_network(args.net_target, ports=_parse_ports(args.net_ports), use_ai=args.ai)
        result.findings.extend(net_result.findings)
        result.files_scanned += net_result.files_scanned
        result.scanned_file_names.extend(net_result.scanned_file_names)
        result.ai_file_contents.update(net_result.ai_file_contents)
        result.ai_target_kind.update(net_result.ai_target_kind)
        display_target_parts.append(args.net_target)

    display_target = ", ".join(display_target_parts)

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

        exit_code = 2 if any(gates_exit_code(f, threshold_rank, args.include_test_files) for f in result.findings) else 0

    print_report(result, display_target, args.ai, risk_summary, recommendations, ai_error, exit_code, args.fail_on,
                 include_test_files=args.include_test_files)

    if args.json_out:
        save_json_report(result, risk_summary, recommendations, exit_code, args.json_out)
        print(f"\n[*] JSON report written to {args.json_out}")

    if args.report_out:
        md = generate_markdown_report(result, display_target, args.ai, risk_summary, recommendations, ai_error,
                                       exit_code, args.fail_on, include_test_files=args.include_test_files)
        with open(args.report_out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"[*] Markdown report written to {args.report_out}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
