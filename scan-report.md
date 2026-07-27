# Security Scan Report

**Target:** `C:\Users\Ahmed.alkhanjary\Desktop\ai-pr-summary`  
**Scanned:** 2026-07-27 09:54:06  
**Files:** 20 scanned — 9 with finding(s), 11 clean

**Summary:** 1 high, 1 medium, 1 low (63 dismissed)

---

## Findings

### exposed-secret-key (1 finding(s), worst: high)

**[HIGH] (ai-found)** — `.env:1`

- **Impact:** Leaking this key can allow unauthorized access to the LLM service
- **Fix:** Move the key to a secure environment variable or secret manager and remove it from the file

### uses-without-specified-commit (1 finding(s), worst: medium)

**[MEDIUM] (ai-found)** — `.github\workflows\pr-summary.yml:14`

- **Impact:** If the upstream workflow is modified, malicious or faulty code could be executed during the CI run.
- **Fix:** Pin the reusable workflow by using a specific commit SHA or a tagged release instead of the branch name.

### hardcoded-placeholder-credentials (1 finding(s), worst: low)

**[LOW] (ai-found)** — `.env.example:1`

- **Impact:** If used in production it could expose legitimate credentials or allow unauthorized access.
- **Fix:** Replace the placeholder with an actual key before deployment or remove the key altogether.

**3 finding(s)** across 20 file(s) (0 regex, 3 ai-found)

---

## Possible False Positives / Unverified (63)

> These were dismissed by AI review or a fast heuristic — not confirmed safe. Treat this as our best guess, not certainty. Review before fully trusting it.

**By category:** dangerous-call (26), hardcoded-secret (21), insecure-transport (9), xss (3), weak-crypto (3), debug-mode-exposed (1)

### `tests\test_security.py` (42 dismissed, worst: critical)

| Line | Severity | Category | Status | Reason |
|---|---|---|---|---|
| 184 | CRITICAL | hardcoded-secret | AI | AWS key in a test diff |
| 187 | CRITICAL | hardcoded-secret | AI | AWS key in test diff |
| 192 | CRITICAL | hardcoded-secret | AI | AWS key in test diff |
| 326 | CRITICAL | hardcoded-secret | AI | AWS key with colon in test diff |
| 327 | CRITICAL | hardcoded-secret | AI | another AWS key test case |
| 328 | CRITICAL | hardcoded-secret | AI | another AWS key test case |
| 333 | CRITICAL | hardcoded-secret | AI | AWS key redaction test |
| 336 | CRITICAL | hardcoded-secret | AI | AWS key redaction test in diff |
| 37 | HIGH | hardcoded-secret | AI | secret appears in a test diff, not in production code |
| 49 | HIGH | dangerous-call | AI | eval example used to test scanner logic |
| 55 | HIGH | insecure-transport | AI | TLS disable test case, test data |
| 91 | HIGH | dangerous-call | AI | removed eval line in test, not scanned |
| 99 | HIGH | dangerous-call | AI | os.system example in test diff |
| 119 | HIGH | dangerous-call | AI | eval in test diff |
| 157 | HIGH | xss | AI | XSS innerHTML test input |
| 211 | HIGH | dangerous-call | AI | same test line, duplicate entry |
| 263 | HIGH | hardcoded-secret | AI | API key placeholder in test diff |
| 299 | HIGH | dangerous-call | AI | double-plus line test |
| 300 | HIGH | dangerous-call | AI | double-plus line test |
| 308 | HIGH | dangerous-call | AI | detection of dangerous call in diff |
| 346 | HIGH | hardcoded-secret | AI | Nosec flag test with real secret |
| 353 | HIGH | insecure-transport | AI | nosed flag with TLS disable test |
| 355 | HIGH | insecure-transport | AI | nosed flag test in diff |
| 361 | HIGH | insecure-transport | AI | nosed flag cause caching test in diff |
| 368 | HIGH | insecure-transport | AI | nosed flag test in diff |
| 375 | HIGH | insecure-transport | AI | nosed flag and severity test in diff |
| 384 | HIGH | dangerous-call | AI | os.system test in diff |
| 390 | HIGH | hardcoded-secret | AI | API key test under tests path |
| 396 | HIGH | hardcoded-secret | AI | API key test under docs |
| 402 | HIGH | dangerous-call | AI | eval test in Markdown file |
| 412 | HIGH | dangerous-call | AI | eval test in error message |
| 424 | HIGH | dangerous-call | AI | eval test in report generation |
| 437 | HIGH | dangerous-call | AI | expired baseline test with eval |
| 455 | HIGH | dangerous-call | AI | baseline without expiry test |
| 483 | HIGH | dangerous-call | AI | unquoted secret with comment test |
| 498 | HIGH | hardcoded-secret | AI | API key in diff for redact_diff_for_llm test |
| 513 | HIGH | hardcoded-secret | AI | mixed diff with secret for redact_diff_for_llm |
| 61 | MEDIUM | weak-crypto | AI | weak hash test input in diff |
| 109 | MEDIUM | weak-crypto | AI | MD5 hashing test in diff |
| 110 | MEDIUM | hardcoded-secret | AI | hardcoded password in test diff |
| 176 | MEDIUM | hardcoded-secret | AI | password test, secret redaction test |
| 211 | MEDIUM | hardcoded-secret | AI | same test line, duplicate entry |

### `tests\test_cli.py` (10 dismissed, worst: high)

| Line | Severity | Category | Status | Reason |
|---|---|---|---|---|
| 37 | HIGH | dangerous-call | AI | Test fixture creating diff with eval; not real code usage. |
| 73 | HIGH | dangerous-call | AI | Test generating diff for auth file; eval is test content. |
| 95 | HIGH | hardcoded-secret | AI | Test diff simulating secret; placeholder not real credential. |
| 107 | HIGH | hardcoded-secret | AI | Test diff includes secret placeholder with nosec; test input. |
| 115 | HIGH | insecure-transport | AI | Test diff uses verify=False; intended to test detection. |
| 117 | HIGH | insecure-transport | AI | Same as line 115; test scenario. |
| 157 | HIGH | dangerous-call | AI | Comment explaining diff marker; no actual code. |
| 164 | HIGH | dangerous-call | AI | Diff content for test; no real execution. |
| 218 | HIGH | dangerous-call | AI | Test repository file with eval; part of test data. |
| 229 | HIGH | dangerous-call | AI | Assertion checking diff content; no runtime effect. |

### `README.md` (5 dismissed, worst: high)

| Line | Severity | Category | Status | Reason |
|---|---|---|---|---|
| 180 | HIGH | dangerous-call | AI | Documentation list of dangerous calls, not actual code. |
| 181 | HIGH | xss | AI | Documentation XSS sinks list, not code. |
| 183 | HIGH | insecure-transport | AI | Documentation insecure transport list, not code. |
| 202 | HIGH | dangerous-call | AI | Explanation text, not code. |
| 185 | MEDIUM | debug-mode-exposed | AI | Documentation risky config list, not code. |

### `summarize_pr.py` (4 dismissed, worst: high)

| Line | Severity | Category | Status | Reason |
|---|---|---|---|---|
| 138 | HIGH | xss | AI | Line defines a regex rule for XSS detection; no runtime usage of [redacted] occurs. |
| 165 | HIGH | weak-crypto | AI | Line defines a regex rule for ECB mode detection; code does not use ECB encryption. |
| 365 | HIGH | dangerous-call | AI | Line is a comment illustrating a diff example that contains "eval(" in plain text; no exec of eval. |
| 366 | HIGH | dangerous-call | AI | Same as line 365; comment only, not functionally executing eval. |

### `.github\workflows\ci.yml` (1 dismissed, worst: high)

| Line | Severity | Category | Status | Reason |
|---|---|---|---|---|
| 30 | HIGH | dangerous-call | AI | Line creates a diff file containing eval(user_input) as test data to verify scanner, not actual code execution |

### `selftest.py` (1 dismissed, worst: medium)

| Line | Severity | Category | Status | Reason |
|---|---|---|---|---|
| 1 | MEDIUM | hardcoded-secret | AI | The file appears to be a self-test or fixture; the password value is likely test data rather than a real credential. |

---

## AI Risk Summary

The repository contains a real API key directly in the source (.env) at line 1, exposing it to anyone who clones the code. This unsecured credential can be misused to gain unauthorized access to the associated service or data. Additionally, the CI workflow pulls a reusable workflow from a branch reference instead of a fixed commit SHA, which opens the possibility of unintended or malicious changes being applied to the build process without notice.

## Recommended Fix

- Move the actual API key out of the repository and into a protected secrets manager or CI environment variable, and delete the key from all source files.
- Add the .env file (and any other files containing sensitive data) to .gitignore and ensure those files are never committed.
- Replace the branch reference in .github/workflows/pr-summary.yml with a specific commit SHA to lock the workflow to a known, reviewed version.
- Validate that .env.example only contains placeholder values and is properly documented so developers know not to use it as a real configuration source.
- Run a scan to confirm no other secrets remain in the codebase after these changes.
- Implement a CI gate that fails if any confidential keys are accidentally committed in future pushes.

---

**Exit code:** `2` (findings at or above configured threshold (high))