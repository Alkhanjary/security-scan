# security-scan

A lightweight, offline-first security scanner with three modes — **code**, **web**, and **network** — plus an optional AI layer that verifies findings and writes a plain-language risk summary.

Only scan code, sites, and hosts you own or are explicitly authorized to test.

## Quick start

```bash
py scanner.py
```

That's it — no arguments scans the current directory for hardcoded secrets and risky code patterns.

Point it at other things and it figures out what to do:

```bash
py scanner.py https://example.com     # web scan (auto-detected from the URL)
py scanner.py 10.0.0.5                # network scan (auto-detected from the IP/CIDR)
py scanner.py ./some-repo             # code scan of a specific folder
```

## Flags

| Flag | What it does |
|---|---|
| `--code` | Run the code scan (default if nothing else is specified) |
| `--web` | Run the web scan — needs a URL, either as `target` or via `--url` |
| `--network` | Run the network scan — needs a host/CIDR, either as `target` or via `--net-target` |
| `--all` | Run all three: code, web, and network |
| `--ai` | Turn on AI verification + risk summary for whichever scan(s) you ran |
| `--fail-on <level>` | Minimum severity (`critical`/`high`/`medium`/`low`/`none`) that causes a non-zero exit code (default: `high`) |
| `--json <path>` | Write a JSON report |
| `--report <path>` | Write a shareable Markdown report |
| `--include-test-files` | Also gate the exit code on findings inside test/fixture files |

Examples:

```bash
py scanner.py --code --ai
py scanner.py --web https://example.com --ai
py scanner.py --network 127.0.0.1 --net-ports 22,80,443 --ai
py scanner.py --all --url https://example.com --net-target 127.0.0.1 --ai --report report.md
```

For full control (combining scan types, explicit targets for each), the underlying `--scan code,web,network` / `--url` / `--net-target` flags still work exactly as `--code`/`--web`/`--network`/`--all` do — see `py scanner.py --help`.

## What each scan looks for

- **Code** — hardcoded secrets/API keys, dangerous calls (`eval`, `exec`, `os.system`, `shell=True`), SQL injection patterns, XSS sinks, insecure deserialization (`pickle`, unsafe YAML), weak crypto, insecure transport, infra misconfig (privileged containers, `:latest` images, etc.), and more.
- **Web** — missing security headers (HSTS, CSP, X-Frame-Options, ...), insecure cookie flags, TLS certificate/protocol issues, reflected XSS, error-based SQL injection (via a lightweight same-origin crawl).
- **Network** — open ports, risky exposed services (FTP, Telnet, RDP, VNC), outdated-looking service banners.

## The `--ai` layer

With `--ai`, every finding from whichever scan(s) you ran is sent to an LLM for verification (true/false positive) and the model also looks for anything the deterministic checks missed. It then writes an overall plain-language risk summary and recommended fixes.

- The **regex/port scan is always the source of truth** for exit codes — `--ai` only refines it, never replaces it.
- **Code scan**: sends real file content to the LLM (secret values are always redacted first).
- **Web/network scans**: send only collected scan evidence — response headers, cookies, TLS info, open ports, banners — never raw traffic or credentials.

### Configuring `--ai`

Copy `.env.example` to `.env` in this same folder and set:

```
LLM_API_KEY=your-key-here
LLM_BASE_URL=https://ollama.com/v1   # or any OpenAI-compatible endpoint
LLM_MODEL=gpt-oss:20b-cloud
```

This `.env` is loaded **only** from this script's own directory — never from whatever you're scanning — so a malicious target repo can't redirect your API key or endpoint.

## Modules

- `scanner.py` — code scanner + CLI entry point (also orchestrates web/network scans and the shared AI layer)
- `web_scan.py` — web scanner, runnable standalone: `py web_scan.py https://example.com --ai`
- `network_scan.py` — network scanner, runnable standalone: `py network_scan.py 10.0.0.0/24 --ai`

## Notes

- A clean scan means "no implemented rule matched" — it is **not** a guarantee of security.
- Findings in test/fixture files (`tests/`, `test_*.py`, etc.) are shown but excluded from the exit-code gate by default, since they're often the scanner's own test data rather than real leaks.
- File size, directory depth, and per-file/total finding caps are enforced during code scans; symlinks are never followed.
