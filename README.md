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
| `--web` | Run the web scan. With a URL (`target` or `--url`) it scans that. With no URL, it auto-launches an app from the target folder — see below |
| `--network` | Run the network scan — needs a host/CIDR, either as `target` or via `--net-target` |
| `--all` | Run all three: code, web, and network |
| `--ai` | Turn on AI verification + risk summary for whichever scan(s) you ran |
| `--fail-on <level>` | Minimum severity (`critical`/`high`/`medium`/`low`/`none`) that causes a non-zero exit code (default: `high`) |
| `--json <path>` | Write a JSON report |
| `--report <path>` | Write a shareable Markdown report |
| `--include-test-files` | Also gate the exit code on findings inside test/fixture files |
| `--web-max-pages <n>` | How many same-origin pages the web scan may crawl (default: 25). Raise it to cover a bigger site |

Examples:

```bash
py scanner.py --code --ai
py scanner.py --web https://example.com --ai
py scanner.py --network 127.0.0.1 --net-ports 22,80,443 --ai
py scanner.py --all --url https://example.com --net-target 127.0.0.1 --ai --report report.md
```

For full control (combining scan types, explicit targets for each), the underlying `--scan code,web,network` / `--url` / `--net-target` flags still work exactly as `--code`/`--web`/`--network`/`--all` do — see `py scanner.py --help`.

## Web scan without a live URL

If a folder doesn't have a deployed/running site yet, `--web` will try to launch it for you:

```bash
py scanner.py --web ./my-app
```

It detects and starts (in this order) Django, FastAPI, Flask, Node (npm/yarn/pnpm — `start`/`dev`/`serve` script), Ruby (Rails/Rack), Go, PHP, Docker Compose, a generic Python entrypoint, or a static HTML site — whichever matches first — waits for it to respond, runs the full web scan against it, then shuts it down again. Combine with `--code`/`--all` and it reuses the same folder for both the code scan and the app it launches.

If nothing is detected, or the app never comes up (e.g. dependencies aren't installed), it fails with a clear message telling you to start it yourself and pass `--url` instead — it never guesses at how to run something it doesn't recognize.

Only launch and scan apps you own or are explicitly authorized to test.

## What each scan looks for

- **Code** — hardcoded secrets/API keys, dangerous calls (`eval`, `exec`, `os.system`, `shell=True`), SQL injection patterns, XSS sinks, insecure deserialization (`pickle`, unsafe YAML), weak crypto, insecure transport, infra misconfig (privileged containers, `:latest` images, etc.), and more.
- **Web** — missing security headers (HSTS, CSP, X-Frame-Options, ...), insecure cookie flags (Secure/HttpOnly/SameSite), TLS certificate and protocol issues, mixed content, reflected XSS and error-based SQL injection (via a same-origin crawl), publicly reachable sensitive files (`.env`, `.git/HEAD`, `wp-config.php`, backups, private keys, ...), directory listings, CORS misconfiguration (wildcard-with-credentials, arbitrary origin reflection), risky HTTP methods (TRACE/PUT/DELETE), open redirects, and technology/version disclosure.
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

## Web UI

Everything the CLI does, in a browser — plus scan history, trend charts and one-click report exports.

```bash
py web/app.py
```

Then open <http://127.0.0.1:5057>. It binds to loopback only.

Three tabs:

- **Scan** — pick a source (a folder on this machine via a built-in folder browser, an uploaded folder, or just a URL/host), tick which scans to run, toggle AI verification, and watch live progress with a real percentage. Coverage is adjustable: choose how many pages the web scan crawls (25 to 1000), and whether the network scan covers the common services, ports 1-1024, or all 65535.
- **Analysis** — where you land the moment a scan finishes: severity metrics, the AI risk summary and recommended fixes, a finding-types chart, filters (severity, category, actionable vs. AI-dismissed, free-text), and a list/detail view of every finding.
- **History** — every past scan, saved to disk so it survives restarts. Trend chart across runs, rename/delete, and a two-scan compare showing what's new, what's fixed and what's still there.

Export a report as **HTML, PDF, Word (.docx), Excel (.xlsx), Markdown, CSV, JSON or SARIF**. PDF/Word/Excel need `reportlab`, `python-docx` and `openpyxl` respectively — the UI only offers the formats your install can actually produce. SARIF is the format GitHub code scanning and most security dashboards ingest.

Install everything with:

```bash
py -m pip install -r requirements.txt
```

Notes:

- The web UI shells out to `scanner.py` exactly as you would on the command line, so results are identical to the CLI's and a hung scan can't take the server down. Cancel stops the subprocess.
- Unlike the CLI (which defaults to `--fail-on high`), the dashboard defaults the gate to **none** — it's for reading findings, not gating a build. Pick a threshold in *Scan options* if you want a pass/fail verdict.
- The dashboard reads local folders and can launch local apps. Only point it at code, sites, and hosts you own or are explicitly authorized to test.

## Modules

- `scanner.py` — code scanner + CLI entry point (also orchestrates web/network scans and the shared AI layer)
- `web_scan.py` — web scanner, runnable standalone: `py web_scan.py https://example.com --ai`. Covers headers, cookies, TLS, XSS, SQLi, exposed files, CORS, and redirects, plus:
  - CSP *content* (not just presence): `unsafe-inline`/`unsafe-eval`/wildcard sources, and weak/short `Strict-Transport-Security` max-age
  - Missing Subresource Integrity on cross-origin `<script>` tags, and exposed JavaScript source maps (verified as real maps, not a soft-404)
  - A live debug/error page on a guaranteed-404 path (Werkzeug, Django, Rails, PHP, ASP.NET, Node signatures) — catches debug mode left on remotely, no source access needed
  - CORS reflecting the literal `null` origin, in addition to the existing wildcard/arbitrary-origin checks
  - A real `TRACE` request confirming cross-site tracing (not just reading it off the `Allow` header), and forms on an HTTPS page submitting to plain HTTP
  - Negotiated TLS cipher checked for RC4/3DES/NULL/export/anonymous suites
  - `robots.txt` Disallow entries that look sensitive, cacheable responses that set a cookie, and a versioned CMS/framework `<meta name="generator">` tag
  - S3/GCS/Azure Blob bucket URLs found on the page, probed for a genuinely public listing
- `network_scan.py` — network scanner, runnable standalone: `py network_scan.py 10.0.0.0/24 --ai`. Flags open ports, risky exposed services (FTP/Telnet/RDP/VNC, plus SMB/RPC/MSSQL/MySQL/PostgreSQL/Redis/Elasticsearch/MongoDB/Docker API/Memcached), and outdated service banners — matched offline against known-backdoored distributions (e.g. vsftpd 2.3.4) and per-product minimum-supported-version thresholds. No live CVE lookup: a hit means "go check CVEs for this exact version," not a confirmed exploit. Also runs a handful of active, read-only probes, never brute-forcing or state-changing:
  - Unauthenticated access: FTP anonymous login, Redis `PING`, Elasticsearch cluster info, Docker Engine API version, Memcached `stats`, and VNC's RFB handshake checked for the "None" security type
  - DNS zone transfer (AXFR) — a standard query any correctly configured server refuses
  - SMTP open relay — `MAIL FROM`/`RCPT TO` between two external addresses, aborted with `RSET` before `DATA` so no message is ever actually sent
  - SSH banners checked for the obsolete protocol-1 identification string
- `app_launcher.py` — detects and starts a local app from a folder for `--web` to scan when no URL is given
- `web/` — the Flask web UI: `app.py` (routes), `scan_jobs.py` (background scan jobs + history), `reports.py` (report exports)

## Notes

- A clean scan means "no implemented rule matched" — it is **not** a guarantee of security.
- Findings in test/fixture files (`tests/`, `test_*.py`, etc.) are shown but excluded from the exit-code gate by default, since they're often the scanner's own test data rather than real leaks.
- File size, directory depth, and per-file/total finding caps are enforced during code scans; symlinks are never followed.
