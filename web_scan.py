#!/usr/bin/env python3
"""
web_scan.py

Web vulnerability scanner module for security-scan. Mirrors the
architecture of scanner.py: rule-keyed SEVERITY / DESCRIPTION / IMPACT /
IMPROVEMENT tables, the shared Finding / ScanResult dataclasses, and the
same colorama-based CLI conventions — so its output slots directly into
your existing report writer and --ai review layer.

Checks implemented:
- Security response headers (HSTS, CSP, X-Content-Type-Options, etc.)
- Cookie flags (Secure / HttpOnly)
- TLS: certificate expiry, protocol version
- Reflected XSS (payload-in-query, unescaped-in-response)
- Error-based SQL injection (payload-in-query, DB error signature in response)
- Lightweight same-origin crawl to discover parameterized URLs and forms

Only scan applications you own or are explicitly authorized to test.
"""

import re
import socket
import ssl
import sys
import argparse
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

import requests

# Reuse the shared data model and CLI helpers from scanner.py so findings
# from this module are indistinguishable in shape from code-scan findings,
# and can be merged into the same report / --ai review pipeline.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scanner import Finding, ScanResult, _c, Fore, Style, SEV_COLOR, SEVERITY_RANK  # noqa: E402

requests.packages.urllib3.disable_warnings()

# ---------------------------------------------------------------------------
# Rule tables — same shape as scanner.py's SEVERITY / DESCRIPTION / IMPACT /
# IMPROVEMENT dicts, keyed by rule slug, so web findings merge cleanly.
# ---------------------------------------------------------------------------

SEVERITY = {
    "missing-hsts": "medium",
    "missing-csp": "medium",
    "missing-x-content-type-options": "low",
    "missing-x-frame-options": "medium",
    "missing-referrer-policy": "low",
    "missing-permissions-policy": "low",
    "cookie-missing-secure": "medium",
    "cookie-missing-httponly": "medium",
    "server-header-disclosure": "low",
    "no-https": "high",
    "tls-cert-expired": "high",
    "tls-cert-expiring-soon": "medium",
    "tls-outdated-protocol": "high",
    "tls-handshake-failed": "medium",
    "reflected-xss": "high",
    "sql-injection-error-based": "high",
    "exposed-sensitive-file": "critical",
    "directory-listing-enabled": "medium",
    "cors-wildcard-with-credentials": "critical",
    "cors-reflects-arbitrary-origin": "high",
    "cookie-missing-samesite": "low",
    "dangerous-http-method": "medium",
    "tech-stack-disclosure": "low",
    "mixed-content": "medium",
    "open-redirect": "medium",
}

DESCRIPTION = {
    "missing-hsts": "Strict-Transport-Security header not set",
    "missing-csp": "Content-Security-Policy header not set",
    "missing-x-content-type-options": "X-Content-Type-Options header not set",
    "missing-x-frame-options": "X-Frame-Options header not set",
    "missing-referrer-policy": "Referrer-Policy header not set",
    "missing-permissions-policy": "Permissions-Policy header not set",
    "cookie-missing-secure": "Cookie set without the Secure flag",
    "cookie-missing-httponly": "Cookie set without the HttpOnly flag",
    "server-header-disclosure": "Server header discloses software/version",
    "no-https": "Site served over plain HTTP, not HTTPS",
    "tls-cert-expired": "TLS certificate has expired",
    "tls-cert-expiring-soon": "TLS certificate expiring within 14 days",
    "tls-outdated-protocol": "Server negotiated an outdated TLS version",
    "tls-handshake-failed": "Could not complete a TLS handshake",
    "reflected-xss": "Payload reflected unescaped in the response body",
    "sql-injection-error-based": "Database error signature returned after payload injection",
    "exposed-sensitive-file": "Sensitive file publicly reachable",
    "directory-listing-enabled": "Directory listing is enabled",
    "cors-wildcard-with-credentials": "CORS allows any origin while permitting credentials",
    "cors-reflects-arbitrary-origin": "CORS reflects any supplied Origin header",
    "cookie-missing-samesite": "Cookie set without a SameSite attribute",
    "dangerous-http-method": "Risky HTTP method enabled",
    "tech-stack-disclosure": "Response header discloses the technology stack",
    "mixed-content": "HTTPS page loads sub-resources over plain HTTP",
    "open-redirect": "Redirect target is taken from a URL parameter",
}

IMPACT = {
    "missing-hsts": "Users can be downgraded to plain HTTP by a network attacker, exposing traffic to interception.",
    "missing-csp": "Increases the impact of any XSS found elsewhere — no browser-level restriction on injected scripts.",
    "missing-x-content-type-options": "Browsers may MIME-sniff responses, allowing content to be interpreted in unintended ways.",
    "missing-x-frame-options": "The page can be embedded in a hidden iframe, enabling clickjacking attacks.",
    "missing-referrer-policy": "Full URLs (potentially including sensitive query params) may leak to third-party sites via the Referer header.",
    "missing-permissions-policy": "No restriction on which browser features (camera, geolocation, etc.) this page or embedded content can access.",
    "cookie-missing-secure": "The cookie can be sent over plain HTTP and intercepted on the network.",
    "cookie-missing-httponly": "Client-side JavaScript, including an injected XSS payload, can read this cookie.",
    "server-header-disclosure": "Reveals server software/version, helping an attacker target known vulnerabilities for that version.",
    "no-https": "All traffic, including credentials or session tokens, is sent unencrypted and can be intercepted or modified.",
    "tls-cert-expired": "Browsers will show security warnings, and the connection provides no real identity assurance.",
    "tls-cert-expiring-soon": "Site will start showing certificate warnings once this expires, breaking trust and access.",
    "tls-outdated-protocol": "Older TLS versions have known cryptographic weaknesses (e.g. POODLE, BEAST).",
    "tls-handshake-failed": "Clients may be unable to connect securely, or a misconfiguration may be silently blocking access.",
    "reflected-xss": "An attacker can craft a link that executes arbitrary JavaScript in a victim's browser session (session theft, defacement, phishing).",
    "sql-injection-error-based": "Confirms the input reaches a SQL query unsanitized — full database read/write/delete access may be possible.",
    "exposed-sensitive-file": "Anyone can download it. Depending on the file this can hand over credentials, API keys, database settings, or the entire source history.",
    "directory-listing-enabled": "Anyone can browse the directory tree and discover files that were never meant to be linked, including backups and configuration.",
    "cors-wildcard-with-credentials": "Any website can make authenticated cross-origin requests and read the responses, effectively bypassing the same-origin policy for logged-in users.",
    "cors-reflects-arbitrary-origin": "An attacker-controlled site is echoed back as an allowed origin, letting it read responses meant only for the user.",
    "cookie-missing-samesite": "The cookie is attached to cross-site requests, leaving the session open to cross-site request forgery.",
    "dangerous-http-method": "Methods such as PUT, DELETE or TRACE can allow file upload, deletion, or credential theft via cross-site tracing.",
    "tech-stack-disclosure": "Names the framework, language or exact version in use, letting an attacker look up known vulnerabilities for it.",
    "mixed-content": "The plain-HTTP sub-resources can be intercepted or rewritten in transit, which undermines the HTTPS protection of the whole page.",
    "open-redirect": "The site can be used to bounce victims to an attacker's domain from a link that looks legitimate, aiding phishing.",
}

IMPROVEMENT = {
    "missing-hsts": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
    "missing-csp": "Add a Content-Security-Policy header restricting script/style/frame sources to trusted origins.",
    "missing-x-content-type-options": "Add 'X-Content-Type-Options: nosniff' to all responses.",
    "missing-x-frame-options": "Add 'X-Frame-Options: DENY' (or a CSP frame-ancestors directive) unless framing is intentionally required.",
    "missing-referrer-policy": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    "missing-permissions-policy": "Add a Permissions-Policy header disabling unused browser features by default.",
    "cookie-missing-secure": "Set the Secure attribute on all cookies served over HTTPS.",
    "cookie-missing-httponly": "Set the HttpOnly attribute on session/auth cookies that don't need JS access.",
    "server-header-disclosure": "Suppress or genericize the Server header at the web server / reverse proxy config level.",
    "no-https": "Serve the site exclusively over HTTPS and redirect all HTTP traffic to HTTPS.",
    "tls-cert-expired": "Renew the certificate immediately via your CA or ACME client (e.g. Let's Encrypt/certbot).",
    "tls-cert-expiring-soon": "Renew the certificate now; consider automating renewal (e.g. certbot with a cron/systemd timer).",
    "tls-outdated-protocol": "Disable TLS 1.0/1.1 in server config; require TLS 1.2 or higher.",
    "tls-handshake-failed": "Check server TLS configuration, firewall rules, and certificate chain completeness.",
    "reflected-xss": "Contextually encode/escape all user-controlled output; adopt a CSP as defense in depth.",
    "sql-injection-error-based": "Use parameterized queries / prepared statements instead of building SQL from raw input; never expose raw DB errors to clients.",
    "exposed-sensitive-file": "Block the path at the web server or reverse proxy, move the file outside the web root, and rotate any credential it exposed — assume it has been read.",
    "directory-listing-enabled": "Turn off automatic indexing (Apache 'Options -Indexes', nginx 'autoindex off') and add an index file.",
    "cors-wildcard-with-credentials": "Never combine 'Access-Control-Allow-Origin: *' with credentials. Echo back only origins from an explicit allow-list.",
    "cors-reflects-arbitrary-origin": "Validate the Origin header against an explicit allow-list instead of reflecting whatever was sent.",
    "cookie-missing-samesite": "Set 'SameSite=Lax' (or 'Strict' for session cookies) on every cookie that does not need cross-site delivery.",
    "dangerous-http-method": "Disable the method at the server or proxy unless the application genuinely needs it; TRACE should always be off.",
    "tech-stack-disclosure": "Remove or genericize the header (e.g. nginx 'server_tokens off', Express 'app.disable(\"x-powered-by\")').",
    "mixed-content": "Serve every sub-resource over HTTPS, and add 'Content-Security-Policy: upgrade-insecure-requests' as a backstop.",
    "open-redirect": "Redirect only to a fixed allow-list of paths, or reject any target that is not relative to your own origin.",
}

CATEGORY = "web-scan"

SECURITY_HEADERS = {
    "strict-transport-security": "missing-hsts",
    "content-security-policy": "missing-csp",
    "x-content-type-options": "missing-x-content-type-options",
    "x-frame-options": "missing-x-frame-options",
    "referrer-policy": "missing-referrer-policy",
    "permissions-policy": "missing-permissions-policy",
}

XSS_PAYLOADS = [
    "<script>alert('xsstest1')</script>",
    "\"><script>alert('xsstest2')</script>",
]

SQLI_PAYLOADS = ["'", "\" OR \"1\"=\"1", "' OR '1'='1"]

# Paths worth probing directly: each is a file that should never be publicly
# readable, and each has a content signature so a catch-all 200 (SPA index,
# soft-404 page) can't be mistaken for a real hit.
SENSITIVE_PATHS = [
    ("/.env", ("=",)),
    ("/.git/HEAD", ("ref:", "ref :")),
    ("/.git/config", ("[core]",)),
    ("/.aws/credentials", ("aws_access_key_id",)),
    ("/.npmrc", ("_authtoken", "registry=")),
    ("/docker-compose.yml", ("services:", "version:")),
    ("/Dockerfile", ("FROM ",)),
    ("/wp-config.php", ("DB_PASSWORD", "DB_NAME")),
    ("/config.php", ("<?php",)),
    ("/web.config", ("<configuration",)),
    ("/.htpasswd", (":",)),
    ("/phpinfo.php", ("phpinfo()", "PHP Version")),
    ("/server-status", ("Apache Server Status",)),
    ("/.DS_Store", ("Bud1",)),
    ("/backup.sql", ("insert into", "create table")),
    ("/database.sql", ("insert into", "create table")),
    ("/id_rsa", ("PRIVATE KEY",)),
    ("/.ssh/id_rsa", ("PRIVATE KEY",)),
]

# Headers that name the stack. Flagged only when present — the value itself
# is the evidence.
TECH_HEADERS = ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                 "x-generator", "x-drupal-cache", "x-runtime"]

RISKY_METHODS = ["TRACE", "TRACK", "PUT", "DELETE", "CONNECT"]

# Parameter names that typically carry a redirect destination.
REDIRECT_PARAMS = ["url", "next", "redirect", "redirect_uri", "redirect_url",
                    "return", "returnurl", "return_to", "goto", "dest",
                    "destination", "continue", "target"]

DIRECTORY_LISTING_SIGNATURES = [
    "index of /", "<title>directory listing", "[to parent directory]",
]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "sqlstate", "pg_query()", "psql:",
    "ora-01756", "microsoft odbc", "sqlite3.operationalerror",
]


class WebScanner:
    def __init__(self, target_url, timeout=8, verify_ssl=True, max_crawl_pages=25, show_progress=True):
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_crawl_pages = max_crawl_pages
        self.show_progress = show_progress
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "security-scan/1.0 (web module)"})
        self.result = ScanResult()
        # Plain-language notes collected as the scan runs — becomes the
        # "evidence" text sent to the AI layer for this target (headers,
        # cookies, TLS info, crawl/injection results), so --ai can verify
        # web findings the same way it verifies code findings.
        self._evidence = []

    def _note(self, line):
        self._evidence.append(line)

    def _add(self, rule, location, evidence=""):
        self.result.findings.append(Finding(
            rule=rule,
            severity=SEVERITY.get(rule, "medium"),
            file=location,          # reused field: URL instead of filepath
            line=0,                  # not line-addressable for web findings
            display_line=evidence,
            description=DESCRIPTION.get(rule, rule),
            source="regex",
            impact=IMPACT.get(rule, ""),
            improvement=IMPROVEMENT.get(rule, ""),
        ))
        self._note(f"FINDING {rule}: {DESCRIPTION.get(rule, rule)}" + (f" — {evidence}" if evidence else ""))

    def _log(self, msg):
        if self.show_progress:
            print(_c(msg, Style.DIM), flush=True)

    # ---------------------------------------------------------- headers/TLS
    def check_security_headers(self):
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout, verify=self.verify_ssl)
        except requests.RequestException as e:
            self._add("no-https" if self.target_url.startswith("http://") else "tls-handshake-failed",
                       self.target_url, str(e))
            return None

        headers = {k.lower(): v for k, v in resp.headers.items()}
        self._note(f"HTTP status: {resp.status_code}")
        self._note(f"Response headers: {dict(resp.headers)}")
        for header, rule in SECURITY_HEADERS.items():
            if header not in headers:
                self._add(rule, self.target_url)

        insecure_cookies = [c.name for c in resp.cookies if not c.secure]
        if insecure_cookies and self.target_url.startswith("https://"):
            self._add("cookie-missing-secure", self.target_url, f"cookies: {insecure_cookies}")

        no_httponly = [c.name for c in resp.cookies if not c.has_nonstandard_attr("HttpOnly") and "HttpOnly" not in str(c)]
        if no_httponly:
            self._add("cookie-missing-httponly", self.target_url, f"cookies: {no_httponly}")
        if resp.cookies:
            self._note(f"Cookies set: {[c.name for c in resp.cookies]}")

        # A bare product name is far less useful to an attacker than one
        # carrying a version, so only flag when a version number is present.
        server = headers.get("server")
        if server and re.search(r"\d+\.\d+", server):
            self._add("server-header-disclosure", self.target_url, f"Server: {server}")

        no_samesite = [c.name for c in resp.cookies
                        if not any(k.lower() == "samesite" for k in (c._rest or {}))]
        if no_samesite:
            self._add("cookie-missing-samesite", self.target_url, f"cookies: {no_samesite}")

        for header in TECH_HEADERS:
            if header in headers:
                self._add("tech-stack-disclosure", self.target_url,
                           f"{header}: {headers[header]}")

        self._check_cors(headers)
        self._check_mixed_content(resp)
        return resp

    def _check_cors(self, headers):
        """A wildcard origin is only dangerous when credentials are allowed;
        reflecting an arbitrary origin is dangerous on its own, so probe with
        a throwaway origin to see whether it comes back."""
        allow_origin = headers.get("access-control-allow-origin")
        allow_creds = (headers.get("access-control-allow-credentials") or "").lower() == "true"
        if allow_origin == "*" and allow_creds:
            self._add("cors-wildcard-with-credentials", self.target_url,
                       "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true")
            return

        probe = "https://security-scan-probe.invalid"
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout,
                                     verify=self.verify_ssl, headers={"Origin": probe})
        except requests.RequestException:
            return
        echoed = resp.headers.get("Access-Control-Allow-Origin")
        if echoed and probe in echoed:
            creds = (resp.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
            rule = "cors-wildcard-with-credentials" if creds else "cors-reflects-arbitrary-origin"
            self._add(rule, self.target_url, f"sent Origin: {probe} — echoed back as {echoed}")

    def _check_mixed_content(self, resp):
        if not self.target_url.startswith("https://"):
            return
        refs = re.findall(r'(?:src|href)\s*=\s*["\'](http://[^"\']+)["\']', resp.text or "", re.I)
        # Ignore http:// used purely as an XML namespace or doctype identifier.
        refs = [r for r in refs if "w3.org" not in r and "schemas." not in r]
        if refs:
            self._add("mixed-content", self.target_url,
                       f"{len(refs)} plain-HTTP sub-resource(s), e.g. {refs[0][:120]}")

    # -------------------------------------------------- exposure / methods
    def check_exposed_files(self):
        """Requests a fixed list of files that should never be public.

        Each path carries a content signature: a site that answers 200 to
        everything (SPA fallback, custom soft-404) would otherwise produce a
        finding for every entry in the list.
        """
        base = self.target_url
        for path, signatures in SENSITIVE_PATHS:
            try:
                resp = self.session.get(base + path, timeout=self.timeout,
                                         verify=self.verify_ssl, allow_redirects=False)
            except requests.RequestException:
                continue
            if resp.status_code != 200:
                continue
            body = (resp.text or "")[:4000].lower()
            if not any(sig.lower() in body for sig in signatures):
                continue
            self._add("exposed-sensitive-file", base + path,
                       f"HTTP 200, {len(resp.content)} bytes, matched expected content")
        self._note(f"Probed {len(SENSITIVE_PATHS)} sensitive path(s).")

    def check_directory_listing(self):
        for path in ("/", "/assets/", "/static/", "/uploads/", "/images/", "/files/", "/backup/"):
            try:
                resp = self.session.get(self.target_url + path, timeout=self.timeout,
                                         verify=self.verify_ssl)
            except requests.RequestException:
                continue
            if resp.status_code != 200:
                continue
            body = (resp.text or "")[:4000].lower()
            if any(sig in body for sig in DIRECTORY_LISTING_SIGNATURES):
                self._add("directory-listing-enabled", self.target_url + path,
                           "response body looks like an auto-generated index")

    def check_http_methods(self):
        try:
            resp = self.session.options(self.target_url, timeout=self.timeout, verify=self.verify_ssl)
        except requests.RequestException:
            return
        allowed = resp.headers.get("Allow") or resp.headers.get("Access-Control-Allow-Methods") or ""
        self._note(f"Allowed HTTP methods advertised: {allowed or '(none advertised)'}")
        found = [m for m in RISKY_METHODS if re.search(rf"\b{m}\b", allowed, re.I)]
        if found:
            self._add("dangerous-http-method", self.target_url, f"Allow: {allowed}")

    def check_open_redirect(self, param_urls):
        """Flags a redirect whose destination came from the query string.

        Only reports when the response actually redirects off-site to the
        probe domain — a page that merely accepts the parameter and ignores
        it is not an open redirect.
        """
        probe = "https://security-scan-probe.invalid/"
        tested = 0
        for url in param_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            targets = [p for p in params if p.lower() in REDIRECT_PARAMS]
            if not targets:
                continue
            for param in targets:
                mutated = dict(params)
                mutated[param] = [probe]
                new_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
                try:
                    resp = self.session.get(new_url, timeout=self.timeout,
                                             verify=self.verify_ssl, allow_redirects=False)
                except requests.RequestException:
                    continue
                tested += 1
                location = resp.headers.get("Location", "")
                if resp.is_redirect and "security-scan-probe.invalid" in location:
                    self._add("open-redirect", new_url,
                               f"{param}={probe} → Location: {location}")
        if tested:
            self._note(f"Tested {tested} redirect parameter(s).")

    def check_ssl(self):
        parsed = urlparse(self.target_url)
        if parsed.scheme != "https":
            self._add("no-https", self.target_url)
            return

        host, port = parsed.hostname, parsed.port or 443
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()

            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (not_after - datetime.now(timezone.utc)).days
            self._note(f"TLS protocol negotiated: {version}; certificate expires in {days_left} day(s)")
            if days_left < 0:
                self._add("tls-cert-expired", self.target_url, f"expired {abs(days_left)} days ago")
            elif days_left < 14:
                self._add("tls-cert-expiring-soon", self.target_url, f"{days_left} days left")

            if version in ("TLSv1", "TLSv1.1"):
                self._add("tls-outdated-protocol", self.target_url, f"negotiated {version}")

        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as e:
            self._add("tls-handshake-failed", self.target_url, str(e))

    # ------------------------------------------------------------- crawling
    def crawl(self):
        visited, to_visit = set(), [self.target_url]
        param_urls, forms = [], []
        origin = urlparse(self.target_url).netloc

        while to_visit and len(visited) < self.max_crawl_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            self._log(f"[crawl {len(visited)}] {url}")
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            except requests.RequestException:
                continue
            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            if parse_qs(urlparse(url).query):
                param_urls.append(url)
            for m in re.finditer(r'href=["\']([^"\'#]+)', resp.text):
                link = urljoin(url, m.group(1))
                if urlparse(link).netloc == origin and link not in visited:
                    to_visit.append(link)
            for fm in re.finditer(r"<form.*?</form>", resp.text, re.DOTALL | re.IGNORECASE):
                action = re.search(r'action=["\']([^"\']*)', fm.group(0))
                inputs = re.findall(r'name=["\']([^"\']+)', fm.group(0))
                forms.append({"page": url, "action": urljoin(url, action.group(1)) if action else url, "inputs": inputs})

        self._note(f"Crawled {len(visited)} page(s); found {len(param_urls)} parameterized URL(s) "
                   f"and {len(forms)} form(s)")
        return param_urls, forms

    # ----------------------------------------------------- injection tests
    def _mutate_and_check(self, param_urls, payloads, matcher, rule):
        for url in param_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                for payload in payloads:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                    try:
                        resp = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
                    except requests.RequestException:
                        continue
                    if matcher(resp, payload):
                        self._add(rule, test_url, f"param='{param}'")
                        break  # one confirmed hit per param is enough

    def test_xss(self, param_urls):
        self._mutate_and_check(
            param_urls, XSS_PAYLOADS,
            matcher=lambda resp, payload: payload in resp.text,
            rule="reflected-xss",
        )

    def test_sqli(self, param_urls):
        self._mutate_and_check(
            param_urls, SQLI_PAYLOADS,
            matcher=lambda resp, _p: any(sig in resp.text.lower() for sig in SQL_ERROR_SIGNATURES),
            rule="sql-injection-error-based",
        )

    # ----------------------------------------------------------------- run
    def run_all(self, use_ai: bool = False) -> ScanResult:
        self._log(f"Scanning {self.target_url} ...")
        self.check_security_headers()
        self.check_ssl()

        self._log("Checking HTTP methods ...")
        self.check_http_methods()
        self._log(f"Probing {len(SENSITIVE_PATHS)} sensitive path(s) ...")
        self.check_exposed_files()
        self._log("Checking for directory listings ...")
        self.check_directory_listing()

        param_urls, forms = self.crawl()
        self.result.scanned_file_names = [self.target_url]
        self.result.files_scanned = len(param_urls) or 1
        if param_urls:
            self._log(f"Testing {len(param_urls)} parameterized URL(s) for XSS/SQLi...")
            self.test_xss(param_urls)
            self.test_sqli(param_urls)
            self._log("Testing redirect parameters ...")
            self.check_open_redirect(param_urls)
        if self.show_progress:
            print(_c(f"Web scan done: {len(self.result.findings)} finding(s).", Style.DIM), flush=True)

        if use_ai and self._evidence:
            self.result.ai_file_contents[self.target_url] = "\n".join(self._evidence)
            self.result.ai_target_kind[self.target_url] = "web"
        return self.result


def scan_url(target_url, use_ai: bool = False, **kwargs) -> ScanResult:
    """Entry point for embedding in scanner.py's main()."""
    return WebScanner(target_url, **kwargs).run_all(use_ai=use_ai)


def print_report(result: ScanResult, target: str):
    print(_c(f"\nWeb scan report for {target}", Style.BRIGHT))
    if not result.findings:
        print(_c("No findings.", Fore.GREEN))
        return
    ranked = sorted(result.findings, key=lambda f: SEVERITY_RANK.get(f.severity, 0), reverse=True)
    for f in ranked:
        color = SEV_COLOR.get(f.severity, "")
        confirm = " (AI-confirmed)" if f.ai_verdict == "true_positive" else (
            " (AI: likely false positive)" if f.ai_verdict == "false_positive" else (
                " (AI-found)" if f.source == "ai" else ""))
        print(f"{_c(f'[{f.severity.upper()}]', color)} {f.description}{confirm}")
        print(f"  location: {f.file}")
        if f.display_line:
            print(f"  evidence: {f.display_line}")
        if f.ai_reason:
            print(f"  ai note:  {f.ai_reason}")
        if f.impact:
            print(f"  impact:   {f.impact}")
        if f.improvement:
            print(f"  fix:      {f.improvement}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Web vulnerability scan module")
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--no-verify-ssl", action="store_true")
    parser.add_argument("--ai", action="store_true",
                         help="Send collected scan evidence (headers, cookies, TLS info — never source "
                              "code) to the AI layer to verify findings and look for anything the regex "
                              "checks missed. Requires LLM_API_KEY in this script's own .env.")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    args = parser.parse_args()

    result = scan_url(args.url, use_ai=args.ai, verify_ssl=not args.no_verify_ssl, show_progress=not args.quiet)

    if args.ai:
        from scanner import load_config, run_ai_verify_and_scan
        config = load_config()
        if not config.get("api_key"):
            print(_c("[!] --ai requested but LLM_API_KEY not set in scanner.py's own .env — skipping.", Fore.YELLOW),
                  file=sys.stderr)
        else:
            run_ai_verify_and_scan(result, config, show_progress=not args.quiet)

    print_report(result, args.url)
    sys.exit(1 if any(f.severity in ("critical", "high") for f in result.findings) else 0)


if __name__ == "__main__":
    main()
