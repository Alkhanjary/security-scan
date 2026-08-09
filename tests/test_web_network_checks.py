"""
Test suite for the web/network checks added this session:

web_scan.py:
  - csp-weak-directive (CSP present but allows unsafe-inline/eval/wildcard)
  - missing-sri (cross-origin <script> without an integrity attribute)
  - exposed-debug-error-page (stack-trace/debugger signature on a 404 path)
  - cms-version-disclosure (<meta name=generator> with a version number)

network_scan.py:
  - ftp-anonymous-login, redis-unauthenticated,
    elasticsearch-unauthenticated, docker-api-unauthenticated
    (active, single-request unauthenticated-access probes)

Each web check gets a small stdlib HTTPServer fixture serving exactly the
content that should trigger it; each network probe is called directly
against a minimal raw-socket fake service, sidestepping scan_host()'s
port-number dispatch (which only maps the real well-known ports, e.g. 21
for FTP) so the fake service doesn't need a privileged port to bind to.
"""

import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import web_scan  # noqa: E402
import network_scan  # noqa: E402


# --------------------------------------------------------------------- web

class _VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/security-scan-404-probe-x7q9z/":
            self.send_response(500)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Traceback (most recent call last):</h1>"
                              b"<pre>File app.py line 42</pre></body></html>")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Security-Policy",
                          "default-src 'self'; script-src 'self' 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(
            b"<html><head>"
            b"<meta name=\"generator\" content=\"WordPress 5.8.1\">"
            b"<script src=\"https://cdn.example.com/analytics.js\"></script>"
            b"</head><body>hello</body></html>"
        )


@pytest.fixture(scope="module")
def vuln_web_server():
    srv = HTTPServer(("127.0.0.1", 0), _VulnHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()


def test_web_checks_all_fire(vuln_web_server):
    result = web_scan.scan_url(f"http://127.0.0.1:{vuln_web_server}", verify_ssl=False, show_progress=False)
    rules_found = {f.rule for f in result.findings}
    for rule in ("csp-weak-directive", "missing-sri", "exposed-debug-error-page", "cms-version-disclosure"):
        assert rule in rules_found, f"{rule} did not fire; findings were {rules_found}"


def test_csp_weak_directive_not_flagged_without_unsafe_keywords():
    scanner = web_scan.WebScanner("https://example.invalid", show_progress=False)
    scanner._check_csp_directives("default-src 'self'; script-src 'self' https://trusted.cdn")
    assert not scanner.result.findings


def test_missing_sri_ignores_same_origin_script():
    scanner = web_scan.WebScanner("https://example.com", show_progress=False)
    scanner._check_sri("https://example.com/page", '<script src="/static/app.js"></script>')
    assert not scanner.result.findings


def test_missing_sri_ignores_script_with_integrity():
    scanner = web_scan.WebScanner("https://example.com", show_progress=False)
    scanner._check_sri(
        "https://example.com/page",
        '<script src="https://cdn.example.com/x.js" integrity="sha384-abc" crossorigin="anonymous"></script>',
    )
    assert not scanner.result.findings


# ----------------------------------------------------------------- network

def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve_once(port, handler):
    """Accepts exactly one connection, hands it to `handler`, then exits."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    srv.settimeout(5)
    conn, _ = srv.accept()
    try:
        handler(conn)
    finally:
        conn.close()
        srv.close()


def _ftp_handler(conn):
    conn.sendall(b"220 fake ftp\r\n")
    conn.recv(256)
    conn.sendall(b"331 Please specify the password.\r\n")
    conn.recv(256)
    conn.sendall(b"230 Login successful.\r\n")
    try:
        conn.recv(256)
    except OSError:
        pass


def test_ftp_anonymous_login_detected():
    port = _free_port()
    t = threading.Thread(target=_serve_once, args=(port, _ftp_handler), daemon=True)
    t.start()
    time.sleep(0.2)
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_ftp_anonymous("127.0.0.1", port)
    t.join(timeout=2)
    assert {f.rule for f in scanner.result.findings} == {"ftp-anonymous-login"}


def _redis_handler(conn):
    conn.recv(256)
    conn.sendall(b"+PONG\r\n")


def test_redis_unauthenticated_detected():
    port = _free_port()
    t = threading.Thread(target=_serve_once, args=(port, _redis_handler), daemon=True)
    t.start()
    time.sleep(0.2)
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_redis_unauthenticated("127.0.0.1", port)
    t.join(timeout=2)
    assert {f.rule for f in scanner.result.findings} == {"redis-unauthenticated"}


def test_redis_not_flagged_when_auth_required():
    port = _free_port()

    def handler(conn):
        conn.recv(256)
        conn.sendall(b"-NOAUTH Authentication required.\r\n")

    t = threading.Thread(target=_serve_once, args=(port, handler), daemon=True)
    t.start()
    time.sleep(0.2)
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_redis_unauthenticated("127.0.0.1", port)
    t.join(timeout=2)
    assert not scanner.result.findings


def _http_json_handler(body):
    def handler(conn):
        conn.recv(1024)
        resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                 + str(len(body)).encode() + b"\r\n\r\n" + body)
        conn.sendall(resp)
    return handler


def test_elasticsearch_unauthenticated_detected():
    port = _free_port()
    body = b'{"cluster_name":"fake-cluster","version":{"number":"7.9.0"}}'
    t = threading.Thread(target=_serve_once, args=(port, _http_json_handler(body)), daemon=True)
    t.start()
    time.sleep(0.2)
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_elasticsearch_unauthenticated("127.0.0.1", port)
    t.join(timeout=2)
    assert {f.rule for f in scanner.result.findings} == {"elasticsearch-unauthenticated"}


def test_docker_api_unauthenticated_detected():
    port = _free_port()
    body = b'{"Version":"20.10.7","ApiVersion":"1.41"}'
    t = threading.Thread(target=_serve_once, args=(port, _http_json_handler(body)), daemon=True)
    t.start()
    time.sleep(0.2)
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_docker_api_unauthenticated("127.0.0.1", port)
    t.join(timeout=2)
    assert {f.rule for f in scanner.result.findings} == {"docker-api-unauthenticated"}


def test_risky_ports_include_new_services():
    for port in (445, 1433, 3306, 5432, 6379, 9200, 27017, 2375, 11211, 135):
        assert port in network_scan.RISKY_PORTS
