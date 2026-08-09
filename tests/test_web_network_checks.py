"""
Test suite for the web/network checks added this session:

web_scan.py:
  - csp-weak-directive (CSP present but allows unsafe-inline/eval/wildcard)
  - missing-sri (cross-origin <script> without an integrity attribute)
  - exposed-debug-error-page (stack-trace/debugger signature on a 404 path)
  - cms-version-disclosure (<meta name=generator> with a version number)
  - weak-tls-cipher (signature matching against a negotiated cipher name)
  - exposed-source-map (a .js.map file that's actually a real source map)
  - cross-site-tracing (TRACE request echoes back a canary header)
  - open-cloud-storage-bucket (bucket URL in page content + public listing)

  - cors-null-origin-accepted (Origin: null reflected in the CORS header)
  - insecure-form-submission (HTTPS page, form action posts to plain HTTP)
  - weak-hsts-max-age (HSTS present but max-age under ~6 months)
  - robots-disclosed-sensitive-path (robots.txt Disallow looks sensitive)
  - cacheable-sensitive-response (Set-Cookie with no Cache-Control no-store/private)

network_scan.py:
  - ftp-anonymous-login, redis-unauthenticated,
    elasticsearch-unauthenticated, docker-api-unauthenticated,
    vnc-no-authentication, memcached-stats-exposed
    (active, single-request unauthenticated-access probes)
  - ssh-protocol-1-legacy (pure banner-string check)
  - dns-zone-transfer-allowed (a real, minimal DNS AXFR query over TCP)
  - smtp-open-relay (MAIL FROM/RCPT TO aborted with RSET before DATA —
    no message is ever actually sent)
  - mongodb-unauthenticated (hand-built BSON/OP_QUERY listDatabases command)
  - snmp-default-community (hand-built ASN.1/BER SNMPv1 GetRequest over UDP
    — the only UDP-based check, since SNMP is invisible to a TCP port scan)

Each web check gets a small stdlib HTTPServer fixture serving exactly the
content that should trigger it; each network probe is called directly
against a minimal raw-socket fake service, sidestepping scan_host()'s
port-number dispatch (which only maps the real well-known ports, e.g. 21
for FTP) so the fake service doesn't need a privileged port to bind to.
"""

import socket
import struct
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
        if self.path == "/app.js.map":
            body = b'{"version":3,"sources":["app.ts"],"mappings":"AAAA"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin/\nDisallow: /public/\n")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Security-Policy",
                          "default-src 'self'; script-src 'self' 'unsafe-inline'")
        self.send_header("Strict-Transport-Security", "max-age=300")
        self.send_header("Set-Cookie", "session=abc123; Secure; HttpOnly")
        if self.headers.get("Origin") == "null":
            self.send_header("Access-Control-Allow-Origin", "null")
        self.end_headers()
        self.wfile.write(
            b"<html><head>"
            b"<meta name=\"generator\" content=\"WordPress 5.8.1\">"
            b"<script src=\"https://cdn.example.com/analytics.js\"></script>"
            b"<script src=\"/app.js\"></script>"
            b"</head><body>hello</body></html>"
        )

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, TRACE")
        self.end_headers()

    def do_TRACE(self):
        canary = self.headers.get("X-Security-Scan-Trace-Canary-8f2a", "")
        body = f"TRACE / HTTP/1.1\r\nX-Security-Scan-Trace-Canary-8f2a: {canary}\r\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.end_headers()
        self.wfile.write(body)


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
    for rule in ("csp-weak-directive", "missing-sri", "exposed-debug-error-page",
                 "cms-version-disclosure", "weak-hsts-max-age", "cacheable-sensitive-response",
                 "robots-disclosed-sensitive-path", "cors-null-origin-accepted"):
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


def test_round2_web_checks_all_fire(vuln_web_server):
    # exposed-source-map and open-cloud-storage-bucket need the page content;
    # cross-site-tracing needs the OPTIONS + TRACE round trip.
    base = f"http://127.0.0.1:{vuln_web_server}"

    scanner = web_scan.WebScanner(base, verify_ssl=False, show_progress=False)
    resp = scanner.session.get(scanner.target_url, timeout=5)
    scanner._check_source_maps(scanner.target_url, resp.text)
    assert "exposed-source-map" in {f.rule for f in scanner.result.findings}

    scanner2 = web_scan.WebScanner(base, verify_ssl=False, show_progress=False)
    scanner2.check_http_methods()
    assert "cross-site-tracing" in {f.rule for f in scanner2.result.findings}


def test_open_cloud_storage_bucket_detected(monkeypatch):
    # Point the S3 vhost pattern's probe-URL builder at a local fake bucket
    # listing server instead of the real s3.amazonaws.com — this must never
    # make a genuine outbound request to AWS during a test run.
    bucket_srv = HTTPServer(("127.0.0.1", 0), _BucketListingHandler)
    bucket_port = bucket_srv.server_address[1]
    t = threading.Thread(target=bucket_srv.serve_forever, daemon=True)
    t.start()
    try:
        pattern, _orig_fn, signature = web_scan.CLOUD_BUCKET_PATTERNS[0]
        monkeypatch.setattr(web_scan, "CLOUD_BUCKET_PATTERNS",
                             [(pattern, lambda name: f"http://127.0.0.1:{bucket_port}/", signature)]
                             + web_scan.CLOUD_BUCKET_PATTERNS[1:])

        scanner = web_scan.WebScanner("https://example.com", show_progress=False)
        scanner._check_cloud_buckets(
            '<a href="https://my-test-bucket.s3.amazonaws.com/file.txt">link</a>')
        assert "open-cloud-storage-bucket" in {f.rule for f in scanner.result.findings}
    finally:
        bucket_srv.shutdown()


class _BucketListingHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.end_headers()
        self.wfile.write(b"<ListBucketResult><Name>my-test-bucket</Name></ListBucketResult>")


@pytest.mark.parametrize("cipher_name,expected", [
    ("RC4-SHA", True),
    ("DES-CBC3-SHA", True),
    ("ADH-AES256-SHA", True),
    ("EXP-RC4-MD5", True),
    ("NULL-SHA", True),
    ("TLS_AES_256_GCM_SHA384", False),
    ("ECDHE-RSA-AES128-GCM-SHA256", False),
    ("TLS_CHACHA20_POLY1305_SHA256", False),
])
def test_weak_cipher_signature_matching(cipher_name, expected):
    matched = any(w in cipher_name.upper() for w in web_scan.WEAK_CIPHER_SIGNATURES)
    assert matched == expected


def test_insecure_form_submission_https_page_http_action():
    scanner = web_scan.WebScanner("https://example.com", show_progress=False)
    scanner._check_form_action("https://example.com/login", "http://example.com/submit")
    assert {f.rule for f in scanner.result.findings} == {"insecure-form-submission"}


def test_insecure_form_submission_not_flagged_when_both_https():
    scanner = web_scan.WebScanner("https://example.com", show_progress=False)
    scanner._check_form_action("https://example.com/login", "https://example.com/submit")
    assert not scanner.result.findings


@pytest.mark.parametrize("hsts_value,expected", [
    ("max-age=300", True),
    ("max-age=86400", True),
    ("max-age=31536000; includeSubDomains", False),
    ("max-age=15768000", False),
])
def test_hsts_max_age(hsts_value, expected):
    scanner = web_scan.WebScanner("https://example.com", show_progress=False)
    scanner._check_hsts_max_age(hsts_value)
    assert bool(scanner.result.findings) == expected


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


def _vnc_handler_no_auth(conn):
    conn.sendall(b"RFB 003.008\n")
    conn.recv(12)  # echoed version
    conn.sendall(bytes([1, 1]))  # 1 security type offered: type 1 (None)


def test_vnc_no_authentication_detected():
    port = _free_port()
    t = threading.Thread(target=_serve_once, args=(port, _vnc_handler_no_auth), daemon=True)
    t.start()
    time.sleep(0.2)
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_vnc_no_auth("127.0.0.1", port)
    t.join(timeout=2)
    assert {f.rule for f in scanner.result.findings} == {"vnc-no-authentication"}


def test_vnc_not_flagged_when_password_required():
    port = _free_port()

    def handler(conn):
        conn.sendall(b"RFB 003.008\n")
        conn.recv(12)
        conn.sendall(bytes([1, 2]))  # 1 security type offered: type 2 (VNC Authentication)

    t = threading.Thread(target=_serve_once, args=(port, handler), daemon=True)
    t.start()
    time.sleep(0.2)
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_vnc_no_auth("127.0.0.1", port)
    t.join(timeout=2)
    assert not scanner.result.findings


@pytest.mark.parametrize("banner,expected", [
    ("SSH-1.99-OpenSSH_2.9", True),
    ("SSH-1.5-1.2.27", True),
    ("SSH-2.0-OpenSSH_9.6", False),
    (None, False),
    ("", False),
])
def test_check_ssh_protocol(banner, expected):
    result = network_scan.check_ssh_protocol(banner)
    assert (result is not None) == expected


def _dns_axfr_allow_handler(conn):
    length_bytes = conn.recv(2)
    qlen = struct.unpack(">H", length_bytes)[0]
    query = b""
    while len(query) < qlen:
        query += conn.recv(qlen - len(query))
    # RCODE=0 (no error), ANCOUNT=3 — a real server would follow with the
    # actual records, but the header alone is enough to prove AXFR wasn't refused.
    header = struct.pack(">HHHHHH", 0x1337, 0x8180, 1, 3, 0, 0)
    conn.sendall(struct.pack(">H", len(header)) + header)


def test_dns_zone_transfer_allowed_detected():
    port = _free_port()
    t = threading.Thread(target=_serve_once, args=(port, _dns_axfr_allow_handler), daemon=True)
    t.start()
    time.sleep(0.2)
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_dns_axfr("127.0.0.1", port, "example.com")
    t.join(timeout=2)
    assert {f.rule for f in scanner.result.findings} == {"dns-zone-transfer-allowed"}


def test_dns_zone_transfer_skips_bare_ip_zone():
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_dns_axfr("127.0.0.1", _free_port(), "127.0.0.1")
    assert not scanner.result.findings  # never even attempts a connection


def test_dns_zone_transfer_not_flagged_when_refused():
    port = _free_port()

    def handler(conn):
        length_bytes = conn.recv(2)
        qlen = struct.unpack(">H", length_bytes)[0]
        conn.recv(qlen)
        # RCODE=5 (REFUSED), ANCOUNT=0
        header = struct.pack(">HHHHHH", 0x1337, 0x8185, 1, 0, 0, 0)
        conn.sendall(struct.pack(">H", len(header)) + header)

    t = threading.Thread(target=_serve_once, args=(port, handler), daemon=True)
    t.start()
    time.sleep(0.2)
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_dns_axfr("127.0.0.1", port, "example.com")
    t.join(timeout=2)
    assert not scanner.result.findings


def _smtp_open_relay_handler(conn):
    conn.sendall(b"220 fake.mail.server ESMTP\r\n")
    conn.recv(256)  # EHLO
    conn.sendall(b"250-fake.mail.server\r\n250 OK\r\n")
    conn.recv(256)  # MAIL FROM
    conn.sendall(b"250 OK\r\n")
    conn.recv(256)  # RCPT TO
    conn.sendall(b"250 OK\r\n")
    conn.recv(256)  # RSET
    conn.sendall(b"250 OK\r\n")
    try:
        conn.recv(256)  # QUIT
    except OSError:
        pass


def test_smtp_open_relay_detected():
    port = _free_port()
    t = threading.Thread(target=_serve_once, args=(port, _smtp_open_relay_handler), daemon=True)
    t.start()
    time.sleep(0.2)
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_smtp_open_relay("127.0.0.1", port)
    t.join(timeout=2)
    assert {f.rule for f in scanner.result.findings} == {"smtp-open-relay"}


def test_smtp_not_flagged_when_relay_rejected():
    port = _free_port()

    def handler(conn):
        conn.sendall(b"220 fake.mail.server ESMTP\r\n")
        conn.recv(256)
        conn.sendall(b"250-fake.mail.server\r\n250 OK\r\n")
        conn.recv(256)
        conn.sendall(b"250 OK\r\n")
        conn.recv(256)
        conn.sendall(b"553 Relaying denied\r\n")
        conn.recv(256)
        conn.sendall(b"250 OK\r\n")
        try:
            conn.recv(256)
        except OSError:
            pass

    t = threading.Thread(target=_serve_once, args=(port, handler), daemon=True)
    t.start()
    time.sleep(0.2)
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_smtp_open_relay("127.0.0.1", port)
    t.join(timeout=2)
    assert not scanner.result.findings


def _memcached_stats_handler(conn):
    conn.recv(256)
    conn.sendall(b"STAT pid 1234\r\nSTAT uptime 100\r\nEND\r\n")


def test_memcached_stats_exposed_detected():
    port = _free_port()
    t = threading.Thread(target=_serve_once, args=(port, _memcached_stats_handler), daemon=True)
    t.start()
    time.sleep(0.2)
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_memcached_stats("127.0.0.1", port)
    t.join(timeout=2)
    assert {f.rule for f in scanner.result.findings} == {"memcached-stats-exposed"}


def _mongo_reply_handler(reply_doc):
    def handler(conn):
        header = conn.recv(16)
        msg_len = struct.unpack("<i", header[:4])[0]
        body = b""
        while len(body) < msg_len - 16:
            chunk = conn.recv(msg_len - 16 - len(body))
            if not chunk:
                break
            body += chunk
        reply_body = (struct.pack("<i", 0) + struct.pack("<q", 0)
                       + struct.pack("<i", 0) + struct.pack("<i", 1) + reply_doc)
        reply_header = struct.pack("<iii", 2, 1, 1)  # opCode 1 = OP_REPLY
        conn.sendall(struct.pack("<i", 16 + len(reply_body)) + reply_header + reply_body)
    return handler


def test_mongodb_unauthenticated_detected():
    port = _free_port()
    doc = b'{"databases": [{"name": "admin"}], "ok": 1}'
    t = threading.Thread(target=_serve_once, args=(port, _mongo_reply_handler(doc)), daemon=True)
    t.start()
    time.sleep(0.2)
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_mongodb_unauthenticated("127.0.0.1", port)
    t.join(timeout=2)
    assert {f.rule for f in scanner.result.findings} == {"mongodb-unauthenticated"}


def test_mongodb_not_flagged_when_auth_enforced():
    port = _free_port()
    doc = b'{"ok": 0, "errmsg": "not authorized on admin to execute command", "code": 13}'
    t = threading.Thread(target=_serve_once, args=(port, _mongo_reply_handler(doc)), daemon=True)
    t.start()
    time.sleep(0.2)
    scanner = network_scan.NetworkScanner(show_progress=False)
    scanner._probe_mongodb_unauthenticated("127.0.0.1", port)
    t.join(timeout=2)
    assert not scanner.result.findings


def test_snmp_default_community_detected(monkeypatch):
    port = _free_port()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))

    def fake_server():
        sock.settimeout(3)
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            return
        NS = network_scan.NetworkScanner
        varbind = NS._ber_tlv(0x30, NS._ber_oid("1.3.6.1.2.1.1.1.0") + NS._ber_tlv(0x04, b"fake sysdescr"))
        varbind_list = NS._ber_tlv(0x30, varbind)
        pdu_body = NS._ber_int(1) + NS._ber_int(0) + NS._ber_int(0) + varbind_list
        pdu = NS._ber_tlv(0xA2, pdu_body)  # GetResponse-PDU
        message = NS._ber_tlv(0x30, NS._ber_int(0) + NS._ber_tlv(0x04, b"public") + pdu)
        sock.sendto(message, addr)

    t = threading.Thread(target=fake_server, daemon=True)
    t.start()
    time.sleep(0.2)

    # probe_snmp_default_community hardcodes UDP/161 — redirect sendto at
    # the socket-module level for this test rather than touching production
    # code with a test-only port parameter.
    real_socket_cls = socket.socket

    class _RedirectingSocket(real_socket_cls):
        def sendto(self, data, addr):
            return super().sendto(data, ("127.0.0.1", port))

    monkeypatch.setattr(socket, "socket", lambda *a, **kw: _RedirectingSocket(*a, **kw))
    try:
        scanner = network_scan.NetworkScanner(show_progress=False)
        scanner.probe_snmp_default_community("127.0.0.1")
    finally:
        monkeypatch.setattr(socket, "socket", real_socket_cls)
    t.join(timeout=2)
    sock.close()
    assert {f.rule for f in scanner.result.findings} == {"snmp-default-community"}


def test_snmp_default_community_not_flagged_on_timeout():
    # Nothing listening on this port — must not fire and must not hang.
    port = _free_port()
    scanner = network_scan.NetworkScanner(show_progress=False)
    start = time.time()

    class _NS(network_scan.NetworkScanner):
        def probe_snmp_default_community(self, host, community="public"):
            query = self._snmp_get_request(community, "1.3.6.1.2.1.1.1.0")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(1.5)
                sock.sendto(query, (host, port))
                data, _addr = sock.recvfrom(2048)
            except (socket.timeout, OSError):
                return
            finally:
                sock.close()
            if len(data) > 2 and data[0] == 0x30 and b"\xa2" in data[:40]:
                self._add("snmp-default-community", host, port, "unexpected response")

    scanner = _NS(show_progress=False)
    scanner.probe_snmp_default_community("127.0.0.1")
    assert time.time() - start < 3
    assert not scanner.result.findings


@pytest.mark.parametrize("oid,expected_bytes", [
    ("1.3.6.1.2.1.1.1.0", bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])),
    ("1.3.6.1.4.1.9.9.13.1.3.1.3", bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x09, 0x09, 0x0D, 0x01, 0x03, 0x01, 0x03])),
])
def test_ber_oid_encoding(oid, expected_bytes):
    encoded = network_scan.NetworkScanner._ber_oid(oid)
    # tag(0x06) + length byte + body
    assert encoded[0] == 0x06
    assert encoded[2:] == expected_bytes
