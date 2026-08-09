#!/usr/bin/env python3
"""
network_scan.py

Network scanner module for security-scan. Mirrors scanner.py's architecture:
rule-keyed SEVERITY / DESCRIPTION / IMPACT / IMPROVEMENT tables and the
shared Finding / ScanResult dataclasses, so output slots into the same
report writer and --ai review layer as the code and web scan modules.

Capabilities:
- Host discovery via TCP-connect probing (no root/raw sockets required)
- Port scanning (threaded TCP connect scan), now including the common
  database/admin ports that should never face the internet (MSSQL, MySQL,
  PostgreSQL, Redis, Elasticsearch, MongoDB, Docker API, Memcached)
- Service/banner detection, including offline matching against known-
  backdoored distributions (e.g. vsftpd 2.3.4) and per-product minimum-
  supported-version thresholds (OpenSSH, Apache, nginx, IIS, MySQL, ...)
- Active, read-only unauthenticated-access probes for FTP (anonymous login),
  Redis (PING with no auth), Elasticsearch (cluster info with no auth), the
  Docker Engine API (version info with no auth), and VNC (RFB handshake
  checked for the "None" security type) — one request/response each, no
  brute-forcing or state-changing commands
- SSH banners checked for the obsolete, broken protocol-1 identification string

Only scan hosts/networks you own or are explicitly authorized to test.
Unauthorized network scanning may be illegal depending on jurisdiction.
"""

import re
import socket
import ipaddress
import sys
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scanner import Finding, ScanResult, _c, Fore, Style, SEV_COLOR, SEVERITY_RANK  # noqa: E402

# ---------------------------------------------------------------------------
# Rule tables — same shape as scanner.py / web_scan.py
# ---------------------------------------------------------------------------

RISKY_PORTS = {
    21: "ftp", 23: "telnet", 3389: "rdp", 5900: "vnc",
    135: "msrpc", 445: "smb", 1433: "mssql", 3306: "mysql", 5432: "postgresql",
    6379: "redis", 9200: "elasticsearch", 27017: "mongodb", 2375: "docker-api",
    11211: "memcached",
}

SEVERITY = {
    "open-port": "low",
    "risky-service-exposed": "high",
    "outdated-service-banner": "medium",
    "ftp-anonymous-login": "high",
    "redis-unauthenticated": "critical",
    "elasticsearch-unauthenticated": "critical",
    "docker-api-unauthenticated": "critical",
    "vnc-no-authentication": "critical",
    "ssh-protocol-1-legacy": "high",
}

DESCRIPTION = {
    "open-port": "Open TCP port detected",
    "risky-service-exposed": "Commonly-attacked service exposed on the network",
    "outdated-service-banner": "Service banner suggests outdated/unsupported software",
    "ftp-anonymous-login": "FTP server accepts anonymous login",
    "redis-unauthenticated": "Redis instance accepts commands without authentication",
    "elasticsearch-unauthenticated": "Elasticsearch instance exposes cluster data without authentication",
    "docker-api-unauthenticated": "Docker Engine API is reachable without authentication",
    "vnc-no-authentication": "VNC server offers 'None' as a security type — anyone can connect without a password",
    "ssh-protocol-1-legacy": "Server offers the obsolete, cryptographically broken SSH protocol version 1",
}

IMPACT = {
    "open-port": "An open port expands the attack surface; whether it's a real risk depends on the service and its exposure (internal vs internet-facing).",
    "risky-service-exposed": "Services like FTP, Telnet, RDP, and VNC are frequent targets for credential brute-forcing and have a history of serious vulnerabilities.",
    "outdated-service-banner": "Older service versions may have known, publicly documented vulnerabilities with available exploits.",
    "ftp-anonymous-login": "Anyone can log in and read (and often write) whatever the FTP root exposes, with no credentials required.",
    "redis-unauthenticated": "Anyone can read, write, or delete every key, and Redis's own CONFIG/replication commands can often be abused for full remote code execution on the host.",
    "elasticsearch-unauthenticated": "Anyone can read, modify, or delete every index, and older versions allow scripted queries that lead to remote code execution.",
    "docker-api-unauthenticated": "The Docker API grants container/host control — an attacker can start a privileged container that mounts the host filesystem, a well-known path to full host compromise.",
    "vnc-no-authentication": "Anyone who can reach the port gets full remote-desktop control of the machine — keyboard, mouse, and screen — with zero credentials.",
    "ssh-protocol-1-legacy": "SSH-1 has known cryptographic weaknesses and man-in-the-middle vulnerabilities that SSH-2 was designed to fix; sessions can potentially be decrypted or hijacked.",
}

IMPROVEMENT = {
    "open-port": "Close this port if the service isn't needed externally, or restrict access via firewall rules / security groups to trusted IPs only.",
    "risky-service-exposed": "Disable the service if unused, restrict it to a VPN/bastion host, enforce key-based auth (SSH) or strong MFA, and never expose it directly to the internet.",
    "outdated-service-banner": "Update the service to a current, supported version and confirm known CVEs for the detected version have been patched.",
    "ftp-anonymous-login": "Disable anonymous FTP access unless the server is intentionally a public read-only drop, and prefer SFTP/FTPS over plain FTP regardless.",
    "redis-unauthenticated": "Set 'requirepass', bind to localhost or a private interface only, and enable protected-mode; never expose Redis directly to the internet.",
    "elasticsearch-unauthenticated": "Enable Elasticsearch security (authentication + TLS), and bind the transport/HTTP interfaces to a private network only.",
    "docker-api-unauthenticated": "Never expose the Docker socket/API over TCP without TLS client-certificate authentication; bind it to localhost or a Unix socket instead.",
    "vnc-no-authentication": "Require a strong VNC password (or better, tunnel VNC over SSH/VPN) and never expose the port directly to the internet.",
    "ssh-protocol-1-legacy": "Disable SSH protocol 1 in the server config (modern OpenSSH defaults to SSH-2 only; explicitly check 'Protocol'/'sshd_config' if this fired).",
}

CATEGORY = "network-scan"

DISCOVERY_PORTS = [22, 80, 135, 139, 443, 445, 3389]
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                445, 993, 995, 1433, 1723, 2375, 3306, 3389, 5432, 5900,
                6379, 8080, 8443, 9200, 11211, 27017]

WELL_KNOWN_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1723: "pptp", 2375: "docker-api", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

SERVICE_PROBES = {80: b"HEAD / HTTP/1.0\r\n\r\n", 8080: b"HEAD / HTTP/1.0\r\n\r\n"}

# Offline heuristics for the "outdated-service-banner" rule — no live CVE
# lookup (this tool is offline-first), just two hardcoded, well-documented
# categories: exact distributions that shipped with a backdoor, and
# per-product minimum-supported-version thresholds. A hit means "go check
# CVEs for this exact version" — it is not a live vulnerability match.
KNOWN_BACKDOORED_BANNERS = [
    (re.compile(r"vsftpd\s*2\.3\.4", re.I),
     "vsftpd 2.3.4's distribution archive was backdoored (CVE-2011-2523) — grants a remote root shell."),
    (re.compile(r"proftpd\s*1\.3\.3c", re.I),
     "ProFTPD 1.3.3c's distribution archive was backdoored (CVE-2010-4221)."),
    (re.compile(r"unreal3\.2\.8\.1", re.I),
     "UnrealIRCd 3.2.8.1's distribution archive was backdoored (CVE-2010-2075)."),
]

# product label -> (regex to extract "major.minor" from the banner, minimum
# actively-supported version as a (major, minor) tuple). Anything below the
# minimum is flagged — thresholds are deliberately conservative (long-EOL
# releases only) to avoid flagging current stable versions as outdated.
OUTDATED_VERSION_THRESHOLDS = [
    ("OpenSSH", re.compile(r"OpenSSH[_/](\d+)\.(\d+)", re.I), (7, 4)),
    ("Apache", re.compile(r"Apache/(\d+)\.(\d+)", re.I), (2, 4)),
    ("nginx", re.compile(r"nginx/(\d+)\.(\d+)", re.I), (1, 20)),
    ("vsftpd", re.compile(r"vsftpd\s*(\d+)\.(\d+)", re.I), (3, 0)),
    ("ProFTPD", re.compile(r"ProFTPD\s*(\d+)\.(\d+)", re.I), (1, 3)),
    ("Microsoft-IIS", re.compile(r"Microsoft-IIS/(\d+)\.(\d+)", re.I), (10, 0)),
    ("MySQL", re.compile(r"(\d+)\.(\d+)\.\d+\S*mysql", re.I), (5, 7)),
    ("Postfix", re.compile(r"Postfix\s*\(?(\d+)\.(\d+)", re.I), (3, 0)),
    ("OpenSSL", re.compile(r"OpenSSL/(\d+)\.(\d+)", re.I), (1, 1)),
]


def check_banner_version(banner):
    """Returns evidence text if `banner` matches a known-backdoored
    distribution or falls below a hardcoded minimum-supported-version
    threshold for that product, else None."""
    if not banner:
        return None
    for pattern, note in KNOWN_BACKDOORED_BANNERS:
        if pattern.search(banner):
            return note
    for product, pattern, min_version in OUTDATED_VERSION_THRESHOLDS:
        m = pattern.search(banner)
        if not m:
            continue
        found = (int(m.group(1)), int(m.group(2)))
        if found < min_version:
            return (f"{product} {found[0]}.{found[1]} detected — older than the minimum "
                     f"actively-supported {product} {min_version[0]}.{min_version[1]}; "
                     f"check for known CVEs against this exact version.")
    return None


def check_ssh_protocol(banner):
    """SSH servers send their identification string unprompted on connect
    ("SSH-1.5-...", "SSH-1.99-...", "SSH-2.0-..."). 1.99 means the server
    still accepts protocol-1 clients for compatibility, so it's flagged too."""
    if banner and re.match(r"^SSH-1\.", banner):
        return f"banner advertises SSH protocol 1: {banner[:60]!r}"
    return None


class NetworkScanner:
    def __init__(self, connect_timeout=1.0, max_workers=200, show_progress=True):
        self.connect_timeout = connect_timeout
        self.max_workers = max_workers
        self.show_progress = show_progress
        self.result = ScanResult()
        # Plain-language notes collected per host as the scan runs — becomes
        # the "evidence" text sent to the AI layer for that host (open ports,
        # services, banners), so --ai can verify network findings the same
        # way it verifies code findings.
        self._evidence = {}

    def _note(self, host, line):
        self._evidence.setdefault(host, []).append(line)

    def _add(self, rule, host, port=0, evidence=""):
        self.result.findings.append(Finding(
            rule=rule,
            severity=SEVERITY.get(rule, "medium"),
            file=host,        # reused field: host instead of filepath
            line=port,        # reused field: port instead of line number, so
                               # scanner.py's "{file}:{line}" prints as host:port
            display_line=evidence,
            description=DESCRIPTION.get(rule, rule),
            source="regex",
            impact=IMPACT.get(rule, ""),
            improvement=IMPROVEMENT.get(rule, ""),
        ))
        self._note(host, f"FINDING port {port}: {rule} — {DESCRIPTION.get(rule, rule)}"
                          + (f" ({evidence})" if evidence else ""))

    def _log(self, msg):
        if self.show_progress:
            print(_c(msg, Style.DIM), flush=True)

    # ------------------------------------------------------------ discovery
    def _host_is_up(self, host):
        for port in DISCOVERY_PORTS:
            try:
                with socket.create_connection((host, port), timeout=self.connect_timeout):
                    return True
            except (socket.timeout, ConnectionRefusedError, OSError):
                continue
        return False

    def discover_hosts(self, subnet_cidr):
        network = ipaddress.ip_network(subnet_cidr, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
        self._log(f"Discovering live hosts in {subnet_cidr} ({len(hosts)} addresses)...")
        live = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futs = {ex.submit(self._host_is_up, h): h for h in hosts}
            for fut in as_completed(futs):
                host = futs[fut]
                try:
                    if fut.result():
                        live.append(host)
                        self._log(f"  host up: {host}")
                except Exception:
                    pass
        return sorted(live, key=lambda ip: ipaddress.ip_address(ip))

    # ------------------------------------------------------------ port scan
    def _grab_banner(self, sock, port):
        try:
            probe = SERVICE_PROBES.get(port, b"")
            if probe:
                sock.sendall(probe)
            sock.settimeout(1.0)
            return sock.recv(256).decode(errors="replace").strip()
        except (socket.timeout, OSError):
            return None

    def _scan_port(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=self.connect_timeout) as sock:
                return port, True, self._grab_banner(sock, port)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return port, False, None

    def scan_host(self, host, ports=None):
        ports = ports or COMMON_PORTS
        self._log(f"Port scanning {host} ({len(ports)} ports)...")
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futs = [ex.submit(self._scan_port, host, p) for p in ports]
            for fut in as_completed(futs):
                port, is_open, banner = fut.result()
                if is_open:
                    service = self._guess_service(port, banner)
                    open_ports.append({"port": port, "service": service, "banner": banner})

        open_ports.sort(key=lambda x: x["port"])
        self._note(host, f"{len(open_ports)} open port(s) out of {len(ports)} scanned")
        for entry in open_ports:
            evidence = f"service={entry['service']}" + (f" banner={entry['banner']!r}" if entry["banner"] else "")
            self._add("open-port", host, entry["port"], evidence)
            if entry["port"] in RISKY_PORTS:
                self._add("risky-service-exposed", host, entry["port"], f"{RISKY_PORTS[entry['port']]} exposed")
            banner_note = check_banner_version(entry["banner"])
            if banner_note:
                self._add("outdated-service-banner", host, entry["port"], banner_note)
            ssh_note = check_ssh_protocol(entry["banner"])
            if ssh_note:
                self._add("ssh-protocol-1-legacy", host, entry["port"], ssh_note)

            if entry["port"] == 21:
                self._probe_ftp_anonymous(host, entry["port"])
            elif entry["port"] == 6379:
                self._probe_redis_unauthenticated(host, entry["port"])
            elif entry["port"] == 9200:
                self._probe_elasticsearch_unauthenticated(host, entry["port"])
            elif entry["port"] == 2375:
                self._probe_docker_api_unauthenticated(host, entry["port"])
            elif entry["port"] == 5900:
                self._probe_vnc_no_auth(host, entry["port"])

        return open_ports

    @staticmethod
    def _guess_service(port, banner):
        if banner:
            low = banner.lower()
            if "ssh" in low:
                return "ssh"
            if "http" in low:
                return "http"
        return WELL_KNOWN_SERVICES.get(port, "unknown")

    # ------------------------------------------- active unauthenticated-access probes
    # These go one step past "the port is open": they make one small,
    # read-only request in the service's own protocol and check whether it
    # succeeds without credentials. Each is a single request/response — no
    # brute-forcing, no state-changing commands.
    def _raw_probe(self, host, port, payload, read_size=1024, timeout=2.5):
        try:
            with socket.create_connection((host, port), timeout=self.connect_timeout) as sock:
                sock.settimeout(timeout)
                if payload:
                    sock.sendall(payload)
                return sock.recv(read_size).decode(errors="replace")
        except (socket.timeout, OSError):
            return None

    def _probe_ftp_anonymous(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=self.connect_timeout) as sock:
                sock.settimeout(2.5)
                sock.recv(512)  # banner
                sock.sendall(b"USER anonymous\r\n")
                sock.recv(512)
                sock.sendall(b"PASS anonymous@example.com\r\n")
                reply = sock.recv(512).decode(errors="replace")
                sock.sendall(b"QUIT\r\n")
        except (socket.timeout, OSError):
            return
        if reply.startswith("230"):
            self._add("ftp-anonymous-login", host, port, reply.strip().splitlines()[0][:150])

    def _probe_redis_unauthenticated(self, host, port):
        reply = self._raw_probe(host, port, b"PING\r\n", read_size=64)
        if reply and reply.startswith("+PONG"):
            self._add("redis-unauthenticated", host, port, "PING accepted without authentication")

    def _probe_elasticsearch_unauthenticated(self, host, port):
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        reply = self._raw_probe(host, port, req, read_size=2048)
        if not reply:
            return
        if "401" in reply.split("\r\n", 1)[0] or "security_exception" in reply.lower():
            return  # auth is actually enforced
        if '"cluster_name"' in reply:
            self._add("elasticsearch-unauthenticated", host, port, "GET / returned cluster info without authentication")

    def _probe_docker_api_unauthenticated(self, host, port):
        req = f"GET /version HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        reply = self._raw_probe(host, port, req, read_size=2048)
        if reply and "200" in reply.split("\r\n", 1)[0] and '"ApiVersion"' in reply:
            self._add("docker-api-unauthenticated", host, port, "GET /version returned Docker Engine info without authentication")

    def _probe_vnc_no_auth(self, host, port):
        """The RFB handshake: server sends its version string, client
        echoes a version back, then server lists the security types it
        offers. Type 1 ("None") means anyone who connects is in — no
        password exchange happens at all."""
        try:
            with socket.create_connection((host, port), timeout=self.connect_timeout) as sock:
                sock.settimeout(2.5)
                greeting = sock.recv(12)  # e.g. b"RFB 003.008\n"
                if not greeting.startswith(b"RFB "):
                    return
                sock.sendall(greeting)
                resp = sock.recv(64)
        except (socket.timeout, OSError):
            return
        if not resp:
            return
        version = greeting[4:11].decode(errors="replace")  # "003.008"
        if version >= "003.007":
            # ProtocolVersion 3.7+: [num-security-types][type, type, ...]
            num_types = resp[0]
            types = list(resp[1:1 + num_types])
            if 1 in types:
                self._add("vnc-no-authentication", host, port, f"offered security types: {types}")
        elif len(resp) >= 4:
            # ProtocolVersion 3.3: server dictates a single 4-byte security type
            sec_type = int.from_bytes(resp[:4], "big")
            if sec_type == 1:
                self._add("vnc-no-authentication", host, port, "security type: None (1)")

    def _finalize_ai_evidence(self, use_ai: bool):
        if not use_ai:
            return
        for host, lines in self._evidence.items():
            self.result.ai_file_contents[host] = "\n".join(lines)
            self.result.ai_target_kind[host] = "network"

    # ----------------------------------------------------------------- run
    def run_subnet_scan(self, subnet_cidr, ports=None, use_ai: bool = False) -> ScanResult:
        live_hosts = self.discover_hosts(subnet_cidr)
        self.result.scanned_file_names = live_hosts
        self.result.files_scanned = len(live_hosts)
        for host in live_hosts:
            self.scan_host(host, ports=ports)
        if self.show_progress:
            print(_c(f"Network scan done: {len(live_hosts)} host(s) up, "
                      f"{len(self.result.findings)} finding(s).", Style.DIM), flush=True)
        self._finalize_ai_evidence(use_ai)
        return self.result

    def run_host_scan(self, host, ports=None, use_ai: bool = False) -> ScanResult:
        self.result.scanned_file_names = [host]
        self.result.files_scanned = 1
        self.scan_host(host, ports=ports)
        if self.show_progress:
            print(_c(f"Network scan done: {len(self.result.findings)} finding(s).", Style.DIM), flush=True)
        self._finalize_ai_evidence(use_ai)
        return self.result


def _parse_ports(port_str):
    if not port_str:
        return None
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def scan_network(target, ports=None, use_ai: bool = False, **kwargs) -> ScanResult:
    """Entry point for embedding in scanner.py's main(). `target` can be a
    single host or a CIDR subnet."""
    scanner = NetworkScanner(**kwargs)
    if "/" in target:
        return scanner.run_subnet_scan(target, ports=ports, use_ai=use_ai)
    return scanner.run_host_scan(target, ports=ports, use_ai=use_ai)


def print_report(result: ScanResult, target: str):
    print(_c(f"\nNetwork scan report for {target}", Style.BRIGHT))
    if not result.findings:
        print(_c("No open ports found.", Fore.GREEN))
        return
    ranked = sorted(result.findings, key=lambda f: SEVERITY_RANK.get(f.severity, 0), reverse=True)
    for f in ranked:
        color = SEV_COLOR.get(f.severity, "")
        confirm = " (AI-confirmed)" if f.ai_verdict == "true_positive" else (
            " (AI: likely false positive)" if f.ai_verdict == "false_positive" else (
                " (AI-found)" if f.source == "ai" else ""))
        print(f"{_c(f'[{f.severity.upper()}]', color)} {f.description}{confirm}")
        location = f"{f.file}:{f.line}" if f.line else f.file
        print(f"  location: {location}")
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
    parser = argparse.ArgumentParser(description="Network scan module")
    parser.add_argument("target", help="Host IP/hostname, or CIDR subnet e.g. 10.0.0.0/24")
    parser.add_argument("--ports", help="Comma/range list, e.g. 22,80,443 or 1-1024")
    parser.add_argument("--ai", action="store_true",
                         help="Send collected scan evidence (open ports, services, banners — never "
                              "raw traffic) to the AI layer to verify findings and look for anything "
                              "the port/banner checks missed. Requires LLM_API_KEY in scanner.py's own "
                              ".env. One API call per live host, so this is slower for subnet scans.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    result = scan_network(args.target, ports=_parse_ports(args.ports), use_ai=args.ai, show_progress=not args.quiet)

    if args.ai:
        from scanner import load_config, run_ai_verify_and_scan
        config = load_config()
        if not config.get("api_key"):
            print(_c("[!] --ai requested but LLM_API_KEY not set in scanner.py's own .env — skipping.", Fore.YELLOW),
                  file=sys.stderr)
        else:
            run_ai_verify_and_scan(result, config, show_progress=not args.quiet)

    print_report(result, args.target)
    sys.exit(1 if any(f.severity in ("critical", "high") for f in result.findings) else 0)


if __name__ == "__main__":
    main()
