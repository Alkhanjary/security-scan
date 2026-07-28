#!/usr/bin/env python3
"""
network_scan.py

Network scanner module for security-scan. Mirrors scanner.py's architecture:
rule-keyed SEVERITY / DESCRIPTION / IMPACT / IMPROVEMENT tables and the
shared Finding / ScanResult dataclasses, so output slots into the same
report writer and --ai review layer as the code and web scan modules.

Capabilities:
- Host discovery via TCP-connect probing (no root/raw sockets required)
- Port scanning (threaded TCP connect scan)
- Basic service/banner detection

Only scan hosts/networks you own or are explicitly authorized to test.
Unauthorized network scanning may be illegal depending on jurisdiction.
"""

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

RISKY_PORTS = {21: "ftp", 23: "telnet", 3389: "rdp", 5900: "vnc"}

SEVERITY = {
    "open-port": "low",
    "risky-service-exposed": "high",
    "outdated-service-banner": "medium",
}

DESCRIPTION = {
    "open-port": "Open TCP port detected",
    "risky-service-exposed": "Commonly-attacked service exposed on the network",
    "outdated-service-banner": "Service banner suggests outdated/unsupported software",
}

IMPACT = {
    "open-port": "An open port expands the attack surface; whether it's a real risk depends on the service and its exposure (internal vs internet-facing).",
    "risky-service-exposed": "Services like FTP, Telnet, RDP, and VNC are frequent targets for credential brute-forcing and have a history of serious vulnerabilities.",
    "outdated-service-banner": "Older service versions may have known, publicly documented vulnerabilities with available exploits.",
}

IMPROVEMENT = {
    "open-port": "Close this port if the service isn't needed externally, or restrict access via firewall rules / security groups to trusted IPs only.",
    "risky-service-exposed": "Disable the service if unused, restrict it to a VPN/bastion host, enforce key-based auth (SSH) or strong MFA, and never expose it directly to the internet.",
    "outdated-service-banner": "Update the service to a current, supported version and confirm known CVEs for the detected version have been patched.",
}

CATEGORY = "network-scan"

DISCOVERY_PORTS = [22, 80, 135, 139, 443, 445, 3389]
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443]

WELL_KNOWN_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1723: "pptp",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt",
}

SERVICE_PROBES = {80: b"HEAD / HTTP/1.0\r\n\r\n"}


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
