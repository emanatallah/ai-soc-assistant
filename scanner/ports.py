"""
AI SOC Assistant - Scanner Module: Port Scanner
---------------------------------------------------
Purpose: Scan open ports on a target and identify running services.
Returns results in the standardized module output format so other
team modules (Analyzer, Database, CLI) can consume it consistently.

Legal warning: Only use this tool on targets you own or have
explicit permission to test.
"""

from __future__ import annotations

import json
import argparse
import socket
from datetime import datetime
from typing import Any

try:
    import nmap
except ImportError:
    nmap = None


RISKY_PORTS = {
    21: "FTP - unencrypted data",
    23: "Telnet - old and insecure protocol",
    445: "SMB - vulnerable to exploits like EternalBlue",
    3389: "RDP - common brute-force target",
    5900: "VNC - often weak/no encryption",
    3306: "MySQL - database exposed externally",
    6379: "Redis - often no authentication by default"
}


def _standard_output(
    module: str,
    target: str,
    status: str,
    data: dict[str, Any] | None = None,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    """Wraps any module's result in the team-wide standard format."""
    return {
        "module": module,
        "target": target,
        "status": status,
        "timestamp": datetime.now().isoformat(),
        "data": data or {},
        "errors": errors or []
    }


def scan_ports(
    target: str,
    port_range: str = "1-1000",
    stealth: bool = False,
) -> dict[str, Any]:
    """
    Scan the given target for open ports and services.
    """
    errors = []

    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return _standard_output(
            "ports", target, "error",
            data={"resolved_ip": None, "open_ports": [], "risky_ports": []},
            errors=[f"Could not resolve '{target}' to an IP address."]
        )

    if nmap is None:
        return _standard_output(
            "ports", target, "error",
            data={"resolved_ip": resolved_ip, "open_ports": [], "risky_ports": []},
            errors=["python-nmap is not installed. Install dependencies from requirements.txt."]
        )

    try:
        scanner = nmap.PortScanner()
    except Exception as e:
        return _standard_output(
            "ports", target, "error",
            data={"resolved_ip": resolved_ip, "open_ports": [], "risky_ports": []},
            errors=[f"nmap is unavailable: {str(e)}"]
        )
    scan_args = "-Pn -sS -sV -T4" if stealth else "-Pn -sV -T4"

    try:
        scanner.scan(target, port_range, arguments=scan_args)
    except Exception as e:
        return _standard_output(
            "ports", target, "error",
            data={"resolved_ip": resolved_ip, "open_ports": [], "risky_ports": []},
            errors=[f"nmap scan failed: {str(e)}"]
        )

    if target not in scanner.all_hosts() and resolved_ip not in scanner.all_hosts():
        errors.append("Target did not respond. It may be behind a firewall.")
        return _standard_output(
            "ports", target, "success",
            data={"resolved_ip": resolved_ip, "open_ports": [], "risky_ports": []},
            errors=errors
        )

    host = resolved_ip if resolved_ip in scanner.all_hosts() else target

    open_ports = []
    risky_ports = []

    for proto in scanner[host].all_protocols():
        for port in sorted(scanner[host][proto].keys()):
            port_info = scanner[host][proto][port]
            if port_info.get("state") == "open":
                entry = {
                    "port": port,
                    "protocol": proto,
                    "service": port_info.get("name"),
                    "product": port_info.get("product"),
                    "version": port_info.get("version"),
                }
                open_ports.append(entry)

                if port in RISKY_PORTS:
                    risky_ports.append({"port": port, "reason": RISKY_PORTS[port]})

    return _standard_output(
        "ports", target, "success",
        data={
            "resolved_ip": resolved_ip,
            "open_ports": open_ports,
            "risky_ports": risky_ports
        },
        errors=errors
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Port scanner module")
    parser.add_argument("-t", "--target", required=True, help="Target domain or IP (e.g. example.com)")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range (default: 1-1000)")
    parser.add_argument("--stealth", action="store_true", help="Use SYN stealth scan (requires sudo)")
    args = parser.parse_args()

    result = scan_ports(args.target, port_range=args.ports, stealth=args.stealth)
    print(json.dumps(result, indent=4, ensure_ascii=False))
