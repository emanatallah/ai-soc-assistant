"""
AI SOC Assistant - Scanner Module: SSL/TLS Checker
---------------------------------------------------
Purpose: Connect to a target on port 443 and inspect its SSL/TLS
certificate for expiration, weak protocol versions, and issuer info.
Returns results in the standardized module output format so other
team modules (Analyzer, Database, CLI) can consume it consistently.

Legal warning: Only use this tool on targets you own or have
explicit permission to test.
"""

from __future__ import annotations

import json
import argparse
import ssl
import socket
from datetime import datetime, timezone
from typing import Any


WEAK_PROTOCOLS = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]
WEAK_CIPHER_MARKERS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]


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


def scan_ssl(target: str, port: int = 443) -> dict[str, Any]:
    """
    Inspect the SSL/TLS certificate of a target on the given port.
    """
    errors = []
    data = {
        "reachable": False,
        "issuer": None,
        "subject": None,
        "valid_from": None,
        "valid_until": None,
        "days_until_expiry": None,
        "protocol_version": None,
        "cipher": None,
        "is_expired": None,
        "is_weak_protocol": None,
        "is_weak_cipher": None
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                data["reachable"] = True
                cert = ssock.getpeercert()
                data["protocol_version"] = ssock.version()
                cipher = ssock.cipher()
                data["cipher"] = {
                    "name": cipher[0],
                    "protocol": cipher[1],
                    "bits": cipher[2],
                } if cipher else None

                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                data["issuer"] = issuer.get("organizationName", issuer.get("commonName", "Unknown"))
                data["subject"] = subject.get("commonName", "Unknown")

                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                data["valid_from"] = not_before.isoformat()
                data["valid_until"] = not_after.isoformat()

                days_left = (not_after - datetime.now(timezone.utc)).days
                data["days_until_expiry"] = days_left
                data["is_expired"] = days_left < 0

                if data["is_expired"]:
                    errors.append("Certificate has EXPIRED.")
                elif days_left < 30:
                    errors.append(f"Certificate expires soon ({days_left} days left).")

                data["is_weak_protocol"] = data["protocol_version"] in WEAK_PROTOCOLS
                if data["is_weak_protocol"]:
                    errors.append(f"Weak/outdated protocol in use: {data['protocol_version']}")

                cipher_name = str(data["cipher"].get("name", "")) if data["cipher"] else ""
                data["is_weak_cipher"] = any(
                    marker in cipher_name.upper() for marker in WEAK_CIPHER_MARKERS
                )
                if data["is_weak_cipher"]:
                    errors.append(f"Weak cipher negotiated: {cipher_name}")

    except socket.timeout:
        errors.append("Connection timed out. Target may be unreachable or not using HTTPS.")
    except ssl.SSLError as e:
        errors.append(f"SSL error: {str(e)}")
    except Exception as e:
        errors.append(f"Could not check SSL: {str(e)}")

    status = "success" if data["reachable"] else "error"
    return _standard_output("ssl", target, status, data=data, errors=errors)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSL/TLS checker module")
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g. example.com)")
    args = parser.parse_args()

    result = scan_ssl(args.target)
    print(json.dumps(result, indent=4, ensure_ascii=False))
