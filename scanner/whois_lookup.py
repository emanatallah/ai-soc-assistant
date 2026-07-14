"""
AI SOC Assistant - Scanner Module: WHOIS Lookup
---------------------------------------------------
Purpose: Retrieve domain registration information.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from datetime import datetime
from typing import Any

import whois


def _standard_output(
    module: str,
    target: str,
    status: str,
    data: dict[str, Any] | None = None,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "module": module,
        "target": target,
        "status": status,
        "timestamp": datetime.now().isoformat(),
        "data": data or {},
        "errors": errors or [],
    }


def _to_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return _to_str(value[0]) if value else None
    return str(value)


def scan_whois(target: str) -> dict[str, Any]:
    """
    Perform WHOIS lookup.
    If the target is an IP address, skip the lookup.
    """

    # Skip WHOIS for IP addresses
    try:
        ipaddress.ip_address(target)
        return _standard_output(
            "whois",
            target,
            "success",
            data={
                "skipped": True,
                "reason": "WHOIS lookup is only supported for domain names."
            },
            errors=[],
        )
    except ValueError:
        pass

    try:
        w = whois.whois(target)

        if not w or not getattr(w, "domain_name", None):
            return _standard_output(
                "whois",
                target,
                "error",
                data={},
                errors=[f"No WHOIS data found for '{target}'."],
            )

        name_servers = w.name_servers

        if isinstance(name_servers, str):
            name_servers = [name_servers]
        elif name_servers is None:
            name_servers = []
        else:
            name_servers = [str(ns).lower() for ns in name_servers]

        data = {
            "registrar": _to_str(w.registrar),
            "creation_date": _to_str(w.creation_date),
            "expiration_date": _to_str(w.expiration_date),
            "updated_date": _to_str(w.updated_date),
            "name_servers": sorted(set(name_servers)),
            "organization": _to_str(getattr(w, "org", None)),
            "country": _to_str(getattr(w, "country", None)),
        }

        return _standard_output(
            "whois",
            target,
            "success",
            data=data,
            errors=[],
        )

    except Exception as exc:
        return _standard_output(
            "whois",
            target,
            "error",
            data={},
            errors=[str(exc)],
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WHOIS Lookup")
    parser.add_argument("-t", "--target", required=True)
    args = parser.parse_args()

    print(json.dumps(scan_whois(args.target), indent=4, ensure_ascii=False))