"""
AI SOC Assistant - Scanner Module: DNS Lookup
---------------------------------------------------
Purpose: Query core DNS records for a target domain (A, MX, NS, TXT).
Returns results in the standardized module output format so other
team modules (Analyzer, Database, CLI) can consume it consistently.

Legal warning: Only use this tool on targets you own or have
explicit permission to test.
"""

from __future__ import annotations

import json
import argparse
import dns.resolver
from datetime import datetime
from typing import Any


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


def _query_record(target: str, record_type: str) -> tuple[list[str], str | None]:
    """Query a single DNS record type and return a list of string values."""
    try:
        answers = dns.resolver.resolve(target, record_type)
        return [str(rdata).strip() for rdata in answers], None
    except dns.resolver.NoAnswer:
        return [], None
    except dns.resolver.NXDOMAIN:
        return [], f"Domain '{target}' does not exist."
    except dns.exception.Timeout:
        return [], f"DNS query for {record_type} timed out."
    except Exception as e:
        return [], f"DNS query for {record_type} failed: {str(e)}"


def scan_dns(target: str) -> dict[str, Any]:
    """
    Query core DNS records (A, MX, NS, TXT) for the given domain.
    """
    errors = []
    record_types = ["A", "MX", "NS", "TXT"]
    results = {}

    for record_type in record_types:
        values, error = _query_record(target, record_type)
        results[record_type] = values
        if error:
            errors.append(error)

    status = "error" if not results["A"] and any("does not exist" in e for e in errors) else "success"

    return _standard_output("dns", target, status, data=results, errors=errors)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS lookup module")
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g. example.com)")
    args = parser.parse_args()

    result = scan_dns(args.target)
    print(json.dumps(result, indent=4, ensure_ascii=False))
