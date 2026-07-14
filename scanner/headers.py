"""
AI SOC Assistant - Scanner Module: HTTP Security Headers Checker
---------------------------------------------------------------
Purpose: Check whether a target website implements important HTTP
security headers that protect against common attacks (XSS,
clickjacking, protocol downgrade, MIME sniffing, etc).
Returns results in the standardized module output format so other
team modules (Analyzer, Database, CLI) can consume it consistently.

Legal warning: Only use this tool on targets you own or have
explicit permission to test.
"""

from __future__ import annotations

import json
import argparse
import requests
from datetime import datetime
from typing import Any


SECURITY_HEADERS = {
    "Content-Security-Policy": "Protects against XSS and code injection attacks",
    "X-Frame-Options": "Protects against clickjacking attacks",
    "Strict-Transport-Security": "Forces browsers to use HTTPS only (HSTS)",
    "X-Content-Type-Options": "Prevents MIME type sniffing",
    "Referrer-Policy": "Controls how much referrer info is sent",
    "Permissions-Policy": "Restricts access to browser features (camera, mic, etc)"
}

REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
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


def scan_headers(target: str, use_https: bool = True) -> dict[str, Any]:
    """
    Check for the presence of key HTTP security headers on a target.
    """
    errors = []
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{target}"

    data = {
        "url": url,
        "reachable": False,
        "headers_found": {},
        "missing_headers": []
    }

    try:
        response = requests.get(url, headers=REQUEST_HEADERS, timeout=10, allow_redirects=True)
        data["reachable"] = True
        response_headers = response.headers

        for header, purpose in SECURITY_HEADERS.items():
            if header in response_headers:
                data["headers_found"][header] = response_headers[header]
            else:
                data["missing_headers"].append({"header": header, "purpose": purpose})

    except requests.exceptions.SSLError:
        errors.append("SSL error while connecting. Try use_https=False.")
    except requests.exceptions.ConnectionError:
        errors.append("Could not connect to target. Check the domain or network.")
    except requests.exceptions.Timeout:
        errors.append("Connection timed out.")
    except Exception as e:
        errors.append(f"Unexpected error: {str(e)}")

    status = "success" if data["reachable"] else "error"
    return _standard_output("headers", target, status, data=data, errors=errors)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP security headers checker module")
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g. example.com)")
    args = parser.parse_args()

    result = scan_headers(args.target)
    print(json.dumps(result, indent=4, ensure_ascii=False))
