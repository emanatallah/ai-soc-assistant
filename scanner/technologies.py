"""
AI SOC Assistant - Scanner Module: Technology Detection
---------------------------------------------------------
Purpose: Detect the web server software, backend technology, and CMS
(if any) used by a target website, based on HTTP headers and page
content signatures.
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


CMS_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "/wp-json/"],
    "Joomla": ["/media/jui/", "Joomla!"],
    "Drupal": ["/sites/default/files/", "Drupal.settings"],
    "Magento": ["/skin/frontend/", "Mage.Cookies"],
    "Shopify": ["cdn.shopify.com", "Shopify.theme"]
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


def scan_technologies(target: str, use_https: bool = True) -> dict[str, Any]:
    """
    Detect the web server, backend technology, and CMS used by a target.
    """
    errors = []
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{target}"

    data = {
        "url": url,
        "reachable": False,
        "server": None,
        "powered_by": None,
        "cms_detected": [],
        "detected_headers": {}
    }

    try:
        response = requests.get(url, headers=REQUEST_HEADERS, timeout=10, allow_redirects=True)
        data["reachable"] = True

        response_headers = response.headers
        data["server"] = response_headers.get("Server", "Not disclosed")
        data["powered_by"] = response_headers.get("X-Powered-By", "Not disclosed")

        interesting_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
        for h in interesting_headers:
            if h in response_headers:
                data["detected_headers"][h] = response_headers[h]

        page_text = response.text
        found_cms = []
        for cms, signatures in CMS_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in page_text.lower():
                    found_cms.append(cms)
                    break
        data["cms_detected"] = found_cms

    except requests.exceptions.SSLError:
        errors.append("SSL error while connecting. Try use_https=False.")
    except requests.exceptions.ConnectionError:
        errors.append("Could not connect to target. Check the domain or network.")
    except requests.exceptions.Timeout:
        errors.append("Connection timed out.")
    except Exception as e:
        errors.append(f"Unexpected error: {str(e)}")

    status = "success" if data["reachable"] else "error"
    return _standard_output("technologies", target, status, data=data, errors=errors)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Technology detection module")
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g. example.com)")
    args = parser.parse_args()

    result = scan_technologies(args.target)
    print(json.dumps(result, indent=4, ensure_ascii=False))
