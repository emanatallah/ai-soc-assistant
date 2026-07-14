"""Robots.txt scanner."""

from __future__ import annotations

from typing import Any

import requests

from config import settings
from utils.helpers import build_url, standard_output, validate_target


def scan_robots(target: str, use_https: bool = True) -> dict[str, Any]:
    """Fetch robots.txt from a target."""

    normalized = validate_target(target)
    url = build_url(normalized, use_https=use_https, path="/robots.txt")
    try:
        response = requests.get(
            url,
            headers={"User-Agent": settings.user_agent},
            timeout=settings.request_timeout,
        )
        found = response.status_code == 200
        return standard_output(
            "robots",
            normalized,
            "success",
            data={
                "url": url,
                "found": found,
                "status_code": response.status_code,
                "content": response.text if found else "",
            },
            errors=[] if found else [f"robots.txt returned HTTP {response.status_code}."],
        )
    except requests.RequestException as exc:
        return standard_output(
            "robots",
            normalized,
            "error",
            data={"url": url, "found": False, "content": ""},
            errors=[f"robots.txt fetch failed: {exc}"],
        )

