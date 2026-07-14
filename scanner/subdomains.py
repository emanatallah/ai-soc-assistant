"""Lightweight optional subdomain discovery."""

from __future__ import annotations

import socket
from typing import Any

from config import settings
from utils.helpers import standard_output, validate_target

COMMON_SUBDOMAINS = (
    "www",
    "mail",
    "api",
    "dev",
    "staging",
    "admin",
    "portal",
    "vpn",
    "blog",
    "shop",
)


def scan_subdomains(target: str) -> dict[str, Any]:
    """Discover common subdomains by DNS resolution."""

    normalized = validate_target(target)
    discovered: list[dict[str, str]] = []
    errors: list[str] = []
    for prefix in COMMON_SUBDOMAINS[: settings.max_subdomains]:
        hostname = f"{prefix}.{normalized}"
        try:
            discovered.append({"host": hostname, "ip": socket.gethostbyname(hostname)})
        except OSError:
            continue
    return standard_output(
        "subdomains",
        normalized,
        "success",
        data={"subdomains": discovered},
        errors=errors,
    )

