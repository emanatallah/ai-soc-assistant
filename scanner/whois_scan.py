"""Compatibility WHOIS scanner module for the target architecture."""

from __future__ import annotations

from typing import Any

from scanner.whois_lookup import scan_whois as _scan_whois
from utils.helpers import validate_target


def scan_whois(target: str) -> dict[str, Any]:
    """Lookup WHOIS data for a validated target."""

    return _scan_whois(validate_target(target))

