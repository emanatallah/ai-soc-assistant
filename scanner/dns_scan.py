"""Compatibility DNS scanner module for the target architecture."""

from __future__ import annotations

from typing import Any

from scanner.dns_lookup import scan_dns as _scan_dns
from utils.helpers import validate_target


def scan_dns(target: str) -> dict[str, Any]:
    """Query DNS records for a target using the existing DNS scanner."""

    return _scan_dns(validate_target(target))

