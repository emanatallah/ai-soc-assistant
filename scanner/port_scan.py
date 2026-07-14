"""Compatibility port scanner module for the target architecture."""

from __future__ import annotations

from typing import Any

from scanner.ports import scan_ports as _scan_ports
from utils.helpers import validate_target


def scan_ports(
    target: str,
    port_range: str = "1-1000",
    stealth: bool = False,
) -> dict[str, Any]:
    """Scan ports and services for a validated target."""

    return _scan_ports(validate_target(target), port_range=port_range, stealth=stealth)

