"""Compatibility SSL/TLS scanner module for the target architecture."""

from __future__ import annotations

from typing import Any

from scanner.ssl_check import scan_ssl as _scan_ssl
from utils.helpers import validate_target


def scan_ssl(target: str, port: int = 443) -> dict[str, Any]:
    """Inspect TLS certificate and negotiated protocol."""

    return _scan_ssl(validate_target(target), port=port)

