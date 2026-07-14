"""Reusable helpers for validation, serialization, HTTP URLs, and outputs."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)


def standard_output(
    module: str,
    target: str,
    status: str,
    data: dict[str, Any] | None = None,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    """Wrap scanner results in the project-wide response format."""

    return {
        "module": module,
        "target": target,
        "status": status,
        "timestamp": datetime.now().isoformat(),
        "data": data or {},
        "errors": errors or [],
    }


def normalize_target(target: str) -> str:
    """Normalize a user-provided target into a host name or IP address."""

    value = target.strip()
    if not value:
        raise ValueError("Target is required.")
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value
    return host.strip().lower().rstrip(".")


def validate_target(target: str) -> str:
    """Validate and return a normalized domain name or IP address."""

    normalized = normalize_target(target)
    try:
        ipaddress.ip_address(normalized)
        return normalized
    except ValueError:
        if DOMAIN_RE.match(normalized):
            return normalized
    raise ValueError("Target must be a valid domain name or IP address.")


def build_url(target: str, use_https: bool = True, path: str = "") -> str:
    """Build a normalized HTTP or HTTPS URL for a target and optional path."""

    scheme = "https" if use_https else "http"
    clean_path = path if path.startswith("/") or not path else f"/{path}"
    return f"{scheme}://{validate_target(target)}{clean_path}"


def json_default(value: Any) -> str | None:
    """Serialize common non-JSON values."""

    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    return str(value) if value is not None else None


def to_json(data: Any, pretty: bool = False) -> str:
    """Serialize data as JSON with consistent defaults."""

    indent = 2 if pretty else None
    return json.dumps(data, default=json_default, ensure_ascii=False, indent=indent)

