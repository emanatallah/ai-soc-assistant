"""Risk scoring engine for AI-SOC Assistant."""

from __future__ import annotations

import re
from typing import Any

RISKY_SERVICES = {
    # High-risk remote services
    "ftp": ("FTP exposed", 2.5),

    "telnet": ("Telnet exposed", 3.0),

    "ms-wbt-server": ("RDP exposed", 2.5),

    "microsoft-ds": ("SMB exposed", 2.5),

    # Databases
    "mysql": ("MySQL exposed", 2.0),

    "mongodb": ("MongoDB exposed", 2.5),

    "redis": ("Redis exposed", 2.5),

    # SSH is less risky than Telnet but still worth mentioning
    "ssh": ("SSH exposed", 0.5),
}


def _missing_header_names(items: list[Any]) -> set[str]:
    """Extract missing security header names from scanner output."""

    names: set[str] = set()

    for item in items:
        if isinstance(item, dict) and item.get("header"):
            names.add(str(item["header"]).lower())

        elif isinstance(item, str):
            names.add(item.lower())

    return names


def _severity(score: float) -> str:
    """Convert numeric score to severity."""

    if score >= 8:
        return "Critical"

    if score >= 6:
        return "High"

    if score >= 4:
        return "Medium"

    if score >= 2:
        return "Low"

    return "Informational"


def _detect_outdated_technology(text: str) -> list[tuple[str, float]]:
    """Detect outdated software versions."""

    findings: list[tuple[str, float]] = []

    checks = {
        r"apache/?2\.[0-2]": ("Apache outdated", 1.0),
        r"nginx/?0\.|nginx/?1\.[0-9]\.": ("Nginx outdated", 1.0),
        r"iis/?[1-7]\.": ("IIS outdated", 1.0),
        r"php/?[1-7]\.": ("Old PHP", 1.0),
        r"wordpress/?[1-5]\.": ("Old WordPress", 1.0),
        r"laravel/?[1-7]\.": ("Old Laravel", 1.0),
    }

    for pattern, finding in checks.items():
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(finding)

    return findings


def calculate_risk(scan: dict[str, Any]) -> dict[str, Any]:
    """Calculate risk score from scanner results."""

    risk_inputs = scan.get("risk_inputs", {})

    findings: list[dict[str, Any]] = []

    score = 0.0

    # ----------------------------------------------------
    # Missing Security Headers
    # ----------------------------------------------------

    missing = _missing_header_names(
        risk_inputs.get("missing_headers", [])
    )

    header_rules = {
        "content-security-policy": ("Missing CSP", 1.0),
        "strict-transport-security": ("Missing HSTS", 1.0),
        "x-frame-options": ("Missing X-Frame-Options", 0.7),
        "x-content-type-options": ("Missing X-Content-Type", 0.5),
    }

    for header, (title, weight) in header_rules.items():

        if header in missing:

            findings.append(
                {
                    "title": title,
                    "weight": weight,
                    "category": "headers",
                }
            )

            score += weight

    # ----------------------------------------------------
    # SSL / TLS
    # ----------------------------------------------------

    ssl_data = risk_inputs.get("ssl", {})

    protocol = str(
        ssl_data.get("protocol_version") or ""
    )

    if protocol in {"TLSv1", "TLSv1.1"}:

        findings.append(
            {
                "title": protocol,
                "weight": 1.5,
                "category": "tls",
            }
        )

        score += 1.5

    if ssl_data.get("is_weak_protocol"):

        findings.append(
            {
                "title": "Weak Cipher",
                "weight": 1.0,
                "category": "tls",
            }
        )

        score += 1.0

    if ssl_data.get("is_weak_cipher"):

        findings.append(
            {
                "title": "Weak Cipher",
                "weight": 1.0,
                "category": "tls",
            }
        )

        score += 1.0

    if ssl_data.get("is_expired"):

        findings.append(
            {
                "title": "Expired SSL certificate",
                "weight": 1.5,
                "category": "tls",
            }
        )

        score += 1.5

    # ----------------------------------------------------
    # Risky Services
    # ----------------------------------------------------

    for service in risk_inputs.get("services", []):

        service_name = str(
            service.get("service") or ""
        ).lower()

        if service_name in RISKY_SERVICES:

            title, weight = RISKY_SERVICES[service_name]

            findings.append(
                {
                    "title": title,
                    "weight": weight,
                    "category": "service",
                }
            )

            score += weight

        service_text = " ".join(
            str(service.get(key) or "")
            for key in ("service", "product", "version")
        )

        if (
            "anonymous" in service_text.lower()
            and "ftp" in service_text.lower()
        ):

            findings.append(
                {
                    "title": "Anonymous FTP",
                    "weight": 1.2,
                    "category": "service",
                }
            )

            score += 1.2

    # ----------------------------------------------------
    # Risky Ports
    # ----------------------------------------------------

    for risky_port in risk_inputs.get("risky_ports", []):

        reason = str(
            risky_port.get("reason", "")
        ).lower()

        for service_key, (title, weight) in RISKY_SERVICES.items():

            if (
                service_key in reason
                and not any(
                    item["title"] == title
                    for item in findings
                )
            ):

                findings.append(
                    {
                        "title": title,
                        "weight": weight,
                        "category": "service",
                    }
                )

                score += weight

    # ----------------------------------------------------
    # Outdated Technologies
    # ----------------------------------------------------

    banner_text = " ".join(
        str(value)
        for value in [
            risk_inputs.get("technologies", {}),
            risk_inputs.get("services", []),
        ]
    )

    for title, weight in _detect_outdated_technology(
        banner_text
    ):

        findings.append(
            {
                "title": title,
                "weight": weight,
                "category": "technology",
            }
        )

        score += weight

    final_score = min(
        round(score, 1),
        10.0,
    )

    severity = _severity(final_score)

    summary = (
        "No major risk indicators were detected."
        if not findings
        else f"{len(findings)} risk indicators detected with {severity.lower()} overall severity."
    )

    return {
        "risk_score": final_score,
        "severity": severity,
        "risk_summary": summary,
        "findings": findings,
    }