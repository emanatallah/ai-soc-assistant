"""Local MITRE ATT&CK mapping for scanner findings."""

from __future__ import annotations

from typing import Any


MITRE_MAP = {
    # =========================
    # Remote Services
    # =========================
    "FTP exposed": (
        "T1021",
        "Remote Services",
        "Lateral Movement",
    ),

    "Telnet exposed": (
        "T1021",
        "Remote Services",
        "Lateral Movement",
    ),

    "SSH exposed": (
        "T1021.004",
        "SSH",
        "Lateral Movement",
    ),

    "RDP exposed": (
        "T1021.001",
        "Remote Desktop Protocol",
        "Lateral Movement",
    ),

    "SMB exposed": (
        "T1021.002",
        "SMB/Windows Admin Shares",
        "Lateral Movement",
    ),

    # =========================
    # Databases
    # =========================
    "MySQL exposed": (
        "T1213",
        "Data from Information Repositories",
        "Collection",
    ),

    "MongoDB exposed": (
        "T1213",
        "Data from Information Repositories",
        "Collection",
    ),

    "Redis exposed": (
        "T1213",
        "Data from Information Repositories",
        "Collection",
    ),

    # =========================
    # Authentication
    # =========================
    "Anonymous FTP": (
        "T1078",
        "Valid Accounts",
        "Defense Evasion",
    ),

    # =========================
    # Web Applications
    # =========================
    "HTTP exposed": (
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
    ),

    "HTTPS exposed": (
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
    ),

    # =========================
    # TLS
    # =========================
    "Weak Cipher": (
        "T1557",
        "Adversary-in-the-Middle",
        "Credential Access",
    ),
}


def services_to_findings(
    services: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """
    Convert high-risk exposed services into security findings.
    """

    findings: list[dict[str, str]] = []

    for service in services:

        port = str(service.get("port", ""))
        name = str(service.get("service", "")).lower()

        if port == "21" or "ftp" in name:
            findings.append({"title": "FTP exposed"})

        elif port == "23" or "telnet" in name:
            findings.append({"title": "Telnet exposed"})

        elif port == "3389" or "rdp" in name:
            findings.append({"title": "RDP exposed"})

        elif port == "445" or "smb" in name:
            findings.append({"title": "SMB exposed"})

        elif port == "3306" or "mysql" in name:
            findings.append({"title": "MySQL exposed"})

        elif port == "27017" or "mongodb" in name:
            findings.append({"title": "MongoDB exposed"})

        elif port == "6379" or "redis" in name:
            findings.append({"title": "Redis exposed"})

    return findings


def map_findings_to_mitre(
    findings: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """
    Map findings to MITRE ATT&CK techniques.
    """

    mapped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for finding in findings:

        title = str(finding.get("title", ""))

        if title.startswith("TLS"):
            title = "Weak Cipher"

        technique = MITRE_MAP.get(title)

        if technique is None:
            continue

        key = (title, technique[0])

        if key in seen:
            continue

        seen.add(key)

        mapped.append(
            {
                "finding": title,
                "technique_id": technique[0],
                "technique_name": technique[1],
                "tactic": technique[2],
                "description": (
                    f"The finding '{title}' is associated with "
                    f"MITRE ATT&CK technique {technique[0]} "
                    f"({technique[1]})."
                ),
                "recommendation": (
                    "Review the exposed service, restrict unnecessary access, "
                    "apply security hardening, and continuously monitor for abuse."
                ),
            }
        )

    return mapped 