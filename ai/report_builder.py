"""Build a deterministic security report before sending it to the AI."""

from __future__ import annotations

from typing import Any


SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "Microsoft RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "Remote Desktop Protocol (RDP)",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}


def build_report(scan: dict[str, Any]) -> str:
    findings = scan.get("findings", [])
    services = scan.get("services", [])
    mitre = scan.get("mitre", [])

    lines: list[str] = []

    # =====================================================
    # Executive Summary
    # =====================================================

    lines.append("# Executive Summary\n")

    if findings:
        lines.append(
            f"The assessment identified {len(findings)} security finding(s). "
            f"The calculated risk score is {scan['risk_score']} "
            f"({scan['severity']}). "
            "The findings primarily represent potential exposure that should be reviewed."
        )
    else:
        lines.append(
            "No confirmed security vulnerabilities were identified during this assessment."
        )

    # =====================================================
    # Risk Findings
    # =====================================================

    lines.append("\n# Risk Findings\n")

    if findings:

        for finding in findings:

            title = finding.get("title", "")

            if title == "SMB exposed":
                lines.append("- SMB service (TCP/445) is exposed.")
                lines.append(
                    "  This is an exposure rather than a confirmed vulnerability. "
                    "If SMB is accessible from untrusted networks it may increase the attack surface "
                    "and facilitate unauthorized access or lateral movement."
                )

            elif title == "FTP exposed":
                lines.append("- FTP service is exposed.")
                lines.append(
                    "  FTP does not encrypt credentials or data. "
                    "Use SFTP or FTPS whenever possible."
                )

            elif title == "Telnet exposed":
                lines.append("- Telnet service is exposed.")
                lines.append(
                    "  Telnet transmits traffic in plaintext and should be replaced with SSH."
                )

            elif title == "RDP exposed":
                lines.append("- Remote Desktop Protocol (TCP/3389) is exposed.")
                lines.append(
                    "  Restrict access to trusted hosts and enable Network Level Authentication."
                )

            elif title == "MySQL exposed":
                lines.append("- MySQL service is reachable from the network.")
                lines.append(
                    "  Verify that access is limited to authorized systems only."
                )

            elif title == "MongoDB exposed":
                lines.append("- MongoDB service is exposed.")
                lines.append(
                    "  Ensure authentication is enabled and public access is restricted."
                )

            elif title == "Redis exposed":
                lines.append("- Redis service is exposed.")
                lines.append(
                    "  Redis should not be Internet accessible without authentication."
                )

            elif title.startswith("Missing"):
                lines.append(f"- {title}.")
                lines.append(
                    "  Missing security headers may weaken browser-side protections."
                )

            else:
                lines.append(f"- {title}")

    else:
        lines.append(
            "No confirmed security findings were detected."
        )

    # =====================================================
    # Attack Surface
    # =====================================================

    lines.append("\n# Attack Surface\n")

    if services:

        for service in services:

            port = service.get("port", "-")
            detected = service.get("service") or "unknown"
            product = service.get("product") or ""

            service_name = SERVICE_NAMES.get(port, detected)

            if product:
                lines.append(
                    f"- TCP/{port}: {service_name} ({product})"
                )
            else:
                lines.append(
                    f"- TCP/{port}: {service_name}"
                )

        lines.append("")
        lines.append(
            "The services listed above represent the observable attack surface. "
            "Their presence alone does not indicate a confirmed vulnerability."
        )

    else:
        lines.append("No exposed network services were detected.")

    # =====================================================
    # MITRE
    # =====================================================

    lines.append("\n# MITRE ATT&CK\n")

    if mitre:

        for item in mitre:
            lines.append(
                f"- {item['technique_id']} — "
                f"{item['technique_name']} "
                f"({item['tactic']})"
            )

    else:
        lines.append(
            "No related MITRE ATT&CK techniques were identified."
        )

    # =====================================================
    # Recommendations
    # =====================================================

    lines.append("\n# Recommendations\n")

    if findings:

        added = set()

        for finding in findings:

            title = finding.get("title", "")

            if title == "SMB exposed":

                recommendations = [
                    "Restrict TCP/445 access to trusted hosts only.",
                    "Disable SMBv1 if it is enabled.",
                    "Require SMB signing where possible.",
                    "Monitor SMB authentication events.",
                ]

            elif title == "FTP exposed":

                recommendations = [
                    "Replace FTP with SFTP or FTPS.",
                    "Disable anonymous FTP access.",
                    "Restrict FTP access using firewall rules.",
                ]

            elif title == "Telnet exposed":

                recommendations = [
                    "Replace Telnet with SSH.",
                    "Disable the Telnet service if unnecessary.",
                ]

            elif title == "RDP exposed":

                recommendations = [
                    "Restrict RDP access to trusted IP addresses.",
                    "Enable Network Level Authentication (NLA).",
                    "Require Multi-Factor Authentication.",
                ]

            elif title == "MySQL exposed":

                recommendations = [
                    "Limit MySQL access to internal systems.",
                    "Disable remote root login.",
                    "Enforce strong authentication.",
                ]

            elif title == "MongoDB exposed":

                recommendations = [
                    "Enable authentication.",
                    "Restrict public network access.",
                    "Bind MongoDB to trusted interfaces only.",
                ]

            elif title == "Redis exposed":

                recommendations = [
                    "Enable Redis authentication.",
                    "Restrict access using firewall rules.",
                    "Do not expose Redis directly to the Internet.",
                ]

            elif title == "Missing HSTS":

                recommendations = [
                    "Enable the Strict-Transport-Security header.",
                ]

            elif title == "Missing CSP":

                recommendations = [
                    "Deploy an appropriate Content Security Policy.",
                ]

            elif title == "Missing X-Frame-Options":

                recommendations = [
                    "Add the X-Frame-Options response header.",
                ]

            elif title == "Missing X-Content-Type":

                recommendations = [
                    "Add the X-Content-Type-Options: nosniff header.",
                ]

            else:

                recommendations = [
                    "Review the identified finding and apply appropriate hardening measures."
                ]

            for rec in recommendations:

                if rec not in added:
                    added.add(rec)
                    lines.append(f"- {rec}")

    else:

        lines.append(
            "No immediate remediation is required beyond routine maintenance and continuous monitoring."
        )

    return "\n".join(lines)