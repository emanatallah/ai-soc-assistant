"""Prompt construction for local AI scan analysis."""

from __future__ import annotations

from typing import Any
from utils.helpers import to_json


def build_analysis_prompt(scan_json: dict[str, Any]) -> str:
    return f"""
You are a Senior SOC Analyst.

Analyze ONLY the JSON below.

Rules:
- Use ONLY the JSON.
- Never invent vulnerabilities.
- Never invent MITRE techniques.
- Never invent CVEs.
- If Findings is empty, say no confirmed vulnerabilities were found.
- Only discuss findings that exist.
- Mention MITRE ONLY if the JSON contains MITRE entries.
- Return Markdown only.

Write exactly these sections:

# Executive Summary
Summarize the security posture.

# Risk Findings
Explain each finding.
If none:
No confirmed security findings were detected.

# Attack Surface
Briefly describe the exposed services.
Do not call them vulnerabilities unless they appear in Findings.

# MITRE ATT&CK
If MITRE exists, summarize every technique.
Otherwise write:
No related MITRE ATT&CK techniques were identified.

# Recommendations
Recommendations ONLY for the findings.
If none:
No immediate remediation is required.

JSON:

{to_json(scan_json, pretty=True)}
"""