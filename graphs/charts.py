"""Plotly chart helpers."""

from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def risk_gauge(score: float) -> go.Figure:
    """Create a risk gauge chart."""

    return go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            gauge={"axis": {"range": [0, 10]}, "bar": {"color": "#f97316"}},
            title={"text": "Risk Score"},
        )
    )


def port_graph(scan: dict[str, Any]) -> go.Figure:
    """Create a bar chart of open ports by service."""

    rows = scan.get("ports", [])
    if not rows:
        rows = [{"port": "none", "service": "none"}]
    frame = pd.DataFrame(rows)
    return px.bar(frame, x="port", color="service", title="Open Ports")


def severity_chart(risk: dict[str, Any]) -> go.Figure:
    """Create a severity distribution chart."""

    findings = risk.get("findings", [])
    if not findings:
        findings = [{"category": "none", "weight": 0}]
    frame = pd.DataFrame(findings)
    return px.pie(frame, names="category", values="weight", title="Risk Distribution")


def timeline_chart(history_rows: list[dict[str, Any]]) -> go.Figure:
    """Create a risk timeline chart from scan history rows."""

    if not history_rows:
        history_rows = [{"timestamp": "", "risk_score": 0}]
    frame = pd.DataFrame(history_rows)
    return px.line(frame, x="timestamp", y="risk_score", title="Risk Timeline")

