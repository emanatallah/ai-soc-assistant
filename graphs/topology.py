"""Network topology graph generation."""

from __future__ import annotations

from typing import Any

import networkx as nx
import plotly.graph_objects as go


def build_topology_graph(scan: dict[str, Any]) -> go.Figure:
    """Build a topology graph from unified scan data."""

    graph = nx.Graph()
    target = scan.get("target", "target")
    graph.add_node(target)
    ip = scan.get("ip")
    if ip:
        graph.add_edge(target, ip)
    for port in scan.get("ports", []):
        node = f"{port.get('port')}/{port.get('service')}"
        graph.add_edge(ip or target, node)

    positions = nx.spring_layout(graph, seed=42)
    edge_x: list[float] = []
    edge_y: list[float] = []
    for source, dest in graph.edges():
        x0, y0 = positions[source]
        x1, y1 = positions[dest]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    node_x = [positions[node][0] for node in graph.nodes()]
    node_y = [positions[node][1] for node in graph.nodes()]
    labels = list(graph.nodes())
    return go.Figure(
        data=[
            go.Scatter(x=edge_x, y=edge_y, mode="lines", line={"width": 1}),
            go.Scatter(x=node_x, y=node_y, mode="markers+text", text=labels, textposition="top center"),
        ]
    )

