"""Scanner package exports and unified scan engine."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from config import settings
from utils.helpers import validate_target
from utils.logger import get_logger

LOGGER = get_logger(__name__)


def resolve_ip(target: str) -> str | None:
    """Resolve a target to an IP address when possible."""

    try:
        return socket.gethostbyname(target)
    except OSError:
        return None


def run_unified_scan(target: str) -> dict[str, Any]:
    """Run independent scanner modules and return unified scan JSON."""

    normalized = validate_target(target)
    tasks: dict[str, Callable[[], dict[str, Any]]] = {
        "ping": lambda: _run_ping(normalized),
        "dns": lambda: _run_dns(normalized),
        "whois": lambda: _run_whois(normalized),
        "ssl": lambda: _run_ssl(normalized),
        "headers": lambda: _run_headers(normalized),
        "ports": lambda: _run_ports(normalized),
        "technologies": lambda: _run_technologies(normalized),
        "robots": lambda: _run_robots(normalized),
        "sitemap": lambda: _run_sitemap(normalized),
        "subdomains": lambda: _run_subdomains(normalized),
    }

    module_results: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(8, len(tasks))) as executor:
        future_map = {executor.submit(task): name for name, task in tasks.items()}
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                module_results[name] = future.result(timeout=settings.scan_timeout)
            except Exception as exc:
                LOGGER.exception("Scanner module failed: %s", name)
                module_results[name] = {
                    "module": name,
                    "target": normalized,
                    "status": "error",
                    "data": {},
                    "errors": [str(exc)],
                }

    ports_data = module_results.get("ports", {}).get("data", {})
    headers_data = module_results.get("headers", {}).get("data", {})
    tech_data = module_results.get("technologies", {}).get("data", {})
    ssl_data = module_results.get("ssl", {}).get("data", {})

    open_ports = ports_data.get("open_ports", [])
    services = [
        {
            "port": item.get("port"),
            "service": item.get("service"),
            "product": item.get("product"),
            "version": item.get("version"),
        }
        for item in open_ports
    ]

    return {
        "target": normalized,
        "ip": ports_data.get("resolved_ip") or resolve_ip(normalized),
        "ports": open_ports,
        "services": services,
        "ssl": ssl_data,
        "headers": headers_data,
        "technologies": tech_data.get("technologies", tech_data.get("cms_detected", [])),
        "robots": module_results.get("robots", {}).get("data", {}).get("content", ""),
        "sitemap": module_results.get("sitemap", {}).get("data", {}).get("content", ""),
        "subdomains": module_results.get("subdomains", {}).get("data", {}).get("subdomains", []),
        "modules": module_results,
        "risk_inputs": {
            "missing_headers": headers_data.get("missing_headers", []),
            "risky_ports": ports_data.get("risky_ports", []),
            "ssl": ssl_data,
            "technologies": tech_data,
            "services": services,
        },
    }


def _run_ping(target: str) -> dict[str, Any]:
    """Import and run the ping scanner."""

    from scanner.ping import scan_ping

    return scan_ping(target)


def _run_dns(target: str) -> dict[str, Any]:
    """Import and run the DNS scanner."""

    from scanner.dns_scan import scan_dns

    return scan_dns(target)


def _run_whois(target: str) -> dict[str, Any]:
    """Import and run the WHOIS scanner."""

    from scanner.whois_scan import scan_whois

    return scan_whois(target)


def _run_ssl(target: str) -> dict[str, Any]:
    """Import and run the SSL scanner."""

    from scanner.ssl_scan import scan_ssl

    return scan_ssl(target)


def _run_headers(target: str) -> dict[str, Any]:
    """Import and run the HTTP headers scanner."""

    from scanner.headers import scan_headers

    return scan_headers(target)


def _run_ports(target: str) -> dict[str, Any]:
    """Import and run the port scanner."""

    from scanner.port_scan import scan_ports

    return scan_ports(target, port_range=settings.default_ports)


def _run_technologies(target: str) -> dict[str, Any]:
    """Import and run the technology scanner."""

    from scanner.technologies import scan_technologies

    return scan_technologies(target)


def _run_robots(target: str) -> dict[str, Any]:
    """Import and run the robots scanner."""

    from scanner.robots import scan_robots

    return scan_robots(target)


def _run_sitemap(target: str) -> dict[str, Any]:
    """Import and run the sitemap scanner."""

    from scanner.sitemap import scan_sitemap

    return scan_sitemap(target)


def _run_subdomains(target: str) -> dict[str, Any]:
    """Import and run the subdomain scanner."""

    from scanner.subdomains import scan_subdomains

    return scan_subdomains(target)
