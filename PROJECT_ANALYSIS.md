# AI-SOC Assistant Project Analysis

Generated: 2026-07-06

## Repository Summary

The current repository contains only six scanner modules under `scanner/`:

- `dns_lookup.py`
- `headers.py`
- `ports.py`
- `ssl_check.py`
- `technologies.py`
- `whois_lookup.py`

There is no application entry point, configuration layer, shared utilities, database, AI layer, risk engine, MITRE mapping, reporting, graphs, documentation, or dependency manifest.

The existing modules are useful and should be preserved through compatibility wrappers while the target architecture is introduced.

## Global Findings

### Purpose

The repository currently provides standalone command-line scanner modules for DNS, WHOIS, SSL/TLS, HTTP headers, port scanning, and web technology detection.

### Dependencies

Current modules require:

- `requests`
- `dnspython`
- `python-whois`
- `python-nmap`

Future target architecture also requires:

- `streamlit`
- `beautifulsoup4`
- `networkx`
- `plotly`
- `reportlab`
- `pandas`
- `rich`
- `colorama`
- `ollama`
- `tldextract`
- `cryptography`
- `python-dotenv`

### Problems

- No `requirements.txt`.
- No `scanner/__init__.py`, so imports depend on namespace-package behavior.
- The standard output wrapper is duplicated in every scanner.
- No central configuration for timeouts, paths, ports, or model selection.
- No target validation.
- No centralized logging.
- No unified scanner engine.
- No database persistence.
- No risk scoring.
- No MITRE ATT&CK mapping.
- No AI analysis integration.
- No PDF or graph generation.
- No Streamlit UI.
- No documentation.
- No tests.
- Several functions lack return type annotations.
- Existing CLI modules use relative standalone behavior only.

## File Analysis

### `scanner/dns_lookup.py`

Purpose:

- Queries A, MX, NS, and TXT DNS records for a target domain.
- Returns a standardized result dictionary.
- Provides a small CLI.

Dependencies:

- `argparse`
- `datetime`
- `json`
- `dns.resolver`

Problems:

- Duplicates `_standard_output`.
- Does not use a configurable resolver timeout.
- Does not normalize or validate target input.
- Does not return CNAME/AAAA records required by richer scanning.
- Broad `Exception` catch is useful for resilience but not logged.
- Functions do not all contain explicit return type hints.

Missing logic:

- Shared output model.
- Shared logger.
- Configurable DNS record types.
- Input normalization.

### `scanner/headers.py`

Purpose:

- Fetches a target URL and checks for important HTTP security headers.

Dependencies:

- `argparse`
- `datetime`
- `json`
- `requests`

Problems:

- Duplicates `_standard_output`.
- Always constructs `https://target` or `http://target`, so passing a full URL breaks.
- No fallback from HTTPS to HTTP.
- No target validation.
- No central timeout/user agent config.
- Does not expose raw headers separately from security-header findings.
- Functions do not all contain explicit return type hints.

Missing logic:

- Header risk inputs for the risk engine.
- Redirect URL and status code capture.
- Shared HTTP client settings.

### `scanner/ports.py`

Purpose:

- Resolves the target and uses `python-nmap` to identify open ports and services.
- Flags risky ports.

Dependencies:

- `argparse`
- `datetime`
- `json`
- `socket`
- `nmap`

Problems:

- Requires the system `nmap` executable, but no install docs exist.
- SYN stealth mode may require elevated privileges and can fail on Windows.
- No validation of the port range string.
- No central timeout, scan rate, or default port configuration.
- Does not handle missing `nmap` dependency separately from scan failure.
- Functions do not all contain explicit return type hints.

Missing logic:

- Service/version normalization for unified scan output.
- Broader exposed service risk mapping.
- Safer fallback when `python-nmap` is unavailable.

### `scanner/ssl_check.py`

Purpose:

- Connects to a target over TLS, reads certificate metadata, and reports protocol and expiry state.

Dependencies:

- `argparse`
- `datetime`
- `json`
- `socket`
- `ssl`

Problems:

- Only checks the negotiated protocol, not explicitly TLS 1.0/1.1 support.
- Does not report cipher details.
- Does not validate target input.
- Does not handle certificates with missing fields defensively enough.
- Functions do not all contain explicit return type hints.

Missing logic:

- TLS version probing.
- Weak cipher reporting.
- Configurable port/timeout.
- Better certificate subject alternative name extraction.

### `scanner/technologies.py`

Purpose:

- Detects server software, powered-by headers, and common CMS signatures from a web response.

Dependencies:

- `argparse`
- `datetime`
- `json`
- `requests`

Problems:

- Duplicates `_standard_output`.
- Always constructs a URL from scheme and target.
- Signature detection is simple string matching.
- No HTML parser usage despite `beautifulsoup4` being part of target dependencies.
- No version extraction for WordPress, PHP, Laravel, Apache, Nginx, or IIS.
- Functions do not all contain explicit return type hints.

Missing logic:

- Technology list compatible with unified scan JSON.
- Version extraction.
- Shared HTTP settings.

### `scanner/whois_lookup.py`

Purpose:

- Retrieves WHOIS domain registration metadata.

Dependencies:

- `argparse`
- `datetime`
- `json`
- `whois`

Problems:

- Duplicates `_standard_output`.
- No target normalization.
- WHOIS library behavior varies by TLD and network conditions.
- No timeout control.
- Functions do not all contain explicit return type hints.

Missing logic:

- Shared serialization helpers.
- Better handling for list-valued WHOIS fields.
- Integration into unified target metadata.

## Architecture Gaps Against Target Structure

Missing files/directories:

- `app.py`
- `config.py`
- `scanner/__init__.py`
- `scanner/ping.py`
- `scanner/dns_scan.py`
- `scanner/whois_scan.py`
- `scanner/ssl_scan.py`
- `scanner/port_scan.py`
- `scanner/robots.py`
- `scanner/sitemap.py`
- `scanner/subdomains.py`
- `ai/analyzer.py`
- `ai/mitre_mapper.py`
- `ai/prompt.py`
- `ai/risk_engine.py`
- `database/sqlite.py`
- `database/models.py`
- `reports/pdf.py`
- `graphs/topology.py`
- `graphs/charts.py`
- `utils/logger.py`
- `utils/helpers.py`
- `assets/`
- `history/`
- `requirements.txt`
- `README.md`
- `INSTALL.md`
- `PROJECT_STRUCTURE.md`
- `CHANGELOG.md`

## Recommended Incremental Rebuild Plan

1. Add shared config, helpers, logger, output wrapper, and package initializers.
2. Add compatibility scanner modules matching the target names while preserving old modules.
3. Add missing scanner capabilities: ping, robots, sitemap, subdomains, unified scan engine.
4. Add risk scoring and MITRE mapping.
5. Add local Ollama analysis with graceful fallback when Ollama is unavailable.
6. Add SQLite storage and scan history comparison.
7. Add graph and PDF generation.
8. Add Streamlit app.
9. Add dependency manifest and documentation.
10. Run compile/import checks and fix runtime issues.

