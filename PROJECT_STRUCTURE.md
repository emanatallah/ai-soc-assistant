# Project Structure

```text
AI-SOC/
  app.py
  config.py
  scanner/
    __init__.py
    ping.py
    dns_scan.py
    whois_scan.py
    ssl_scan.py
    port_scan.py
    headers.py
    technologies.py
    robots.py
    sitemap.py
    subdomains.py
    dns_lookup.py
    whois_lookup.py
    ssl_check.py
    ports.py
  ai/
    analyzer.py
    mitre_mapper.py
    prompt.py
    risk_engine.py
  database/
    sqlite.py
    models.py
  reports/
    pdf.py
  graphs/
    topology.py
    charts.py
  utils/
    logger.py
    helpers.py
  assets/
  history/
  requirements.txt
```

The original scanner filenames are preserved for backward compatibility. The target architecture modules wrap or reuse them.

