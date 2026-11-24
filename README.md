# AI SOC Assistant

An educational team project for collecting reconnaissance data and exploring security analysis and reporting with Python.

## Eman's contribution
I contributed six Scanner Engine modules to this IEEE team project: ports, DNS, WHOIS, SSL/TLS, HTTP headers, and technology detection. These modules return structured JSON for the team's analysis and reporting pipeline.

## Running the current CLI
Install Python and Nmap, then clone this repository:

```bash
git clone https://github.com/eman688/ai-soc-assistant.git
cd ai-soc-assistant
python -m venv .venv
```

Activate the virtual environment for your operating system, then run:

```bash
python -m pip install -r requirements.txt
python app.py
```

Optional local AI features require a separately configured Ollama installation and model. The command above starts the current Rich-based CLI, not a Streamlit interface.

## Repository map
- app.py: command-line entry point
- config.py: application configuration
- scanner/: reconnaissance modules and unified scan output
- ai/: analysis, risk, mapping, and report-building code
- database/: SQLite storage
- reports/: PDF report generation
- graphs/: chart and topology helpers
- utils/: shared helpers and logging

## Use and limitations
Use only on systems you own or have explicit permission to assess. This is an educational project, not a replacement for a full security assessment. Findings and AI output require human review. Installation and end-to-end scanning have not been independently verified as part of this documentation update.

## Attribution
This repository is team work. Existing author and copyright credits to Yusef Dafsher are retained. Eman's contribution is described separately above; this documentation does not claim she authored the whole framework.

## License

This project is released under the MIT License.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files to use, modify, distribute, and sublicense the software under the terms of the MIT License.

See the LICENSE file for complete license information.


Copyright © 2026 Yusef Dafsher.

All rights reserved.
