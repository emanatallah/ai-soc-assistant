# Installation

## Requirements

- Python 3.12
- Nmap executable installed and available in `PATH` for port scanning
- Optional: Ollama for local AI analysis

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

## Run

```powershell
python app.py
```

The SQLite database and generated reports are stored under `history/`.

## Environment Variables

- `AI_SOC_REQUEST_TIMEOUT`
- `AI_SOC_SCAN_TIMEOUT`
- `AI_SOC_DEFAULT_PORTS`
- `AI_SOC_DATABASE_PATH`
- `AI_SOC_HISTORY_DIR`
- `AI_SOC_ASSETS_DIR`
- `AI_SOC_MODELS`
- `AI_SOC_USER_AGENT`
- `AI_SOC_MAX_SUBDOMAINS`
- `OLLAMA_HOST`
