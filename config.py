"""Central configuration for AI-SOC Assistant."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv()


@dataclass(frozen=True)
class Settings:
    """Runtime settings loaded from environment variables."""

    app_name: str = "AI-SOC Assistant"

    request_timeout: int = int(
        os.getenv("AI_SOC_REQUEST_TIMEOUT", "10")
    )

    scan_timeout: int = int(
        os.getenv("AI_SOC_SCAN_TIMEOUT", "30")
    )

    default_ports: str = os.getenv(
        "AI_SOC_DEFAULT_PORTS",
        "1-1000",
    )

    database_path: Path = Path(
        os.getenv(
            "AI_SOC_DATABASE_PATH",
            "history/ai_soc.sqlite3",
        )
    )

    history_dir: Path = Path(
        os.getenv(
            "AI_SOC_HISTORY_DIR",
            "history",
        )
    )

    assets_dir: Path = Path(
        os.getenv(
            "AI_SOC_ASSETS_DIR",
            "assets",
        )
    )

    ollama_host: str = os.getenv(
        "OLLAMA_HOST",
        "http://localhost:11434",
    )

    # ترتيب الموديلات حسب الأفضلية
    preferred_models: tuple[str, ...] = tuple(
        model.strip()
        for model in os.getenv(
            "AI_SOC_MODELS",
            "qwen2.5:7b,llama3.1:8b,mistral,gemma,qwen:latest",
        ).split(",")
        if model.strip()
    )

    user_agent: str = os.getenv(
        "AI_SOC_USER_AGENT",
        "AI-SOC-Assistant/1.0 Authorized-Security-Scanner",
    )

    max_subdomains: int = int(
        os.getenv(
            "AI_SOC_MAX_SUBDOMAINS",
            "25",
        )
    )


settings = Settings()