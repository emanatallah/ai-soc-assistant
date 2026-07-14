"""Ollama-backed local AI report formatter."""

from __future__ import annotations

try:
    import ollama
except ImportError:
    ollama = None

from config import settings
from utils.logger import get_logger

LOGGER = get_logger(__name__)


def detect_installed_model() -> str | None:
    """Return the best installed Ollama model."""

    if ollama is None:
        return None

    try:
        models_response = ollama.list()

        if hasattr(models_response, "models"):
            models = models_response.models
        elif isinstance(models_response, dict):
            models = models_response.get("models", [])
        else:
            models = []

        installed = []

        for item in models:
            if isinstance(item, dict):
                name = item.get("name") or item.get("model")
            else:
                name = getattr(item, "name", None) or getattr(item, "model", None)

            if name:
                installed.append(name.lower())

        # Preferred models
        for preferred in settings.preferred_models:
            preferred = preferred.lower()

            for model in installed:
                if model.startswith(preferred):
                    return model

        # Fallback
        for prefix in (
            "qwen2.5",
            "qwen3",
            "llama3.1",
            "llama3",
            "mistral",
            "gemma",
            "qwen",
        ):
            for model in installed:
                if model.startswith(prefix):
                    return model

    except Exception as exc:
        LOGGER.warning("Ollama model detection failed: %s", exc)

    return None


def analyze_scan(report: str) -> str:
    """
    Rewrite a pre-built security report professionally.
    The AI must NOT perform its own analysis.
    """

    model = detect_installed_model()

    if not model:
        return report

    system_prompt = """
You are a professional SOC report editor.

Your job is ONLY to improve writing quality.

STRICT RULES

- Never invent vulnerabilities.
- Never invent CVEs.
- Never invent MITRE ATT&CK techniques.
- Never add findings.
- Never remove findings.
- Never change the risk score.
- Never change severity.
- Never modify recommendations.
- Never modify MITRE mappings.
- Preserve every technical detail exactly.
- Improve wording only.
- Return Markdown only.
"""

    try:
        response = ollama.chat(
            model=model,
            options={
                "temperature": 0.0,
                "top_p": 0.8,
                "num_predict": 700,
            },
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": report,
                },
            ],
        )

        if hasattr(response, "message"):
            return response.message.content

        if isinstance(response, dict):
            return response.get("message", {}).get("content", report)

        return str(response)

    except Exception:
        LOGGER.exception("Ollama formatting failed")
        return report