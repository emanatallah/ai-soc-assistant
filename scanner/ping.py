"""Host reachability scanner."""

from __future__ import annotations

import platform
import subprocess
from typing import Any

from utils.helpers import standard_output, validate_target


def scan_ping(target: str) -> dict[str, Any]:
    """Ping a target once and report whether it responds."""

    normalized = validate_target(target)
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"
    command = ["ping", count_flag, "1", timeout_flag, "3", normalized]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        reachable = completed.returncode == 0
        return standard_output(
            "ping",
            normalized,
            "success" if reachable else "error",
            data={"reachable": reachable, "output": completed.stdout[-1000:]},
            errors=[] if reachable else ["Host did not respond to ping."],
        )
    except Exception as exc:
        return standard_output(
            "ping",
            normalized,
            "error",
            data={"reachable": False, "output": ""},
            errors=[f"Ping failed: {exc}"],
        )

