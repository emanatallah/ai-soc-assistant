"""SQLite persistence for scan history."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from config import settings
from database.models import SCANS_TABLE_SQL
from utils.helpers import to_json


def get_connection(path: Path | None = None) -> sqlite3.Connection:
    """Create a SQLite connection and ensure schema exists."""

    db_path = path or settings.database_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.execute(SCANS_TABLE_SQL)
    connection.commit()
    return connection


def save_scan(
    target: str,
    scan_results: dict[str, Any],
    risk: dict[str, Any],
    ai_report: str,
    mitre: list[dict[str, Any]],
) -> int:
    """Persist a completed scan and return the inserted row ID."""

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans (
                target,
                timestamp,
                scan_results,
                risk_score,
                severity,
                ai_report,
                mitre
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target,
                datetime.now().isoformat(),
                to_json(scan_results),
                float(risk.get("risk_score", 0)),
                risk.get("severity", "Informational"),
                ai_report,
                to_json(mitre),
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)


def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    """Return recent scan history rows."""

    with get_connection() as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def compare_latest_scans(target: str) -> dict[str, Any]:
    """Compare the two most recent scans for a target."""

    with get_connection() as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT * FROM scans
            WHERE target = ?
            ORDER BY id DESC
            LIMIT 2
            """,
            (target,),
        ).fetchall()

    if len(rows) < 2:
        return {
            "target": target,
            "available": False,
            "message": "Need at least two scans.",
        }

    latest = dict(rows[0])
    previous = dict(rows[1])

    return {
        "target": target,
        "available": True,
        "latest": {
            "risk_score": latest["risk_score"],
            "timestamp": latest["timestamp"],
        },
        "previous": {
            "risk_score": previous["risk_score"],
            "timestamp": previous["timestamp"],
        },
        "delta": round(
            float(latest["risk_score"]) -
            float(previous["risk_score"]),
            2,
        ),
    }




def compare_two_targets(
    target1: str,
    target2: str,
) -> dict[str, Any]:
    """Compare the latest scan of two different targets."""

    with get_connection() as connection:
        connection.row_factory = sqlite3.Row

        first = connection.execute(
            """
            SELECT * FROM scans
            WHERE target = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (target1,),
        ).fetchone()

        second = connection.execute(
            """
            SELECT * FROM scans
            WHERE target = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (target2,),
        ).fetchone()

    if first is None:
        return {
            "available": False,
            "message": f"No scan found for '{target1}'.",
        }

    if second is None:
        return {
            "available": False,
            "message": f"No scan found for '{target2}'.",
        }

    first = dict(first)
    second = dict(second)

    return {
    "available": True,

    "target1": {
        "target": first["target"],
        "risk_score": first["risk_score"],
        "severity": first.get("severity", "N/A"),
        "timestamp": first["timestamp"],
    },

    "target2": {
        "target": second["target"],
        "risk_score": second["risk_score"],
        "severity": second.get("severity", "N/A"),
        "timestamp": second["timestamp"],
    },

    "delta": round(
        float(second["risk_score"]) -
        float(first["risk_score"]),
        2,
    ),
}