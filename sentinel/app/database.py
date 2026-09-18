import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent.parent.parent / "sentinel.db"


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                ip_address TEXT,
                username TEXT,
                request_data TEXT,
                timestamp TEXT NOT NULL,
                detected INTEGER NOT NULL DEFAULT 0,
                threat_type TEXT,
                risk_score INTEGER DEFAULT 0,
                severity TEXT
            )
            """
        )
        connection.commit()


def save_event(event_data: dict[str, Any]) -> int:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO security_events (
                event_type,
                ip_address,
                username,
                request_data,
                timestamp,
                detected,
                threat_type,
                risk_score,
                severity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_data.get("event_type"),
                event_data.get("ip_address"),
                event_data.get("username"),
                event_data.get("request_data"),
                event_data.get("timestamp"),
                int(event_data.get("detected", 0)),
                event_data.get("threat_type"),
                int(event_data.get("risk_score", 0)),
                event_data.get("severity"),
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)


def fetch_recent_events(limit: int = 20) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM security_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def fetch_dashboard_stats() -> dict[str, int]:
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) AS count FROM security_events").fetchone()["count"]
        detected = connection.execute(
            "SELECT COUNT(*) AS count FROM security_events WHERE detected = 1"
        ).fetchone()["count"]
        critical = connection.execute(
            "SELECT COUNT(*) AS count FROM security_events WHERE severity = 'CRITICAL'"
        ).fetchone()["count"]
        high = connection.execute(
            "SELECT COUNT(*) AS count FROM security_events WHERE severity = 'HIGH'"
        ).fetchone()["count"]
        medium = connection.execute(
            "SELECT COUNT(*) AS count FROM security_events WHERE severity = 'MEDIUM'"
        ).fetchone()["count"]

    return {
        "total_events": total,
        "detected_threats": detected,
        "critical_threats": critical,
        "high_threats": high,
        "medium_threats": medium,
    }
