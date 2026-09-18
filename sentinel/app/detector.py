from __future__ import annotations

from datetime import datetime
from typing import Any


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def detect_brute_force(event: dict[str, Any], recent_events: list[dict[str, Any]], threshold: int = 5, window_seconds: int = 60) -> bool:
    if event.get("event_type") != "LOGIN_FAILED":
        return False

    ip_address = event.get("ip_address")
    if not ip_address:
        return False

    current_time = _parse_timestamp(event.get("timestamp"))
    if current_time is None:
        return False

    matching_events = [
        recent_event
        for recent_event in recent_events
        if recent_event.get("event_type") == "LOGIN_FAILED"
        and recent_event.get("ip_address") == ip_address
    ]

    recent_count = 0
    for recent_event in matching_events:
        event_time = _parse_timestamp(recent_event.get("timestamp"))
        if event_time is None:
            continue
        if (current_time - event_time).total_seconds() <= window_seconds:
            recent_count += 1

    return recent_count + 1 >= threshold


def detect_sql_injection(payload: str) -> bool:
    if not payload:
        return False

    patterns = [
        "' or 1=1",
        "' or '1'='1",
        "union select",
        "drop table",
        "or 1=1",
    ]
    normalized = payload.lower()
    return any(pattern in normalized for pattern in patterns)


def detect_path_traversal(payload: str) -> bool:
    if not payload:
        return False

    normalized = payload.lower()
    traversal_markers = ["../", "..\\", "..%2f", "..%5c"]
    return any(marker in normalized for marker in traversal_markers)


def detect_xss(payload: str) -> bool:
    if not payload:
        return False

    normalized = payload.lower()
    xss_markers = ["<script>", "javascript:", "onerror=", "onload=", "<script"]
    return any(marker in normalized for marker in xss_markers)


def detect_threat(event: dict[str, Any], recent_events: list[dict[str, Any]], brute_force_threshold: int = 5) -> dict[str, Any]:
    payload = str(event.get("request_data") or "")
    event_type = event.get("event_type", "")

    if detect_brute_force(event, recent_events, threshold=brute_force_threshold):
        return {"detected": True, "threat_type": "BRUTE_FORCE"}

    if detect_sql_injection(payload):
        return {"detected": True, "threat_type": "SQL_INJECTION"}

    if detect_path_traversal(payload):
        return {"detected": True, "threat_type": "PATH_TRAVERSAL"}

    if detect_xss(payload):
        return {"detected": True, "threat_type": "XSS"}

    return {"detected": False, "threat_type": None}
