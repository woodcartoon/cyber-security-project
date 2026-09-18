from sentinel.app.detector import detect_threat
from sentinel.app.risk import calculate_risk


def test_normal_event_not_detected() -> None:
    event = {
        "event_type": "LOGIN_SUCCESS",
        "ip_address": "192.168.1.10",
        "username": "alice",
        "request_data": "",
        "timestamp": "2026-09-18T12:00:00",
    }

    result = detect_threat(event, [])
    assert result["detected"] is False
    assert result["threat_type"] is None


def test_brute_force_detected() -> None:
    event = {
        "event_type": "LOGIN_FAILED",
        "ip_address": "192.168.1.50",
        "username": "admin",
        "request_data": "",
        "timestamp": "2026-09-18T12:00:00",
    }
    recent = [
        {"event_type": "LOGIN_FAILED", "ip_address": "192.168.1.50", "timestamp": "2026-09-18T11:59:45"},
        {"event_type": "LOGIN_FAILED", "ip_address": "192.168.1.50", "timestamp": "2026-09-18T11:59:50"},
        {"event_type": "LOGIN_FAILED", "ip_address": "192.168.1.50", "timestamp": "2026-09-18T11:59:55"},
        {"event_type": "LOGIN_FAILED", "ip_address": "192.168.1.50", "timestamp": "2026-09-18T11:59:59"},
    ]

    result = detect_threat(event, recent)
    assert result["threat_type"] == "BRUTE_FORCE"


def test_sql_injection_detected() -> None:
    event = {
        "event_type": "HTTP_REQUEST",
        "ip_address": "192.168.1.20",
        "username": "admin",
        "request_data": "' OR 1=1 --",
        "timestamp": "2026-09-18T12:01:00",
    }

    result = detect_threat(event, [])
    assert result["threat_type"] == "SQL_INJECTION"


def test_path_traversal_detected() -> None:
    event = {
        "event_type": "HTTP_REQUEST",
        "ip_address": "192.168.1.20",
        "username": "admin",
        "request_data": "../../etc/passwd",
        "timestamp": "2026-09-18T12:02:00",
    }

    result = detect_threat(event, [])
    assert result["threat_type"] == "PATH_TRAVERSAL"


def test_xss_detected() -> None:
    event = {
        "event_type": "HTTP_REQUEST",
        "ip_address": "192.168.1.20",
        "username": "admin",
        "request_data": "<script>alert('test')</script>",
        "timestamp": "2026-09-18T12:03:00",
    }

    result = detect_threat(event, [])
    assert result["threat_type"] == "XSS"


def test_risk_scoring() -> None:
    assert calculate_risk("BRUTE_FORCE")["risk_score"] == 70
    assert calculate_risk("BRUTE_FORCE")["severity"] == "HIGH"

    assert calculate_risk("SQL_INJECTION")["risk_score"] == 90
    assert calculate_risk("SQL_INJECTION")["severity"] == "CRITICAL"
