from fastapi.testclient import TestClient

from sentinel.app.main import app

client = TestClient(app)


def test_create_event_endpoint() -> None:
    response = client.post(
        "/events",
        json={
            "event_type": "LOGIN_FAILED",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "request_data": "",
            "timestamp": "2026-09-18T12:00:00",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["message"] == "Event processed"
    assert payload["detected"] is False


def test_create_event_detects_sql_injection() -> None:
    response = client.post(
        "/events",
        json={
            "event_type": "HTTP_REQUEST",
            "ip_address": "192.168.1.77",
            "username": "admin",
            "request_data": "' OR 1=1 --",
            "timestamp": "2026-09-18T12:10:00",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["detected"] is True
    assert payload["threat_type"] == "SQL_INJECTION"
    assert payload["risk_score"] == 90
    assert payload["severity"] == "CRITICAL"
