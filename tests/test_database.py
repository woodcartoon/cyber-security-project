from sentinel.app.database import init_db, save_event


def test_database_initializes_and_saves_event() -> None:
    init_db()

    event_id = save_event(
        {
            "event_type": "LOGIN_FAILED",
            "ip_address": "192.168.1.10",
            "username": "admin",
            "request_data": "",
            "timestamp": "2026-09-18T12:00:00",
            "detected": 0,
            "threat_type": None,
            "risk_score": 0,
            "severity": None,
        }
    )

    assert isinstance(event_id, int)
    assert event_id > 0
