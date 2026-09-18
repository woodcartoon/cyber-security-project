from datetime import datetime

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

from sentinel.app.database import fetch_recent_events, init_db, save_event
from sentinel.app.detector import detect_threat
from sentinel.app.risk import calculate_risk


class SecurityEvent(BaseModel):
    event_type: str = Field(..., min_length=1)
    ip_address: str = Field(..., min_length=1)
    username: str = Field(..., min_length=1)
    request_data: str = ""
    timestamp: str = Field(..., min_length=1)

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: str) -> str:
        try:
            datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("timestamp must be a valid ISO datetime string") from exc
        return value


app = FastAPI(title="Sentinel", version="0.1.0")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "online", "service": "Sentinel"}


@app.post("/events")
def create_event(event: SecurityEvent) -> dict[str, object]:
    event_payload = event.model_dump()
    recent_events = fetch_recent_events(limit=50)
    detection = detect_threat(event_payload, recent_events)
    risk = calculate_risk(detection["threat_type"])

    event_payload["detected"] = int(detection["detected"])
    event_payload["threat_type"] = detection["threat_type"]
    event_payload["risk_score"] = int(risk["risk_score"])
    event_payload["severity"] = risk["severity"]

    save_event(event_payload)

    return {
        "message": "Event processed",
        "detected": bool(detection["detected"]),
        "threat_type": detection["threat_type"],
        "risk_score": int(risk["risk_score"]),
        "severity": risk["severity"],
    }
