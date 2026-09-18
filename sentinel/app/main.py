from datetime import datetime

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

from sentinel.app.database import init_db, save_event


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
    event_payload["detected"] = False
    event_payload["threat_type"] = None
    event_payload["risk_score"] = 0
    event_payload["severity"] = None

    save_event(event_payload)

    return {
        "message": "Event processed",
        "detected": False,
        "threat_type": None,
        "risk_score": 0,
        "severity": None,
    }
