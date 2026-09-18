THREAT_SCORES = {
    "BRUTE_FORCE": 70,
    "SQL_INJECTION": 90,
    "PATH_TRAVERSAL": 80,
    "XSS": 75,
    "NORMAL": 0,
}

SEVERITY_LEVELS = {
    "LOW": (0, 29),
    "MEDIUM": (30, 59),
    "HIGH": (60, 79),
    "CRITICAL": (80, 100),
}


def calculate_risk(threat_type: str | None) -> dict[str, object]:
    if not threat_type:
        return {"risk_score": 0, "severity": "LOW"}

    score = min(100, THREAT_SCORES.get(threat_type, 0))

    if 0 <= score <= 29:
        severity = "LOW"
    elif 30 <= score <= 59:
        severity = "MEDIUM"
    elif 60 <= score <= 79:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    return {"risk_score": score, "severity": severity}
