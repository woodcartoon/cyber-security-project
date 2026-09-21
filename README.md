# Sentinel

Sentinel is a lightweight cybersecurity threat detection project built for local demonstration and learning.

## Overview

The application accepts simulated security events, detects suspicious behavior, calculates a risk score, and displays alerts in a simple web dashboard.

## Installation

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
uvicorn sentinel.app.main:app --reload
```

## Test

```bash
pytest
```

## Health Check

The API exposes the following endpoint:

```bash
GET /health
```

It returns:

```json
{"status": "online", "service": "Sentinel"}
```

## Security

This project only uses local synthetic data for defensive cybersecurity education and demonstration.
