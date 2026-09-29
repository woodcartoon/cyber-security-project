
WTC-PLG7ENBY
# link to youtube
https://youtu.be/cP4Bhd_wyZc
# Sentinel

Sentinel is a lightweight cybersecurity threat detection project built for local demonstration and learning.

## Overview

The application accepts synthetic security events, detects suspicious patterns, calculates risk scores, and stores events in a local SQLite database. Its interactive API documentation can be used to submit demo events.

## Installation

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run

From the project root, activate the virtual environment:

```powershell
.venv\Scripts\Activate.ps1
```

Then start the API server:

```bash
uvicorn sentinel.app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the interactive API, or `http://127.0.0.1:8000/health` to check that the service is running. Keep the terminal open while using the app; press `Ctrl+C` to stop the server.

## Simulate Events

These examples submit synthetic data only to your local Sentinel API. They do not run attacks against a real system.

1. Start the server and open `http://127.0.0.1:8000/docs`.
2. Expand `POST /events`, select **Try it out**, and submit an event like this to trigger SQL injection detection:



```json
{
	"event_type": "HTTP_REQUEST",
	"ip_address": "192.0.2.10",
	"username": "demo",
	"request_data": "' OR 1=1 --",
	"timestamp": "2026-09-29T12:00:00"
}
```

The response should report `detected: true`, `threat_type: SQL_INJECTION`, a risk score of `90`, and `CRITICAL` severity. To try the other request-data detectors, replace `request_data` with one of these harmless example strings:

- Path traversal: `../../etc/passwd` (detected as `PATH_TRAVERSAL`)
- Cross-site scripting: `<script>alert('test')</script>` (detected as `XSS`)

To simulate brute-force activity, submit five `LOGIN_FAILED` events from the same IP within 60 seconds. In PowerShell, with the server running, use:

```powershell
$baseTime = (Get-Date).AddSeconds(-4)
0..4 | ForEach-Object {
		$event = @{
				event_type = "LOGIN_FAILED"
				ip_address = "198.51.100.25"
				username = "demo"
				request_data = ""
				timestamp = $baseTime.AddSeconds($_).ToString("s")
		}
		Invoke-RestMethod -Uri "http://127.0.0.1:8000/events" -Method Post -ContentType "application/json" -Body ($event | ConvertTo-Json)
}
```

The final response should report `BRUTE_FORCE`. Each submitted event is saved to `sentinel.db` in the project root. The current API returns a result for each event but does not yet provide an event-history or dashboard page.

## Test

```bash
pytest
```

## Health Check

The API exposes the following endpoint:

`GET http://127.0.0.1:8000/health`

It returns:

```json
{"status": "online", "service": "Sentinel"}
```

## Security

This project only uses local synthetic data for defensive cybersecurity education and demonstration.
