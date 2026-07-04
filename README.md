# Autonomous Control Layer

FastAPI implementation of the Lemtik Security autonomous control service described in `spec.md`.

## Included

- `POST /execute`
- `POST /revert/{override_id}`
- `GET /overrides/active`
- `GET /devices`
- `POST /devices`
- `PUT /devices/{id}`
- `GET /devices/{id}/status`
- `GET /log`
- `POST /incident/resolved`
- `GET /health`
- `GET /health/bridges`

## Run

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Render

- `render.yaml` defines the web service for Render.
- `Procfile` is included as a fallback process definition.
- Set `INTERNAL_API_KEY` and `DATABASE_URL` in Render environment variables.
- If you want persistent data, point `DATABASE_URL` at Render Postgres or another PostgreSQL instance.

## Environment

- `INTERNAL_API_KEY`
- `RELATIONSHIP_API_IPS` optional comma-separated allow list
- `DEVICE_CREDENTIALS_ENCRYPTION_KEY` optional but required for encrypted credential storage

## Notes

- The current implementation uses in-memory persistence with a SQL schema included in `schema.sql`.
- Adapter integrations are structured for HTTP, MQTT, and WebSocket bridge execution.
- Secrets are redacted in API responses.
# autonomouscontroller
