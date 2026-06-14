# Deployment Checklist

## Backend on Railway

Create one Railway web service from this repository. The checked-in
`railway.json` builds the root `Dockerfile` and starts:

```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

Required production variables:

- `OPENAI_API_KEY`
- `CORS_ALLOWED_ORIGINS=https://<netlify-site>`
- `REDSHIELD_SCAN_EXECUTION_MODE=celery`
- `REDIS_URL`, or both `CELERY_BROKER_URL` and `CELERY_RESULT_BACKEND`
- `REDSHIELD_FIRESTORE_ENABLED=true`
- `REDSHIELD_FIRESTORE_REQUIRED=true`
- `GOOGLE_CLOUD_PROJECT` or `FIRESTORE_PROJECT_ID`
- One of `GOOGLE_APPLICATION_CREDENTIALS_JSON`,
  `GOOGLE_APPLICATION_CREDENTIALS_B64`, `FIREBASE_SERVICE_ACCOUNT_JSON`, or
  `FIREBASE_SERVICE_ACCOUNT_B64`

Create a second Railway worker service from the same repo/image and override
the start command:

```bash
celery -A worker worker --loglevel=info
```

Attach both services to the same Redis service and Firestore project.

## Frontend on Netlify

The checked-in `netlify.toml` builds the Vite app from `frontend/` and publishes
`frontend/dist`.

Set this Netlify environment variable:

```bash
VITE_API_BASE_URL=https://<railway-api-service>
```

Also add the Netlify site origin to the backend `CORS_ALLOWED_ORIGINS` value.

## Local Production-Like Stack

Copy `.env.example` to `.env`, fill secrets, then run:

```bash
docker compose up --build
```

This starts Redis, the FastAPI service, and a Celery worker. Use
`REDSHIELD_SCAN_EXECUTION_MODE=thread` only for simple local development without
Redis.
