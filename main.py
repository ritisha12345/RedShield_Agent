"""FastAPI entrypoint for RedShield APIs."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from utils.settings import (
    get_cors_allowed_origins,
    get_scan_execution_mode,
    load_dotenv_if_available,
)


load_dotenv_if_available()

from api.routes import router
from firebase.firestore import firestore_readiness_from_env

app = FastAPI(title="RedShield API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_allowed_origins(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)


@app.get("/health")
def health() -> dict:
    """Return liveness and deployment configuration readiness."""

    try:
        execution_mode = get_scan_execution_mode()
        queue_status = "required" if execution_mode == "celery" else "disabled"
    except ValueError:
        execution_mode = "invalid"
        queue_status = "misconfigured"

    return {
        "status": "ok" if execution_mode != "invalid" else "degraded",
        "version": app.version,
        "execution_mode": execution_mode,
        "dependencies": {
            "queue": queue_status,
            "firestore": firestore_readiness_from_env(),
        },
    }
