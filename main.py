"""FastAPI entrypoint for RedShield APIs."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from utils.settings import (
    get_cors_allowed_origins,
    load_dotenv_if_available,
)


load_dotenv_if_available()

from api.routes import router
from utils.readiness import deployment_readiness

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

    readiness = deployment_readiness()

    return {
        "status": readiness["status"],
        "version": app.version,
        "execution_mode": readiness["checks"]["execution_mode"]["mode"],
        "dependencies": readiness["checks"],
        "blocking_issues": readiness["blocking_issues"],
    }
