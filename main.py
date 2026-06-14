"""FastAPI entrypoint for RedShield development APIs."""

from fastapi import FastAPI

from api.routes import router


app = FastAPI(title="RedShield API", version="0.1.0")
app.include_router(router)
