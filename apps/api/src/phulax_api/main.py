from fastapi import FastAPI

from phulax_api.health import health
from phulax_api.routers import (
    agents,
    approvals,
    events,
    executions,
    orgs,
    policies,
    sessions,
    tools,
    ui,
)


def create_app() -> FastAPI:
    app = FastAPI(title="Phulax control plane API", version="0.1.0")
    app.get("/health", tags=["ops"])(health)
    app.include_router(orgs.router)
    app.include_router(agents.router)
    app.include_router(tools.router)
    app.include_router(sessions.router)
    app.include_router(events.router)
    app.include_router(policies.router)
    app.include_router(executions.router)
    app.include_router(approvals.router)
    app.include_router(ui.router)
    return app


app = create_app()
