import os

from fastapi import FastAPI

from routes import router
from service import SERVICE

try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
except ModuleNotFoundError:  # pragma: no cover - optional in development images
    AsyncIOScheduler = None


def create_app() -> FastAPI:
    app = FastAPI(
        title="Lemtik Security Autonomous Control Layer",
        version="1.0.0",
    )

    @app.get("/health")
    @app.get("/api/v1/health")
    async def _public_health() -> dict:
        return {"status": "ok", "service": "autonomouscontroller", "environment": app.state.environment}

    app.include_router(router)
    app.state.environment = os.getenv("ENVIRONMENT", "production")

    @app.on_event("startup")
    async def _startup() -> None:
        if AsyncIOScheduler is not None:
            scheduler = AsyncIOScheduler(timezone="UTC")
            scheduler.start()
            SERVICE.set_scheduler(scheduler)
            await SERVICE.reschedule_active_overrides()
            app.state.scheduler = scheduler
        else:
            app.state.scheduler = None
        await SERVICE.reconcile_overrides()

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        scheduler = getattr(app.state, "scheduler", None)
        if scheduler:
            scheduler.shutdown(wait=False)

    return app


app = create_app()
