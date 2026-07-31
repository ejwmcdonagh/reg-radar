"""
FastAPI application entry point.

The scheduler is started inside the lifespan context manager so it shuts down
cleanly on server exit rather than leaving background threads orphaned. This
matters for graceful restarts in production (e.g. Docker, systemd, Fly.io).
"""

import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from fastapi import Depends, FastAPI

from app.tls import configure_trust

# Trust the OS certificate store, required on corporate networks where a proxy CA
# is trusted by the system but absent from certifi's bundle. Shared with the evals
# and the review script so all three behave identically.
configure_trust()
from fastapi.middleware.cors import CORSMiddleware

from app.auth import require_api_key
from app.config import settings
from app.db.client import get_db
from app.routes import cards, clusters, ingestion, pipeline, profile, signals
from app.scheduler import create_scheduler

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)


def _mark_stale_pipeline_runs_failed() -> None:
    """
    Mark any pipeline_runs row stuck in 'running' for over an hour as failed.

    BackgroundTasks die silently if the worker crashes mid-run, leaving rows
    permanently 'running'. A real run completes in well under an hour, so
    anything older than that is definitely dead. Runs once at startup.
    """
    try:
        cutoff = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        db = get_db()
        result = db.table("pipeline_runs").update({
            "status": "failed",
            "completed_at": datetime.now(UTC).isoformat(),
            "error": "Marked failed at startup - worker likely crashed during execution",
        }).eq("status", "running").lt("started_at", cutoff).execute()
        if result.data:
            logger.info("Marked %d stale pipeline runs as failed", len(result.data))
    except Exception:
        # Best-effort cleanup - never let it block startup
        logger.exception("Failed to clean up stale pipeline runs")


@asynccontextmanager
async def lifespan(app: FastAPI):
    _mark_stale_pipeline_runs_failed()

    if settings.scheduler_enabled:
        scheduler = create_scheduler()
        scheduler.start()
        logger.info("Scheduler started with %d jobs", len(scheduler.get_jobs()))
    else:
        scheduler = None
        logger.info("Scheduler disabled - set SCHEDULER_ENABLED=true to enable daily runs")
    yield
    if scheduler:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")


app = FastAPI(
    title="Regulatory Radar API",
    description="Signal ingestion and retrieval for the Regulatory Radar intelligence agent.",
    version="0.1.0",
    lifespan=lifespan,
    # Global auth dependency - no-op when API_KEY env var is not set
    dependencies=[Depends(require_api_key)],
)

# In production, set ALLOWED_ORIGINS="https://your-domain.com" in the env.
# Defaults to ["*"] so local dev works without any config.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(signals.router)
app.include_router(ingestion.router)
app.include_router(clusters.router)
app.include_router(cards.router)
app.include_router(profile.router)
app.include_router(pipeline.router)


@app.get("/health")
async def health():
    # Verify DB connectivity, not just process liveness - a dead DB connection
    # would otherwise look healthy to a load balancer or uptime monitor
    try:
        db = get_db()
        db.table("org_profile").select("id").eq("id", 1).execute()
        return {"status": "ok"}
    except Exception:
        logger.exception("Health check DB ping failed")
        from fastapi import Response
        return Response(content='{"status":"degraded"}', status_code=503, media_type="application/json")
