"""
DataCat — FastAPI application entry point.
"""
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from backend.config import APP_VERSION, APP_TITLE
from backend.database import init_db
from backend.routers import ingest, events, stats, incidents, health as health_router

# Track startup time for /health uptime calculation
_START_TIME = time.monotonic()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB on startup."""
    await init_db()
    yield


app = FastAPI(
    title=APP_TITLE,
    version=APP_VERSION,
    lifespan=lifespan,
)

# ----- API routers -----
app.include_router(ingest.router, prefix="/api/v1", tags=["ingest"])
app.include_router(events.router, prefix="/api/v1", tags=["events"])
app.include_router(stats.router, prefix="/api/v1", tags=["stats"])
app.include_router(incidents.router, prefix="/api/v1", tags=["incidents"])
app.include_router(health_router.router, prefix="/api/v1", tags=["health"])

# ----- Dashboard static files -----
DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"


@app.get("/dashboard", include_in_schema=False)
async def serve_dashboard():
    return FileResponse(DASHBOARD_DIR / "index.html")


# Expose start time for health endpoint
app.state.start_time = _START_TIME
