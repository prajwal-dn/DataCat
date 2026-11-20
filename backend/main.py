"""
DataCat — FastAPI application entry point.
"""
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse

from backend.config import APP_VERSION, APP_TITLE, MAX_PAYLOAD_BYTES
from backend.database import init_db
from backend.routers import ingest, events, stats, incidents, health as health_router, aiops as aiops_router

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


@app.middleware("http")
async def enforce_payload_size_limit(request: Request, call_next):
    """Enforce MAX_PAYLOAD_BYTES hard limit on all incoming requests."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_PAYLOAD_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={
                        "status": "rejected",
                        "reason": "payload_too_large",
                        "detail": f"Payload size exceeds the limit of {MAX_PAYLOAD_BYTES} bytes",
                    },
                )
        except ValueError:
            pass

    return await call_next(request)


# ----- API routers -----
app.include_router(ingest.router, prefix="/api/v1", tags=["ingest"])
app.include_router(events.router, prefix="/api/v1", tags=["events"])
app.include_router(stats.router, prefix="/api/v1", tags=["stats"])
app.include_router(incidents.router, prefix="/api/v1", tags=["incidents"])
app.include_router(health_router.router, prefix="/api/v1", tags=["health"])
app.include_router(aiops_router.router, prefix="/api/v1/aiops", tags=["aiops"])

# ----- Dashboard static files -----
DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"


@app.get("/dashboard", include_in_schema=False)
async def serve_dashboard():
    return FileResponse(DASHBOARD_DIR / "index.html")


app.state.start_time = _START_TIME
