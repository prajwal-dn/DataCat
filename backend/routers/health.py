"""GET /api/v1/health — platform health check."""
import time
import aiosqlite

from fastapi import APIRouter, Request
from backend.config import DB_PATH, APP_VERSION
from backend.models import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check(request: Request):
    # DB connectivity test
    db_status = "connected"
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("SELECT 1")
    except Exception as exc:
        db_status = f"error: {exc}"

    uptime = time.monotonic() - request.app.state.start_time

    return HealthResponse(
        status="ok" if db_status == "connected" else "degraded",
        version=APP_VERSION,
        db=db_status,
        uptime_seconds=round(uptime, 2),
    )
