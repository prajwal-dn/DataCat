"""FastAPI health check route."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
import aiosqlite

from app.db.database import get_db_connection

router = APIRouter(prefix="/api/v1", tags=["Health"])


async def get_db():
    db = await get_db_connection()
    try:
        yield db
    finally:
        await db.close()


@router.get("/health")
async def health_check(db: aiosqlite.Connection = Depends(get_db)):
    """Health check verifying API responsiveness and database connectivity."""
    db_status = "connected"
    try:
        async with db.execute("SELECT 1;") as cursor:
            await cursor.fetchone()
    except Exception:
        db_status = "disconnected"

    status_code = 200 if db_status == "connected" else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "healthy" if db_status == "connected" else "unhealthy",
            "database": db_status,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        },
    )
