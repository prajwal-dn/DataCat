"""FastAPI route for secure telemetry ingestion."""
import logging
from typing import Any
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
import aiosqlite

from app.db.database import get_db_connection
from app.services.ingest_service import IngestionService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Ingest"])


async def get_db():
    db = await get_db_connection()
    try:
        yield db
    finally:
        await db.close()


@router.post("/ingest")
async def ingest_telemetry(
    request: Request,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Secure ingestion endpoint for Tier 1 telemetry and cryptographic receipt."""
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "status": "INVALID_SCHEMA",
                "message": "Malformed JSON in request body",
            },
        )

    status_code, response_data = await IngestionService.process_ingest(db, payload)
    return JSONResponse(status_code=status_code, content=response_data)
