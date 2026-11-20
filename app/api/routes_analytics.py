"""FastAPI routes for DATACAT AIOps Intelligence Engine.

Exposes endpoints for anomalies, correlated incidents, and explainable recommendations.
"""
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
import aiosqlite

from app.db.database import get_db_connection
from app.db.queries import (
    get_anomalies_list,
    get_incident_by_id,
    get_incidents_list,
    get_recommendations_list,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["AIOps Analytics"])


async def get_db():
    db = await get_db_connection()
    try:
        yield db
    finally:
        await db.close()


@router.get("/anomalies")
async def list_anomalies(
    tenant_id: Optional[str] = Query(None, description="Filter by tenant ID"),
    server_id: Optional[str] = Query(None, description="Filter by server ID"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    limit: int = Query(50, ge=1, le=200, description="Max anomalies to retrieve"),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Retrieves detected statistical and threshold anomalies."""
    anomalies = await get_anomalies_list(
        db, tenant_id=tenant_id, server_id=server_id, severity=severity, limit=limit
    )
    return {"anomalies": anomalies, "count": len(anomalies)}


@router.get("/incidents")
async def list_incidents(
    tenant_id: Optional[str] = Query(None, description="Filter by tenant ID"),
    server_id: Optional[str] = Query(None, description="Filter by server ID"),
    status: Optional[str] = Query(None, description="Filter by status (OPEN, RESOLVED)"),
    limit: int = Query(50, ge=1, le=200, description="Max incidents to retrieve"),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Retrieves correlated incidents grouped across related anomaly signals."""
    incidents = await get_incidents_list(
        db, tenant_id=tenant_id, server_id=server_id, status=status, limit=limit
    )
    return {"incidents": incidents, "count": len(incidents)}


@router.get("/incidents/{incident_id}")
async def get_incident_detail(
    incident_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Retrieves detailed operational diagnosis and recommendations for a specific incident."""
    incident = await get_incident_by_id(db, incident_id=incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return incident


@router.get("/recommendations")
async def list_recommendations(
    tenant_id: Optional[str] = Query(None, description="Filter by tenant ID"),
    limit: int = Query(20, ge=1, le=100, description="Max recommendations to retrieve"),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Retrieves explainable operational recommendations grounded in verified metrics."""
    recommendations = await get_recommendations_list(db, tenant_id=tenant_id, limit=limit)
    return {"recommendations": recommendations, "count": len(recommendations)}
