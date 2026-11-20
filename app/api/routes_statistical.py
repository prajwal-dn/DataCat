"""FastAPI routes for DATACAT Statistical Anomaly Detection Engine.

Exposes endpoints for:
  - Latest per-metric statistical analysis records.
  - Metric anomaly history by server + metric.
  - Per-server rolling baseline (median / MAD).
  - Current statistical health summary.
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query
import aiosqlite

from app.db.database import get_db_connection
from app.core.statistical_detector import (
    get_current_statistical_health,
    get_latest_statistical_analysis,
    get_metric_anomaly_history,
    get_server_baselines,
    reload_config,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/statistical", tags=["Statistical Anomaly Detection"])


async def get_db():
    db = await get_db_connection()
    try:
        yield db
    finally:
        await db.close()


@router.get("/analysis")
async def list_statistical_analysis(
    tenant_id: Optional[str] = Query(None, description="Filter by tenant ID"),
    server_id: Optional[str] = Query(None, description="Filter by server ID"),
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Return the most recent per-metric statistical analysis records.

    Each record contains: modified Z-score, rolling median, MAD,
    anomaly classification, severity, detection reason, and persistence count.
    """
    records = await get_latest_statistical_analysis(
        db, tenant_id=tenant_id, server_id=server_id, limit=limit
    )
    return {
        "statistical_analysis": records,
        "count": len(records),
    }


@router.get("/anomaly-history")
async def metric_anomaly_history(
    server_id: str = Query(..., description="Server ID to inspect"),
    metric_name: str = Query(..., description="Metric name: cpu_usage | memory_usage | disk_usage | latency_ms"),
    tenant_id: Optional[str] = Query(None, description="Filter by tenant ID"),
    limit: int = Query(100, ge=1, le=500),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Return historical anomaly detections for a specific server and metric.

    Useful for trending, pattern review, and postmortem analysis.
    """
    history = await get_metric_anomaly_history(
        db, server_id=server_id, metric_name=metric_name,
        tenant_id=tenant_id, limit=limit
    )
    return {
        "server_id": server_id,
        "metric_name": metric_name,
        "anomaly_history": history,
        "count": len(history),
    }


@router.get("/baselines")
async def server_baselines(
    tenant_id: Optional[str] = Query(None, description="Filter by tenant ID"),
    server_id: Optional[str] = Query(None, description="Filter by server ID"),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Return the current rolling baseline (median / MAD) per server and metric.

    Baselines are derived from the most recent verified, non-anomalous
    historical observations stored in SQLite.

    To reset/rebuild a baseline for a server: delete rows from
    ``statistical_analysis_records`` for that server and metric. The engine
    will rebuild automatically as new verified telemetry arrives.
    """
    baselines = await get_server_baselines(db, tenant_id=tenant_id, server_id=server_id)
    return {
        "baselines": baselines,
        "count": len(baselines),
        "baseline_rebuild_instructions": (
            "To rebuild a baseline: DELETE FROM statistical_analysis_records "
            "WHERE server_id = '<id>' AND metric_name = '<metric>'; "
            "The engine will rebuild automatically from the next verified events."
        ),
    }


@router.get("/health")
async def statistical_health(
    tenant_id: Optional[str] = Query(None, description="Filter by tenant ID"),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Return current overall statistical health across all monitored servers.

    Health status values:
    - HEALTHY: No anomalies in the last 15 minutes.
    - CAUTION: At least one metric slightly elevated.
    - WARNING: MEDIUM-severity anomaly detected.
    - DEGRADED: HIGH-severity anomaly detected.
    - CRITICAL: CRITICAL-severity anomaly detected.
    """
    health = await get_current_statistical_health(db, tenant_id=tenant_id)
    return health


@router.post("/config/reload")
async def reload_detection_config():
    """Reload the AIOps threshold configuration from config/aiops_thresholds.yaml.

    Use after editing thresholds without restarting the application.
    """
    reload_config()
    return {
        "status": "OK",
        "message": "Statistical detection configuration reloaded from aiops_thresholds.yaml",
    }
