"""FastAPI routes for DATACAT Unified AIOps Decision Pipeline.

Endpoints:
  - GET /api/v1/aiops/decisions: Unified decisions combining statistical and ML signals.
  - GET /api/v1/aiops/decisions/{event_id}: Detailed decision analysis for a single event.
  - GET /api/v1/aiops/health/{server_id}: Server 4-state health status and recent transitions.
  - GET /api/v1/aiops/pipeline-status: Unified pipeline configuration and detector statuses.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
import aiosqlite

from app.core.detection_config import DetectionConfig
from app.db.database import get_db_connection
from app.ml.inference import get_model

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/aiops", tags=["Unified AIOps Pipeline"])


async def get_db():
    db = await get_db_connection()
    try:
        yield db
    finally:
        await db.close()


@router.get("/decisions")
async def list_aiops_decisions(
    tenant_id: Optional[str] = Query(None, description="Filter by tenant ID"),
    server_id: Optional[str] = Query(None, description="Filter by server ID"),
    decision: Optional[str] = Query(None, description="Filter by decision: ANOMALY, CANDIDATE_ANOMALY, INVESTIGATE, NORMAL"),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, NORMAL"),
    limit: int = Query(50, ge=1, le=500),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Retrieves unified AIOps decisions produced by statistical + ML fusion."""
    clauses = []
    params: list[Any] = []
    if tenant_id:
        clauses.append("tenant_id = ?")
        params.append(tenant_id)
    if server_id:
        clauses.append("server_id = ?")
        params.append(server_id)
    if decision:
        clauses.append("final_anomaly_decision = ?")
        params.append(decision.upper())
    if severity:
        clauses.append("severity = ?")
        params.append(severity.upper())

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)

    query = f"""
    SELECT decision_id, event_id, tenant_id, server_id, timestamp_utc,
           statistical_status, statistical_scores, abnormal_metrics,
           logistic_regression_probability, logistic_regression_prediction,
           model_version, persistence_status, final_anomaly_decision,
           severity, contributing_signals, explanation, created_at_utc
    FROM aiops_decisions
    {where}
    ORDER BY timestamp_utc DESC
    LIMIT ?;
    """
    async with db.execute(query, tuple(params)) as cur:
        rows = await cur.fetchall()
        results = []
        for r in rows:
            d = dict(r)
            try:
                d["statistical_scores"] = json.loads(d["statistical_scores"])
            except Exception:
                pass
            try:
                d["abnormal_metrics"] = json.loads(d["abnormal_metrics"])
            except Exception:
                pass
            try:
                d["persistence_status"] = json.loads(d["persistence_status"])
            except Exception:
                pass
            try:
                d["contributing_signals"] = json.loads(d["contributing_signals"])
            except Exception:
                pass
            results.append(d)

    return {"decisions": results, "count": len(results)}


@router.get("/decisions/{event_id}")
async def get_decision_detail(
    event_id: str,
    tenant_id: Optional[str] = Query(None, description="Tenant scope"),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Retrieves the unified decision record for a specific verified event."""
    clauses = ["event_id = ?"]
    params: list[Any] = [event_id]
    if tenant_id:
        clauses.append("tenant_id = ?")
        params.append(tenant_id)

    query = f"""
    SELECT decision_id, event_id, tenant_id, server_id, timestamp_utc,
           statistical_status, statistical_scores, abnormal_metrics,
           logistic_regression_probability, logistic_regression_prediction,
           model_version, persistence_status, final_anomaly_decision,
           severity, contributing_signals, explanation, created_at_utc
    FROM aiops_decisions
    WHERE {" AND ".join(clauses)}
    LIMIT 1;
    """
    async with db.execute(query, tuple(params)) as cur:
        row = await cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"AIOps decision for event '{event_id}' not found.")
        d = dict(row)
        try:
            d["statistical_scores"] = json.loads(d["statistical_scores"])
            d["abnormal_metrics"] = json.loads(d["abnormal_metrics"])
            d["persistence_status"] = json.loads(d["persistence_status"])
            d["contributing_signals"] = json.loads(d["contributing_signals"])
        except Exception:
            pass
        return d


@router.get("/health/{server_id}")
async def server_health_detail(
    server_id: str,
    tenant_id: Optional[str] = Query(None, description="Tenant scope"),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Returns current 4-state health status and recent health transitions for a server."""
    # 1. Fetch latest decision for this server
    query_dec = """
    SELECT final_anomaly_decision, severity, timestamp_utc, explanation
    FROM aiops_decisions
    WHERE server_id = ?
    ORDER BY timestamp_utc DESC LIMIT 1;
    """
    async with db.execute(query_dec, (server_id,)) as cur:
        dec_row = await cur.fetchone()

    # 2. Fetch transitions
    query_trans = """
    SELECT transition_id, previous_state, current_state, reason, transition_timestamp
    FROM health_state_transitions
    WHERE server_id = ?
    ORDER BY transition_timestamp DESC LIMIT 10;
    """
    async with db.execute(query_trans, (server_id,)) as cur:
        trans_rows = await cur.fetchall()
        transitions = [dict(r) for r in trans_rows]

    current_state = transitions[0]["current_state"] if transitions else "EXCELLENT"

    return {
        "server_id": server_id,
        "current_health_state": current_state,
        "latest_decision": dict(dec_row) if dec_row else None,
        "recent_transitions": transitions,
    }


@router.get("/pipeline-status")
async def pipeline_status():
    """Returns configuration and operational status of the unified AIOps pipeline."""
    cfg = DetectionConfig.load()
    try:
        model = get_model()
        ml_status = {
            "available": True,
            "model_version": model.model_version,
            "threshold": model.threshold,
            "feature_count": len(model.feature_names),
        }
    except Exception as e:
        ml_status = {
            "available": False,
            "error": str(e),
        }

    return {
        "pipeline_name": "DATACAT Unified AIOps Decision Pipeline",
        "version": "2.0.0",
        "statistical_detector": {
            "status": "ACTIVE",
            "modified_z_threshold": cfg.modified_zscore_threshold,
            "rolling_window_size": cfg.rolling_window_size,
            "min_samples_for_baseline": cfg.min_samples_for_baseline,
        },
        "machine_learning_classifier": ml_status,
        "decision_fusion": {
            "high_prob_threshold": cfg.high_prob_threshold,
            "low_prob_threshold": cfg.low_prob_threshold,
            "escalate_on_persistence": cfg.escalate_on_persistence,
            "persistence_escalate_count": cfg.persistence_escalate_count,
        },
        "health_classification": {
            "states": ["EXCELLENT", "GOOD", "FAIR", "POOR"],
            "stale_threshold_seconds": cfg.stale_threshold_seconds,
        },
    }
