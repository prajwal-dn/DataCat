"""FastAPI routes for DATACAT SaaS Observability Dashboard."""
import logging
from typing import Any, Optional
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
import aiosqlite

from app.db.database import get_db_connection
from app.db.queries import (
    get_all_tenants,
    get_collectors_monitoring_list,
    get_dashboard_overview_data,
    get_incidents_list,
    get_latest_server_telemetry_list,
    get_recent_telemetry_events,
    get_recent_verification_records,
    get_server_metric_history,
)
from app.services.health_service import correlate_incidents, evaluate_server_health

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])


async def get_db():
    db = await get_db_connection()
    try:
        yield db
    finally:
        await db.close()


@router.get("/tenants")
async def list_tenants(db: aiosqlite.Connection = Depends(get_db)):
    """Lists registered/monitored tenant IDs for UI filtering."""
    tenants = await get_all_tenants(db)
    return {"tenants": tenants}


@router.get("/overview")
async def dashboard_overview(
    tenant_id: Optional[str] = Query(None, description="Optional tenant scope filter"),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Aggregates high-level telemetry metrics, collector counts, incidents, and overall health."""
    data = await get_dashboard_overview_data(db, tenant_id=tenant_id)

    # Compute overall health and incidents
    latest_servers = await get_latest_server_telemetry_list(db, tenant_id=tenant_id)
    servers_health = []
    for s in latest_servers:
        h = evaluate_server_health(s["metrics"], s["timestamp_utc"])
        servers_health.append({**s, **h})

    failures = await get_recent_verification_records(db, tenant_id=tenant_id, limit=20)
    failed_only = [f for f in failures if f["status"] == "FAILED"]

    runtime_incidents = correlate_incidents(servers_health, failed_only)
    stored_incidents = await get_incidents_list(db, tenant_id=tenant_id, status="OPEN", limit=50)

    # Combine unique incident IDs
    all_incident_ids = set()
    for inc in stored_incidents:
        all_incident_ids.add(inc["incident_id"])
    for inc in runtime_incidents:
        all_incident_ids.add(inc["incident_id"])

    # Compute overall infrastructure health
    health_rank = {"POOR": 4, "FAIR": 3, "GOOD": 2, "EXCELLENT": 1}
    overall_health = "EXCELLENT"
    overall_reason = "All monitored servers reporting nominal baseline telemetry."

    if not servers_health:
        overall_health = "POOR" if data["total_collectors"] == 0 else "GOOD"
        overall_reason = "No telemetry received yet. Waiting for Tier 1 transmission."
    else:
        highest_rank = 1
        for sh in servers_health:
            rank = health_rank.get(sh["health_status"], 1)
            if rank > highest_rank:
                highest_rank = rank
                overall_health = sh["health_status"]
                overall_reason = f"Degradation on {sh['server_id']}: {sh['health_reason']}"

    data["active_incidents"] = len(all_incident_ids)
    data["overall_health"] = overall_health
    data["overall_health_reason"] = overall_reason
    data["monitored_servers_count"] = len(servers_health)
    return data


@router.get("/infrastructure")
async def infrastructure_monitoring(
    tenant_id: Optional[str] = Query(None, description="Optional tenant scope filter"),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Returns real-time status of each monitored hospital server with 4-state health classification."""
    servers = await get_latest_server_telemetry_list(db, tenant_id=tenant_id)
    results = []
    for s in servers:
        h = evaluate_server_health(s["metrics"], s["timestamp_utc"])
        results.append({
            "server_id": s["server_id"],
            "tenant_id": s["tenant_id"],
            "collector_id": s["collector_id"],
            "timestamp_utc": s["timestamp_utc"],
            "metrics": s["metrics"],
            "policy_version": s["policy_version"],
            "payload_hash": s["payload_hash"],
            "health_status": h["health_status"],
            "health_reason": h["health_reason"],
            "is_stale": h["is_stale"],
            "seconds_ago": h["seconds_ago"],
        })
    return {"servers": results}


@router.get("/collectors")
async def collector_monitoring(
    tenant_id: Optional[str] = Query(None, description="Optional tenant scope filter"),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Returns registered Tier 1 collectors, online/offline status, and verification metrics."""
    collectors = await get_collectors_monitoring_list(db, tenant_id=tenant_id)
    sanitized = []
    for c in collectors:
        sanitized.append({
            "collector_id": c["collector_id"],
            "tenant_id": c["tenant_id"],
            "status": c["status"],
            "last_seen_seq": c["last_seen_seq"],
            "last_heartbeat_utc": c["last_heartbeat_utc"],
            "is_online": c["is_online"],
            "accepted_events": c["accepted_events"],
            "failed_verifications": c["failed_verifications"],
        })
    return {"collectors": sanitized}


@router.get("/verifications")
async def verification_history(
    tenant_id: Optional[str] = Query(None, description="Optional tenant scope filter"),
    limit: int = Query(50, ge=1, le=200),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Returns recent cryptographic verification records."""
    records = await get_recent_verification_records(db, tenant_id=tenant_id, limit=limit)
    return {"verifications": records}


@router.get("/events")
async def event_history(
    tenant_id: Optional[str] = Query(None, description="Optional tenant scope filter"),
    server_id: Optional[str] = Query(None, description="Optional server filter"),
    limit: int = Query(50, ge=1, le=200),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Returns recent verified telemetry events."""
    events = await get_recent_telemetry_events(
        db, tenant_id=tenant_id, server_id=server_id, limit=limit
    )
    enriched = []
    for e in events:
        h = evaluate_server_health(e["metrics"], e["timestamp_utc"])
        enriched.append({**e, **h})
    return {"events": enriched}


@router.get("/incidents")
async def incident_history(
    tenant_id: Optional[str] = Query(None, description="Optional tenant scope filter"),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Returns stored correlated incidents as well as runtime health/staleness incidents."""
    # Stored database incidents from AIOps engine
    stored_incidents = await get_incidents_list(db, tenant_id=tenant_id, status="OPEN", limit=50)

    # Runtime health & staleness check
    latest_servers = await get_latest_server_telemetry_list(db, tenant_id=tenant_id)
    servers_health = []
    for s in latest_servers:
        h = evaluate_server_health(s["metrics"], s["timestamp_utc"])
        servers_health.append({**s, **h})

    failures = await get_recent_verification_records(db, tenant_id=tenant_id, limit=20)
    failed_only = [f for f in failures if f["status"] == "FAILED"]
    runtime_incidents = correlate_incidents(servers_health, failed_only)

    # Merge by incident_id
    seen_ids = set()
    merged = []
    for inc in stored_incidents:
        seen_ids.add(inc["incident_id"])
        # Format recommendations if dict
        rec = inc.get("recommendations", {})
        rec_list = rec.get("investigation_steps", []) if isinstance(rec, dict) else []
        merged.append({
            "incident_id": inc["incident_id"],
            "server_id": inc["server_id"],
            "tenant_id": inc["tenant_id"],
            "title": inc["title"],
            "severity": inc["severity"],
            "health_state": inc.get("health_state") or ("POOR" if inc.get("severity") in ("CRITICAL", "HIGH") else "FAIR"),
            "correlated_anomalies_count": inc.get("correlated_anomalies_count", 1),
            "detection_timestamp": inc["detection_timestamp"],
            "contributing_metrics": inc["contributing_metrics"],
            "explanation": inc["explanation"],
            "recommendations": rec_list,
        })

    for inc in runtime_incidents:
        if inc["incident_id"] not in seen_ids:
            seen_ids.add(inc["incident_id"])
            if "health_state" not in inc:
                inc["health_state"] = "POOR" if inc.get("severity") in ("CRITICAL", "HIGH") else "FAIR"
            if "correlated_anomalies_count" not in inc:
                inc["correlated_anomalies_count"] = 1
            merged.append(inc)

    return {"incidents": merged}


@router.get("/servers/{server_id}/history")
async def server_metric_history(
    server_id: str,
    tenant_id: Optional[str] = Query(None, description="Optional tenant scope filter"),
    limit: int = Query(30, ge=5, le=100),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Returns historical metric points for generating lightweight sparklines/graphs."""
    history = await get_server_metric_history(
        db, server_id=server_id, tenant_id=tenant_id, limit=limit
    )
    return {"server_id": server_id, "history": history}
