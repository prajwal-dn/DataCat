"""
GET /api/v1/aiops/overview — Explainable AIOps Intelligence overview.
Analyzes accepted telemetry on-the-fly using deterministic statistical baseline & threshold detection.
Enforces tenant authentication and isolation.
"""
import json
from datetime import datetime, timezone
from typing import Dict, List

import aiosqlite
from fastapi import APIRouter, Depends

from backend.aiops.correlator import correlate_anomalies
from backend.aiops.detector import AnomalySignal, evaluate_metric
from backend.aiops.metrics import extract_metrics
from backend.aiops.schemas import (
    AIOpsOverviewResponse,
    AnomalyItem,
    IncidentItem,
    LatestHostMetric,
)
from backend.auth import require_tenant_auth
from backend.config import DB_PATH

router = APIRouter()

MAX_EVENTS_ANALYZED = 500


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@router.get("/overview", response_model=AIOpsOverviewResponse)
async def get_aiops_overview(
    tenant_id: str = Depends(require_tenant_auth),
):
    """
    Compute explainable AIOps intelligence for the authenticated tenant.
    Reads up to 500 accepted events chronologically, computes rolling baselines,
    evaluates thresholds, correlates incidents, and formulates recommendations.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT event_id, tenant_id, timestamp, source_host, event_type, payload, ingested_at
            FROM events
            WHERE tenant_id = ?
            ORDER BY ingested_at ASC
            LIMIT ?
            """,
            (tenant_id, MAX_EVENTS_ANALYZED),
        ) as cursor:
            rows = await cursor.fetchall()

    if not rows:
        return AIOpsOverviewResponse(
            tenant_id=tenant_id,
            health_status="no_data",
            hosts_monitored=0,
            events_analyzed=0,
            anomaly_count=0,
            correlated_incident_count=0,
            generated_at=_now_utc(),
            latest_metrics=[],
            anomalies=[],
            incidents=[],
        )

    # Rolling history: host -> metric_name -> list of float values
    metric_history: Dict[str, Dict[str, List[float]]] = {}
    # Track latest metrics per host
    latest_per_host: Dict[str, Dict[str, float]] = {}
    latest_ts_per_host: Dict[str, str] = {}

    detected_signals: List[AnomalySignal] = []

    for r in rows:
        host = r["source_host"]
        event_id = r["event_id"]
        ingested_at = r["ingested_at"]

        try:
            payload = json.loads(r["payload"]) if isinstance(r["payload"], str) else r["payload"]
        except Exception:
            continue

        metrics = extract_metrics(payload)
        if not metrics:
            continue

        if host not in metric_history:
            metric_history[host] = {}
            latest_per_host[host] = {}

        latest_ts_per_host[host] = ingested_at

        for m_name, val in metrics.items():
            latest_per_host[host][m_name] = val
            history = metric_history[host].setdefault(m_name, [])

            # Evaluate anomaly before updating historical baseline
            signal = evaluate_metric(
                event_id=event_id,
                source_host=host,
                metric_name=m_name,
                value=val,
                history=history,
                ingested_at=ingested_at,
            )
            if signal is not None:
                detected_signals.append(signal)

            # Record sample in history
            history.append(val)

    # Correlate detected signals into grouped incidents
    raw_incidents = correlate_anomalies(detected_signals)

    # Convert to schema items
    anomaly_items = [
        AnomalyItem(
            event_id=s.event_id,
            source_host=s.source_host,
            metric_name=s.metric_name,
            observed_value=s.observed_value,
            baseline_or_threshold=s.baseline_or_threshold,
            severity=s.severity,
            detection_method=s.detection_method,
            explanation=s.explanation,
            ingested_at=s.ingested_at,
        )
        for s in detected_signals
    ]

    incident_items = [
        IncidentItem(
            incident_id=inc["incident_id"],
            source_host=inc["source_host"],
            severity=inc["severity"],
            title=inc["title"],
            first_seen=inc["first_seen"],
            last_seen=inc["last_seen"],
            signal_count=inc["signal_count"],
            contributing_signals=inc["contributing_signals"],
            unique_event_ids=inc["unique_event_ids"],
            evidence=inc["evidence"],
            explanation=inc["explanation"],
            suggested_recommendation=inc["suggested_recommendation"],
        )
        for inc in raw_incidents
    ]

    # Build latest host metrics list
    latest_metrics_list = []
    for host, m_dict in latest_per_host.items():
        latest_metrics_list.append(
            LatestHostMetric(
                source_host=host,
                cpu_usage=m_dict.get("cpu_usage"),
                memory_usage=m_dict.get("memory_usage"),
                disk_usage=m_dict.get("disk_usage"),
                network_latency_ms=m_dict.get("network_latency_ms"),
                packet_loss_pct=m_dict.get("packet_loss_pct"),
                failed_login_count=m_dict.get("failed_login_count"),
                latest_timestamp=latest_ts_per_host.get(host, _now_utc()),
            )
        )

    # Determine overall health status
    if any(inc["severity"] == "CRITICAL" for inc in raw_incidents):
        overall_health = "critical"
    elif any(inc["severity"] in {"HIGH", "MEDIUM"} for inc in raw_incidents) or anomaly_items:
        overall_health = "degraded"
    else:
        overall_health = "healthy"

    return AIOpsOverviewResponse(
        tenant_id=tenant_id,
        health_status=overall_health,
        hosts_monitored=len(metric_history),
        events_analyzed=len(rows),
        anomaly_count=len(anomaly_items),
        correlated_incident_count=len(incident_items),
        generated_at=_now_utc(),
        latest_metrics=latest_metrics_list,
        anomalies=anomaly_items,
        incidents=incident_items,
    )
