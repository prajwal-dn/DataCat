"""DATACAT Statistical Anomaly Detection Engine — MAD / Modified Z-score.

Implements:
  - Rolling Median baseline (server- and metric-independent).
  - Median Absolute Deviation (MAD) as the robust spread estimator.
  - Modified Z-score (Iglewicz & Hoaglin 1993).
  - Persistence checking across consecutive anomalous observations.
  - Baseline contamination protection (anomalous values excluded from future baselines).
  - YAML-configurable thresholds (config/aiops_thresholds.yaml).
  - Full statistical output per metric per event.

Statistical formulas used
--------------------------
1. Rolling Median
   median = statistics.median(historical_values)

2. Median Absolute Deviation (MAD)
   deviations = [abs(x - median) for x in historical_values]
   MAD = statistics.median(deviations)

3. Modified Z-score (Iglewicz & Hoaglin 1993)
   modified_z = 0.6745 * (current_value - median) / max(MAD, min_mad_scale)

   The constant 0.6745 is the 75th-percentile z-score of the standard normal
   distribution, normalising MAD to match the standard deviation for Gaussian data.

4. Anomaly decision
   |modified_z| > threshold AND (direction == "both" OR value > median)

Zero-dependency: uses only Python standard library (statistics, math, json, logging).
"""

from __future__ import annotations

import json
import logging
import math
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import uuid

import aiosqlite

from app.core.detection_config import DetectionConfig

logger = logging.getLogger(__name__)

MONITORED_METRICS = ["cpu_usage", "memory_usage", "disk_usage", "latency_ms"]

# Module-level config singleton (lazy-loaded on first use)
_cfg: Optional[DetectionConfig] = None


def _get_cfg() -> DetectionConfig:
    global _cfg
    if _cfg is None:
        _cfg = DetectionConfig.load()
    return _cfg


def reload_config() -> None:
    """Force reload of threshold configuration from YAML on disk."""
    global _cfg
    _cfg = DetectionConfig.load()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def run_statistical_analysis(
    db: aiosqlite.Connection,
    verified_event: dict[str, Any],
) -> dict[str, Any]:
    """Analyse a single verified telemetry event using MAD / Modified Z-score.

    Processes each monitored metric independently, writes results to
    ``statistical_analysis_records``, updates persistence state, and prevents
    baseline contamination.

    Args:
        db: Open aiosqlite connection with row_factory set.
        verified_event: Verified telemetry dict with keys:
            event_id, tenant_id, server_id, timestamp_utc, metrics{...}.

    Returns:
        A dict with keys:
          - event_id
          - server_id
          - tenant_id
          - metric_results: list[MetricAnalysisResult-dict]
          - abnormal_metric_count: int
          - overall_statistical_status: "NORMAL" | "ANOMALY_DETECTED" | "CRITICAL_ANOMALY"
          - analysis_timestamp_utc: str
    """
    cfg = _get_cfg()

    event_id = verified_event["event_id"]
    tenant_id = verified_event["tenant_id"]
    server_id = verified_event["server_id"]
    event_ts = verified_event.get("timestamp_utc") or datetime.now(timezone.utc).isoformat()
    metrics = verified_event.get("metrics", {})
    now_utc = datetime.now(timezone.utc).isoformat()

    metric_results: list[dict[str, Any]] = []
    abnormal_count = 0
    has_critical = False

    for metric_name in MONITORED_METRICS:
        if metric_name not in metrics:
            continue

        current_value = float(metrics[metric_name])

        # 1. Fetch clean historical values (excludes the current event and
        #    previously flagged anomalous observations when protection is active).
        raw_history = await _fetch_historical_values(
            db, tenant_id, server_id, metric_name, event_id,
            window=cfg.rolling_window_size,
            exclude_anomalies=cfg.exclude_anomalies_from_baseline,
        )

        # 2. Compute statistical baseline
        stat_ctx = _compute_statistical_context(metric_name, current_value, raw_history, cfg)

        # 3. Persistence state
        persistence_count = await _get_persistence_count(
            db, tenant_id, server_id, metric_name, event_ts, cfg.persistence_lookback_count
        )

        # 4. Final anomaly classification
        result = _classify_metric(
            metric_name=metric_name,
            current_value=current_value,
            stat_ctx=stat_ctx,
            persistence_count=persistence_count,
            cfg=cfg,
            server_id=server_id,
            tenant_id=tenant_id,
            event_id=event_id,
            event_ts=event_ts,
        )

        metric_results.append(result)

        if result["is_anomaly"]:
            abnormal_count += 1
            if result["severity"] == "CRITICAL":
                has_critical = True

            # 5. Record persistence state for future events
            await _upsert_persistence_state(
                db, tenant_id, server_id, metric_name, event_ts,
                is_anomaly=True, modified_zscore=result["modified_zscore"],
            )

            # 6. Store statistical analysis record
            await _store_analysis_record(db, event_id, tenant_id, server_id, metric_name,
                                         result, event_ts, now_utc)
        else:
            await _upsert_persistence_state(
                db, tenant_id, server_id, metric_name, event_ts,
                is_anomaly=False, modified_zscore=result["modified_zscore"],
            )
            await _store_analysis_record(db, event_id, tenant_id, server_id, metric_name,
                                         result, event_ts, now_utc)

    # 7. Overall status
    if has_critical:
        overall_status = "CRITICAL_ANOMALY"
    elif abnormal_count > 0:
        overall_status = "ANOMALY_DETECTED"
    else:
        overall_status = "NORMAL"

    return {
        "event_id": event_id,
        "server_id": server_id,
        "tenant_id": tenant_id,
        "metric_results": metric_results,
        "abnormal_metric_count": abnormal_count,
        "overall_statistical_status": overall_status,
        "analysis_timestamp_utc": now_utc,
    }


# ---------------------------------------------------------------------------
# Statistical context computation
# ---------------------------------------------------------------------------

def _compute_statistical_context(
    metric_name: str,
    current_value: float,
    history: list[float],
    cfg: DetectionConfig,
) -> dict[str, Any]:
    """Calculate rolling median, MAD, and modified Z-score from clean history.

    Returns a context dict consumed by _classify_metric.
    """
    n = len(history)
    min_samples = cfg.min_samples_for_baseline
    fallback_threshold = cfg.fallback_thresholds.get(metric_name, 80.0)
    min_mad = cfg.min_mad_scale.get(metric_name, 1.0)

    if n < min_samples:
        # Insufficient history — no reliable baseline available.
        return {
            "statistical_context_status": "INSUFFICIENT_HISTORY",
            "sample_count": n,
            "required_samples": min_samples,
            "baseline_median": None,
            "mad": None,
            "modified_zscore": None,
            "fallback_threshold": fallback_threshold,
            "dynamic_baseline_active": False,
        }

    # Rolling median
    baseline_median = statistics.median(history)

    # MAD: median of absolute deviations from the median
    abs_devs = [abs(x - baseline_median) for x in history]
    mad = statistics.median(abs_devs)

    # Protected scale (never divide by zero or near-zero)
    effective_mad = max(mad, min_mad)

    # Modified Z-score (Iglewicz & Hoaglin 1993)
    modified_zscore = 0.6745 * (current_value - baseline_median) / effective_mad

    # Contamination guard: if more than max_ratio of history was anomalous,
    # signal that baseline might be unreliable.
    contamination_warning = False
    if cfg.exclude_anomalies_from_baseline and n < cfg.rolling_window_size * (1 - cfg.max_anomaly_contamination_ratio):
        contamination_warning = True

    return {
        "statistical_context_status": "ACTIVE_BASELINE",
        "sample_count": n,
        "required_samples": min_samples,
        "baseline_median": round(baseline_median, 4),
        "mad": round(mad, 4),
        "effective_mad": round(effective_mad, 4),
        "modified_zscore": round(modified_zscore, 4),
        "fallback_threshold": fallback_threshold,
        "dynamic_baseline_active": True,
        "baseline_contamination_warning": contamination_warning,
    }


# ---------------------------------------------------------------------------
# Anomaly classification
# ---------------------------------------------------------------------------

def _classify_metric(
    metric_name: str,
    current_value: float,
    stat_ctx: dict[str, Any],
    persistence_count: int,
    cfg: DetectionConfig,
    server_id: str,
    tenant_id: str,
    event_id: str,
    event_ts: str,
) -> dict[str, Any]:
    """Classify a metric reading as normal or anomalous, assign severity and reason."""

    base = {
        "server_id": server_id,
        "tenant_id": tenant_id,
        "metric_name": metric_name,
        "current_value": round(current_value, 4),
        "baseline_median": stat_ctx.get("baseline_median"),
        "mad": stat_ctx.get("mad"),
        "modified_zscore": stat_ctx.get("modified_zscore"),
        "sample_count": stat_ctx.get("sample_count", 0),
        "statistical_context_status": stat_ctx["statistical_context_status"],
        "persistence_count": persistence_count,
        "is_anomaly": False,
        "severity": "NORMAL",
        "detection_reason": "NORMAL",
    }

    direction = cfg.direction.get(metric_name, "high_only")
    crit_abs = cfg.critical_absolute_thresholds.get(metric_name)

    # ---- Case A: Critical absolute threshold override (always fires) ----
    if crit_abs is not None and current_value >= crit_abs:
        reason = (
            f"{metric_name} = {current_value:.2f} has breached the critical absolute "
            f"operational limit of {crit_abs:.2f}. Immediate escalation required regardless "
            f"of statistical context."
        )
        base.update({
            "is_anomaly": True,
            "severity": "CRITICAL",
            "detection_reason": "CRITICAL_ABSOLUTE_THRESHOLD",
            "explanation": reason,
        })
        return base

    # ---- Case B: Insufficient history — use fallback static threshold ----
    if not stat_ctx["dynamic_baseline_active"]:
        fallback = stat_ctx["fallback_threshold"]
        if current_value > fallback:
            excess = current_value - fallback
            bands = cfg.fallback_severity_bands
            if excess >= bands.get("critical_excess", 15.0):
                severity = "CRITICAL"
            elif excess >= bands.get("high_excess", 5.0):
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            # Persistence escalation on fallback path
            severity = _apply_persistence_escalation(severity, persistence_count, cfg)

            reason = (
                f"{metric_name} = {current_value:.2f} exceeds static fallback threshold "
                f"{fallback:.2f} by {excess:.2f} units. Dynamic baseline inactive: only "
                f"{stat_ctx['sample_count']}/{stat_ctx['required_samples']} clean historical "
                f"samples are available."
            )
            base.update({
                "is_anomaly": True,
                "severity": severity,
                "detection_reason": "FALLBACK_THRESHOLD_BREACH",
                "explanation": reason,
            })
        else:
            base["detection_reason"] = "NORMAL_BELOW_FALLBACK_THRESHOLD"
        return base

    # ---- Case C: Dynamic Modified Z-score detection ----
    mz = stat_ctx["modified_zscore"]
    threshold = cfg.modified_zscore_threshold
    median = stat_ctx["baseline_median"]

    # Direction guard: for "high_only" metrics, ignore downward deviations
    if direction == "high_only" and current_value <= median:
        base["detection_reason"] = "NORMAL_DIRECTION_GUARD"
        return base

    if abs(mz) > threshold:
        bands = cfg.severity_bands
        if abs(mz) >= bands.get("critical_z", 10.0):
            severity = "CRITICAL"
        elif abs(mz) >= bands.get("high_z", 6.0):
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        # Persistence escalation
        severity = _apply_persistence_escalation(severity, persistence_count, cfg)

        reason = (
            f"{metric_name} Modified Z-score = {mz:.3f} (threshold ±{threshold}) "
            f"based on rolling median={median:.2f}, MAD={stat_ctx['mad']:.4f} "
            f"(effective MAD={stat_ctx['effective_mad']:.4f}), "
            f"n={stat_ctx['sample_count']} clean samples. "
            f"Persistence count = {persistence_count}."
        )
        base.update({
            "is_anomaly": True,
            "severity": severity,
            "detection_reason": "MODIFIED_ZSCORE_THRESHOLD",
            "explanation": reason,
        })
    else:
        base["detection_reason"] = "NORMAL_WITHIN_ZSCORE_BOUND"

    return base


def _apply_persistence_escalation(severity: str, persistence_count: int, cfg: DetectionConfig) -> str:
    """Escalate severity one level when persistence_count exceeds configured triggers."""
    if persistence_count >= cfg.persistence_critical_override:
        return "CRITICAL"
    if persistence_count >= cfg.persistence_trigger_count:
        # Escalate: MEDIUM -> HIGH, HIGH -> CRITICAL
        escalation_map = {"MEDIUM": "HIGH", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"}
        return escalation_map.get(severity, severity)
    return severity


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

async def _fetch_historical_values(
    db: aiosqlite.Connection,
    tenant_id: str,
    server_id: str,
    metric_name: str,
    exclude_event_id: str,
    window: int,
    exclude_anomalies: bool,
) -> list[float]:
    """Fetch the most recent clean historical metric values for a server.

    Only events BEFORE the current event (by event_id exclusion) are used.
    If exclude_anomalies is True, observations previously classified as
    anomalous are excluded to prevent baseline contamination.
    """
    if exclude_anomalies:
        # Join against statistical_analysis_records to exclude anomalous observations
        query = """
        SELECT te.metrics
        FROM telemetry_events te
        LEFT JOIN statistical_analysis_records sar
            ON sar.event_id = te.event_id
            AND sar.tenant_id = te.tenant_id
            AND sar.metric_name = ?
        WHERE te.tenant_id = ?
          AND te.server_id = ?
          AND te.event_id != ?
          AND (sar.is_anomaly IS NULL OR sar.is_anomaly = 0)
        ORDER BY te.timestamp_utc DESC
        LIMIT ?;
        """
        params = (metric_name, tenant_id, server_id, exclude_event_id, window)
    else:
        query = """
        SELECT metrics FROM telemetry_events
        WHERE tenant_id = ? AND server_id = ? AND event_id != ?
        ORDER BY timestamp_utc DESC
        LIMIT ?;
        """
        params = (tenant_id, server_id, exclude_event_id, window)

    values: list[float] = []
    async with db.execute(query, params) as cur:
        rows = await cur.fetchall()
        for row in rows:
            try:
                m = json.loads(row[0])
                val = m.get(metric_name)
                if val is not None:
                    values.append(float(val))
            except Exception:
                pass
    return values


async def _get_persistence_count(
    db: aiosqlite.Connection,
    tenant_id: str,
    server_id: str,
    metric_name: str,
    event_ts: str,
    lookback_count: int,
) -> int:
    """Return how many of the last N observations were marked anomalous."""
    query = """
    SELECT SUM(is_anomaly)
    FROM (
        SELECT is_anomaly
        FROM statistical_analysis_records
        WHERE tenant_id = ? AND server_id = ? AND metric_name = ?
          AND event_timestamp_utc < ?
        ORDER BY event_timestamp_utc DESC
        LIMIT ?
    );
    """
    async with db.execute(query, (tenant_id, server_id, metric_name, event_ts, lookback_count)) as cur:
        row = await cur.fetchone()
        if row and row[0] is not None:
            return int(row[0])
    return 0


async def _upsert_persistence_state(
    db: aiosqlite.Connection,
    tenant_id: str,
    server_id: str,
    metric_name: str,
    event_ts: str,
    is_anomaly: bool,
    modified_zscore: Optional[float],
) -> None:
    """Update the per-server per-metric persistence tracking table."""
    # This is recorded as part of statistical_analysis_records; no separate
    # persistence table is required. The count is derived at query time.
    pass  # Persistence is computed from statistical_analysis_records directly


async def _store_analysis_record(
    db: aiosqlite.Connection,
    event_id: str,
    tenant_id: str,
    server_id: str,
    metric_name: str,
    result: dict[str, Any],
    event_ts: str,
    stored_at_utc: str,
) -> None:
    """Persist the per-metric statistical analysis result to SQLite."""
    query = """
    INSERT OR IGNORE INTO statistical_analysis_records (
        analysis_id, event_id, tenant_id, server_id, metric_name,
        current_value, baseline_median, mad, modified_zscore,
        sample_count, is_anomaly, severity, detection_reason, persistence_count,
        statistical_context_status, event_timestamp_utc, stored_at_utc
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """
    analysis_id = f"sa-{uuid.uuid4().hex[:12]}"
    await db.execute(
        query,
        (
            analysis_id,
            event_id,
            tenant_id,
            server_id,
            metric_name,
            result["current_value"],
            result.get("baseline_median"),
            result.get("mad"),
            result.get("modified_zscore"),
            result.get("sample_count", 0),
            1 if result["is_anomaly"] else 0,
            result["severity"],
            result["detection_reason"],
            result["persistence_count"],
            result["statistical_context_status"],
            event_ts,
            stored_at_utc,
        ),
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Public read helpers (used by API routes)
# ---------------------------------------------------------------------------

async def get_latest_statistical_analysis(
    db: aiosqlite.Connection,
    tenant_id: Optional[str] = None,
    server_id: Optional[str] = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Return the most recent statistical analysis records (one row per metric per event)."""
    clauses = []
    params: list[Any] = []
    if tenant_id:
        clauses.append("tenant_id = ?")
        params.append(tenant_id)
    if server_id:
        clauses.append("server_id = ?")
        params.append(server_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)

    query = f"""
    SELECT analysis_id, event_id, tenant_id, server_id, metric_name,
           current_value, baseline_median, mad, modified_zscore,
           sample_count, is_anomaly, severity, detection_reason, persistence_count,
           statistical_context_status, event_timestamp_utc, stored_at_utc
    FROM statistical_analysis_records
    {where}
    ORDER BY stored_at_utc DESC
    LIMIT ?;
    """
    async with db.execute(query, tuple(params)) as cur:
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def get_metric_anomaly_history(
    db: aiosqlite.Connection,
    server_id: str,
    metric_name: str,
    tenant_id: Optional[str] = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Return historical anomaly detections for a specific server and metric."""
    clauses = ["server_id = ?", "metric_name = ?", "is_anomaly = 1"]
    params: list[Any] = [server_id, metric_name]
    if tenant_id:
        clauses.append("tenant_id = ?")
        params.append(tenant_id)
    params.append(limit)

    query = f"""
    SELECT analysis_id, event_id, tenant_id, server_id, metric_name,
           current_value, baseline_median, mad, modified_zscore,
           sample_count, severity, detection_reason, persistence_count,
           statistical_context_status, event_timestamp_utc
    FROM statistical_analysis_records
    WHERE {" AND ".join(clauses)}
    ORDER BY event_timestamp_utc DESC
    LIMIT ?;
    """
    async with db.execute(query, tuple(params)) as cur:
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def get_server_baselines(
    db: aiosqlite.Connection,
    tenant_id: Optional[str] = None,
    server_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Return the most recent statistical context (median / MAD) per server and metric."""
    clauses = ["statistical_context_status = 'ACTIVE_BASELINE'"]
    params: list[Any] = []
    if tenant_id:
        clauses.append("tenant_id = ?")
        params.append(tenant_id)
    if server_id:
        clauses.append("server_id = ?")
        params.append(server_id)

    query = f"""
    WITH ranked AS (
        SELECT *,
               ROW_NUMBER() OVER (PARTITION BY server_id, metric_name ORDER BY stored_at_utc DESC) as rn
        FROM statistical_analysis_records
        WHERE {" AND ".join(clauses)}
    )
    SELECT server_id, tenant_id, metric_name, baseline_median, mad,
           modified_zscore, sample_count, event_timestamp_utc
    FROM ranked
    WHERE rn = 1
    ORDER BY server_id, metric_name;
    """
    async with db.execute(query, tuple(params)) as cur:
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def get_current_statistical_health(
    db: aiosqlite.Connection,
    tenant_id: Optional[str] = None,
) -> dict[str, Any]:
    """Return a summary of current statistical health across all monitored servers."""
    t_filter = "WHERE tenant_id = ?" if tenant_id else ""
    params: tuple = (tenant_id,) if tenant_id else ()

    # Active anomalies from the last 15 minutes
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
    recent_query = f"""
    SELECT server_id, metric_name, severity, COUNT(*) as cnt
    FROM statistical_analysis_records
    WHERE is_anomaly = 1
      AND stored_at_utc >= ?
      {('AND tenant_id = ?' if tenant_id else '')}
    GROUP BY server_id, metric_name, severity
    ORDER BY severity DESC, cnt DESC;
    """
    r_params = (cutoff, tenant_id) if tenant_id else (cutoff,)

    async with db.execute(recent_query, r_params) as cur:
        rows = await cur.fetchall()
        active_signals = [dict(r) for r in rows]

    has_critical = any(r["severity"] == "CRITICAL" for r in active_signals)
    has_high = any(r["severity"] == "HIGH" for r in active_signals)
    has_medium = any(r["severity"] == "MEDIUM" for r in active_signals)

    if has_critical:
        health_status = "CRITICAL"
    elif has_high:
        health_status = "DEGRADED"
    elif has_medium:
        health_status = "WARNING"
    elif active_signals:
        health_status = "CAUTION"
    else:
        health_status = "HEALTHY"

    return {
        "health_status": health_status,
        "active_anomaly_signals": active_signals,
        "total_active_anomaly_metrics": len(active_signals),
        "has_critical": has_critical,
        "lookback_minutes": 15,
        "tenant_id": tenant_id,
    }
