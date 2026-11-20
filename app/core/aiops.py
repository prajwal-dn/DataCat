"""DATACAT AIOps Intelligence Engine.

Pure Python standard-library statistical anomaly detection, incident correlation,
and explainable operational recommendations.

Zero external machine-learning dependencies (no NumPy, Pandas, Scikit-learn, PyTorch).
Statistical methods used: rolling mean, rolling median, standard deviation, and heuristic rules.
"""
from datetime import datetime, timezone, timedelta
import json
import logging
import math
import statistics
from typing import Any, Optional
import uuid
import aiosqlite

logger = logging.getLogger(__name__)

# Baseline parameters
MIN_SAMPLES_FOR_BASELINE = 5  # Historical samples required before dynamic baseline is used
HISTORICAL_SAMPLE_WINDOW = 30  # Max past events to pull for baseline calculation

# Fallback static thresholds used when insufficient historical samples exist
FALLBACK_THRESHOLDS = {
    "cpu_usage": 85.0,     # Percentage
    "memory_usage": 85.0,  # Percentage
    "disk_usage": 90.0,    # Percentage
    "latency_ms": 150.0,   # Milliseconds
}

# Dynamic baseline sensitivity parameters
Z_SCORE_MEDIUM = 2.0
Z_SCORE_HIGH = 2.7
Z_SCORE_CRITICAL = 3.5

# Minimum absolute delta required above mean even if variance is very small
MIN_ABSOLUTE_DELTA = {
    "cpu_usage": 15.0,
    "memory_usage": 15.0,
    "disk_usage": 10.0,
    "latency_ms": 30.0,
}

# Alert suppression window to prevent alert flooding (anti-spam)
ALERT_SUPPRESSION_SECONDS = 120

# Incident correlation window (5 minutes)
CORRELATION_WINDOW_SECONDS = 300


class AIOpsEngine:
    """Statistical intelligence engine for anomaly detection and incident correlation."""

    @classmethod
    async def analyze_event(
        cls, db: aiosqlite.Connection, verified_event: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Processes a verified telemetry event through the AIOps pipeline.

        1. Computes statistical baseline from verified history.
        2. Detects metric anomalies using dynamic Z-score or fallback thresholds.
        3. Suppresses duplicate alerts within suppression window.
        4. Correlates co-occurring anomalies into structured incidents.
        5. Persists anomalies and incidents to SQLite.
        """
        event_id = verified_event["event_id"]
        tenant_id = verified_event["tenant_id"]
        server_id = verified_event["server_id"]
        metrics = verified_event.get("metrics", {})
        now_utc = verified_event.get("timestamp_utc") or datetime.now(timezone.utc).isoformat()

        # Step 1: Pull historical metric values for this server and tenant
        history = await cls._fetch_historical_metrics(db, tenant_id, server_id, event_id)

        detected_anomalies = []
        for metric_name in ["cpu_usage", "memory_usage", "disk_usage", "latency_ms"]:
            if metric_name not in metrics:
                continue

            observed_val = float(metrics[metric_name])
            past_vals = [float(h[metric_name]) for h in history if metric_name in h]

            # Step 2: Compute Baseline
            baseline_info = cls.calculate_baseline(metric_name, past_vals)

            # Step 3: Check for anomaly
            anomaly = cls.detect_anomaly_for_metric(
                tenant_id=tenant_id,
                server_id=server_id,
                metric_name=metric_name,
                observed_value=observed_val,
                baseline_info=baseline_info,
                event_id=event_id,
                now_utc=now_utc,
            )

            if anomaly:
                # Anti-spam check: avoid repeated identical alert within suppression window
                is_suppressed = await cls._is_alert_suppressed(
                    db, tenant_id, server_id, metric_name, now_utc
                )
                if not is_suppressed:
                    await cls._store_anomaly(db, anomaly)
                    detected_anomalies.append(anomaly)
                else:
                    logger.debug("Suppressed duplicate anomaly alert for %s on %s", metric_name, server_id)

        # Step 4: Event correlation & incident generation
        if detected_anomalies:
            await cls.correlate_and_store_incident(db, tenant_id, server_id, detected_anomalies, now_utc)

        return detected_anomalies

    @classmethod
    def calculate_baseline(cls, metric_name: str, past_values: list[float]) -> dict[str, Any]:
        """Calculates statistical baseline using Python's standard library.

        When sample count < MIN_SAMPLES_FOR_BASELINE, indicates fallback mode.
        """
        sample_count = len(past_values)
        if sample_count < MIN_SAMPLES_FOR_BASELINE:
            fallback = FALLBACK_THRESHOLDS.get(metric_name, 80.0)
            return {
                "dynamic_baseline_active": False,
                "sample_count": sample_count,
                "required_samples": MIN_SAMPLES_FOR_BASELINE,
                "expected_baseline": fallback,
                "mean": None,
                "median": None,
                "stdev": None,
                "baseline_type": "configurable_fallback_threshold",
            }

        mean_val = statistics.mean(past_values)
        median_val = statistics.median(past_values)
        stdev_val = statistics.stdev(past_values) if sample_count >= 2 else 0.0

        return {
            "dynamic_baseline_active": True,
            "sample_count": sample_count,
            "required_samples": MIN_SAMPLES_FOR_BASELINE,
            "expected_baseline": round(mean_val, 2),
            "mean": round(mean_val, 2),
            "median": round(median_val, 2),
            "stdev": round(stdev_val, 2),
            "baseline_type": "statistical_rolling_baseline",
        }

    @classmethod
    def detect_anomaly_for_metric(
        cls,
        tenant_id: str,
        server_id: str,
        metric_name: str,
        observed_value: float,
        baseline_info: dict[str, Any],
        event_id: str,
        now_utc: str,
    ) -> Optional[dict[str, Any]]:
        """Evaluates whether an observed metric represents a statistical or threshold anomaly."""
        is_dynamic = baseline_info["dynamic_baseline_active"]
        anomaly_id = f"anom-{uuid.uuid4().hex[:12]}"

        if not is_dynamic:
            # Fallback threshold evaluation
            fallback_limit = baseline_info["expected_baseline"]
            if observed_value > fallback_limit:
                excess = observed_value - fallback_limit
                severity = "CRITICAL" if excess >= 10.0 else "HIGH" if excess >= 5.0 else "MEDIUM"
                samples_info = f"{baseline_info['sample_count']}/{baseline_info['required_samples']} historical samples"
                explanation = (
                    f"Observed {metric_name} of {observed_value:.1f} exceeds the configurable "
                    f"fallback threshold of {fallback_limit:.1f} (dynamic baseline inactive due to "
                    f"insufficient history: {samples_info}) on {server_id}."
                )
                return {
                    "anomaly_id": anomaly_id,
                    "tenant_id": tenant_id,
                    "server_id": server_id,
                    "metric_name": metric_name,
                    "observed_value": round(observed_value, 2),
                    "expected_baseline": round(fallback_limit, 2),
                    "severity": severity,
                    "detection_timestamp": now_utc,
                    "explanation": explanation,
                    "event_id": event_id,
                    "baseline_type": "fallback_threshold",
                }
            return None

        # Dynamic statistical baseline evaluation (Z-Score)
        mean_val = baseline_info["mean"]
        stdev_val = baseline_info["stdev"]
        min_delta = MIN_ABSOLUTE_DELTA.get(metric_name, 10.0)

        delta = observed_value - mean_val
        if delta <= 0:
            return None

        # Safe Z-score calculation
        if stdev_val > 0.001:
            z_score = delta / stdev_val
        else:
            z_score = 4.0 if delta >= min_delta else 0.0

        # Anomaly threshold: must exceed Z-score AND minimum delta
        if z_score >= Z_SCORE_MEDIUM and delta >= min_delta:
            if z_score >= Z_SCORE_CRITICAL or observed_value >= 90.0:
                severity = "CRITICAL"
            elif z_score >= Z_SCORE_HIGH or observed_value >= 80.0:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            explanation = (
                f"Observed {metric_name} of {observed_value:.1f} is {z_score:.1f} standard deviations "
                f"above the rolling statistical baseline mean of {mean_val:.1f} (stdev: {stdev_val:.1f}, "
                f"median: {baseline_info['median']:.1f}, sample size: {baseline_info['sample_count']}) "
                f"on {server_id}."
            )

            return {
                "anomaly_id": anomaly_id,
                "tenant_id": tenant_id,
                "server_id": server_id,
                "metric_name": metric_name,
                "observed_value": round(observed_value, 2),
                "expected_baseline": round(mean_val, 2),
                "severity": severity,
                "detection_timestamp": now_utc,
                "explanation": explanation,
                "event_id": event_id,
                "baseline_type": "statistical_zscore",
            }

        return None

    @classmethod
    async def correlate_and_store_incident(
        cls,
        db: aiosqlite.Connection,
        tenant_id: str,
        server_id: str,
        anomalies: list[dict[str, Any]],
        now_utc: str,
    ) -> dict[str, Any]:
        """Groups related anomalies occurring within the correlation window into an Incident."""
        metric_names = [a["metric_name"] for a in anomalies]
        highest_severity = "MEDIUM"
        if any(a["severity"] == "CRITICAL" for a in anomalies):
            highest_severity = "CRITICAL"
        elif any(a["severity"] == "HIGH" for a in anomalies):
            highest_severity = "HIGH"

        has_cpu = "cpu_usage" in metric_names
        has_mem = "memory_usage" in metric_names
        has_lat = "latency_ms" in metric_names
        has_disk = "disk_usage" in metric_names

        # Multi-signal correlation rules
        if has_cpu and has_mem and has_lat:
            title = "Full-Stack Server Degradation (CPU, Memory & Latency Saturation)"
            highest_severity = "CRITICAL"
            explanation = (
                f"Multi-signal correlation detected concurrent anomalies across compute, memory, and network latency "
                f"on {server_id}. This co-occurrence indicates system-wide performance degradation."
            )
            investigation_steps = [
                "Inspect high-CPU processes and thread pool saturation on the host.",
                "Review memory allocation profiles for memory leak signatures or cache buildup.",
                "Inspect network socket queue backlogs and local packet buffering.",
            ]
        elif has_cpu and has_mem:
            title = "Compute & Memory Resource Saturation"
            explanation = (
                f"Concurrent CPU and memory anomalies detected on {server_id}. Sustained multi-resource pressure "
                f"places host at risk of service unresponsiveness or OOM termination."
            )
            investigation_steps = [
                "Check running services for runaway computational loops or unbounded batch processing.",
                "Examine resident memory size (RSS) per process and restart offending services.",
            ]
        elif has_cpu and has_lat:
            title = "Compute Saturation Inducing Latency Degradation"
            explanation = (
                f"Co-occurring CPU elevation and network/service latency spikes observed on {server_id}. "
                f"Thread scheduling latency is likely bottlenecking network I/O responsiveness."
            )
            investigation_steps = [
                "Analyze process scheduling wait times on the server.",
                "Consider horizontal load shedding or throttling non-critical background jobs.",
            ]
        elif has_mem and has_lat:
            title = "Memory Pressure Inducing Latency Spikes"
            explanation = (
                f"Memory consumption and network latency surged simultaneously on {server_id}. "
                f"Excessive garbage collection pauses or kernel swapping may be degrading I/O throughput."
            )
            investigation_steps = [
                "Examine swap file activity and page fault rates.",
                "Inspect garbage collection (GC) pauses in hospital application daemons.",
            ]
        elif len(metric_names) == 1:
            m = metric_names[0]
            display_name = {
                "cpu_usage": "CPU Utilisation",
                "memory_usage": "Memory Consumption",
                "disk_usage": "Disk Space Utilisation",
                "latency_ms": "Network Latency",
            }.get(m, m.replace('_', ' ').title())
            title = f"Abnormal {display_name} Elevation"
            explanation = anomalies[0]["explanation"]
            investigation_steps = cls._get_single_metric_steps(m, server_id)
        else:
            title = f"Correlated Multi-Metric Anomaly ({', '.join(metric_names)})"
            explanation = f"Multiple metrics ({', '.join(metric_names)}) deviated from expected baselines simultaneously on {server_id}."
            investigation_steps = ["Review recent operational deployments or load spikes on this host."]

        # Grounded recommendations structure
        recommendations = {
            "what_happened": title,
            "affected_server": server_id,
            "contributing_metrics": [
                {
                    "metric": a["metric_name"],
                    "observed": a["observed_value"],
                    "baseline": a["expected_baseline"],
                    "severity": a["severity"],
                }
                for a in anomalies
            ],
            "why_flagged": explanation,
            "investigation_steps": investigation_steps,
        }

        # Check for existing open incident within correlation window (anti-spam)
        existing_incident = await cls._find_recent_open_incident(db, tenant_id, server_id, now_utc)

        if existing_incident:
            incident_id = existing_incident["incident_id"]
            update_sql = """
            UPDATE incidents
            SET severity = CASE WHEN ? = 'CRITICAL' THEN 'CRITICAL' ELSE severity END,
                title = ?,
                contributing_metrics = ?,
                explanation = ?,
                recommendations = ?,
                correlated_anomalies_count = correlated_anomalies_count + ?,
                updated_at_utc = ?
            WHERE incident_id = ?;
            """
            await db.execute(
                update_sql,
                (
                    highest_severity,
                    title,
                    json.dumps(metric_names),
                    explanation,
                    json.dumps(recommendations),
                    len(anomalies),
                    now_utc,
                    incident_id,
                ),
            )
            await db.commit()
            logger.info("Updated existing correlated incident %s for %s", incident_id, server_id)
            return {
                "incident_id": incident_id,
                "tenant_id": tenant_id,
                "server_id": server_id,
                "title": title,
                "severity": highest_severity,
                "recommendations": recommendations,
            }
        else:
            incident_id = f"inc-{uuid.uuid4().hex[:12]}"
            insert_sql = """
            INSERT INTO incidents (
                incident_id, tenant_id, server_id, title, severity, status,
                detection_timestamp, contributing_metrics, explanation,
                recommendations, correlated_anomalies_count, created_at_utc, updated_at_utc
            ) VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, ?);
            """
            await db.execute(
                insert_sql,
                (
                    incident_id,
                    tenant_id,
                    server_id,
                    title,
                    highest_severity,
                    now_utc,
                    json.dumps(metric_names),
                    explanation,
                    json.dumps(recommendations),
                    len(anomalies),
                    now_utc,
                    now_utc,
                ),
            )
            await db.commit()
            logger.info("Created new correlated incident %s for %s", incident_id, server_id)
            return {
                "incident_id": incident_id,
                "tenant_id": tenant_id,
                "server_id": server_id,
                "title": title,
                "severity": highest_severity,
                "recommendations": recommendations,
            }

    @staticmethod
    def _get_single_metric_steps(metric_name: str, server_id: str) -> list[str]:
        if metric_name == "cpu_usage":
            return [
                f"Inspect top active CPU consumers on {server_id} using system monitoring.",
                "Check for unindexed database queries or runaway background batch threads.",
            ]
        elif metric_name == "memory_usage":
            return [
                f"Examine process heap profiles and resident memory size (RSS) on {server_id}.",
                "Check for memory leaks or unbounded in-memory cache accumulation.",
            ]
        elif metric_name == "disk_usage":
            return [
                f"Inspect local storage partitions and log directories on {server_id}.",
                "Verify log rotation policies are active and clean up temporary scratch files.",
            ]
        elif metric_name == "latency_ms":
            return [
                f"Verify network interface statistics and packet drops on {server_id}.",
                "Inspect local network switch throughput and gateway congestion.",
            ]
        return ["Inspect operational server health and service daemon logs."]

    @staticmethod
    async def _fetch_historical_metrics(
        db: aiosqlite.Connection, tenant_id: str, server_id: str, exclude_event_id: str
    ) -> list[dict[str, Any]]:
        query = """
        SELECT metrics FROM telemetry_events
        WHERE tenant_id = ? AND server_id = ? AND event_id != ?
        ORDER BY timestamp_utc DESC
        LIMIT ?;
        """
        async with db.execute(query, (tenant_id, server_id, exclude_event_id, HISTORICAL_SAMPLE_WINDOW)) as cur:
            rows = await cur.fetchall()
            results = []
            for r in rows:
                try:
                    results.append(json.loads(r[0]))
                except Exception:
                    pass
            return results

    @staticmethod
    async def _is_alert_suppressed(
        db: aiosqlite.Connection, tenant_id: str, server_id: str, metric_name: str, now_utc: str
    ) -> bool:
        """Checks if a matching anomaly occurred within the suppression window."""
        try:
            now_dt = datetime.fromisoformat(now_utc.replace("Z", "+00:00"))
        except Exception:
            now_dt = datetime.now(timezone.utc)

        cutoff = (now_dt - timedelta(seconds=ALERT_SUPPRESSION_SECONDS)).isoformat()
        query = """
        SELECT 1 FROM anomalies
        WHERE tenant_id = ? AND server_id = ? AND metric_name = ? AND detection_timestamp >= ?
        LIMIT 1;
        """
        async with db.execute(query, (tenant_id, server_id, metric_name, cutoff)) as cur:
            row = await cur.fetchone()
            return row is not None

    @staticmethod
    async def _store_anomaly(db: aiosqlite.Connection, anomaly: dict[str, Any]) -> None:
        query = """
        INSERT INTO anomalies (
            anomaly_id, tenant_id, server_id, metric_name, observed_value,
            expected_baseline, severity, detection_timestamp, explanation, event_id, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN');
        """
        await db.execute(
            query,
            (
                anomaly["anomaly_id"],
                anomaly["tenant_id"],
                anomaly["server_id"],
                anomaly["metric_name"],
                anomaly["observed_value"],
                anomaly["expected_baseline"],
                anomaly["severity"],
                anomaly["detection_timestamp"],
                anomaly["explanation"],
                anomaly.get("event_id"),
            ),
        )
        await db.commit()

    @staticmethod
    async def _find_recent_open_incident(
        db: aiosqlite.Connection, tenant_id: str, server_id: str, now_utc: str
    ) -> Optional[dict[str, Any]]:
        try:
            now_dt = datetime.fromisoformat(now_utc.replace("Z", "+00:00"))
        except Exception:
            now_dt = datetime.now(timezone.utc)

        cutoff = (now_dt - timedelta(seconds=CORRELATION_WINDOW_SECONDS)).isoformat()
        query = """
        SELECT incident_id, severity, title FROM incidents
        WHERE tenant_id = ? AND server_id = ? AND status = 'OPEN' AND detection_timestamp >= ?
        ORDER BY detection_timestamp DESC
        LIMIT 1;
        """
        async with db.execute(query, (tenant_id, server_id, cutoff)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None
