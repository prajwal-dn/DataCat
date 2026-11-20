"""DATACAT Unified AIOps Decision Pipeline.

Integrates:
  1. Statistical Anomaly Detection Engine (Rolling Median, MAD, Modified Z-score).
  2. Pure-Python Logistic Regression Anomaly Classifier.
  3. Transparent Multi-Signal Decision Fusion.
  4. Multi-Signal Incident Correlation.
  5. 4-State Infrastructure Health Evaluation (EXCELLENT, GOOD, FAIR, POOR).
  6. Atomic SQLite Persistence.

Guarantees:
  - Operates strictly on cryptographically verified telemetry.
  - Zero unapproved libraries (Python standard library + aiosqlite only).
  - Preserves individual evidence from both detectors.
  - Never silently discards statistical anomalies.
"""

from __future__ import annotations

import json
import logging
import math
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import aiosqlite

from app.core.detection_config import DetectionConfig
from app.core.statistical_detector import (
    _compute_statistical_context,
    _fetch_historical_values,
    _get_persistence_count,
    _store_analysis_record,
    run_statistical_analysis,
)
from app.ml.features import (
    FEATURE_NAMES,
    extract_features_for_observation,
)
from app.ml.inference import (
    _fetch_preceding_anomaly_flags,
    _fetch_preceding_metrics,
    get_model,
)

logger = logging.getLogger(__name__)


class UnifiedAIOpsPipeline:
    """Orchestrates end-to-end statistical detection, ML inference, decision fusion, and health evaluation."""

    @classmethod
    async def process_verified_event(
        cls,
        db: aiosqlite.Connection,
        verified_event: dict[str, Any],
        config: Optional[DetectionConfig] = None,
    ) -> dict[str, Any]:
        """Runs the complete unified AIOps decision pipeline on a verified event."""
        cfg = config or DetectionConfig.load()
        now_utc = datetime.now(timezone.utc).isoformat()

        event_id = verified_event["event_id"]
        tenant_id = verified_event["tenant_id"]
        server_id = verified_event["server_id"]
        timestamp_utc = verified_event.get("timestamp_utc") or now_utc
        metrics = verified_event.get("metrics", {})

        # ======================================================================
        # Step 1: Feature Extraction (strictly causal preceding history)
        # ======================================================================
        preceding_history = await _fetch_preceding_metrics(
            db, tenant_id=tenant_id, server_id=server_id, exclude_event_id=event_id, limit=30
        )
        preceding_flags = await _fetch_preceding_anomaly_flags(
            db, tenant_id=tenant_id, server_id=server_id, limit=5
        )

        current_metrics = {
            "cpu_usage": float(metrics.get("cpu_usage", 0.0)),
            "memory_usage": float(metrics.get("memory_usage", 0.0)),
            "disk_usage": float(metrics.get("disk_usage", 0.0)),
            "latency_ms": float(metrics.get("latency_ms", 0.0)),
        }

        feat_res = extract_features_for_observation(
            current_metrics=current_metrics,
            preceding_history=preceding_history,
            preceding_anomaly_flags=preceding_flags,
            min_mad_scale=cfg.min_mad_scale,
            fallback_thresholds=cfg.fallback_thresholds,
        )
        feature_vector = feat_res["features"]
        feature_dict = feat_res["feature_dict"]
        is_warmup = feat_res["metadata"]["is_warmup"]

        # ======================================================================
        # Step 2: Statistical Anomaly Detection
        # ======================================================================
        stat_result = await run_statistical_analysis(db, verified_event)
        abnormal_metrics = [
            r["metric_name"]
            for r in stat_result.get("metric_results", [])
            if r["is_anomaly"]
        ]
        has_stat_anomaly = len(abnormal_metrics) > 0
        stat_severity = "NORMAL"
        if any(r["severity"] == "CRITICAL" for r in stat_result.get("metric_results", [])):
            stat_severity = "CRITICAL"
        elif any(r["severity"] == "HIGH" for r in stat_result.get("metric_results", [])):
            stat_severity = "HIGH"
        elif any(r["severity"] == "MEDIUM" for r in stat_result.get("metric_results", [])):
            stat_severity = "MEDIUM"

        statistical_scores = {
            r["metric_name"]: {
                "current_value": r["current_value"],
                "baseline_median": r.get("baseline_median"),
                "mad": r.get("mad"),
                "modified_zscore": r.get("modified_zscore"),
                "is_anomaly": r["is_anomaly"],
                "severity": r["severity"],
                "persistence_count": r.get("persistence_count", 0),
            }
            for r in stat_result.get("metric_results", [])
        }

        # Max persistence count
        max_persistence = max(
            [r.get("persistence_count", 0) for r in stat_result.get("metric_results", [])] or [0]
        )

        # ======================================================================
        # Step 3: Logistic Regression ML Inference
        # ======================================================================
        ml_prob = 0.0
        ml_pred = 0
        ml_thresh = cfg.high_prob_threshold
        model_version = "1.0.0"
        ml_available = True
        top_signals: list[str] = []

        try:
            model = get_model()
            model_version = model.model_version
            ml_thresh = model.threshold

            x_std = model.standardizer.transform_one(feature_vector)
            ml_prob, ml_pred = model.predict_one_standardized(x_std)

            # Extract top signals by linear impact
            contributions = []
            for j, fname in enumerate(model.feature_names):
                impact = model.weights[j] * x_std[j]
                contributions.append((fname, impact))
            contributions.sort(key=lambda c: abs(c[1]), reverse=True)
            top_signals = [f"{fname}(impact={imp:+.2f})" for fname, imp in contributions[:4]]

        except Exception as e:
            logger.warning("ML model inference fallback (model unavailable or invalid): %s", e)
            ml_available = False
            model_version = "UNAVAILABLE"
            ml_prob = 0.0
            ml_pred = 0

        # ======================================================================
        # Step 4 & 5: Decision Fusion & Explanation
        # ======================================================================
        has_ml_anomaly = ml_pred == 1 or ml_prob >= ml_thresh

        decision_data = cls._fuse_decisions(
            has_stat_anomaly=has_stat_anomaly,
            has_ml_anomaly=has_ml_anomaly,
            stat_severity=stat_severity,
            abnormal_metrics=abnormal_metrics,
            statistical_scores=statistical_scores,
            ml_prob=ml_prob,
            ml_thresh=ml_thresh,
            ml_available=ml_available,
            max_persistence=max_persistence,
            is_warmup=is_warmup,
            top_signals=top_signals,
            cfg=cfg,
        )

        final_decision = decision_data["final_anomaly_decision"]
        final_severity = decision_data["severity"]
        explanation = decision_data["explanation"]
        contributing_signals = decision_data["contributing_signals"]

        # ======================================================================
        # Step 6: Incident Correlation
        # ======================================================================
        incident_id = None
        if final_decision in ("ANOMALY", "CANDIDATE_ANOMALY", "INVESTIGATE"):
            incident_id = await cls._correlate_incident(
                db=db,
                tenant_id=tenant_id,
                server_id=server_id,
                final_decision=final_decision,
                severity=final_severity,
                abnormal_metrics=abnormal_metrics,
                explanation=explanation,
                timestamp_utc=timestamp_utc,
                now_utc=now_utc,
                cfg=cfg,
            )

        # ======================================================================
        # Step 7: Server Health Evaluation & Transition Tracking
        # ======================================================================
        health_info = await cls._evaluate_and_record_health(
            db=db,
            tenant_id=tenant_id,
            server_id=server_id,
            metrics=current_metrics,
            timestamp_utc=timestamp_utc,
            final_decision=final_decision,
            severity=final_severity,
            max_persistence=max_persistence,
            now_utc=now_utc,
            cfg=cfg,
        )

        # ======================================================================
        # Step 8: Persist Unified Decision Record
        # ======================================================================
        decision_id = f"dec-{uuid.uuid4().hex[:12]}"
        await db.execute(
            """
            INSERT INTO aiops_decisions (
                decision_id, event_id, tenant_id, server_id, timestamp_utc,
                statistical_status, statistical_scores, abnormal_metrics,
                logistic_regression_probability, logistic_regression_prediction,
                model_version, persistence_status, final_anomaly_decision,
                severity, contributing_signals, explanation, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                decision_id,
                event_id,
                tenant_id,
                server_id,
                timestamp_utc,
                stat_result.get("overall_statistical_status", "NORMAL"),
                json.dumps(statistical_scores),
                json.dumps(abnormal_metrics),
                round(ml_prob, 4),
                ml_pred,
                model_version,
                json.dumps({"max_persistence_count": max_persistence, "is_warmup": is_warmup}),
                final_decision,
                final_severity,
                json.dumps(contributing_signals),
                explanation,
                now_utc,
            ),
        )
        await db.commit()

        return {
            "decision_id": decision_id,
            "event_id": event_id,
            "tenant_id": tenant_id,
            "server_id": server_id,
            "timestamp_utc": timestamp_utc,
            "statistical_status": stat_result.get("overall_statistical_status", "NORMAL"),
            "statistical_scores": statistical_scores,
            "abnormal_metrics": abnormal_metrics,
            "logistic_regression_probability": round(ml_prob, 4),
            "logistic_regression_prediction": ml_pred,
            "model_version": model_version,
            "persistence_status": {"persistence_count": max_persistence, "is_warmup": is_warmup},
            "final_anomaly_decision": final_decision,
            "severity": final_severity,
            "contributing_signals": contributing_signals,
            "explanation": explanation,
            "incident_id": incident_id,
            "health_state": health_info["current_state"],
        }

    # --------------------------------------------------------------------------
    # Fusion Logic (The 4 Quadrants)
    # --------------------------------------------------------------------------

    @classmethod
    def _fuse_decisions(
        cls,
        has_stat_anomaly: bool,
        has_ml_anomaly: bool,
        stat_severity: str,
        abnormal_metrics: list[str],
        statistical_scores: dict[str, Any],
        ml_prob: float,
        ml_thresh: float,
        ml_available: bool,
        max_persistence: int,
        is_warmup: bool,
        top_signals: list[str],
        cfg: DetectionConfig,
    ) -> dict[str, Any]:
        """Implements transparent decision fusion across statistical & ML layers."""
        signals: list[str] = []
        for m in abnormal_metrics:
            info = statistical_scores.get(m, {})
            mz = info.get("modified_zscore")
            signals.append(f"Stat:{m}(Z={mz})" if mz is not None else f"Stat:{m}")
        if ml_available:
            signals.append(f"ML:prob={ml_prob:.4f}")

        # Case A: Statistical Anomaly + High ML Probability -> Strong Anomaly
        if has_stat_anomaly and (has_ml_anomaly or ml_prob >= cfg.low_prob_threshold):
            severity = stat_severity
            if ml_prob >= 0.85 and severity in ("MEDIUM", "NORMAL"):
                severity = "HIGH"
            if max_persistence >= cfg.persistence_escalate_count:
                severity = "CRITICAL"

            metrics_str = ", ".join(abnormal_metrics)
            explanation = (
                f"Strong anomaly confirmed: Statistical engine identified {len(abnormal_metrics)} "
                f"abnormal metric(s) [{metrics_str}] (stat severity: {stat_severity}), and "
                f"Logistic Regression predicts anomaly with {ml_prob*100:.1f}% probability (threshold: {ml_thresh:.2f})."
            )
            return {
                "final_anomaly_decision": "ANOMALY",
                "severity": severity,
                "explanation": explanation,
                "contributing_signals": signals + top_signals[:2],
            }

        # Case B: Statistical Anomaly + Low ML Probability -> Disagreement (Candidate Anomaly)
        # Never silently discard a statistical alert
        if has_stat_anomaly and not has_ml_anomaly:
            metrics_str = ", ".join(abnormal_metrics)
            # If persistent or critical, preserve as ANOMALY; otherwise CANDIDATE_ANOMALY
            if max_persistence >= cfg.persistence_escalate_count or stat_severity == "CRITICAL":
                decision = "ANOMALY"
                severity = stat_severity
                explanation = (
                    f"Statistical anomaly confirmed by persistence ({max_persistence} consecutive breaches) "
                    f"or critical threshold: [{metrics_str}], despite lower ML probability ({ml_prob*100:.1f}%)."
                )
            else:
                decision = "CANDIDATE_ANOMALY"
                severity = "MEDIUM" if stat_severity in ("HIGH", "CRITICAL") else "LOW"
                explanation = (
                    f"Detector disagreement: Statistical engine flagged {len(abnormal_metrics)} abnormal "
                    f"metric(s) [{metrics_str}], but Logistic Regression estimated lower anomaly "
                    f"probability ({ml_prob*100:.1f}% < threshold {ml_thresh:.2f}). Preserved as candidate anomaly."
                )

            return {
                "final_anomaly_decision": decision,
                "severity": severity,
                "explanation": explanation,
                "contributing_signals": signals,
            }

        # Case C: No Statistical Anomaly + High ML Probability -> Multivariate Pattern Alert
        if not has_stat_anomaly and has_ml_anomaly:
            severity = "HIGH" if ml_prob >= 0.85 else "MEDIUM"
            signals_str = ", ".join(top_signals[:3])
            explanation = (
                f"Detector disagreement (Subtle multi-metric pattern): No individual metric exceeded "
                f"univariate statistical thresholds, but Logistic Regression identified an anomalous "
                f"multivariate pattern with {ml_prob*100:.1f}% probability. Key signals: {signals_str}."
            )
            return {
                "final_anomaly_decision": "INVESTIGATE",
                "severity": severity,
                "explanation": explanation,
                "contributing_signals": top_signals[:4],
            }

        # Case D: Neither detector identifies anomaly -> NORMAL
        return {
            "final_anomaly_decision": "NORMAL",
            "severity": "NORMAL",
            "explanation": (
                f"Telemetry is within normal statistical baselines and model bounds "
                f"(ML probability: {ml_prob*100:.1f}%)."
            ),
            "contributing_signals": [f"ML:prob={ml_prob:.4f}"],
        }

    # --------------------------------------------------------------------------
    # Incident Correlation
    # --------------------------------------------------------------------------

    @classmethod
    async def _correlate_incident(
        cls,
        db: aiosqlite.Connection,
        tenant_id: str,
        server_id: str,
        final_decision: str,
        severity: str,
        abnormal_metrics: list[str],
        explanation: str,
        timestamp_utc: str,
        now_utc: str,
        cfg: DetectionConfig,
    ) -> str:
        """Groups related anomalies into an open incident within the correlation window."""
        window_seconds = cfg.correlation_window_seconds
        event_time_str = timestamp_utc or now_utc
        try:
            now_dt = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
        except Exception:
            now_dt = datetime.now(timezone.utc)
        cutoff = (now_dt - timedelta(seconds=window_seconds)).isoformat()

        # Find existing OPEN incident for this server
        query = """
        SELECT incident_id, contributing_metrics, severity, correlated_anomalies_count
        FROM incidents
        WHERE tenant_id = ? AND server_id = ? AND status = 'OPEN' 
          AND detection_timestamp >= ? AND detection_timestamp <= ?
        ORDER BY detection_timestamp DESC LIMIT 1;
        """
        async with db.execute(query, (tenant_id, server_id, cutoff, event_time_str)) as cur:
            row = await cur.fetchone()

        if row:
            inc_id = row[0]
            existing_metrics = []
            try:
                existing_metrics = json.loads(row[1])
            except Exception:
                pass
            merged_metrics = list(dict.fromkeys(existing_metrics + abnormal_metrics))

            # Escalate severity if incoming is higher
            current_sev = row[2]
            new_sev = "CRITICAL" if (severity == "CRITICAL" or current_sev == "CRITICAL") else (
                "HIGH" if (severity == "HIGH" or current_sev == "HIGH") else severity
            )

            title = cls._generate_incident_title(merged_metrics, server_id)
            update_sql = """
            UPDATE incidents
            SET contributing_metrics = ?,
                severity = ?,
                title = ?,
                explanation = ?,
                correlated_anomalies_count = correlated_anomalies_count + 1,
                updated_at_utc = ?
            WHERE incident_id = ?;
            """
            await db.execute(
                update_sql,
                (json.dumps(merged_metrics), new_sev, title, explanation, now_utc, inc_id),
            )
            await db.commit()
            return inc_id
        else:
            inc_id = f"inc-{uuid.uuid4().hex[:12]}"
            title = cls._generate_incident_title(abnormal_metrics, server_id)
            recommendations = {
                "what_happened": title,
                "affected_server": server_id,
                "contributing_metrics": abnormal_metrics,
                "severity": severity,
                "investigation_steps": cls._get_investigation_steps(abnormal_metrics),
            }
            insert_sql = """
            INSERT INTO incidents (
                incident_id, tenant_id, server_id, title, severity, status,
                detection_timestamp, contributing_metrics, explanation, recommendations,
                correlated_anomalies_count, created_at_utc, updated_at_utc
            ) VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, 1, ?, ?);
            """
            await db.execute(
                insert_sql,
                (
                    inc_id,
                    tenant_id,
                    server_id,
                    title,
                    severity,
                    event_time_str,
                    json.dumps(abnormal_metrics),
                    explanation,
                    json.dumps(recommendations),
                    now_utc,
                    now_utc,
                ),
            )
            await db.commit()
            return inc_id

    @staticmethod
    def _generate_incident_title(metrics: list[str], server_id: str) -> str:
        has_cpu = "cpu_usage" in metrics
        has_mem = "memory_usage" in metrics
        has_lat = "latency_ms" in metrics
        has_disk = "disk_usage" in metrics

        if has_cpu and has_mem and has_lat:
            return f"Full-Stack Saturation (CPU, Memory & Latency) on {server_id}"
        elif has_cpu and has_mem:
            return f"Compute & Memory Resource Exhaustion on {server_id}"
        elif has_cpu and has_lat:
            return f"CPU Contention Inducing Latency Degradation on {server_id}"
        elif has_mem and has_lat:
            return f"Memory Pressure Inducing Latency Jitter on {server_id}"
        elif has_disk:
            return f"Storage Partition Pressure Alert on {server_id}"
        elif has_cpu:
            return f"High CPU Utilization Spike on {server_id}"
        elif has_mem:
            return f"High Memory Consumption Alert on {server_id}"
        elif has_lat:
            return f"Network Latency Saturation on {server_id}"
        return f"AIOps Operational Anomaly Alert on {server_id}"

    @staticmethod
    def _get_investigation_steps(metrics: list[str]) -> list[str]:
        steps = []
        if "cpu_usage" in metrics:
            steps.append("Inspect top CPU-consuming processes and thread pool saturation.")
        if "memory_usage" in metrics:
            steps.append("Check process resident memory size (RSS) and review heap allocation profiles.")
        if "disk_usage" in metrics:
            steps.append("Inspect log directories, verify rotation policies, and purge temporary scratch partitions.")
        if "latency_ms" in metrics:
            steps.append("Verify network switch queues, packet drops, and gateway interface statistics.")
        if not steps:
            steps.append("Review recent operational deployments and workload spikes on the host.")
        return steps

    # --------------------------------------------------------------------------
    # Health Evaluation & State Transitions
    # --------------------------------------------------------------------------

    @classmethod
    async def _evaluate_and_record_health(
        cls,
        db: aiosqlite.Connection,
        tenant_id: str,
        server_id: str,
        metrics: dict[str, float],
        timestamp_utc: str,
        final_decision: str,
        severity: str,
        max_persistence: int,
        now_utc: str,
        cfg: DetectionConfig,
    ) -> dict[str, Any]:
        """Evaluates 4-tier health state and records state transitions in SQLite."""
        # Check staleness
        try:
            event_dt = datetime.fromisoformat(timestamp_utc.replace("Z", "+00:00"))
            now_dt = datetime.fromisoformat(now_utc.replace("Z", "+00:00"))
            seconds_ago = max(0.0, (now_dt - event_dt).total_seconds())
        except Exception:
            seconds_ago = 0.0

        stale = seconds_ago > cfg.stale_threshold_seconds

        # Evaluate state: POOR, FAIR, GOOD, EXCELLENT
        if stale:
            state = "POOR"
            reason = f"Telemetry is stale: last observed {int(seconds_ago)}s ago (> {cfg.stale_threshold_seconds}s limit)"
        elif severity == "CRITICAL" or final_decision == "ANOMALY" and max_persistence >= 3:
            state = "POOR"
            reason = f"Critical anomaly detected with persistence={max_persistence}"
        elif severity == "HIGH" or final_decision == "ANOMALY":
            state = "FAIR"
            reason = f"Active anomaly detected (severity: {severity})"
        elif final_decision in ("CANDIDATE_ANOMALY", "INVESTIGATE"):
            state = "FAIR"
            reason = f"Detector investigation flag ({final_decision})"
        elif (metrics.get("cpu_usage", 0) >= cfg.cpu_fair or
              metrics.get("memory_usage", 0) >= cfg.memory_fair or
              metrics.get("disk_usage", 0) >= cfg.disk_fair or
              metrics.get("latency_ms", 0) >= cfg.latency_fair):
            state = "GOOD"
            reason = "Mild metric elevation within safe operational thresholds"
        else:
            state = "EXCELLENT"
            reason = "All metrics normal, healthy baselines, and active telemetry"

        # Check previous state to record transitions
        prev_state = await cls._get_latest_health_state(db, tenant_id, server_id)
        effective_prev = prev_state or "UNKNOWN"
        if effective_prev != state:
            trans_id = f"tr-{uuid.uuid4().hex[:12]}"
            await db.execute(
                """
                INSERT INTO health_state_transitions (
                    transition_id, tenant_id, server_id, previous_state, current_state, reason, transition_timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (trans_id, tenant_id, server_id, effective_prev, state, reason, now_utc),
            )
            await db.commit()
            logger.info("Server %s transitioned health: %s -> %s (%s)", server_id, effective_prev, state, reason)

        return {
            "current_state": state,
            "previous_state": effective_prev,
            "reason": reason,
            "is_stale": stale,
        }

    @staticmethod
    async def _get_latest_health_state(
        db: aiosqlite.Connection, tenant_id: str, server_id: str
    ) -> Optional[str]:
        query = """
        SELECT current_state FROM health_state_transitions
        WHERE tenant_id = ? AND server_id = ?
        ORDER BY transition_timestamp DESC LIMIT 1;
        """
        async with db.execute(query, (tenant_id, server_id)) as cur:
            row = await cur.fetchone()
            return row[0] if row else None
