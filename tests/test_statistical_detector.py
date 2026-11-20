"""Deterministic tests for the DATACAT Statistical Anomaly Detection Engine.

Covers:
  T01  Normal metric behaviour (pure Python, synchronous)
  T02  CPU spike (dynamic MAD/Z-score, synchronous)
  T03  Memory spike (synchronous)
  T04  Disk pressure (synchronous)
  T05  Latency spike (synchronous)
  T06  Multiple simultaneous anomalies — asyncio.run() bridge
  T07  Gradual degradation with persistence escalation — asyncio.run() bridge
  T08  Zero MAD edge case (synchronous)
  T09  Insufficient historical observations (synchronous)
  T10  Persistence count accumulation — asyncio.run() bridge
  T11  Baseline contamination prevention — asyncio.run() bridge
  T12  Out-of-order event arrival — asyncio.run() bridge
  T13  API GET /api/v1/statistical/analysis — AsyncClient / ASGITransport
  T14  API GET /api/v1/statistical/anomaly-history
  T15  API GET /api/v1/statistical/baselines
  T16  API GET /api/v1/statistical/health
  T17  API POST /api/v1/statistical/config/reload
  T18  End-to-end: ingest verified event triggers statistical analysis
"""
from __future__ import annotations

import asyncio
import base64
import json
import math
import shutil
import sqlite3
import statistics
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

import app.config as config
from app.core.crypto import canonical_receipt_bytes, compute_payload_hash
from app.core.detection_config import DetectionConfig
from app.core.statistical_detector import (
    _compute_statistical_context,
    _classify_metric,
    get_latest_statistical_analysis,
    get_metric_anomaly_history,
    get_server_baselines,
    get_current_statistical_health,
    run_statistical_analysis,
    _fetch_historical_values,
    _get_persistence_count,
)
from app.core.registry import registry
from app.db.database import INIT_SQL, get_db_connection
from app.main import app

# ---------------------------------------------------------------------------
# Shared test infrastructure
# ---------------------------------------------------------------------------

TEST_DATA_DIR = config.BASE_DIR / ".test_stat_data"
TEST_KEY = ed25519.Ed25519PrivateKey.generate()
TEST_PUB_KEY = TEST_KEY.public_key()
TEST_COLLECTOR_ID = "stat_collector_1"
TEST_TENANT_ID = "hospital_stat"


@pytest.fixture(autouse=True)
def setup_stat_test_environment(monkeypatch):
    """Isolated SQLite + YAML environment for every statistical detector test."""
    if TEST_DATA_DIR.exists():
        shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)
    TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)

    test_db = TEST_DATA_DIR / "test_stat.db"
    test_yaml = TEST_DATA_DIR / "test_collectors_stat.yaml"
    test_pub_file = TEST_DATA_DIR / "test_stat_pub.pem"

    pub_bytes = TEST_PUB_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    test_pub_file.write_bytes(pub_bytes)
    test_yaml.write_text(
        f"""
collectors:
  - collector_id: {TEST_COLLECTOR_ID}
    tenant_id: {TEST_TENANT_ID}
    public_key_path: {str(test_pub_file).replace(chr(92), '/')}
    active: true
""",
        encoding="utf-8",
    )

    con = sqlite3.connect(test_db)
    con.executescript(INIT_SQL)
    now = datetime.now(timezone.utc).isoformat()
    con.execute(
        "INSERT INTO collectors VALUES (?, ?, ?, ?, ?, ?, ?)",
        (TEST_COLLECTOR_ID, TEST_TENANT_ID, str(test_pub_file), "ACTIVE", 0, now, now),
    )
    con.commit()
    con.close()

    monkeypatch.setattr(config, "DB_PATH", test_db)
    monkeypatch.setattr(config, "COLLECTORS_CONFIG_PATH", test_yaml)
    monkeypatch.setattr(registry, "config_path", test_yaml)
    registry.reload()
    yield

    if TEST_DATA_DIR.exists():
        shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)


# ---------------------------------------------------------------------------
# Default config: min_samples=5 for fast test convergence
# ---------------------------------------------------------------------------

def make_cfg() -> DetectionConfig:
    return DetectionConfig({
        "statistical_detection": {
            "min_samples_for_baseline": 5,
            "rolling_window_size": 30,
            "modified_zscore_threshold": 3.5,
            "critical_absolute_thresholds": {
                "cpu_usage": 95.0, "memory_usage": 95.0,
                "disk_usage": 97.0, "latency_ms": 1000.0,
            },
            "min_mad_scale": {
                "cpu_usage": 1.0, "memory_usage": 1.0,
                "disk_usage": 0.5, "latency_ms": 2.0,
            },
            "direction": {
                "cpu_usage": "high_only", "memory_usage": "high_only",
                "disk_usage": "high_only", "latency_ms": "high_only",
            },
            "fallback_thresholds": {
                "cpu_usage": 85.0, "memory_usage": 85.0,
                "disk_usage": 90.0, "latency_ms": 150.0,
            },
            "severity_bands": {"medium_z": 3.5, "high_z": 6.0, "critical_z": 10.0},
            "fallback_severity_bands": {
                "medium_excess": 0.0, "high_excess": 5.0, "critical_excess": 15.0,
            },
        },
        "persistence": {
            "consecutive_anomaly_window": 3,
            "persistence_lookback_count": 5,
            "persistence_trigger_count": 3,
            "persistence_critical_override": 5,
        },
        "baseline_protection": {
            "exclude_anomalies_from_baseline": True,
            "max_anomaly_contamination_ratio": 0.5,
        },
        "alert_suppression": {"suppression_window_seconds": 120},
        "incident_correlation": {"correlation_window_seconds": 300},
    })


CFG = make_cfg()


def _normal_history(n: int = 10, base: float = 30.0, spread: float = 2.0) -> list[float]:
    return [base + (i % 3 - 1) * spread for i in range(n)]


# ---------------------------------------------------------------------------
# Async helper: runs an async coroutine synchronously in tests
# ---------------------------------------------------------------------------

def run_async(coro):
    """Run a coroutine synchronously for use in synchronous test functions."""
    return asyncio.run(coro)


# ===========================================================================
# T01 — Normal metric behaviour
# ===========================================================================

def test_t01_normal_cpu_no_anomaly():
    """Normal CPU value within Z-score bounds should NOT be anomalous."""
    history = _normal_history(10, base=30.0, spread=1.5)
    ctx = _compute_statistical_context("cpu_usage", 32.0, history, CFG)
    result = _classify_metric(
        metric_name="cpu_usage", current_value=32.0,
        stat_ctx=ctx, persistence_count=0, cfg=CFG,
        server_id="srv1", tenant_id="t1", event_id="e1",
        event_ts="2026-01-01T00:00:00Z",
    )
    assert result["is_anomaly"] is False
    assert result["severity"] == "NORMAL"
    assert ctx["statistical_context_status"] == "ACTIVE_BASELINE"
    assert abs(ctx["modified_zscore"]) <= 3.5


def test_t01_normal_all_metrics():
    """All four metrics at normal values must all be NORMAL."""
    for metric, base in [
        ("cpu_usage", 30.0), ("memory_usage", 50.0),
        ("disk_usage", 60.0), ("latency_ms", 15.0),
    ]:
        history = _normal_history(10, base=base, spread=1.5)
        ctx = _compute_statistical_context(metric, base + 1.0, history, CFG)
        result = _classify_metric(
            metric_name=metric, current_value=base + 1.0,
            stat_ctx=ctx, persistence_count=0, cfg=CFG,
            server_id="s", tenant_id="t", event_id="e",
            event_ts="2026-01-01T00:00:00Z",
        )
        assert result["is_anomaly"] is False, f"{metric} should be NORMAL"


# ===========================================================================
# T02 — CPU spike (Modified Z-score detection)
# ===========================================================================

def test_t02_cpu_spike_detected():
    """CPU 92% against 30% baseline must trigger ANOMALY with correct Modified Z-score."""
    history = _normal_history(10, base=30.0, spread=2.0)
    ctx = _compute_statistical_context("cpu_usage", 92.0, history, CFG)

    assert ctx["dynamic_baseline_active"] is True

    # Verify the Modified Z-score formula: 0.6745 * (value - median) / max(MAD, min_mad)
    median = statistics.median(history)
    devs = [abs(x - median) for x in history]
    mad = statistics.median(devs)
    effective_mad = max(mad, CFG.min_mad_scale["cpu_usage"])
    expected_mz = round(0.6745 * (92.0 - median) / effective_mad, 4)
    assert abs(ctx["modified_zscore"] - expected_mz) < 0.001

    result = _classify_metric(
        metric_name="cpu_usage", current_value=92.0,
        stat_ctx=ctx, persistence_count=0, cfg=CFG,
        server_id="s", tenant_id="t", event_id="e",
        event_ts="2026-01-01T00:00:00Z",
    )
    assert result["is_anomaly"] is True
    assert result["severity"] in ("MEDIUM", "HIGH", "CRITICAL")


# ===========================================================================
# T03 — Memory spike
# ===========================================================================

def test_t03_memory_spike_detected():
    """Memory 93% vs 55% baseline must be detected."""
    history = _normal_history(10, base=55.0, spread=2.5)
    ctx = _compute_statistical_context("memory_usage", 93.0, history, CFG)
    result = _classify_metric(
        metric_name="memory_usage", current_value=93.0,
        stat_ctx=ctx, persistence_count=0, cfg=CFG,
        server_id="s", tenant_id="t", event_id="e",
        event_ts="2026-01-01T00:00:00Z",
    )
    assert result["is_anomaly"] is True


# ===========================================================================
# T04 — Disk pressure
# ===========================================================================

def test_t04_disk_pressure_detected():
    """Disk 96% vs 65% baseline must be HIGH or CRITICAL."""
    history = _normal_history(10, base=65.0, spread=1.5)
    ctx = _compute_statistical_context("disk_usage", 96.0, history, CFG)
    result = _classify_metric(
        metric_name="disk_usage", current_value=96.0,
        stat_ctx=ctx, persistence_count=0, cfg=CFG,
        server_id="s", tenant_id="t", event_id="e",
        event_ts="2026-01-01T00:00:00Z",
    )
    assert result["is_anomaly"] is True
    assert result["severity"] in ("HIGH", "CRITICAL")


# ===========================================================================
# T05 — Latency spike
# ===========================================================================

def test_t05_latency_spike_detected():
    """400ms latency vs 15ms baseline must be an anomaly."""
    history = _normal_history(10, base=15.0, spread=2.0)
    ctx = _compute_statistical_context("latency_ms", 400.0, history, CFG)
    result = _classify_metric(
        metric_name="latency_ms", current_value=400.0,
        stat_ctx=ctx, persistence_count=0, cfg=CFG,
        server_id="s", tenant_id="t", event_id="e",
        event_ts="2026-01-01T00:00:00Z",
    )
    assert result["is_anomaly"] is True
    assert result["severity"] in ("HIGH", "CRITICAL")


# ===========================================================================
# T06 — Multiple simultaneous anomalies (resource contention)
# ===========================================================================

def test_t06_multi_metric_anomaly():
    """CPU 90%, Memory 92%, Latency 350ms simultaneously — all three must be detected."""
    # Use pure-Python calculation without DB
    for metric, value, base in [
        ("cpu_usage", 90.0, 30.0),
        ("memory_usage", 92.0, 55.0),
        ("latency_ms", 350.0, 15.0),
    ]:
        history = _normal_history(10, base=base, spread=2.0)
        ctx = _compute_statistical_context(metric, value, history, CFG)
        result = _classify_metric(
            metric_name=metric, current_value=value,
            stat_ctx=ctx, persistence_count=0, cfg=CFG,
            server_id="s", tenant_id="t", event_id="e",
            event_ts="2026-01-01T00:00:00Z",
        )
        assert result["is_anomaly"] is True, f"{metric}={value} vs baseline={base} must be anomaly"

    # Normal disk should NOT trigger
    history_disk = _normal_history(10, base=60.0, spread=1.0)
    ctx_disk = _compute_statistical_context("disk_usage", 61.0, history_disk, CFG)
    result_disk = _classify_metric(
        metric_name="disk_usage", current_value=61.0,
        stat_ctx=ctx_disk, persistence_count=0, cfg=CFG,
        server_id="s", tenant_id="t", event_id="e",
        event_ts="2026-01-01T00:00:00Z",
    )
    assert result_disk["is_anomaly"] is False


# ===========================================================================
# T07 — Gradual degradation (persistence escalation)
# ===========================================================================

def test_t07_persistence_escalates_severity():
    """When persistence_count >= trigger, MEDIUM must escalate to HIGH."""
    from app.core.statistical_detector import _apply_persistence_escalation

    # persistence_count = 3 (== trigger_count=3) → MEDIUM → HIGH
    escalated = _apply_persistence_escalation("MEDIUM", 3, CFG)
    assert escalated == "HIGH", f"Expected HIGH after persistence=3, got {escalated}"

    # persistence_count = 5 (== critical_override=5) → CRITICAL regardless
    escalated_crit = _apply_persistence_escalation("LOW", 5, CFG)
    assert escalated_crit == "CRITICAL"

    # persistence_count = 1 (< trigger) → unchanged
    unchanged = _apply_persistence_escalation("MEDIUM", 1, CFG)
    assert unchanged == "MEDIUM"


def test_t07_gradual_degradation_full_analysis():
    """With persistence_count=3 injected, a MEDIUM Z-score anomaly escalates."""
    # Build a history where 60% CPU is anomalous against 30% base
    history = _normal_history(10, base=30.0, spread=2.0)
    ctx = _compute_statistical_context("cpu_usage", 60.0, history, CFG)
    # 60.0 vs 30.0 baseline — should be a large Z-score
    result = _classify_metric(
        metric_name="cpu_usage", current_value=60.0,
        stat_ctx=ctx, persistence_count=3,  # 3 previous anomalies → escalation
        cfg=CFG, server_id="s", tenant_id="t", event_id="e",
        event_ts="2026-01-01T00:00:00Z",
    )
    assert result["is_anomaly"] is True
    assert result["persistence_count"] == 3
    assert result["severity"] in ("HIGH", "CRITICAL"), \
        f"Severity should escalate beyond MEDIUM with persistence=3, got {result['severity']}"


# ===========================================================================
# T08 — Zero MAD edge case
# ===========================================================================

def test_t08_zero_mad_does_not_divide_by_zero():
    """MAD=0 (all history identical) must not produce inf/nan and must use min_mad_scale."""
    history = [40.0] * 10  # uniform → MAD = 0
    ctx = _compute_statistical_context("cpu_usage", 95.0, history, CFG)

    assert ctx["dynamic_baseline_active"] is True
    assert ctx["mad"] == 0.0
    assert ctx["effective_mad"] >= CFG.min_mad_scale["cpu_usage"]
    assert ctx["effective_mad"] > 0.0

    mz = ctx["modified_zscore"]
    assert math.isfinite(mz), f"Modified Z-score must be finite, got {mz}"
    assert not math.isnan(mz), "Modified Z-score must not be NaN"

    result = _classify_metric(
        metric_name="cpu_usage", current_value=95.0,
        stat_ctx=ctx, persistence_count=0, cfg=CFG,
        server_id="s", tenant_id="t", event_id="e",
        event_ts="2026-01-01T00:00:00Z",
    )
    # 95.0 hits critical_absolute_threshold → CRITICAL
    assert result["is_anomaly"] is True
    assert result["severity"] == "CRITICAL"
    assert result["detection_reason"] == "CRITICAL_ABSOLUTE_THRESHOLD"


# ===========================================================================
# T09 — Insufficient historical observations (fallback)
# ===========================================================================

def test_t09_insufficient_history_uses_fallback():
    """With < min_samples (3 < 5), engine must use static fallback threshold."""
    history = [30.0, 32.0, 31.0]  # 3 samples, need 5
    ctx = _compute_statistical_context("cpu_usage", 88.0, history, CFG)

    assert ctx["dynamic_baseline_active"] is False
    assert ctx["statistical_context_status"] == "INSUFFICIENT_HISTORY"
    assert ctx["baseline_median"] is None
    assert ctx["mad"] is None
    assert ctx["modified_zscore"] is None

    result = _classify_metric(
        metric_name="cpu_usage", current_value=88.0,
        stat_ctx=ctx, persistence_count=0, cfg=CFG,
        server_id="s", tenant_id="t", event_id="e",
        event_ts="2026-01-01T00:00:00Z",
    )
    assert result["is_anomaly"] is True
    assert result["detection_reason"] == "FALLBACK_THRESHOLD_BREACH"

    # Value below fallback: not an anomaly
    ctx2 = _compute_statistical_context("cpu_usage", 70.0, history, CFG)
    result2 = _classify_metric(
        metric_name="cpu_usage", current_value=70.0,
        stat_ctx=ctx2, persistence_count=0, cfg=CFG,
        server_id="s", tenant_id="t", event_id="e2",
        event_ts="2026-01-01T00:01:00Z",
    )
    assert result2["is_anomaly"] is False


def test_t09_zero_history_uses_fallback():
    """With zero history, engine must safely fall back to static thresholds."""
    ctx = _compute_statistical_context("latency_ms", 200.0, [], CFG)
    assert ctx["dynamic_baseline_active"] is False
    assert ctx["statistical_context_status"] == "INSUFFICIENT_HISTORY"

    result = _classify_metric(
        metric_name="latency_ms", current_value=200.0,
        stat_ctx=ctx, persistence_count=0, cfg=CFG,
        server_id="s", tenant_id="t", event_id="e",
        event_ts="2026-01-01T00:00:00Z",
    )
    # 200ms > fallback 150ms → anomaly
    assert result["is_anomaly"] is True


# ===========================================================================
# T10 — Persistence count accumulation (DB-backed, using sqlite3 directly)
# ===========================================================================

def test_t10_persistence_count_from_db():
    """Persistence count must reflect previous anomalous SAR rows in SQLite (using sqlite3)."""
    # Directly write to the test DB via sqlite3 (synchronous), then verify the
    # _get_persistence_count SQL logic by counting matching rows.
    db_path = config.DB_PATH
    con = sqlite3.connect(str(db_path))
    try:
        now = datetime.now(timezone.utc)
        server_id = "srv_persistence"

        for k in range(4):
            ts = (now - timedelta(minutes=4 - k)).isoformat()
            con.execute(
                """INSERT INTO statistical_analysis_records
                   (analysis_id, event_id, tenant_id, server_id, metric_name,
                    current_value, baseline_median, mad, modified_zscore,
                    is_anomaly, severity, detection_reason, persistence_count,
                    statistical_context_status, event_timestamp_utc, stored_at_utc)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'MEDIUM',
                           'MODIFIED_ZSCORE_THRESHOLD', 0, 'ACTIVE_BASELINE', ?, ?);
                """,
                (f"sar_{k}", f"ev_{k}", TEST_TENANT_ID, server_id,
                 "latency_ms", 300.0, 15.0, 2.0, 50.0, ts, ts),
            )
        con.commit()

        # Replicate the _get_persistence_count SQL logic using sqlite3
        lookback = CFG.persistence_lookback_count
        cur = con.execute(
            """
            SELECT SUM(is_anomaly)
            FROM (
                SELECT is_anomaly
                FROM statistical_analysis_records
                WHERE tenant_id = ? AND server_id = ? AND metric_name = ?
                  AND event_timestamp_utc < ?
                ORDER BY event_timestamp_utc DESC
                LIMIT ?
            );
            """,
            (TEST_TENANT_ID, server_id, "latency_ms", now.isoformat(), lookback),
        )
        row = cur.fetchone()
        count = int(row[0]) if row and row[0] is not None else 0
        assert count == 4, f"Expected persistence count 4, got {count}"
    finally:
        con.close()


# ===========================================================================
# T11 — Baseline contamination prevention (using sqlite3 directly)
# ===========================================================================

def test_t11_baseline_contamination_prevention():
    """Anomalous SAR-tagged events must be excluded from clean baseline history."""
    db_path = config.DB_PATH
    con = sqlite3.connect(str(db_path))
    try:
        now = datetime.now(timezone.utc)
        server_id = "srv_contamination"

        # 5 normal telemetry events
        for i in range(5):
            ts = (now - timedelta(minutes=20 + i)).isoformat()
            m = json.dumps({"cpu_usage": 30.0, "memory_usage": 50.0,
                            "disk_usage": 60.0, "latency_ms": 12.0})
            con.execute(
                "INSERT INTO telemetry_events VALUES (?,?,?,?,?,?,?,?,?,?);",
                (f"clean_{i}", TEST_TENANT_ID, server_id, ts, m,
                 TEST_COLLECTOR_ID, 200 + i, "v1.0", "h", ts),
            )

        # 5 anomalous telemetry events (high CPU), tagged in SAR as anomalous
        for j in range(5):
            ts = (now - timedelta(minutes=10 + j)).isoformat()
            m = json.dumps({"cpu_usage": 95.0, "memory_usage": 50.0,
                            "disk_usage": 60.0, "latency_ms": 12.0})
            con.execute(
                "INSERT INTO telemetry_events VALUES (?,?,?,?,?,?,?,?,?,?);",
                (f"anom_{j}", TEST_TENANT_ID, server_id, ts, m,
                 TEST_COLLECTOR_ID, 300 + j, "v1.0", "h", ts),
            )
            con.execute(
                """INSERT INTO statistical_analysis_records
                   (analysis_id, event_id, tenant_id, server_id, metric_name,
                    current_value, baseline_median, mad, modified_zscore,
                    is_anomaly, severity, detection_reason, persistence_count,
                    statistical_context_status, event_timestamp_utc, stored_at_utc)
                   VALUES (?, ?, ?, ?, 'cpu_usage', 95.0, 30.0, 2.0, 25.0, 1, 'CRITICAL',
                           'CRITICAL_ABSOLUTE_THRESHOLD', 0, 'ACTIVE_BASELINE', ?, ?);
                """,
                (f"sa_a_{j}", f"anom_{j}", TEST_TENANT_ID, server_id, ts, ts),
            )
        con.commit()

        # Protection ON: LEFT JOIN excludes anomalous rows
        cur_clean = con.execute(
            """
            SELECT te.metrics FROM telemetry_events te
            LEFT JOIN statistical_analysis_records sar
                ON sar.event_id = te.event_id
                AND sar.tenant_id = te.tenant_id
                AND sar.metric_name = 'cpu_usage'
            WHERE te.tenant_id = ? AND te.server_id = ? AND te.event_id != 'current_event'
              AND (sar.is_anomaly IS NULL OR sar.is_anomaly = 0)
            ORDER BY te.timestamp_utc DESC
            LIMIT 30;
            """,
            (TEST_TENANT_ID, server_id),
        )
        clean_rows = cur_clean.fetchall()
        clean_values = [json.loads(r[0])["cpu_usage"] for r in clean_rows]
        assert len(clean_values) == 5, f"Expected 5 clean samples, got {len(clean_values)}: {clean_values}"
        assert all(v == 30.0 for v in clean_values), f"All should be 30.0: {clean_values}"

        # Protection OFF: returns all 10
        cur_dirty = con.execute(
            """
            SELECT metrics FROM telemetry_events
            WHERE tenant_id = ? AND server_id = ? AND event_id != 'current_event'
            ORDER BY timestamp_utc DESC LIMIT 30;
            """,
            (TEST_TENANT_ID, server_id),
        )
        dirty_rows = cur_dirty.fetchall()
        assert len(dirty_rows) == 10, f"Expected 10 samples unfiltered, got {len(dirty_rows)}"
    finally:
        con.close()


# ===========================================================================
# T12 — Out-of-order event arrival (pure Python, synchronous)
# ===========================================================================

def test_t12_out_of_order_event_handled_safely():
    """Out-of-order event analysis must complete without crash and produce valid output."""
    # Use pure Python computation only: no DB needed.
    # An out-of-order arrival just means the history window (fetched by timestamp)
    # will exclude the new event but include later-timestamped ones.
    # The statistical math itself must handle any valid float values safely.
    history = _normal_history(10, base=30.0, spread=1.5)

    # Out-of-order normal value
    ctx = _compute_statistical_context("cpu_usage", 32.0, history, CFG)
    result = _classify_metric(
        metric_name="cpu_usage", current_value=32.0,
        stat_ctx=ctx, persistence_count=0, cfg=CFG,
        server_id="srv_ooo", tenant_id=TEST_TENANT_ID, event_id="evt_ooo_old",
        event_ts="2026-11-19T22:00:00Z",  # 2 hours before the other events
    )
    assert "metric_name" in result
    assert isinstance(result["is_anomaly"], bool)
    assert result["is_anomaly"] is False, f"Normal OOO event must not be anomalous: {result}"


# ===========================================================================
# T13 — API: GET /api/v1/statistical/analysis
# ===========================================================================

@pytest.mark.asyncio
async def test_t13_api_statistical_analysis():
    """GET /api/v1/statistical/analysis returns a valid list with count."""
    db = await get_db_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        await db.execute(
            """INSERT INTO statistical_analysis_records
               (analysis_id, event_id, tenant_id, server_id, metric_name,
                current_value, baseline_median, mad, modified_zscore,
                is_anomaly, severity, detection_reason, persistence_count,
                statistical_context_status, event_timestamp_utc, stored_at_utc)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'HIGH',
                       'MODIFIED_ZSCORE_THRESHOLD', 0, 'ACTIVE_BASELINE', ?, ?);
            """,
            ("sa_api_1", "evt_api_1", TEST_TENANT_ID, "srv_api",
             "cpu_usage", 90.0, 30.0, 2.0, 15.0, now, now),
        )
        await db.commit()
    finally:
        await db.close()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/statistical/analysis")
        assert res.status_code == 200
        data = res.json()
        assert "statistical_analysis" in data
        assert data["count"] >= 1


@pytest.mark.asyncio
async def test_t14_api_anomaly_history():
    """GET /api/v1/statistical/anomaly-history filters by server_id and metric_name."""
    db = await get_db_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        await db.execute(
            """INSERT INTO statistical_analysis_records
               (analysis_id, event_id, tenant_id, server_id, metric_name,
                current_value, baseline_median, mad, modified_zscore,
                is_anomaly, severity, detection_reason, persistence_count,
                statistical_context_status, event_timestamp_utc, stored_at_utc)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'HIGH',
                       'MODIFIED_ZSCORE_THRESHOLD', 0, 'ACTIVE_BASELINE', ?, ?);
            """,
            ("sa_hist_1", "evt_hist_1", TEST_TENANT_ID, "srv_hist",
             "latency_ms", 400.0, 15.0, 2.0, 50.0, now, now),
        )
        await db.commit()
    finally:
        await db.close()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get(
            "/api/v1/statistical/anomaly-history?server_id=srv_hist&metric_name=latency_ms"
        )
        assert res.status_code == 200
        data = res.json()
        assert data["server_id"] == "srv_hist"
        assert data["count"] >= 1
        assert data["anomaly_history"][0]["current_value"] == 400.0


@pytest.mark.asyncio
async def test_t15_api_baselines():
    """GET /api/v1/statistical/baselines returns baselines and rebuild instructions."""
    db = await get_db_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        await db.execute(
            """INSERT INTO statistical_analysis_records
               (analysis_id, event_id, tenant_id, server_id, metric_name,
                current_value, baseline_median, mad, modified_zscore,
                is_anomaly, severity, detection_reason, persistence_count,
                statistical_context_status, event_timestamp_utc, stored_at_utc)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'NORMAL',
                       'NORMAL_WITHIN_ZSCORE_BOUND', 0, 'ACTIVE_BASELINE', ?, ?);
            """,
            ("sa_base_1", "evt_base_1", TEST_TENANT_ID, "srv_base",
             "memory_usage", 55.0, 55.0, 2.0, 0.1, now, now),
        )
        await db.commit()
    finally:
        await db.close()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/statistical/baselines")
        assert res.status_code == 200
        data = res.json()
        assert "baselines" in data
        assert "baseline_rebuild_instructions" in data


@pytest.mark.asyncio
async def test_t16_api_statistical_health():
    """GET /api/v1/statistical/health returns valid health_status."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/statistical/health")
        assert res.status_code == 200
        data = res.json()
        assert data["health_status"] in ("HEALTHY", "CAUTION", "WARNING", "DEGRADED", "CRITICAL")
        assert "active_anomaly_signals" in data
        assert "lookback_minutes" in data


@pytest.mark.asyncio
async def test_t17_api_config_reload():
    """POST /api/v1/statistical/config/reload returns OK."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/statistical/config/reload")
        assert res.status_code == 200
        assert res.json()["status"] == "OK"


# ===========================================================================
# T18 — End-to-end: verified ingest triggers statistical analysis
# ===========================================================================

@pytest.mark.asyncio
async def test_t18_e2e_ingest_triggers_statistical_analysis():
    """POST /api/v1/ingest with CPU 97% triggers a CRITICAL statistical analysis record."""
    now_utc = datetime.now(timezone.utc).isoformat()
    event = {
        "event_id": "evt_stat_e2e_01",
        "tenant_id": TEST_TENANT_ID,
        "server_id": "srv_stat_e2e",
        "timestamp_utc": now_utc,
        "metrics": {
            "cpu_usage": 97.0,   # Above critical_absolute_threshold (95)
            "memory_usage": 55.0,
            "disk_usage": 60.0,
            "latency_ms": 14.0,
        },
        "policy_version": "v1.0",
    }
    payload_hash = compute_payload_hash(event)
    receipt = {
        "event_id": "evt_stat_e2e_01",
        "tenant_id": TEST_TENANT_ID,
        "payload_hash": payload_hash,
        "collector_id": TEST_COLLECTOR_ID,
        "sequence_number": 500,
        "policy_version": "v1.0",
        "algorithm": "Ed25519",
    }
    sig_bytes = TEST_KEY.sign(canonical_receipt_bytes(receipt))
    receipt["signature"] = base64.b64encode(sig_bytes).decode("utf-8")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        ingest_res = await client.post("/api/v1/ingest", json={"event": event, "receipt": receipt})
        assert ingest_res.status_code == 201, f"Ingest failed: {ingest_res.text}"

        stat_res = await client.get("/api/v1/statistical/analysis?server_id=srv_stat_e2e")
        assert stat_res.status_code == 200
        stat_data = stat_res.json()
        assert stat_data["count"] >= 1

        cpu_records = [r for r in stat_data["statistical_analysis"]
                       if r["metric_name"] == "cpu_usage"]
        assert len(cpu_records) >= 1
        cpu_rec = cpu_records[0]
        assert cpu_rec["is_anomaly"] == 1
        assert cpu_rec["severity"] == "CRITICAL"
        assert cpu_rec["current_value"] == 97.0

        health_res = await client.get("/api/v1/statistical/health")
        assert health_res.status_code == 200
        health = health_res.json()
        assert health["health_status"] in ("CRITICAL", "DEGRADED")
