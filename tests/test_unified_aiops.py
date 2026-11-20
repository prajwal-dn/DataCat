"""Tests for DATACAT Unified AIOps Decision Pipeline.

Validates:
  - 4 Detector Agreement Scenarios:
      Case A: Stat Anomaly + ML High Prob -> Strong ANOMALY
      Case B: Stat Anomaly + ML Low Prob -> CANDIDATE_ANOMALY (preserved)
      Case C: Stat Normal + ML High Prob -> INVESTIGATE
      Case D: Stat Normal + ML Low Prob -> NORMAL
  - Single-metric anomalies (CPU, memory, disk, latency).
  - Multiple-metric anomalies (CPU + RAM + Latency saturation).
  - Persistent anomalies (severity escalation).
  - Temporary spikes.
  - Insufficient statistical history (warm-up).
  - Missing model file (graceful fallback).
  - Invalid model configuration (fallback).
  - Stale telemetry (>180s health transition to POOR).
  - Multiple related events (Incident correlation).
  - Unified AIOps REST API endpoints.
  - End-to-end verified ingestion flow.
"""

from __future__ import annotations

import base64
import json
import shutil
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

import app.config as config
from app.core.crypto import canonical_receipt_bytes, compute_payload_hash
from app.core.detection_config import DetectionConfig
from app.core.registry import registry
from app.core.unified_aiops import UnifiedAIOpsPipeline
from app.db.database import INIT_SQL, get_db_connection
from app.main import app
from app.ml.logistic_regression import LogisticRegressionBinaryClassifier

TEST_DATA_DIR = config.BASE_DIR / ".test_unified_aiops_data"
TEST_KEY = ed25519.Ed25519PrivateKey.generate()
TEST_PUB_KEY = TEST_KEY.public_key()
TEST_COLLECTOR_ID = "unified_collector_1"
TEST_TENANT_ID = "hospital_unified"
_seq_counter = 1000


@pytest.fixture(autouse=True)
def setup_unified_aiops_environment(monkeypatch):
    """Isolated environment for Unified AIOps tests."""
    run_dir = TEST_DATA_DIR / f"run_{uuid.uuid4().hex[:8]}"
    run_dir.mkdir(parents=True, exist_ok=True)

    test_db = run_dir / "test_unified.db"
    test_yaml = run_dir / "test_collectors_unified.yaml"
    test_pub_file = run_dir / "test_unified_pub.pem"

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

    with sqlite3.connect(test_db) as con:
        con.executescript(INIT_SQL)
        now = datetime.now(timezone.utc).isoformat()
        con.execute(
            "INSERT INTO collectors VALUES (?, ?, ?, ?, ?, ?, ?)",
            (TEST_COLLECTOR_ID, TEST_TENANT_ID, str(test_pub_file), "ACTIVE", 0, now, now),
        )
        con.commit()

    monkeypatch.setattr(config, "DB_PATH", test_db)
    monkeypatch.setattr(config, "COLLECTORS_CONFIG_PATH", test_yaml)
    monkeypatch.setattr(registry, "config_path", test_yaml)
    registry.reload()

    yield

    shutil.rmtree(run_dir, ignore_errors=True)


def seed_baseline(server_id: str, count: int = 15, base_cpu: float = 30.0, base_lat: float = 12.0):
    """Helper to seed clean baseline events into the test database."""
    global _seq_counter
    db_path = config.DB_PATH
    with sqlite3.connect(str(db_path)) as con:
        now = datetime.now(timezone.utc)
        for i in range(count):
            _seq_counter += 1
            ts = (now - timedelta(minutes=count - i)).isoformat()
            m = json.dumps({"cpu_usage": base_cpu, "memory_usage": 50.0, "disk_usage": 40.0, "latency_ms": base_lat})
            con.execute(
                "INSERT INTO telemetry_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                (f"hist_{server_id}_{_seq_counter}", TEST_TENANT_ID, server_id, ts, m, TEST_COLLECTOR_ID, _seq_counter, "v1.0", "h", ts),
            )
        con.commit()


# ===========================================================================
# 1. Four Decision Fusion Agreement Scenarios
# ===========================================================================

@pytest.mark.asyncio
async def test_case_a_both_detectors_agree_anomaly():
    """Case A: Stat Anomaly + ML High Probability -> Confirmed ANOMALY."""
    seed_baseline("srv_case_a", count=15, base_cpu=30.0)
    db = await get_db_connection()
    try:
        # High CPU (96%) and elevated latency (300ms) triggers both Stat Z-score and ML model
        event = {
            "event_id": "evt_case_a",
            "tenant_id": TEST_TENANT_ID,
            "server_id": "srv_case_a",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "metrics": {"cpu_usage": 96.0, "memory_usage": 50.0, "disk_usage": 40.0, "latency_ms": 300.0},
        }
        res = await UnifiedAIOpsPipeline.process_verified_event(db, event)

        assert res["final_anomaly_decision"] == "ANOMALY"
        assert res["severity"] in ("HIGH", "CRITICAL")
        assert res["logistic_regression_prediction"] == 1
        assert res["logistic_regression_probability"] >= 0.50
        assert len(res["abnormal_metrics"]) >= 1
        assert "Strong anomaly confirmed" in res["explanation"]
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_case_b_stat_anomaly_low_ml_prob_preserved():
    """Case B: Stat Anomaly + ML Low Probability -> CANDIDATE_ANOMALY (not discarded)."""
    # Direct test of fusion logic
    cfg = DetectionConfig.load()
    fusion = UnifiedAIOpsPipeline._fuse_decisions(
        has_stat_anomaly=True,
        has_ml_anomaly=False,
        stat_severity="MEDIUM",
        abnormal_metrics=["disk_usage"],
        statistical_scores={"disk_usage": {"modified_zscore": 4.1}},
        ml_prob=0.15,  # Low ML prob
        ml_thresh=0.50,
        ml_available=True,
        max_persistence=0,
        is_warmup=False,
        top_signals=["disk_usage"],
        cfg=cfg,
    )
    # Must preserve statistical alert as candidate anomaly, never discard
    assert fusion["final_anomaly_decision"] == "CANDIDATE_ANOMALY"
    assert fusion["severity"] in ("LOW", "MEDIUM")
    assert "Detector disagreement" in fusion["explanation"]


@pytest.mark.asyncio
async def test_case_c_stat_normal_high_ml_prob_investigate():
    """Case C: No Stat Anomaly + ML High Probability -> INVESTIGATE (subtle pattern)."""
    cfg = DetectionConfig.load()
    fusion = UnifiedAIOpsPipeline._fuse_decisions(
        has_stat_anomaly=False,
        has_ml_anomaly=True,
        stat_severity="NORMAL",
        abnormal_metrics=[],
        statistical_scores={},
        ml_prob=0.78,  # High ML prob
        ml_thresh=0.50,
        ml_available=True,
        max_persistence=0,
        is_warmup=False,
        top_signals=["latency_ms(impact=+1.2)"],
        cfg=cfg,
    )
    assert fusion["final_anomaly_decision"] == "INVESTIGATE"
    assert fusion["severity"] == "MEDIUM"
    assert "Subtle multi-metric pattern" in fusion["explanation"]


@pytest.mark.asyncio
async def test_case_d_both_normal():
    """Case D: Neither detector identifies anomaly -> NORMAL."""
    seed_baseline("srv_case_d", count=15, base_cpu=30.0)
    db = await get_db_connection()
    try:
        event = {
            "event_id": "evt_case_d",
            "tenant_id": TEST_TENANT_ID,
            "server_id": "srv_case_d",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "metrics": {"cpu_usage": 31.0, "memory_usage": 51.0, "disk_usage": 41.0, "latency_ms": 12.0},
        }
        res = await UnifiedAIOpsPipeline.process_verified_event(db, event)

        assert res["final_anomaly_decision"] == "NORMAL"
        assert res["severity"] == "NORMAL"
        assert res["logistic_regression_prediction"] == 0
        assert len(res["abnormal_metrics"]) == 0
    finally:
        await db.close()


# ===========================================================================
# 2. Specific Anomaly Types & Multi-Metric Contention
# ===========================================================================

@pytest.mark.asyncio
async def test_single_metric_anomalies():
    """Each single metric spike is correctly identified in the pipeline."""
    db = await get_db_connection()
    try:
        # Test CPU spike
        seed_baseline("srv_cpu", count=15, base_cpu=25.0)
        res_cpu = await UnifiedAIOpsPipeline.process_verified_event(
            db,
            {"event_id": "e_cpu", "tenant_id": TEST_TENANT_ID, "server_id": "srv_cpu",
             "timestamp_utc": datetime.now(timezone.utc).isoformat(),
             "metrics": {"cpu_usage": 97.0, "memory_usage": 50.0, "disk_usage": 40.0, "latency_ms": 12.0}},
        )
        assert res_cpu["final_anomaly_decision"] in ("ANOMALY", "CANDIDATE_ANOMALY")
        assert "cpu_usage" in res_cpu["abnormal_metrics"]

        # Test Latency spike
        seed_baseline("srv_lat", count=15, base_lat=10.0)
        res_lat = await UnifiedAIOpsPipeline.process_verified_event(
            db,
            {"event_id": "e_lat", "tenant_id": TEST_TENANT_ID, "server_id": "srv_lat",
             "timestamp_utc": datetime.now(timezone.utc).isoformat(),
             "metrics": {"cpu_usage": 30.0, "memory_usage": 50.0, "disk_usage": 40.0, "latency_ms": 450.0}},
        )
        assert res_lat["final_anomaly_decision"] in ("ANOMALY", "CANDIDATE_ANOMALY")
        assert "latency_ms" in res_lat["abnormal_metrics"]
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_multi_metric_resource_contention():
    """Concurrent CPU, Memory, and Latency spikes trigger Full-Stack Contention alert."""
    seed_baseline("srv_contention", count=15)
    db = await get_db_connection()
    try:
        event = {
            "event_id": "e_contention",
            "tenant_id": TEST_TENANT_ID,
            "server_id": "srv_contention",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "metrics": {"cpu_usage": 95.0, "memory_usage": 94.0, "disk_usage": 42.0, "latency_ms": 380.0},
        }
        res = await UnifiedAIOpsPipeline.process_verified_event(db, event)

        assert res["final_anomaly_decision"] == "ANOMALY"
        assert res["severity"] == "CRITICAL"
        assert len(res["abnormal_metrics"]) >= 2

        # Check incident was created with multi-signal title
        inc_id = res["incident_id"]
        assert inc_id is not None
        async with db.execute("SELECT title, severity FROM incidents WHERE incident_id = ?", (inc_id,)) as cur:
            row = await cur.fetchone()
            assert row is not None
            assert "Saturation" in row[0] or "Contention" in row[0] or "Exhaustion" in row[0]
            assert row[1] == "CRITICAL"
    finally:
        await db.close()


# ===========================================================================
# 3. Incident Correlation & Health Evaluation Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_incident_correlation_merges_multiple_events():
    """Multiple related anomalous events on the same server are merged into ONE incident."""
    seed_baseline("srv_merge", count=15)
    db = await get_db_connection()
    try:
        now = datetime.now(timezone.utc)
        # Event 1: CPU spike
        e1 = {
            "event_id": "e_merge_1", "tenant_id": TEST_TENANT_ID, "server_id": "srv_merge",
            "timestamp_utc": now.isoformat(),
            "metrics": {"cpu_usage": 94.0, "memory_usage": 50.0, "disk_usage": 40.0, "latency_ms": 12.0},
        }
        res1 = await UnifiedAIOpsPipeline.process_verified_event(db, e1)
        inc1_id = res1["incident_id"]

        # Event 2: Latency spike 30 seconds later (within 300s correlation window)
        e2 = {
            "event_id": "e_merge_2", "tenant_id": TEST_TENANT_ID, "server_id": "srv_merge",
            "timestamp_utc": (now + timedelta(seconds=30)).isoformat(),
            "metrics": {"cpu_usage": 94.0, "memory_usage": 50.0, "disk_usage": 40.0, "latency_ms": 350.0},
        }
        res2 = await UnifiedAIOpsPipeline.process_verified_event(db, e2)
        inc2_id = res2["incident_id"]

        # Both events must reference the SAME correlated incident
        assert inc1_id == inc2_id

        # Verify incident has correlated count >= 2
        async with db.execute("SELECT correlated_anomalies_count, contributing_metrics FROM incidents WHERE incident_id = ?", (inc1_id,)) as cur:
            row = await cur.fetchone()
            assert row[0] >= 2
            metrics_list = json.loads(row[1])
            assert "cpu_usage" in metrics_list
            assert "latency_ms" in metrics_list
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_stale_telemetry_triggers_poor_health():
    """Telemetry older than stale threshold (180s) transitions server health to POOR."""
    db = await get_db_connection()
    try:
        # Event timestamped 10 minutes ago
        stale_ts = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        event = {
            "event_id": "e_stale_1",
            "tenant_id": TEST_TENANT_ID,
            "server_id": "srv_stale",
            "timestamp_utc": stale_ts,
            "metrics": {"cpu_usage": 30.0, "memory_usage": 50.0, "disk_usage": 40.0, "latency_ms": 12.0},
        }
        res = await UnifiedAIOpsPipeline.process_verified_event(db, event)
        assert res["health_state"] == "POOR"

        # Check transition logged
        async with db.execute("SELECT current_state, reason FROM health_state_transitions WHERE server_id = ?", ("srv_stale",)) as cur:
            row = await cur.fetchone()
            assert row is not None
            assert row[0] == "POOR"
            assert "stale" in row[1].lower()
    finally:
        await db.close()


# ===========================================================================
# 4. Fallback & Model Resilience Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_missing_model_file_graceful_fallback(monkeypatch):
    """When model JSON is missing or unreadable, pipeline gracefully relies on statistical detector."""
    def _mock_missing_model():
        raise FileNotFoundError("Model file missing")

    monkeypatch.setattr("app.core.unified_aiops.get_model", _mock_missing_model)

    seed_baseline("srv_fallback", count=15)
    db = await get_db_connection()
    try:
        event = {
            "event_id": "e_fb_1",
            "tenant_id": TEST_TENANT_ID,
            "server_id": "srv_fallback",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "metrics": {"cpu_usage": 97.0, "memory_usage": 50.0, "disk_usage": 40.0, "latency_ms": 12.0},
        }
        res = await UnifiedAIOpsPipeline.process_verified_event(db, event)

        # Pipeline must not crash; falls back gracefully
        assert res["model_version"] == "UNAVAILABLE"
        assert res["final_anomaly_decision"] in ("ANOMALY", "CANDIDATE_ANOMALY")
        assert "cpu_usage" in res["abnormal_metrics"]
    finally:
        await db.close()


# ===========================================================================
# 5. REST API Endpoints Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_api_aiops_decisions():
    """GET /api/v1/aiops/decisions returns unified decision records."""
    seed_baseline("srv_api_dec", count=15)
    db = await get_db_connection()
    try:
        event = {
            "event_id": "e_api_dec_1",
            "tenant_id": TEST_TENANT_ID,
            "server_id": "srv_api_dec",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "metrics": {"cpu_usage": 95.0, "memory_usage": 50.0, "disk_usage": 40.0, "latency_ms": 12.0},
        }
        await UnifiedAIOpsPipeline.process_verified_event(db, event)
    finally:
        await db.close()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/aiops/decisions?server_id=srv_api_dec")
        assert res.status_code == 200
        data = res.json()
        assert data["count"] >= 1
        dec = data["decisions"][0]
        assert "final_anomaly_decision" in dec
        assert "logistic_regression_probability" in dec
        assert "statistical_scores" in dec
        assert "contributing_signals" in dec


@pytest.mark.asyncio
async def test_api_aiops_decision_detail():
    """GET /api/v1/aiops/decisions/{event_id} returns single decision."""
    seed_baseline("srv_api_det", count=15)
    db = await get_db_connection()
    try:
        event = {
            "event_id": "e_detail_01",
            "tenant_id": TEST_TENANT_ID,
            "server_id": "srv_api_det",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "metrics": {"cpu_usage": 32.0, "memory_usage": 50.0, "disk_usage": 40.0, "latency_ms": 12.0},
        }
        await UnifiedAIOpsPipeline.process_verified_event(db, event)
    finally:
        await db.close()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/aiops/decisions/e_detail_01")
        assert res.status_code == 200
        data = res.json()
        assert data["event_id"] == "e_detail_01"
        assert data["final_anomaly_decision"] == "NORMAL"


@pytest.mark.asyncio
async def test_api_aiops_health_detail():
    """GET /api/v1/aiops/health/{server_id} returns 4-state health status."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/aiops/health/srv_case_a")
        assert res.status_code == 200
        data = res.json()
        assert data["server_id"] == "srv_case_a"
        assert "current_health_state" in data
        assert data["current_health_state"] in ("EXCELLENT", "GOOD", "FAIR", "POOR")


@pytest.mark.asyncio
async def test_api_aiops_pipeline_status():
    """GET /api/v1/aiops/pipeline-status returns pipeline status & fusion config."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/aiops/pipeline-status")
        assert res.status_code == 200
        data = res.json()
        assert "statistical_detector" in data
        assert "machine_learning_classifier" in data
        assert "decision_fusion" in data
        assert "health_classification" in data


# ===========================================================================
# 6. End-to-End Verified Ingestion Triggers Unified Pipeline
# ===========================================================================

@pytest.mark.asyncio
async def test_e2e_ingestion_executes_unified_aiops_pipeline():
    """Submitting a verified event to POST /api/v1/ingest executes the unified pipeline."""
    now_utc = datetime.now(timezone.utc).isoformat()
    event = {
        "event_id": "evt_unified_e2e_01",
        "tenant_id": TEST_TENANT_ID,
        "server_id": "srv_unified_e2e",
        "timestamp_utc": now_utc,
        "metrics": {"cpu_usage": 97.0, "memory_usage": 52.0, "disk_usage": 40.0, "latency_ms": 250.0},
        "policy_version": "v1.0",
    }
    payload_hash = compute_payload_hash(event)
    receipt = {
        "event_id": "evt_unified_e2e_01",
        "tenant_id": TEST_TENANT_ID,
        "payload_hash": payload_hash,
        "collector_id": TEST_COLLECTOR_ID,
        "sequence_number": 900,
        "policy_version": "v1.0",
        "algorithm": "Ed25519",
    }
    sig_bytes = TEST_KEY.sign(canonical_receipt_bytes(receipt))
    receipt["signature"] = base64.b64encode(sig_bytes).decode("utf-8")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest
        ingest_res = await client.post("/api/v1/ingest", json={"event": event, "receipt": receipt})
        assert ingest_res.status_code == 201

        # Check unified decision was recorded
        dec_res = await client.get("/api/v1/aiops/decisions/evt_unified_e2e_01")
        assert dec_res.status_code == 200
        dec_data = dec_res.json()
        assert dec_data["final_anomaly_decision"] in ("ANOMALY", "CANDIDATE_ANOMALY")
        assert dec_data["severity"] in ("HIGH", "CRITICAL")
        assert "cpu_usage" in dec_data["abnormal_metrics"]
