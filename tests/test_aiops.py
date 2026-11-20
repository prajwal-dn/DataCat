"""Deterministic integration and functional tests for DATACAT AIOps Intelligence Engine."""
import base64
import os
import shutil
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

import app.config as config
from app.core.aiops import AIOpsEngine, MIN_SAMPLES_FOR_BASELINE, FALLBACK_THRESHOLDS
from app.core.crypto import canonical_receipt_bytes, compute_payload_hash
from app.core.registry import registry
from app.db.database import INIT_SQL, get_db_connection
from app.main import app

TEST_DATA_DIR = config.BASE_DIR / ".test_aiops_data"
TEST_KEY = ed25519.Ed25519PrivateKey.generate()
TEST_PUB_KEY = TEST_KEY.public_key()


@pytest.fixture(autouse=True)
def setup_aiops_test_environment(monkeypatch):
    """Configures isolated test environment for AIOps engine tests."""
    if TEST_DATA_DIR.exists():
        shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)
    TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)

    test_db = TEST_DATA_DIR / "test_datacat_aiops.db"
    test_yaml = TEST_DATA_DIR / "test_collectors_aiops.yaml"
    test_pub_file = TEST_DATA_DIR / "test_collector_pub.pem"

    pub_bytes = TEST_PUB_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    test_pub_file.write_bytes(pub_bytes)

    test_yaml.write_text(f"""
collectors:
  - collector_id: aiops_collector_1
    tenant_id: hospital_01
    public_key_path: {str(test_pub_file).replace('\\', '/')}
    active: true
""", encoding="utf-8")

    # Initialize SQLite schema
    con = sqlite3.connect(test_db)
    con.executescript(INIT_SQL)
    now_utc = datetime.now(timezone.utc).isoformat()
    con.execute(
        "INSERT INTO collectors VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("aiops_collector_1", "hospital_01", str(test_pub_file), "ACTIVE", 0, now_utc, now_utc)
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


def test_baseline_engine_fallback_when_insufficient_samples():
    """Verifies that with < MIN_SAMPLES_FOR_BASELINE, dynamic baseline is inactive and fallback is used."""
    past_cpu = [40.0, 42.0, 41.5]  # 3 samples < 5
    baseline = AIOpsEngine.calculate_baseline("cpu_usage", past_cpu)

    assert baseline["dynamic_baseline_active"] is False
    assert baseline["sample_count"] == 3
    assert baseline["expected_baseline"] == FALLBACK_THRESHOLDS["cpu_usage"]
    assert baseline["baseline_type"] == "configurable_fallback_threshold"


def test_baseline_engine_statistical_calculation_with_sufficient_samples():
    """Verifies that with >= MIN_SAMPLES_FOR_BASELINE, rolling mean, median and stdev are computed."""
    past_cpu = [40.0, 42.0, 44.0, 40.0, 44.0, 42.0]  # 6 samples >= 5
    baseline = AIOpsEngine.calculate_baseline("cpu_usage", past_cpu)

    assert baseline["dynamic_baseline_active"] is True
    assert baseline["sample_count"] == 6
    assert baseline["mean"] == 42.0
    assert baseline["median"] == 42.0
    assert baseline["stdev"] > 0.0
    assert baseline["baseline_type"] == "statistical_rolling_baseline"


@pytest.mark.asyncio
async def test_anomaly_detection_with_fallback_threshold():
    """Tests anomaly detection when history is insufficient and fallback threshold triggers."""
    db = await get_db_connection()
    try:
        now_utc = datetime.now(timezone.utc).isoformat()
        # Event with 88.0% CPU (exceeding 85.0% fallback)
        test_event = {
            "event_id": "evt_aiops_1",
            "tenant_id": "hospital_01",
            "server_id": "srv_icu_fallback",
            "timestamp_utc": now_utc,
            "metrics": {
                "cpu_usage": 88.0,
                "memory_usage": 40.0,
                "disk_usage": 50.0,
                "latency_ms": 15.0,
            },
            "policy_version": "v1.0",
        }

        anomalies = await AIOpsEngine.analyze_event(db, test_event)
        assert len(anomalies) == 1
        anom = anomalies[0]

        # Verify all required fields
        assert "anomaly_id" in anom
        assert anom["tenant_id"] == "hospital_01"
        assert anom["server_id"] == "srv_icu_fallback"
        assert anom["metric_name"] == "cpu_usage"
        assert anom["observed_value"] == 88.0
        assert anom["expected_baseline"] == 85.0
        assert anom["severity"] in ["MEDIUM", "HIGH", "CRITICAL"]
        assert "detection_timestamp" in anom
        assert "explanation" in anom
        assert "fallback threshold" in anom["explanation"]
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_dynamic_zscore_anomaly_and_anti_spam():
    """Tests dynamic Z-score anomaly detection after historical baseline is established and checks anti-spam."""
    db = await get_db_connection()
    try:
        now = datetime.now(timezone.utc)
        server_id = "srv_cardiology_01"

        # Seed 6 baseline events around 30% CPU
        for i in range(6):
            ts = (now - timedelta(minutes=10 - i)).isoformat()
            await db.execute(
                """
                INSERT INTO telemetry_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    f"evt_hist_{i}", "hospital_01", server_id, ts,
                    '{"cpu_usage": 30.0, "memory_usage": 35.0, "disk_usage": 40.0, "latency_ms": 10.0}',
                    "aiops_collector_1", i + 1, "v1.0", "hash", ts
                )
            )
        await db.commit()

        # Now send a spike to 78.0% CPU (significantly above 30.0% baseline mean)
        spike_event = {
            "event_id": "evt_spike_1",
            "tenant_id": "hospital_01",
            "server_id": server_id,
            "timestamp_utc": now.isoformat(),
            "metrics": {
                "cpu_usage": 78.0,
                "memory_usage": 35.0,
                "disk_usage": 40.0,
                "latency_ms": 10.0,
            },
            "policy_version": "v1.0",
        }

        anomalies = await AIOpsEngine.analyze_event(db, spike_event)
        assert len(anomalies) == 1
        anom = anomalies[0]
        assert anom["metric_name"] == "cpu_usage"
        assert anom["baseline_type"] == "statistical_zscore"
        assert "standard deviations above" in anom["explanation"]

        # Anti-spam check: sending an identical spike immediately afterwards within 120s must be suppressed
        second_spike = dict(spike_event, event_id="evt_spike_2")
        suppressed_anomalies = await AIOpsEngine.analyze_event(db, second_spike)
        # Should be suppressed (0 new anomalies created)
        assert len(suppressed_anomalies) == 0
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_event_correlation_into_single_incident():
    """Verifies that concurrent CPU, Memory, and Latency anomalies are correlated into ONE incident."""
    db = await get_db_connection()
    try:
        now_utc = datetime.now(timezone.utc).isoformat()
        server_id = "srv_er_saturation"

        # Multi-signal spike event (CPU 92%, Memory 89%, Latency 220ms)
        multi_spike = {
            "event_id": "evt_multi_1",
            "tenant_id": "hospital_01",
            "server_id": server_id,
            "timestamp_utc": now_utc,
            "metrics": {
                "cpu_usage": 92.0,     # Exceeds fallback 85%
                "memory_usage": 89.0,  # Exceeds fallback 85%
                "disk_usage": 40.0,
                "latency_ms": 220.0,   # Exceeds fallback 150ms
            },
            "policy_version": "v1.0",
        }

        anomalies = await AIOpsEngine.analyze_event(db, multi_spike)
        assert len(anomalies) == 3  # CPU, Memory, Latency anomalies detected

        # Verify ONE correlated incident was stored in incidents table
        async with db.execute("SELECT * FROM incidents WHERE server_id = ?;", (server_id,)) as cur:
            incidents = await cur.fetchall()
            assert len(incidents) == 1
            inc = dict(incidents[0])
            assert inc["severity"] == "CRITICAL"
            assert "Full-Stack Server Degradation" in inc["title"]
            assert inc["correlated_anomalies_count"] == 3

            # Verify recommendations are grounded in metrics
            import json
            rec = json.loads(inc["recommendations"])
            assert rec["affected_server"] == server_id
            assert len(rec["investigation_steps"]) >= 2
            assert len(rec["contributing_metrics"]) == 3
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_aiops_api_endpoints():
    """Tests the new AIOps endpoints: /anomalies, /incidents, /incidents/{id}, /recommendations."""
    # Seed an anomaly and incident into the test database
    db = await get_db_connection()
    try:
        now_utc = datetime.now(timezone.utc).isoformat()
        await db.execute(
            """
            INSERT INTO anomalies VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN');
            """,
            ("anom_test_1", "hospital_01", "srv_api_01", "cpu_usage", 95.0, 40.0, "CRITICAL", now_utc, "High CPU", "evt_1")
        )
        await db.execute(
            """
            INSERT INTO incidents VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, 1, ?, ?);
            """,
            (
                "inc_test_1", "hospital_01", "srv_api_01", "CPU Saturation Detected", "CRITICAL",
                now_utc, '["cpu_usage"]', "Sustained high load",
                '{"what_happened": "High CPU", "affected_server": "srv_api_01", "investigation_steps": ["Check processes"]}',
                now_utc, now_utc
            )
        )
        await db.commit()
    finally:
        await db.close()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. GET /api/v1/anomalies
        res1 = await client.get("/api/v1/anomalies")
        assert res1.status_code == 200
        data1 = res1.json()
        assert data1["count"] >= 1
        assert data1["anomalies"][0]["server_id"] == "srv_api_01"

        # 2. GET /api/v1/incidents
        res2 = await client.get("/api/v1/incidents")
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["count"] >= 1
        assert data2["incidents"][0]["incident_id"] == "inc_test_1"

        # 3. GET /api/v1/incidents/{incident_id}
        res3 = await client.get("/api/v1/incidents/inc_test_1")
        assert res3.status_code == 200
        data3 = res3.json()
        assert data3["title"] == "CPU Saturation Detected"
        assert data3["severity"] == "CRITICAL"

        # 4. GET /api/v1/recommendations
        res4 = await client.get("/api/v1/recommendations")
        assert res4.status_code == 200
        data4 = res4.json()
        assert data4["count"] >= 1
        assert data4["recommendations"][0]["affected_server"] == "srv_api_01"


@pytest.mark.asyncio
async def test_end_to_end_ingestion_triggers_aiops():
    """Verifies that submitting a verified event via POST /api/v1/ingest automatically triggers AIOps."""
    # Create signed event with high CPU
    now_utc = datetime.now(timezone.utc).isoformat()
    event = {
        "event_id": "evt_aiops_e2e_1",
        "tenant_id": "hospital_01",
        "server_id": "srv_e2e_icu",
        "timestamp_utc": now_utc,
        "metrics": {
            "cpu_usage": 96.0,  # Exceeds fallback
            "memory_usage": 45.0,
            "disk_usage": 50.0,
            "latency_ms": 12.0,
        },
        "policy_version": "v1.0",
    }
    payload_hash = compute_payload_hash(event)
    receipt = {
        "event_id": "evt_aiops_e2e_1",
        "tenant_id": "hospital_01",
        "payload_hash": payload_hash,
        "collector_id": "aiops_collector_1",
        "sequence_number": 100,
        "policy_version": "v1.0",
        "algorithm": "Ed25519",
    }
    sig_bytes = TEST_KEY.sign(canonical_receipt_bytes(receipt))
    receipt["signature"] = base64.b64encode(sig_bytes).decode("utf-8")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest
        res_ingest = await client.post("/api/v1/ingest", json={"event": event, "receipt": receipt})
        assert res_ingest.status_code == 201

        # Check that an anomaly was automatically created
        res_anom = await client.get("/api/v1/anomalies?server_id=srv_e2e_icu")
        assert res_anom.status_code == 200
        anomalies = res_anom.json()["anomalies"]
        assert len(anomalies) == 1
        assert anomalies[0]["observed_value"] == 96.0

        # Check that a correlated incident was generated
        res_inc = await client.get("/api/v1/incidents?server_id=srv_e2e_icu")
        assert res_inc.status_code == 200
        incidents = res_inc.json()["incidents"]
        assert len(incidents) == 1
        assert "CPU" in incidents[0]["title"]
