"""DATACAT Tier 2 End-to-End Security Audit and Integration Testing Suite.

Implements all 12 rigorous security testing scenarios:
TEST 1: Valid Telemetry Verification & Ingestion
TEST 2: Sensitive & Unknown Fields Strict Rejection & Zero-Log Leakage
TEST 3: SHA-256 Canonical Hash Tampering Detection
TEST 4: Ed25519 Digital Signature Tampering Detection
TEST 5: Unregistered/Unknown Collector Rejection
TEST 6: Multi-Tenant Isolation & Query Scoping
TEST 7: Idempotent Duplicate Delivery Handling
TEST 8: Conflicting Event ID with Different Hash Rejection
TEST 9: Sequence Number Replay Conflict Rejection
TEST 10: Legitimate Out-of-Order Delivery & Event Time Ordering
TEST 11: Database Integrity, Constraints & Concurrent Submissions
TEST 12: Dashboard Validation & Zero Sensitive Data Exposure
"""
import asyncio
import base64
import json
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
from app.core.crypto import canonical_receipt_bytes, compute_payload_hash
from app.core.registry import registry
from app.db.database import INIT_SQL, get_db_connection
from app.main import app

AUDIT_DATA_DIR = config.BASE_DIR / ".test_audit_data"

# Test keypairs
KEY_TENANT_A = ed25519.Ed25519PrivateKey.generate()
PUB_KEY_TENANT_A = KEY_TENANT_A.public_key()

KEY_TENANT_B = ed25519.Ed25519PrivateKey.generate()
PUB_KEY_TENANT_B = KEY_TENANT_B.public_key()


@pytest.fixture(autouse=True)
def setup_security_audit_environment(monkeypatch):
    """Configures isolated test environment with multi-tenant collector registry."""
    if AUDIT_DATA_DIR.exists():
        shutil.rmtree(AUDIT_DATA_DIR, ignore_errors=True)
    AUDIT_DATA_DIR.mkdir(parents=True, exist_ok=True)

    test_db = AUDIT_DATA_DIR / "test_security.db"
    test_yaml = AUDIT_DATA_DIR / "test_collectors.yaml"
    pub_file_a = AUDIT_DATA_DIR / "collector_alpha_pub.pem"
    pub_file_b = AUDIT_DATA_DIR / "collector_beta_pub.pem"

    pub_bytes_a = PUB_KEY_TENANT_A.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_file_a.write_bytes(pub_bytes_a)

    pub_bytes_b = PUB_KEY_TENANT_B.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_file_b.write_bytes(pub_bytes_b)

    test_yaml.write_text(f"""
collectors:
  - collector_id: col_alpha_01
    tenant_id: hospital_alpha
    public_key_path: {str(pub_file_a).replace('\\', '/')}
    active: true
  - collector_id: col_beta_01
    tenant_id: hospital_beta
    public_key_path: {str(pub_file_b).replace('\\', '/')}
    active: true
""", encoding="utf-8")

    # Initialize schema
    con = sqlite3.connect(test_db)
    con.executescript(INIT_SQL)
    now_utc = datetime.now(timezone.utc).isoformat()
    con.execute(
        "INSERT INTO collectors VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("col_alpha_01", "hospital_alpha", str(pub_file_a), "ACTIVE", 0, now_utc, now_utc)
    )
    con.execute(
        "INSERT INTO collectors VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("col_beta_01", "hospital_beta", str(pub_file_b), "ACTIVE", 0, now_utc, now_utc)
    )
    con.commit()
    con.close()

    monkeypatch.setattr(config, "DB_PATH", test_db)
    monkeypatch.setattr(config, "COLLECTORS_CONFIG_PATH", test_yaml)
    monkeypatch.setattr(registry, "config_path", test_yaml)
    registry.reload()

    yield

    if AUDIT_DATA_DIR.exists():
        shutil.rmtree(AUDIT_DATA_DIR, ignore_errors=True)


def build_signed_payload(
    event_id: str,
    tenant_id: str = "hospital_alpha",
    server_id: str = "srv_alpha_icu",
    collector_id: str = "col_alpha_01",
    sequence_number: int = 1,
    metrics: dict = None,
    private_key: ed25519.Ed25519PrivateKey = KEY_TENANT_A,
    timestamp_utc: str = None,
    policy_version: str = "v1.0",
):
    """Builds a strictly valid signed telemetry event."""
    ts = timestamp_utc or datetime.now(timezone.utc).isoformat()
    m = metrics or {
        "cpu_usage": 35.0,
        "memory_usage": 45.0,
        "disk_usage": 55.0,
        "latency_ms": 12.5,
    }

    event = {
        "event_id": event_id,
        "tenant_id": tenant_id,
        "server_id": server_id,
        "timestamp_utc": ts,
        "metrics": m,
        "policy_version": policy_version,
    }

    payload_hash = compute_payload_hash(event)

    receipt = {
        "event_id": event_id,
        "tenant_id": tenant_id,
        "payload_hash": payload_hash,
        "collector_id": collector_id,
        "sequence_number": sequence_number,
        "policy_version": policy_version,
        "algorithm": "Ed25519",
    }

    sig_bytes = private_key.sign(canonical_receipt_bytes(receipt))
    receipt["signature"] = base64.b64encode(sig_bytes).decode("utf-8")

    return {"event": event, "receipt": receipt}


# ==============================================================================
# TEST 1: VALID TELEMETRY
# ==============================================================================
@pytest.mark.asyncio
async def test_01_valid_telemetry_flow():
    """Verify that a cryptographically signed event passes all 7 checks, is stored, and is queryable."""
    payload = build_signed_payload(event_id="sec_test_valid_01", sequence_number=1)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/ingest", json=payload)
        assert res.status_code == 201
        data = res.json()
        assert data["status"] == "ACCEPTED"
        assert data["event_id"] == "sec_test_valid_01"

        # Verify stored in database
        db = await get_db_connection()
        try:
            async with db.execute("SELECT * FROM telemetry_events WHERE event_id = ?", ("sec_test_valid_01",)) as cur:
                row = await cur.fetchone()
                assert row is not None
                assert row["server_id"] == "srv_alpha_icu"
        finally:
            await db.close()

        # Verify dashboard events endpoint can retrieve it
        res_events = await client.get("/api/v1/dashboard/events?tenant_id=hospital_alpha")
        assert res_events.status_code == 200
        events = res_events.json()["events"]
        assert any(e["event_id"] == "sec_test_valid_01" for e in events)


# ==============================================================================
# TEST 2: SENSITIVE AND UNKNOWN FIELDS
# ==============================================================================
@pytest.mark.asyncio
async def test_02_sensitive_and_unknown_fields_rejection(caplog):
    """Verify strict rejection of sensitive/unknown fields, no storage, and zero log exposure."""
    sensitive_name = "CONFIDENTIAL_PATIENT_DOE"
    sensitive_pass = "HIGHLY_SECRET_PASSWORD_999"
    nested_secret = "RESTRICTED_SSN_12345"

    payload = build_signed_payload(event_id="sec_test_sensitive_02", sequence_number=2)
    # Inject sensitive fields into event
    payload["event"]["patient_name"] = sensitive_name
    payload["event"]["password"] = sensitive_pass
    payload["event"]["medical_record"] = {"ssn": nested_secret}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with caplog.at_level("DEBUG"):
            res = await client.post("/api/v1/ingest", json=payload)

        # 1. Verify strict schema rejection
        assert res.status_code == 400
        assert res.json()["status"] == "INVALID_SCHEMA"

        # 2. Verify rejected payload is NOT stored as trusted telemetry
        db = await get_db_connection()
        try:
            async with db.execute("SELECT 1 FROM telemetry_events WHERE event_id = ?", ("sec_test_sensitive_02",)) as cur:
                assert await cur.fetchone() is None
        finally:
            await db.close()

        # 3. Verify sensitive values are NEVER written to application logs
        log_text = caplog.text
        assert sensitive_name not in log_text
        assert sensitive_pass not in log_text
        assert nested_secret not in log_text


# ==============================================================================
# TEST 3: HASH TAMPERING
# ==============================================================================
@pytest.mark.asyncio
async def test_03_hash_tampering_rejection():
    """Verify that altering telemetry metrics without updating hash triggers HASH_MISMATCH rejection."""
    payload = build_signed_payload(event_id="sec_test_tamper_hash_03", sequence_number=3)
    # Tamper with CPU usage in event
    payload["event"]["metrics"]["cpu_usage"] = 99.9

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/ingest", json=payload)
        assert res.status_code == 400
        assert res.json()["status"] == "HASH_MISMATCH"

        # Verify not inserted
        db = await get_db_connection()
        try:
            async with db.execute("SELECT 1 FROM telemetry_events WHERE event_id = ?", ("sec_test_tamper_hash_03",)) as cur:
                assert await cur.fetchone() is None
        finally:
            await db.close()


# ==============================================================================
# TEST 4: SIGNATURE TAMPERING
# ==============================================================================
@pytest.mark.asyncio
async def test_04_signature_tampering_rejection():
    """Verify that modifying any signed receipt field invalidates Ed25519 signature."""
    payload = build_signed_payload(event_id="sec_test_tamper_sig_04", sequence_number=4)
    # Tamper with signed receipt field (sequence number)
    payload["receipt"]["sequence_number"] = 9999

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/ingest", json=payload)
        assert res.status_code == 401
        assert res.json()["status"] == "INVALID_SIGNATURE"


# ==============================================================================
# TEST 5: UNKNOWN COLLECTOR
# ==============================================================================
@pytest.mark.asyncio
async def test_05_unknown_collector_rejection():
    """Verify rejection of telemetry claiming an unregistered collector identifier."""
    rogue_key = ed25519.Ed25519PrivateKey.generate()
    payload = build_signed_payload(
        event_id="sec_test_rogue_05",
        collector_id="rogue_collector_999",
        private_key=rogue_key,
        sequence_number=5,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/ingest", json=payload)
        assert res.status_code == 403
        assert res.json()["status"] == "UNKNOWN_COLLECTOR"


# ==============================================================================
# TEST 6: TENANT ISOLATION
# ==============================================================================
@pytest.mark.asyncio
async def test_06_tenant_isolation_and_cross_leakage():
    """Verify that queries scoped to Tenant A never leak Tenant B's telemetry or servers."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest Tenant A event
        p_a = build_signed_payload(
            event_id="evt_iso_alpha_1",
            tenant_id="hospital_alpha",
            server_id="srv_alpha_mri",
            collector_id="col_alpha_01",
            sequence_number=10,
            private_key=KEY_TENANT_A,
        )
        res_a = await client.post("/api/v1/ingest", json=p_a)
        assert res_a.status_code == 201

        # Ingest Tenant B event
        p_b = build_signed_payload(
            event_id="evt_iso_beta_1",
            tenant_id="hospital_beta",
            server_id="srv_beta_radiology",
            collector_id="col_beta_01",
            sequence_number=10,
            private_key=KEY_TENANT_B,
        )
        res_b = await client.post("/api/v1/ingest", json=p_b)
        assert res_b.status_code == 201

        # Query Tenant A infrastructure scope
        res_infra_a = await client.get("/api/v1/dashboard/infrastructure?tenant_id=hospital_alpha")
        assert res_infra_a.status_code == 200
        servers_a = [s["server_id"] for s in res_infra_a.json()["servers"]]
        assert "srv_alpha_mri" in servers_a
        assert "srv_beta_radiology" not in servers_a  # Strictly isolated!

        # Query Tenant B events scope
        res_events_b = await client.get("/api/v1/dashboard/events?tenant_id=hospital_beta")
        assert res_events_b.status_code == 200
        events_b = [e["event_id"] for e in res_events_b.json()["events"]]
        assert "evt_iso_beta_1" in events_b
        assert "evt_iso_alpha_1" not in events_b  # Strictly isolated!


# ==============================================================================
# TEST 7: DUPLICATE DELIVERY
# ==============================================================================
@pytest.mark.asyncio
async def test_07_duplicate_delivery_idempotency():
    """Verify that duplicate submission of identical event returns DUPLICATE (200) without double storage."""
    payload = build_signed_payload(event_id="sec_test_dup_07", sequence_number=20)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First delivery
        res1 = await client.post("/api/v1/ingest", json=payload)
        assert res1.status_code == 201
        assert res1.json()["status"] == "ACCEPTED"

        # Duplicate delivery
        res2 = await client.post("/api/v1/ingest", json=payload)
        assert res2.status_code == 200
        assert res2.json()["status"] == "DUPLICATE"

        # Verify only 1 record in database
        db = await get_db_connection()
        try:
            async with db.execute("SELECT COUNT(*) FROM telemetry_events WHERE event_id = ?", ("sec_test_dup_07",)) as cur:
                count = (await cur.fetchone())[0]
                assert count == 1
        finally:
            await db.close()


# ==============================================================================
# TEST 8: CONFLICTING EVENT
# ==============================================================================
@pytest.mark.asyncio
async def test_08_conflicting_event_rejection():
    """Verify rejection when an existing event ID is submitted with a conflicting payload."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First event
        p1 = build_signed_payload(
            event_id="sec_test_conflict_08",
            sequence_number=30,
            metrics={"cpu_usage": 10.0, "memory_usage": 20.0, "disk_usage": 30.0, "latency_ms": 5.0},
        )
        assert (await client.post("/api/v1/ingest", json=p1)).status_code == 201

        # Conflicting event with same event_id but different metrics and sequence
        p2 = build_signed_payload(
            event_id="sec_test_conflict_08",
            sequence_number=31,
            metrics={"cpu_usage": 90.0, "memory_usage": 80.0, "disk_usage": 70.0, "latency_ms": 50.0},
        )
        res = await client.post("/api/v1/ingest", json=p2)
        assert res.status_code == 409
        assert res.json()["status"] == "DUPLICATE_CONFLICT"


# ==============================================================================
# TEST 9: SEQUENCE NUMBER REUSE
# ==============================================================================
@pytest.mark.asyncio
async def test_09_sequence_number_reuse_rejection():
    """Verify rejection when a collector attempts to reuse a previously observed sequence number."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Sequence 40
        p1 = build_signed_payload(event_id="evt_seq_first", sequence_number=40)
        assert (await client.post("/api/v1/ingest", json=p1)).status_code == 201

        # Different event_id attempting to reuse sequence 40
        p2 = build_signed_payload(event_id="evt_seq_reused", sequence_number=40)
        res = await client.post("/api/v1/ingest", json=p2)
        assert res.status_code == 409
        assert res.json()["status"] == "SEQUENCE_CONFLICT"


# ==============================================================================
# TEST 10: OUT-OF-ORDER DELIVERY
# ==============================================================================
@pytest.mark.asyncio
async def test_10_out_of_order_delivery_and_time_ordering():
    """Verify that delayed events with unused sequence numbers are accepted and displayed in event-time order."""
    now = datetime.now(timezone.utc)
    ts_earlier = (now - timedelta(minutes=5)).isoformat()
    ts_later = now.isoformat()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Step 1: Submit later event first (Sequence 60)
        p_later = build_signed_payload(
            event_id="evt_time_later",
            server_id="srv_ooo_order",
            sequence_number=60,
            timestamp_utc=ts_later,
        )
        res1 = await client.post("/api/v1/ingest", json=p_later)
        assert res1.status_code == 201

        # Step 2: Submit delayed earlier event (Sequence 55 < 60)
        p_earlier = build_signed_payload(
            event_id="evt_time_earlier",
            server_id="srv_ooo_order",
            sequence_number=55,
            timestamp_utc=ts_earlier,
        )
        res2 = await client.post("/api/v1/ingest", json=p_earlier)
        assert res2.status_code == 201  # Successfully accepted!

        # Step 3: Verify event history returns events in event-time order (DESC)
        res_events = await client.get("/api/v1/dashboard/events?server_id=srv_ooo_order")
        assert res_events.status_code == 200
        events = res_events.json()["events"]
        assert len(events) == 2
        assert events[0]["event_id"] == "evt_time_later"
        assert events[1]["event_id"] == "evt_time_earlier"


# ==============================================================================
# TEST 11: DATABASE INTEGRITY & CONCURRENT DUPLICATES
# ==============================================================================
@pytest.mark.asyncio
async def test_11_database_integrity_and_concurrency():
    """Verify unique database constraints, transaction atomicity, and safe concurrent submissions."""
    db = await get_db_connection()
    try:
        # 1. Direct duplicate insert on PRIMARY KEY (tenant_id, event_id) must fail with IntegrityError
        with pytest.raises(sqlite3.IntegrityError):
            await db.execute(
                "INSERT INTO telemetry_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("evt_raw_1", "hospital_alpha", "srv_1", "2026-11-20T16:00:00Z", "{}", "col_alpha_01", 80, "v1.0", "h1", "2026-11-20T16:00:00Z")
            )
            await db.execute(
                "INSERT INTO telemetry_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("evt_raw_1", "hospital_alpha", "srv_1", "2026-11-20T16:00:00Z", "{}", "col_alpha_01", 81, "v1.0", "h2", "2026-11-20T16:00:00Z")
            )
        await db.rollback()

        # 2. Direct duplicate insert on UNIQUE (collector_id, sequence_number) must fail
        with pytest.raises(sqlite3.IntegrityError):
            await db.execute(
                "INSERT INTO telemetry_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("evt_raw_2a", "hospital_alpha", "srv_1", "2026-11-20T16:00:00Z", "{}", "col_alpha_01", 85, "v1.0", "h1", "2026-11-20T16:00:00Z")
            )
            await db.execute(
                "INSERT INTO telemetry_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("evt_raw_2b", "hospital_alpha", "srv_1", "2026-11-20T16:00:00Z", "{}", "col_alpha_01", 85, "v1.0", "h2", "2026-11-20T16:00:00Z")
            )
        await db.rollback()
    finally:
        await db.close()

    # 3. Concurrent duplicate submissions across async workers
    p_concurrent = build_signed_payload(event_id="evt_concurrent_race", sequence_number=90)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        responses = await asyncio.gather(
            client.post("/api/v1/ingest", json=p_concurrent),
            client.post("/api/v1/ingest", json=p_concurrent),
            client.post("/api/v1/ingest", json=p_concurrent),
        )
        status_codes = [r.status_code for r in responses]
        # At least one accepted (201), remaining handled cleanly as duplicate (200) or race resolved
        assert 201 in status_codes
        for code in status_codes:
            assert code in [200, 201]

        # Verify exactly 1 record persisted in SQLite
        db = await get_db_connection()
        try:
            async with db.execute("SELECT COUNT(*) FROM telemetry_events WHERE event_id = ?", ("evt_concurrent_race",)) as cur:
                count = (await cur.fetchone())[0]
                assert count == 1
        finally:
            await db.close()


# ==============================================================================
# TEST 12: DASHBOARD VALIDATION & SENSITIVE DATA CHECK
# ==============================================================================
@pytest.mark.asyncio
async def test_12_dashboard_validation_and_zero_sensitive_data():
    """Verify that dashboard endpoints retrieve database records and never expose private keys or raw logs."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest a healthy event and an anomaly event
        p_healthy = build_signed_payload(
            event_id="evt_dash_healthy",
            server_id="srv_dash_1",
            sequence_number=110,
            metrics={"cpu_usage": 30.0, "memory_usage": 40.0, "disk_usage": 50.0, "latency_ms": 15.0},
        )
        assert (await client.post("/api/v1/ingest", json=p_healthy)).status_code == 201

        p_critical = build_signed_payload(
            event_id="evt_dash_critical",
            server_id="srv_dash_2",
            sequence_number=111,
            metrics={"cpu_usage": 97.0, "memory_usage": 92.0, "disk_usage": 50.0, "latency_ms": 210.0},
        )
        assert (await client.post("/api/v1/ingest", json=p_critical)).status_code == 201

        # 1. Overview API
        res_overview = await client.get("/api/v1/dashboard/overview")
        assert res_overview.status_code == 200
        overview_data = res_overview.json()
        assert overview_data["verified_events"] >= 2
        assert overview_data["overall_health"] == "POOR"

        # 2. Infrastructure API - Check Health States
        res_infra = await client.get("/api/v1/dashboard/infrastructure")
        assert res_infra.status_code == 200
        servers = {s["server_id"]: s for s in res_infra.json()["servers"]}
        assert servers["srv_dash_1"]["health_status"] == "EXCELLENT"
        assert servers["srv_dash_2"]["health_status"] == "POOR"

        # 3. Anomalies API
        res_anom = await client.get("/api/v1/anomalies?server_id=srv_dash_2")
        assert res_anom.status_code == 200
        anomalies = res_anom.json()["anomalies"]
        assert len(anomalies) >= 1

        # 4. Incidents & Recommendations Traceability
        res_inc = await client.get("/api/v1/incidents?server_id=srv_dash_2")
        assert res_inc.status_code == 200
        incidents = res_inc.json()["incidents"]
        assert len(incidents) >= 1
        inc = incidents[0]
        assert "recommendations" in inc
        assert len(inc["recommendations"]) >= 1

        # 5. Zero Sensitive Data Exposure Check across all endpoints
        endpoints = [
            "/api/v1/dashboard/overview",
            "/api/v1/dashboard/infrastructure",
            "/api/v1/dashboard/collectors",
            "/api/v1/dashboard/verifications",
            "/api/v1/dashboard/events",
            "/api/v1/anomalies",
            "/api/v1/incidents",
            "/api/v1/recommendations",
        ]
        for ep in endpoints:
            res_ep = await client.get(ep)
            assert res_ep.status_code == 200
            text_lower = res_ep.text.lower()
            assert "private_key" not in text_lower
            assert "-----begin" not in text_lower
            assert "password" not in text_lower
            assert "patient" not in text_lower
