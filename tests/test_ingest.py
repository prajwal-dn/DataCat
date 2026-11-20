"""End-to-end integration tests for DATACAT Tier 2 Ingestion API and security rules."""
import base64
import os
import shutil
import sqlite3
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

import app.config as config
from app.core.crypto import canonical_receipt_bytes, compute_payload_hash
from app.core.registry import registry
from app.db.database import INIT_SQL
from app.main import app

# Generate ephemeral test keypair for test_collector_1
TEST_PRIVATE_KEY = ed25519.Ed25519PrivateKey.generate()
TEST_PUBLIC_KEY = TEST_PRIVATE_KEY.public_key()

TEST_DATA_DIR = config.BASE_DIR / ".test_data"


@pytest.fixture(autouse=True)
def setup_test_environment(monkeypatch):
    """Configures isolated workspace-local test database and collector configuration."""
    if TEST_DATA_DIR.exists():
        shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)
    TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)

    test_db = TEST_DATA_DIR / "test_datacat.db"
    test_yaml = TEST_DATA_DIR / "test_collectors.yaml"
    test_pub_key = TEST_DATA_DIR / "test_collector_pub.pem"

    pub_bytes = TEST_PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    test_pub_key.write_bytes(pub_bytes)

    test_yaml.write_text(f"""
collectors:
  - collector_id: test_collector_1
    tenant_id: hospital_01
    public_key_path: {str(test_pub_key).replace('\\', '/')}
    active: true
  - collector_id: inactive_collector
    tenant_id: hospital_01
    public_key_path: {str(test_pub_key).replace('\\', '/')}
    active: false
""", encoding="utf-8")

    # Initialize SQLite tables
    con = sqlite3.connect(test_db)
    con.executescript(INIT_SQL)
    now_utc = "2026-11-20T16:00:00Z"
    con.execute(
        "INSERT INTO collectors (collector_id, tenant_id, public_key_path, status, last_seen_seq, created_at_utc) VALUES (?, ?, ?, ?, 0, ?)",
        ("test_collector_1", "hospital_01", str(test_pub_key), "ACTIVE", now_utc),
    )
    con.execute(
        "INSERT INTO collectors (collector_id, tenant_id, public_key_path, status, last_seen_seq, created_at_utc) VALUES (?, ?, ?, ?, 0, ?)",
        ("inactive_collector", "hospital_01", str(test_pub_key), "SUSPENDED", now_utc),
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


def create_signed_payload(
    event_id: str = "evt_100",
    tenant_id: str = "hospital_01",
    collector_id: str = "test_collector_1",
    sequence_number: int = 1,
    cpu_usage: float = 25.5,
    private_key: ed25519.Ed25519PrivateKey = TEST_PRIVATE_KEY,
    tamper_hash: bool = False,
    extra_field_in_event: bool = False,
):
    event = {
        "event_id": event_id,
        "tenant_id": tenant_id,
        "server_id": "srv_icu_01",
        "timestamp_utc": "2026-11-20T16:00:00Z",
        "metrics": {
            "cpu_usage": cpu_usage,
            "memory_usage": 50.0,
            "disk_usage": 40.0,
            "latency_ms": 15.2,
        },
        "policy_version": "v1.0",
    }
    if extra_field_in_event:
        event["unauthorized_field"] = "malicious_data"

    payload_hash = compute_payload_hash(event)
    if tamper_hash:
        payload_hash = "f" * 64

    receipt = {
        "event_id": event_id,
        "tenant_id": tenant_id,
        "payload_hash": payload_hash,
        "collector_id": collector_id,
        "sequence_number": sequence_number,
        "policy_version": "v1.0",
        "algorithm": "Ed25519",
    }

    sig_bytes = private_key.sign(canonical_receipt_bytes(receipt))
    receipt["signature"] = base64.b64encode(sig_bytes).decode("utf-8")

    return {"event": event, "receipt": receipt}


@pytest.mark.asyncio
async def test_health_check_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert data["database"] == "connected"


@pytest.mark.asyncio
async def test_valid_ingestion_flow():
    payload = create_signed_payload(event_id="evt_valid_1", sequence_number=1)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/ingest", json=payload)
        assert res.status_code == 201
        data = res.json()
        assert data["status"] == "ACCEPTED"
        assert data["event_id"] == "evt_valid_1"


@pytest.mark.asyncio
async def test_duplicate_idempotent_event():
    payload = create_signed_payload(event_id="evt_dup_1", sequence_number=2)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res1 = await client.post("/api/v1/ingest", json=payload)
        assert res1.status_code == 201

        # Resending same event ID with identical payload and hash
        res2 = await client.post("/api/v1/ingest", json=payload)
        assert res2.status_code == 200
        data = res2.json()
        assert data["status"] == "DUPLICATE"


@pytest.mark.asyncio
async def test_duplicate_event_with_conflicting_hash():
    payload1 = create_signed_payload(event_id="evt_conflict_1", sequence_number=3, cpu_usage=20.0)
    payload2 = create_signed_payload(event_id="evt_conflict_1", sequence_number=4, cpu_usage=99.0)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res1 = await client.post("/api/v1/ingest", json=payload1)
        assert res1.status_code == 201

        res2 = await client.post("/api/v1/ingest", json=payload2)
        assert res2.status_code == 409
        data = res2.json()
        assert data["status"] == "DUPLICATE_CONFLICT"


@pytest.mark.asyncio
async def test_sequence_number_reuse_rejection():
    # Send event 1 with sequence number 5
    p1 = create_signed_payload(event_id="evt_seq_1", sequence_number=5)
    # Send different event with same sequence number 5
    p2 = create_signed_payload(event_id="evt_seq_2", sequence_number=5)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res1 = await client.post("/api/v1/ingest", json=p1)
        assert res1.status_code == 201

        res2 = await client.post("/api/v1/ingest", json=p2)
        assert res2.status_code == 409
        data = res2.json()
        assert data["status"] == "SEQUENCE_CONFLICT"


@pytest.mark.asyncio
async def test_out_of_order_event_accepted():
    # Send sequence 10, then sequence 8 (both unused)
    p_future = create_signed_payload(event_id="evt_seq_10", sequence_number=10)
    p_delayed = create_signed_payload(event_id="evt_seq_8", sequence_number=8)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res1 = await client.post("/api/v1/ingest", json=p_future)
        assert res1.status_code == 201

        res2 = await client.post("/api/v1/ingest", json=p_delayed)
        assert res2.status_code == 201
        data = res2.json()
        assert data["status"] == "ACCEPTED"


@pytest.mark.asyncio
async def test_tampered_payload_hash_mismatch():
    payload = create_signed_payload(event_id="evt_tamper_hash", sequence_number=15, tamper_hash=True)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/ingest", json=payload)
        assert res.status_code == 400
        data = res.json()
        assert data["status"] == "HASH_MISMATCH"


@pytest.mark.asyncio
async def test_invalid_signature_rejection():
    # Sign with a different, unauthorized private key
    unauthorized_key = ed25519.Ed25519PrivateKey.generate()
    payload = create_signed_payload(event_id="evt_bad_sig", sequence_number=20, private_key=unauthorized_key)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/ingest", json=payload)
        assert res.status_code == 401
        data = res.json()
        assert data["status"] == "INVALID_SIGNATURE"


@pytest.mark.asyncio
async def test_unknown_or_inactive_collector():
    # Unknown collector
    p_unknown = create_signed_payload(event_id="evt_unknown", collector_id="unregistered_collector", sequence_number=25)
    # Inactive collector
    p_inactive = create_signed_payload(event_id="evt_inactive", collector_id="inactive_collector", sequence_number=26)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res1 = await client.post("/api/v1/ingest", json=p_unknown)
        assert res1.status_code == 403
        assert res1.json()["status"] == "UNKNOWN_COLLECTOR"

        res2 = await client.post("/api/v1/ingest", json=p_inactive)
        assert res2.status_code == 403
        assert res2.json()["status"] == "UNKNOWN_COLLECTOR"


@pytest.mark.asyncio
async def test_tenant_mismatch_rejection():
    payload = create_signed_payload(event_id="evt_wrong_tenant", tenant_id="rogue_tenant", sequence_number=30)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/ingest", json=payload)
        assert res.status_code == 403
        assert res.json()["status"] == "TENANT_MISMATCH"


@pytest.mark.asyncio
async def test_strict_extra_field_rejection():
    payload = create_signed_payload(event_id="evt_extra_field", sequence_number=35, extra_field_in_event=True)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/ingest", json=payload)
        assert res.status_code == 400
        assert res.json()["status"] == "INVALID_SCHEMA"


@pytest.mark.asyncio
async def test_metric_out_of_range_rejection():
    payload = create_signed_payload(event_id="evt_range_err", sequence_number=40, cpu_usage=150.0)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/ingest", json=payload)
        assert res.status_code == 400
        assert res.json()["status"] == "INVALID_SCHEMA"
