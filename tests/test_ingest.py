"""
Tests for POST /api/v1/ingest.

All tests use real cryptographic operations (Ed25519 & SHA-256).
Verifies rejection handling, privacy guarantees, tenant consistency, concurrency,
request size limits, and sanitization of rejection audits.
"""
import asyncio
import json
import uuid
import aiosqlite
import pytest
from backend.config import DB_PATH, MAX_PAYLOAD_BYTES
from tests.conftest import build_valid_event

pytestmark = pytest.mark.asyncio


async def test_ingest_valid_event(client, ed25519_keypair, tenant_id):
    """Happy path: valid hash, valid signature, registered key -> 202 accepted."""
    private_key, pub_b64 = ed25519_keypair
    body = build_valid_event(private_key, pub_b64, tenant_id)

    resp = await client.post(
        "/api/v1/ingest",
        json=body,
        headers={"X-Tenant-ID": tenant_id},
    )
    assert resp.status_code == 202, resp.text
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["hash_verified"] is True
    assert data["signature_verified"] is True
    assert data["duplicate"] is False
    assert "stored_at" in data


async def test_ingest_duplicate_event(client, ed25519_keypair, tenant_id):
    """Submitting the same (tenant_id, event_id) twice -> second gets 409."""
    private_key, pub_b64 = ed25519_keypair
    shared_id = str(uuid.uuid4())
    body = build_valid_event(private_key, pub_b64, tenant_id, event_id=shared_id)

    r1 = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert r1.status_code == 202

    r2 = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert r2.status_code == 409
    assert r2.json()["reason"] == "duplicate_event"


async def test_ingest_concurrent_duplicates(client, ed25519_keypair, tenant_id):
    """Concurrent submissions of the same event -> exactly one 202, others 409."""
    private_key, pub_b64 = ed25519_keypair
    shared_id = str(uuid.uuid4())
    body = build_valid_event(private_key, pub_b64, tenant_id, event_id=shared_id)

    tasks = [
        client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
        for _ in range(5)
    ]
    responses = await asyncio.gather(*tasks)

    status_codes = [r.status_code for r in responses]
    assert status_codes.count(202) == 1
    assert status_codes.count(409) == 4


async def test_ingest_bad_hash(client, ed25519_keypair, tenant_id):
    """Tampered payload hash -> 400 hash_mismatch."""
    private_key, pub_b64 = ed25519_keypair
    body = build_valid_event(private_key, pub_b64, tenant_id, tamper_hash=True)

    resp = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert resp.status_code == 400
    assert resp.json()["reason"] == "hash_mismatch"


async def test_ingest_bad_signature(client, ed25519_keypair, tenant_id):
    """Invalid signature bytes -> 400 invalid_signature."""
    private_key, pub_b64 = ed25519_keypair
    body = build_valid_event(private_key, pub_b64, tenant_id, tamper_signature=True)

    resp = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert resp.status_code == 400
    assert resp.json()["reason"] == "invalid_signature"


async def test_ingest_wrong_tenant_in_signature(client, ed25519_keypair, tenant_id):
    """Domain-separated signature signed over different tenant -> 400 invalid_signature."""
    private_key, pub_b64 = ed25519_keypair
    wrong_tid = str(uuid.uuid4())
    body = build_valid_event(private_key, pub_b64, tenant_id, wrong_tenant_in_sig=wrong_tid)

    resp = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert resp.status_code == 400
    assert resp.json()["reason"] == "invalid_signature"


async def test_ingest_unknown_collector(client, ed25519_keypair):
    """Unregistered tenant_id -> 400 unknown_collector."""
    private_key, pub_b64 = ed25519_keypair
    unregistered_tenant = str(uuid.uuid4())
    body = build_valid_event(private_key, pub_b64, unregistered_tenant)

    resp = await client.post(
        "/api/v1/ingest",
        json=body,
        headers={"X-Tenant-ID": unregistered_tenant},
    )
    assert resp.status_code == 400
    assert resp.json()["reason"] == "unknown_collector"


async def test_ingest_untrusted_key(client, ed25519_keypair, tenant_id):
    """Key in request body does not match registered trusted key -> 400 untrusted_key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import base64
    private_key, _ = ed25519_keypair
    rogue_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    rogue_b64 = base64.b64encode(rogue_key).decode()

    body = build_valid_event(private_key, rogue_b64, tenant_id, wrong_pubkey_b64=rogue_b64)

    resp = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert resp.status_code == 400
    assert resp.json()["reason"] == "untrusted_key"


async def test_ingest_header_tenant_mismatch(client, ed25519_keypair, tenant_id):
    """X-Tenant-ID header does not match body.tenant_id -> 400 tenant_mismatch."""
    private_key, pub_b64 = ed25519_keypair
    body = build_valid_event(private_key, pub_b64, tenant_id)

    other_tenant = str(uuid.uuid4())
    resp = await client.post(
        "/api/v1/ingest",
        json=body,
        headers={"X-Tenant-ID": other_tenant},
    )
    assert resp.status_code == 400
    assert resp.json()["reason"] == "tenant_mismatch"


async def test_ingest_missing_header_tenant(client, ed25519_keypair, tenant_id):
    """Missing X-Tenant-ID header -> 400 tenant_mismatch."""
    private_key, pub_b64 = ed25519_keypair
    body = build_valid_event(private_key, pub_b64, tenant_id)

    resp = await client.post("/api/v1/ingest", json=body)
    assert resp.status_code == 400
    assert resp.json()["reason"] == "tenant_mismatch"


async def test_ingest_missing_required_fields(client, tenant_id):
    """Malformed schema -> 422 Unprocessable Entity."""
    resp = await client.post(
        "/api/v1/ingest",
        json={"tenant_id": tenant_id},
        headers={"X-Tenant-ID": tenant_id},
    )
    assert resp.status_code == 422


async def test_ingest_payload_size_limit_exceeded(client, ed25519_keypair, tenant_id):
    """Request exceeding MAX_PAYLOAD_BYTES is rejected with 413."""
    private_key, pub_b64 = ed25519_keypair
    body = build_valid_event(private_key, pub_b64, tenant_id)
    # Inflate body with large string > 1 MB
    body["event"]["payload"]["bloat"] = "X" * (MAX_PAYLOAD_BYTES + 1024)

    raw_json = json.dumps(body)
    resp = await client.post(
        "/api/v1/ingest",
        content=raw_json,
        headers={"X-Tenant-ID": tenant_id, "Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    assert resp.json()["reason"] == "payload_too_large"


async def test_rejection_audit_sanitization(client, ed25519_keypair, tenant_id):
    """
    Malicious or non-standard characters in rejection metadata (e.g. XSS payloads)
    must be strictly filtered and sanitized before writing to rejection_audit.
    """
    private_key, pub_b64 = ed25519_keypair
    raw_bad_event_id = "evt-<script>alert('xss')</script>-123"
    raw_bad_host = "host'; DROP TABLE events; --"
    raw_bad_type = "type<img src=x onerror=alert(1)>"

    body = build_valid_event(
        private_key,
        pub_b64,
        tenant_id,
        event_id=raw_bad_event_id,
        event_type=raw_bad_type,
        source_host=raw_bad_host,
        tamper_signature=True,
    )

    resp = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert resp.status_code == 400

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM rejection_audit WHERE tenant_id = ? ORDER BY id DESC LIMIT 1",
            (tenant_id,),
        ) as cur:
            row = await cur.fetchone()
            assert row is not None
            # Verify script tags and SQL injection strings are filtered out
            assert "<script>" not in row["event_id"]
            assert "DROP TABLE" not in row["source_host"]
            assert "<img" not in row["event_type"]


async def test_rejected_data_privacy(client, ed25519_keypair, tenant_id):
    """
    Privacy verification:
    1. Rejection is stored in rejection_audit with sanitized metadata only.
    2. Raw payload, signature, and keys are NEVER stored in rejection_audit.
    3. Rejected event is NEVER inserted into the events table.
    """
    private_key, pub_b64 = ed25519_keypair
    tampered_evt_id = str(uuid.uuid4())
    body = build_valid_event(private_key, pub_b64, tenant_id, event_id=tampered_evt_id, tamper_hash=True)

    resp = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert resp.status_code == 400

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Check events table: MUST NOT EXIST
        async with db.execute("SELECT * FROM events WHERE event_id = ?", (tampered_evt_id,)) as cur:
            event_row = await cur.fetchone()
            assert event_row is None, "Rejected event must not be present in events table"

        # Check rejection_audit: MUST EXIST with sanitized metadata only
        async with db.execute(
            "SELECT * FROM rejection_audit WHERE event_id = ?", (tampered_evt_id,)
        ) as cur:
            audit_row = await cur.fetchone()
            assert audit_row is not None
            assert audit_row["rejected_reason"] == "hash_mismatch"
            assert audit_row["tenant_id"] == tenant_id
            columns = audit_row.keys()
            assert "payload" not in columns
            assert "signature" not in columns
            assert "public_key" not in columns
