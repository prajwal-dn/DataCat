"""
Tests for POST /api/v1/ingest.

All cases use a real Ed25519 keypair (generated in conftest.py).
No cryptographic mocking.
"""
import uuid
import pytest
import pytest_asyncio


pytestmark = pytest.mark.asyncio


async def test_ingest_valid_event(client, ed25519_keypair, tenant_id):
    """Happy path: valid hash + valid signature → 202 accepted."""
    from tests.conftest import build_valid_event
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
    """Submitting the same event_id twice → second gets 409."""
    from tests.conftest import build_valid_event
    private_key, pub_b64 = ed25519_keypair
    shared_id = str(uuid.uuid4())
    body = build_valid_event(private_key, pub_b64, tenant_id, event_id=shared_id)

    r1 = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert r1.status_code == 202

    r2 = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert r2.status_code == 409
    assert r2.json()["reason"] == "duplicate_event"


async def test_ingest_bad_hash(client, ed25519_keypair, tenant_id):
    """Tampered hash → 400 hash_mismatch."""
    from tests.conftest import build_valid_event
    private_key, pub_b64 = ed25519_keypair
    body = build_valid_event(private_key, pub_b64, tenant_id, tamper_hash=True)

    resp = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert resp.status_code == 400
    assert resp.json()["reason"] == "hash_mismatch"


async def test_ingest_bad_signature(client, ed25519_keypair, tenant_id):
    """Valid hash, invalid signature → 400 invalid_signature."""
    from tests.conftest import build_valid_event
    private_key, pub_b64 = ed25519_keypair
    body = build_valid_event(private_key, pub_b64, tenant_id, tamper_signature=True)

    resp = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert resp.status_code == 400
    assert resp.json()["reason"] == "invalid_signature"


async def test_ingest_wrong_tenant_in_signature(client, ed25519_keypair, tenant_id):
    """
    Signature signed over wrong_tenant:hash → fails even if hash is correct.
    This validates tenant-binding protection.
    """
    from tests.conftest import build_valid_event
    private_key, pub_b64 = ed25519_keypair
    body = build_valid_event(
        private_key, pub_b64, tenant_id,
        wrong_tenant_in_sig="00000000-0000-0000-0000-000000000000",
    )

    resp = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert resp.status_code == 400
    assert resp.json()["reason"] == "invalid_signature"


async def test_ingest_unknown_tenant(client, ed25519_keypair):
    """Tenant not in trusted_keys → 400 unknown_collector."""
    from tests.conftest import build_valid_event
    private_key, pub_b64 = ed25519_keypair
    unknown_tenant = str(uuid.uuid4())
    body = build_valid_event(private_key, pub_b64, unknown_tenant)
    body["tenant_id"] = unknown_tenant
    body["event"]["event_id"] = str(uuid.uuid4())

    resp = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": unknown_tenant})
    assert resp.status_code == 400
    assert resp.json()["reason"] == "unknown_collector"


async def test_ingest_header_body_tenant_mismatch(client, ed25519_keypair, tenant_id):
    """X-Tenant-ID header ≠ body tenant_id → 400 tenant_mismatch."""
    from tests.conftest import build_valid_event
    private_key, pub_b64 = ed25519_keypair
    body = build_valid_event(private_key, pub_b64, tenant_id)

    resp = await client.post(
        "/api/v1/ingest",
        json=body,
        headers={"X-Tenant-ID": "different-tenant-id"},
    )
    assert resp.status_code == 400


async def test_ingest_missing_required_fields(client, tenant_id):
    """Missing required fields → 422 validation error."""
    resp = await client.post(
        "/api/v1/ingest",
        json={"tenant_id": tenant_id},
        headers={"X-Tenant-ID": tenant_id},
    )
    assert resp.status_code == 422


async def test_rejected_event_has_no_payload_in_db(client, ed25519_keypair, tenant_id):
    """
    Privacy rule: rejected events must not store the payload in the DB.
    """
    import aiosqlite
    from backend.config import DB_PATH
    from tests.conftest import build_valid_event

    private_key, pub_b64 = ed25519_keypair
    body = build_valid_event(private_key, pub_b64, tenant_id, tamper_hash=True)
    evt_id = body["event"]["event_id"]

    resp = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert resp.status_code == 400

    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT payload FROM events WHERE event_id = ?", (evt_id,)
        ) as cur:
            row = await cur.fetchone()

    # row may not exist (hash tamper before dedup insert) OR payload must be NULL
    if row is not None:
        assert row[0] is None, "Rejected event must not store payload"
