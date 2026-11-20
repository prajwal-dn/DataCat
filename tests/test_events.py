"""
Tests for GET /api/v1/events, /stats, /incidents, /health.
Enforces strict tenant authentication and authorization.
"""
import uuid
import pytest
from backend.database import register_tenant_token
from tests.conftest import build_valid_event

pytestmark = pytest.mark.asyncio


async def test_health_returns_ok(client):
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("ok", "degraded")
    assert "version" in data
    assert "db" in data
    assert isinstance(data["uptime_seconds"], (int, float))


async def test_dashboard_serves_html(client):
    resp = await client.get("/dashboard")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")


async def test_events_requires_token(client, tenant_id):
    """Omitting Authorization header on /events returns 401."""
    resp = await client.get(f"/api/v1/events?tenant_id={tenant_id}")
    assert resp.status_code == 401


async def test_events_invalid_token(client, tenant_id):
    """Providing invalid token on /events returns 401."""
    resp = await client.get(
        f"/api/v1/events?tenant_id={tenant_id}",
        headers={"Authorization": "Bearer bad-token-value"},
    )
    assert resp.status_code == 401


async def test_events_token_tenant_mismatch_forbidden(client, tenant_id, tenant_token):
    """Providing token for Tenant A while requesting Tenant B returns 403 Forbidden."""
    other_tenant = str(uuid.uuid4())
    resp = await client.get(
        f"/api/v1/events?tenant_id={other_tenant}",
        headers={"Authorization": f"Bearer {tenant_token}"},
    )
    assert resp.status_code == 403


async def test_stats_requires_token(client, tenant_id):
    """Omitting token on /stats returns 401."""
    resp = await client.get(f"/api/v1/stats?tenant_id={tenant_id}")
    assert resp.status_code == 401


async def test_incidents_requires_token(client, tenant_id):
    """Omitting token on /incidents returns 401."""
    resp = await client.get(f"/api/v1/incidents?tenant_id={tenant_id}")
    assert resp.status_code == 401


async def test_stats_authorized_access(client, ed25519_keypair, tenant_id, tenant_token):
    """Authorized tenant token receives valid metrics."""
    private_key, pub_b64 = ed25519_keypair
    body = build_valid_event(private_key, pub_b64, tenant_id, event_id=str(uuid.uuid4()))
    r = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert r.status_code == 202

    resp = await client.get(
        f"/api/v1/stats?tenant_id={tenant_id}",
        headers={"Authorization": f"Bearer {tenant_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_events"] >= 1
    assert data["accepted"] >= 1


async def test_events_authorized_access(client, ed25519_keypair, tenant_id, tenant_token):
    """Authorized tenant token receives only matching tenant events."""
    resp = await client.get(
        f"/api/v1/events?tenant_id={tenant_id}&limit=10&offset=0",
        headers={"Authorization": f"Bearer {tenant_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "events" in data
    for evt in data["events"]:
        assert evt["tenant_id"] == tenant_id


async def test_incidents_authorized_access(client, ed25519_keypair, tenant_id, tenant_token):
    """Authorized tenant token receives only matching tenant incidents."""
    private_key, pub_b64 = ed25519_keypair
    # Trigger a rejection
    body = build_valid_event(private_key, pub_b64, tenant_id, tamper_signature=True)
    await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})

    # Test using X-API-Key header alternative
    resp = await client.get(
        f"/api/v1/incidents?tenant_id={tenant_id}",
        headers={"X-API-Key": tenant_token},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "incidents" in data
    assert len(data["incidents"]) >= 1
    for inc in data["incidents"]:
        assert inc["tenant_id"] == tenant_id
