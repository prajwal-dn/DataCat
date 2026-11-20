"""
Tests for GET /api/v1/events, /stats, /incidents, /health.
Enforces strict tenant scoping — omitting tenant_id must fail.
"""
import uuid
import pytest
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


async def test_events_requires_tenant_id(client):
    """Omitting tenant_id on /events must be rejected."""
    resp = await client.get("/api/v1/events")
    assert resp.status_code == 422


async def test_stats_requires_tenant_id(client):
    """Omitting tenant_id on /stats must be rejected."""
    resp = await client.get("/api/v1/stats")
    assert resp.status_code == 422


async def test_incidents_requires_tenant_id(client):
    """Omitting tenant_id on /incidents must be rejected."""
    resp = await client.get("/api/v1/incidents")
    assert resp.status_code == 422


async def test_stats_returns_tenant_counts(client, ed25519_keypair, tenant_id):
    """Stats endpoint returns real DB metrics for the requested tenant."""
    private_key, pub_b64 = ed25519_keypair
    body = build_valid_event(private_key, pub_b64, tenant_id, event_id=str(uuid.uuid4()))
    r = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert r.status_code == 202

    resp = await client.get(f"/api/v1/stats?tenant_id={tenant_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_events"] >= 1
    assert data["accepted"] >= 1


async def test_events_tenant_isolation(client, ed25519_keypair, tenant_id):
    """Events query returns only events belonging to the queried tenant."""
    resp = await client.get(f"/api/v1/events?tenant_id={tenant_id}&limit=10&offset=0")
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "events" in data
    for evt in data["events"]:
        assert evt["tenant_id"] == tenant_id


async def test_incidents_tenant_isolation(client, ed25519_keypair, tenant_id):
    """Incidents query returns only rejections for the queried tenant."""
    private_key, pub_b64 = ed25519_keypair
    # Trigger a rejection
    body = build_valid_event(private_key, pub_b64, tenant_id, tamper_signature=True)
    await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})

    resp = await client.get(f"/api/v1/incidents?tenant_id={tenant_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert "incidents" in data
    assert len(data["incidents"]) >= 1
    for inc in data["incidents"]:
        assert inc["tenant_id"] == tenant_id
