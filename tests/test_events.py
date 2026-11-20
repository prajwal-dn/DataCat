"""Tests for GET /api/v1/events, /stats, /incidents, /health."""
import pytest
import pytest_asyncio

pytestmark = pytest.mark.asyncio


async def test_health_returns_ok(client):
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("ok", "degraded")
    assert "version" in data
    assert "db" in data
    assert isinstance(data["uptime_seconds"], (int, float))


async def test_stats_returns_counts(client, ed25519_keypair, tenant_id):
    """Stats endpoint returns real DB counts (not hardcoded)."""
    from tests.conftest import build_valid_event
    import uuid
    private_key, pub_b64 = ed25519_keypair

    # Ingest one fresh event so stats are non-zero
    body = build_valid_event(private_key, pub_b64, tenant_id, event_id=str(uuid.uuid4()))
    r = await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})
    assert r.status_code == 202

    resp = await client.get("/api/v1/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_events"] >= 1
    assert data["accepted"] >= 1
    assert isinstance(data["rejected"], int)


async def test_events_pagination(client, ed25519_keypair, tenant_id):
    """Events endpoint returns paginated real data."""
    resp = await client.get("/api/v1/events?limit=5&offset=0")
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "events" in data
    assert len(data["events"]) <= 5


async def test_events_filter_by_status(client):
    resp = await client.get("/api/v1/events?status=accepted")
    assert resp.status_code == 200
    for evt in resp.json()["events"]:
        assert evt["status"] == "accepted"


async def test_incidents_returns_rejections(client, ed25519_keypair, tenant_id):
    """Incidents endpoint shows rejected events."""
    from tests.conftest import build_valid_event
    import uuid
    private_key, pub_b64 = ed25519_keypair

    # Force a rejection
    body = build_valid_event(private_key, pub_b64, tenant_id, tamper_signature=True)
    await client.post("/api/v1/ingest", json=body, headers={"X-Tenant-ID": tenant_id})

    resp = await client.get("/api/v1/incidents")
    assert resp.status_code == 200
    data = resp.json()
    assert "incidents" in data
    # At least one incident from this test session
    assert len(data["incidents"]) >= 1
    for inc in data["incidents"]:
        assert "incident_type" in inc
        assert "event_id" in inc


async def test_events_tenant_filter(client, tenant_id):
    """Filter by tenant_id returns only matching events."""
    resp = await client.get(f"/api/v1/events?tenant_id={tenant_id}")
    assert resp.status_code == 200
    for evt in resp.json()["events"]:
        assert evt["tenant_id"] == tenant_id


async def test_dashboard_serves_html(client):
    """Dashboard route returns HTML."""
    resp = await client.get("/dashboard")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
