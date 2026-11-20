"""Integration and functional tests for DATACAT Tier 2 SaaS Dashboard & Health Engine."""
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
from app.core.crypto import canonical_receipt_bytes, compute_payload_hash
from app.core.registry import registry
from app.db.database import INIT_SQL
from app.main import app

TEST_DATA_DIR = config.BASE_DIR / ".test_dashboard_data"
TEST_KEY = ed25519.Ed25519PrivateKey.generate()
TEST_PUB_KEY = TEST_KEY.public_key()


@pytest.fixture(autouse=True)
def setup_dashboard_environment(monkeypatch):
    """Configures test database with known server events and collector records."""
    if TEST_DATA_DIR.exists():
        shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)
    TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)

    test_db = TEST_DATA_DIR / "test_datacat_dash.db"
    test_yaml = TEST_DATA_DIR / "test_collectors_dash.yaml"
    test_pub_file = TEST_DATA_DIR / "test_collector_pub.pem"

    pub_bytes = TEST_PUB_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    test_pub_file.write_bytes(pub_bytes)

    test_yaml.write_text(f"""
collectors:
  - collector_id: hospital_collector_1
    tenant_id: hospital_01
    public_key_path: {str(test_pub_file).replace('\\', '/')}
    active: true
  - collector_id: clinic_collector_2
    tenant_id: clinic_02
    public_key_path: {str(test_pub_file).replace('\\', '/')}
    active: true
""", encoding="utf-8")

    # Initialize tables
    con = sqlite3.connect(test_db)
    con.executescript(INIT_SQL)

    now = datetime.now(timezone.utc)
    recent_ts = now.isoformat()
    # Stale timestamp: 10 minutes ago
    stale_ts = (now - timedelta(minutes=10)).isoformat()

    # Seed collectors
    con.execute(
        "INSERT INTO collectors VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("hospital_collector_1", "hospital_01", str(test_pub_file), "ACTIVE", 10, recent_ts, recent_ts)
    )
    con.execute(
        "INSERT INTO collectors VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("clinic_collector_2", "clinic_02", str(test_pub_file), "ACTIVE", 5, stale_ts, stale_ts)
    )

    # Seed telemetry events:
    # 1. Healthy server (EXCELLENT)
    con.execute(
        "INSERT INTO telemetry_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "evt_srv_1", "hospital_01", "srv_icu_01", recent_ts,
            '{"cpu_usage": 32.5, "memory_usage": 45.0, "disk_usage": 50.0, "latency_ms": 12.0}',
            "hospital_collector_1", 1, "v1.0", "a" * 64, recent_ts
        )
    )
    # 2. Critical compute server (POOR - CPU 94.5%)
    con.execute(
        "INSERT INTO telemetry_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "evt_srv_2", "hospital_01", "srv_er_db", recent_ts,
            '{"cpu_usage": 94.5, "memory_usage": 60.0, "disk_usage": 55.0, "latency_ms": 25.0}',
            "hospital_collector_1", 2, "v1.0", "b" * 64, recent_ts
        )
    )
    # 3. Stale telemetry server (POOR due to stale data > 180s)
    con.execute(
        "INSERT INTO telemetry_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "evt_srv_3", "clinic_02", "srv_mri_03", stale_ts,
            '{"cpu_usage": 10.0, "memory_usage": 20.0, "disk_usage": 30.0, "latency_ms": 5.0}',
            "clinic_collector_2", 1, "v1.0", "c" * 64, stale_ts
        )
    )

    # Seed verification records (1 verified, 1 failed)
    con.execute(
        "INSERT INTO verification_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("v_rec_1", "evt_srv_1", "hospital_01", "hospital_collector_1", "VERIFIED", 1, 1, 1, 1, 1, 1, 1, 1, "a"*64, "a"*64, None, recent_ts)
    )
    con.execute(
        "INSERT INTO verification_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("v_rec_2", "evt_bad_sig", "hospital_01", "hospital_collector_1", "FAILED", 1, 1, 1, 1, 0, 1, 1, 2, "d"*64, "d"*64, "Ed25519 signature mismatch", recent_ts)
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


@pytest.mark.asyncio
async def test_dashboard_html_page_served():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/")
        assert res.status_code == 200
        assert "text/html" in res.headers.get("content-type", "")
        assert "DATACAT" in res.text


@pytest.mark.asyncio
async def test_dashboard_overview_metrics():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/dashboard/overview")
        assert res.status_code == 200
        data = res.json()
        assert data["total_collectors"] == 2
        assert data["online_collectors"] == 1
        assert data["offline_collectors"] == 1
        assert data["verified_events"] == 3
        assert data["rejected_events"] == 1
        # Worst-case health aggregation should detect POOR due to critical CPU or stale data
        assert data["overall_health"] == "POOR"
        assert data["active_incidents"] > 0


@pytest.mark.asyncio
async def test_infrastructure_health_classification_and_staleness():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/dashboard/infrastructure")
        assert res.status_code == 200
        data = res.json()
        servers = {s["server_id"]: s for s in data["servers"]}

        # 1. srv_icu_01 must be EXCELLENT
        assert servers["srv_icu_01"]["health_status"] == "EXCELLENT"
        assert servers["srv_icu_01"]["is_stale"] is False

        # 2. srv_er_db must be POOR due to CPU >= 90%
        assert servers["srv_er_db"]["health_status"] == "POOR"
        assert "Critical CPU" in servers["srv_er_db"]["health_reason"]

        # 3. srv_mri_03 must be POOR due to stale telemetry > 180s (despite low CPU/RAM)
        assert servers["srv_mri_03"]["health_status"] == "POOR"
        assert servers["srv_mri_03"]["is_stale"] is True
        assert "Telemetry stale" in servers["srv_mri_03"]["health_reason"]


@pytest.mark.asyncio
async def test_collector_monitoring_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/dashboard/collectors")
        assert res.status_code == 200
        data = res.json()
        collectors = {c["collector_id"]: c for c in data["collectors"]}

        assert "hospital_collector_1" in collectors
        c1 = collectors["hospital_collector_1"]
        assert c1["is_online"] is True
        assert c1["accepted_events"] == 2
        assert c1["failed_verifications"] == 1
        # Ensure private key is NOT exposed
        assert "private" not in str(c1).lower()


@pytest.mark.asyncio
async def test_incidents_detection_and_correlation():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/dashboard/incidents")
        assert res.status_code == 200
        data = res.json()
        incidents = data["incidents"]
        assert len(incidents) >= 2

        titles = [i["title"] for i in incidents]
        # Should have Compute Saturation and Stale Data incidents
        assert any("CPU" in t for t in titles)
        assert any("Stale" in t for t in titles)

        # Verify each incident has actionable recommendations
        for inc in incidents:
            assert len(inc["recommendations"]) > 0
            assert "recommendations" in inc
            assert "explanation" in inc


@pytest.mark.asyncio
async def test_tenant_scoping_filter():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Filter by hospital_01 only
        res = await client.get("/api/v1/dashboard/infrastructure?tenant_id=hospital_01")
        assert res.status_code == 200
        data = res.json()
        server_ids = [s["server_id"] for s in data["servers"]]
        assert "srv_icu_01" in server_ids
        assert "srv_er_db" in server_ids
        assert "srv_mri_03" not in server_ids  #Belongs to clinic_02


@pytest.mark.asyncio
async def test_server_sparkline_history():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/dashboard/servers/srv_icu_01/history")
        assert res.status_code == 200
        data = res.json()
        assert data["server_id"] == "srv_icu_01"
        assert len(data["history"]) >= 1
