"""
Tests for DATACAT AIOps Intelligence Engine.
Tests metric extraction, threshold anomalies, MAD historical baselines,
incident correlation, explainable recommendations, and API authorization.
"""
import asyncio
import json
import uuid
import aiosqlite
import pytest
from backend.aiops.correlator import correlate_anomalies
from backend.aiops.detector import AnomalySignal, evaluate_metric
from backend.aiops.metrics import extract_metrics
from backend.aiops.recommendations import generate_recommendation
from backend.config import DB_PATH
from backend.database import register_tenant_token
from tests.conftest import build_valid_event


# ── Metric Extraction Tests ──────────────────────────────────────────────

def test_metric_extraction_aliases_and_nested():
    """Verify alias resolution, nested metrics object, and canonical names."""
    payload = {
        "source": "collector-agent",
        "cpu_pct": 45.2,
        "metrics": {
            "ram_pct": 72.8,
            "response_time_ms": 120.5,
            "disk_percent": 88.0,
            "packet_loss": 1.2,
            "failed_logins": 3,
        },
    }
    extracted = extract_metrics(payload)
    assert extracted["cpu_usage"] == 45.2
    assert extracted["memory_usage"] == 72.8
    assert extracted["network_latency_ms"] == 120.5
    assert extracted["disk_usage"] == 88.0
    assert extracted["packet_loss_pct"] == 1.2
    assert extracted["failed_login_count"] == 3.0


def test_metric_extraction_rejects_invalid_values():
    """Booleans, NaNs, infinities, out-of-bound percentages, and mem_mb must be rejected."""
    payload = {
        "cpu_usage": True,  # Boolean must be rejected
        "memory_usage": float("nan"),  # NaN rejected
        "disk_usage": 150.0,  # Out of 0-100 percentage range rejected
        "mem_mb": 8192,  # Memory in MB must not be mistaken for percentage
        "network_latency_ms": -25.0,  # Negative latency rejected
        "failed_login_count": "three",  # Non-numeric string rejected
        "packet_loss_pct": -5.0,  # Negative percentage rejected
    }
    extracted = extract_metrics(payload)
    assert "cpu_usage" not in extracted
    assert "memory_usage" not in extracted
    assert "disk_usage" not in extracted
    assert "network_latency_ms" not in extracted
    assert "failed_login_count" not in extracted
    assert "packet_loss_pct" not in extracted


# ── Anomaly Detection Tests ──────────────────────────────────────────────

def test_normal_metrics_do_not_trigger_anomalies():
    """Values well within thresholds and normal baselines produce no anomaly."""
    history = [30.0, 32.0, 29.0, 31.0, 30.5, 33.0, 28.5, 31.0]
    signal = evaluate_metric("evt-1", "host-a", "cpu_usage", 32.0, history, "2026-11-20T12:00:00Z")
    assert signal is None


def test_cpu_high_threshold_detection():
    """CPU usage >= 90% triggers HIGH severity."""
    history = [40.0, 42.0, 45.0, 41.0, 43.0, 40.0, 44.0, 42.0]
    signal = evaluate_metric("evt-1", "host-a", "cpu_usage", 92.0, history, "2026-11-20T12:00:00Z")
    assert signal is not None
    assert signal.severity == "HIGH"
    assert signal.metric_name == "cpu_usage"
    assert "high warning threshold" in signal.explanation.lower()


def test_memory_threshold_detection():
    """Memory usage >= 90% triggers HIGH severity."""
    history = [50.0] * 8
    signal = evaluate_metric("evt-2", "host-a", "memory_usage", 94.0, history, "2026-11-20T12:00:00Z")
    assert signal is not None
    assert signal.severity == "HIGH"
    assert signal.metric_name == "memory_usage"


def test_critical_severity_detection():
    """Values >= critical thresholds trigger CRITICAL severity."""
    history = [60.0] * 8
    # CPU critical threshold is 98%
    signal = evaluate_metric("evt-3", "host-a", "cpu_usage", 99.1, history, "2026-11-20T12:00:00Z")
    assert signal is not None
    assert signal.severity == "CRITICAL"

    # Latency critical threshold is 1000 ms
    lat_signal = evaluate_metric("evt-4", "host-a", "network_latency_ms", 1250.0, [50.0] * 8, "2026-11-20T12:00:00Z")
    assert lat_signal is not None
    assert lat_signal.severity == "CRITICAL"


def test_historical_mad_baseline_detection_after_eight_samples():
    """
    If a host historically runs CPU at 20-25%, a sudden spike to 70% must be flagged
    as a statistical MAD anomaly (MEDIUM severity) even if it hasn't crossed the static 90% threshold.
    """
    history = [20.0, 22.0, 21.0, 23.0, 20.5, 21.5, 22.5, 21.0]
    signal = evaluate_metric("evt-5", "host-a", "cpu_usage", 70.0, history, "2026-11-20T12:00:00Z")
    assert signal is not None
    assert signal.severity == "MEDIUM"
    assert signal.detection_method == "statistical_mad"
    assert "deviated significantly" in signal.explanation.lower()


def test_fewer_than_eight_samples_skips_mad_detection():
    """Historical baseline requires at least 8 samples; below 8 samples it doesn't false-alarm on baseline."""
    history = [20.0, 21.0, 22.0]
    signal = evaluate_metric("evt-6", "host-a", "cpu_usage", 70.0, history, "2026-11-20T12:00:00Z")
    assert signal is None


# ── Correlation & Recommendations Tests ──────────────────────────────────

def test_multiple_signals_from_one_host_correlated():
    """Multiple anomalies on the same host within 5 minutes form one correlated incident."""
    sig1 = AnomalySignal("evt-1", "server-01", "cpu_usage", 95.0, 90.0, "HIGH", "static", "high cpu", "2026-11-20T14:00:00Z")
    sig2 = AnomalySignal("evt-2", "server-01", "memory_usage", 94.0, 90.0, "HIGH", "static", "high ram", "2026-11-20T14:02:00Z")
    sig3 = AnomalySignal("evt-3", "server-01", "network_latency_ms", 450.0, 300.0, "HIGH", "static", "high latency", "2026-11-20T14:03:00Z")

    incidents = correlate_anomalies([sig1, sig2, sig3])
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["source_host"] == "server-01"
    assert inc["signal_count"] == 3
    assert set(inc["unique_event_ids"]) == {"evt-1", "evt-2", "evt-3"}
    assert "Resource Exhaustion" in inc["title"]


def test_signals_from_different_hosts_are_not_correlated():
    """Signals from server-01 and server-02 must never be grouped into the same incident."""
    sig1 = AnomalySignal("evt-1", "server-01", "cpu_usage", 96.0, 90.0, "HIGH", "static", "high cpu", "2026-11-20T14:00:00Z")
    sig2 = AnomalySignal("evt-2", "server-02", "cpu_usage", 95.0, 90.0, "HIGH", "static", "high cpu", "2026-11-20T14:01:00Z")

    incidents = correlate_anomalies([sig1, sig2])
    assert len(incidents) == 2
    hosts = {inc["source_host"] for inc in incidents}
    assert hosts == {"server-01", "server-02"}


def test_recommendations_explain_detected_metrics():
    """Combined CPU, Memory, and Latency anomalies produce explainable guidance."""
    rec = generate_recommendation(["cpu_usage", "memory_usage", "network_latency_ms"])
    assert "resource exhaustion" in rec.lower()
    assert "processes" in rec.lower()

    rec_single = generate_recommendation(["failed_login_count"])
    assert "authentication failure" in rec_single.lower()


# ── AIOps API Endpoint Tests ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_aiops_overview_empty_tenant_returns_no_data(client, ed25519_keypair):
    """A tenant with no accepted events returns health_status='no_data'."""
    new_tenant = str(uuid.uuid4())
    token = "empty-tenant-token"
    await register_tenant_token(new_tenant, token)

    resp = await client.get(
        f"/api/v1/aiops/overview?tenant_id={new_tenant}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["health_status"] == "no_data"
    assert data["hosts_monitored"] == 0
    assert data["events_analyzed"] == 0
    assert data["incidents"] == []


@pytest.mark.asyncio
async def test_aiops_overview_requires_auth(client, tenant_id):
    """Calling /api/v1/aiops/overview without token returns 401."""
    resp = await client.get(f"/api/v1/aiops/overview?tenant_id={tenant_id}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_aiops_overview_tenant_isolation_forbidden(client, tenant_id, tenant_token):
    """Token for Tenant A cannot access Tenant B's AIOps overview."""
    other_tenant = str(uuid.uuid4())
    resp = await client.get(
        f"/api/v1/aiops/overview?tenant_id={other_tenant}",
        headers={"Authorization": f"Bearer {tenant_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_aiops_overview_end_to_end_computation(client, ed25519_keypair, tenant_id, tenant_token):
    """
    Ingest real telemetry events with an anomaly, verify AIOps endpoint computes
    actual intelligence, detects the anomaly, and forms a correlated incident.
    """
    private_key, pub_b64 = ed25519_keypair
    test_host = f"prod-worker-{uuid.uuid4().hex[:6]}"

    # Send 1 normal event
    e1 = build_valid_event(
        private_key, pub_b64, tenant_id,
        source_host=test_host,
        event_id=str(uuid.uuid4()),
        custom_payload={"cpu_pct": 35.0, "ram_pct": 50.0},
    )
    r1 = await client.post("/api/v1/ingest", json=e1, headers={"X-Tenant-ID": tenant_id})
    assert r1.status_code == 202

    # Send 1 critical anomaly event (CPU 99%, Latency 1100ms)
    e2 = build_valid_event(
        private_key, pub_b64, tenant_id,
        source_host=test_host,
        event_id=str(uuid.uuid4()),
        custom_payload={"cpu_pct": 99.0, "latency_ms": 1100.0},
    )
    r2 = await client.post("/api/v1/ingest", json=e2, headers={"X-Tenant-ID": tenant_id})
    assert r2.status_code == 202

    # Call AIOps overview
    resp = await client.get(
        f"/api/v1/aiops/overview?tenant_id={tenant_id}",
        headers={"Authorization": f"Bearer {tenant_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["health_status"] == "critical"
    assert data["hosts_monitored"] >= 1
    assert data["events_analyzed"] >= 2
    assert data["anomaly_count"] >= 2
    assert data["correlated_incident_count"] >= 1

    # Check incident structure
    inc = data["incidents"][0]
    assert inc["source_host"] == test_host
    assert inc["severity"] == "CRITICAL"
    assert len(inc["contributing_signals"]) >= 2
    assert len(inc["suggested_recommendation"]) > 10
