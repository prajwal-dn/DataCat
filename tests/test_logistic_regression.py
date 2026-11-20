"""Tests for DATACAT Pure-Python Logistic Regression Anomaly Detection.

Covers:
  - Feature extraction & causal time-series ordering.
  - Feature standardization (means, stds, zero-variance safety).
  - Logistic Regression training process (loss reduction, weight updates).
  - Model serialization and deserialization (JSON round-trip).
  - Prediction consistency and probability calibration.
  - Normal observation classification.
  - Single-metric anomalies (CPU, memory, disk, latency).
  - Multi-metric anomalies (combined resource contention).
  - Numerical stability under extreme values (+/- 10,000).
  - Warm-up & insufficient historical observation handling.
  - API endpoints (/api/v1/ml/model-info, /api/v1/ml/evaluation, /api/v1/ml/reload, /api/v1/ml/predict).
  - End-to-end integration via POST /api/v1/ingest.
"""

from __future__ import annotations

import base64
import json
import math
import shutil
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

import app.config as config
from app.core.crypto import canonical_receipt_bytes, compute_payload_hash
from app.core.registry import registry
from app.db.database import INIT_SQL, get_db_connection
from app.main import app
from app.ml.features import (
    FEATURE_NAMES,
    extract_features_for_observation,
    extract_features_from_chronological_series,
)
from app.ml.logistic_regression import (
    LogisticRegressionBinaryClassifier,
    Standardizer,
    stable_sigmoid,
)
from app.ml.inference import (
    get_model,
    predict_telemetry_event,
    reload_model,
)

# ---------------------------------------------------------------------------
# Test Infrastructure
# ---------------------------------------------------------------------------

TEST_DATA_DIR = config.BASE_DIR / ".test_ml_data"
TEST_KEY = ed25519.Ed25519PrivateKey.generate()
TEST_PUB_KEY = TEST_KEY.public_key()
TEST_COLLECTOR_ID = "ml_collector_1"
TEST_TENANT_ID = "hospital_ml"


@pytest.fixture(autouse=True)
def setup_ml_test_environment(monkeypatch):
    """Isolated environment for ML tests."""
    if TEST_DATA_DIR.exists():
        shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)
    TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)

    test_db = TEST_DATA_DIR / "test_ml.db"
    test_yaml = TEST_DATA_DIR / "test_collectors_ml.yaml"
    test_pub_file = TEST_DATA_DIR / "test_ml_pub.pem"

    pub_bytes = TEST_PUB_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    test_pub_file.write_bytes(pub_bytes)
    test_yaml.write_text(
        f"""
collectors:
  - collector_id: {TEST_COLLECTOR_ID}
    tenant_id: {TEST_TENANT_ID}
    public_key_path: {str(test_pub_file).replace(chr(92), '/')}
    active: true
""",
        encoding="utf-8",
    )

    con = sqlite3.connect(test_db)
    con.executescript(INIT_SQL)
    now = datetime.now(timezone.utc).isoformat()
    con.execute(
        "INSERT INTO collectors VALUES (?, ?, ?, ?, ?, ?, ?)",
        (TEST_COLLECTOR_ID, TEST_TENANT_ID, str(test_pub_file), "ACTIVE", 0, now, now),
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


# ===========================================================================
# 1. Feature Extraction & Warm-Up Tests
# ===========================================================================

def test_feature_extraction_dimension_and_order():
    """Feature vector must contain exactly 14 features matching FEATURE_NAMES."""
    current = {"cpu_usage": 32.0, "memory_usage": 50.0, "disk_usage": 40.0, "latency_ms": 12.0}
    res = extract_features_for_observation(current, preceding_history=[])
    features = res["features"]

    assert len(features) == 14
    assert len(FEATURE_NAMES) == 14
    assert res["feature_dict"]["cpu_usage"] == 32.0
    assert res["feature_dict"]["memory_usage"] == 50.0
    assert res["feature_dict"]["disk_usage"] == 40.0
    assert res["feature_dict"]["latency_ms"] == 12.0


def test_feature_extraction_warmup_handling():
    """When history is empty, changes must be 0.0 and warmup must be flagged."""
    current = {"cpu_usage": 30.0, "memory_usage": 50.0, "disk_usage": 40.0, "latency_ms": 10.0}
    res = extract_features_for_observation(current, preceding_history=[])

    assert res["metadata"]["is_warmup"] is True
    assert res["feature_dict"]["cpu_change"] == 0.0
    assert res["feature_dict"]["memory_change"] == 0.0
    assert res["feature_dict"]["disk_change"] == 0.0
    assert res["feature_dict"]["latency_change"] == 0.0
    assert res["feature_dict"]["persistence_indicator"] == 0.0


def test_feature_extraction_chronological_causality():
    """Consecutive observations must calculate delta x_t - x_{t-1} without leakage."""
    series = [
        {"cpu_usage": 30.0, "memory_usage": 50.0, "disk_usage": 40.0, "latency_ms": 10.0},
        {"cpu_usage": 35.0, "memory_usage": 52.0, "disk_usage": 41.0, "latency_ms": 15.0},
        {"cpu_usage": 90.0, "memory_usage": 53.0, "disk_usage": 41.0, "latency_ms": 16.0},
    ]
    extracted = extract_features_from_chronological_series(series)
    assert len(extracted) == 3

    # Row 0 delta = 0
    assert extracted[0]["feature_dict"]["cpu_change"] == 0.0
    # Row 1 delta = 35 - 30 = 5.0
    assert extracted[1]["feature_dict"]["cpu_change"] == 5.0
    # Row 2 delta = 90 - 35 = 55.0
    assert extracted[2]["feature_dict"]["cpu_change"] == 55.0


# ===========================================================================
# 2. Standardization Tests
# ===========================================================================

def test_standardizer_fit_and_transform():
    """Standardizer must transform data to mean=0 and std=1, handling zero variance."""
    fnames = ["f1", "f2", "f3_constant"]
    X = [
        [10.0, 100.0, 5.0],
        [20.0, 200.0, 5.0],
        [30.0, 300.0, 5.0],
    ]
    std = Standardizer(fnames)
    std.fit(X)

    assert std.means[0] == 20.0
    assert std.means[1] == 200.0
    assert std.means[2] == 5.0

    # Constant feature variance is 0, regularized to std = 1.0
    assert std.stds[2] == 1.0

    X_scaled = std.transform(X)
    # Row 1 (mean values) should have scaled value 0.0
    assert abs(X_scaled[1][0] - 0.0) < 1e-4
    assert abs(X_scaled[1][1] - 0.0) < 1e-4
    # Constant column stays 0.0
    assert all(row[2] == 0.0 for row in X_scaled)


# ===========================================================================
# 3. Model Training & Loss Reduction Tests
# ===========================================================================

def test_logistic_regression_training_reduces_loss():
    """Fitting on a linearly separable toy problem must achieve high accuracy and decreasing loss."""
    fnames = ["f1", "f2"]
    # 20 samples: f1 > 50 -> class 1, f1 < 50 -> class 0
    X = [[10.0, 5.0], [15.0, 6.0], [20.0, 4.0], [25.0, 7.0], [30.0, 5.0],
         [70.0, 5.0], [75.0, 6.0], [80.0, 4.0], [85.0, 7.0], [90.0, 5.0]]
    y = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1]

    clf = LogisticRegressionBinaryClassifier(feature_names=fnames)
    fit_res = clf.fit(X, y, learning_rate=0.1, iterations=500, l2_lambda=0.01)

    loss_history = fit_res["loss_history"]
    assert len(loss_history) >= 2
    initial_loss = loss_history[0]["loss"]
    final_loss = loss_history[-1]["loss"]
    assert final_loss < initial_loss, f"Loss did not decrease: {initial_loss} -> {final_loss}"

    eval_res = clf.evaluate_dataset(X, y, threshold=0.5)
    assert eval_res["accuracy"] >= 0.90
    assert eval_res["f1_score"] >= 0.90


# ===========================================================================
# 4. Model Persistence & JSON Round-Trip Tests
# ===========================================================================

def test_model_json_serialization_round_trip():
    """Model must serialize to JSON and reload with exact identical weights and threshold."""
    fnames = ["c1", "c2"]
    clf = LogisticRegressionBinaryClassifier(
        feature_names=fnames,
        weights=[0.854321, -0.123456],
        intercept=1.234567,
        threshold=0.35,
        model_version="1.0.0",
        standardizer=Standardizer(fnames, means=[10.0, 20.0], stds=[2.0, 5.0]),
        training_configuration={"learning_rate": 0.05},
        training_metadata={"samples": 100},
    )

    save_file = TEST_DATA_DIR / "temp_model.json"
    clf.save(save_file)
    assert save_file.exists()

    loaded = LogisticRegressionBinaryClassifier.load(save_file)
    assert loaded.model_version == "1.0.0"
    assert loaded.threshold == 0.35
    assert loaded.intercept == 1.234567
    assert loaded.weights == [0.854321, -0.123456]
    assert loaded.standardizer.means == [10.0, 20.0]
    assert loaded.standardizer.stds == [2.0, 5.0]

    # Predictions must match byte-for-byte
    test_vec = [12.0, 25.0]
    prob1, pred1 = clf.predict_one(test_vec)
    prob2, pred2 = loaded.predict_one(test_vec)
    assert prob1 == prob2
    assert pred1 == pred2


# ===========================================================================
# 5. Numerical Stability Tests
# ===========================================================================

def test_numerical_stability_extreme_values():
    """Large positive (+10,000) and negative (-10,000) inputs must not overflow or return NaN."""
    assert stable_sigmoid(10000.0) == 1.0
    assert stable_sigmoid(-10000.0) == 0.0
    assert not math.isnan(stable_sigmoid(500.0))
    assert not math.isnan(stable_sigmoid(-500.0))

    # Test with classifier instance
    clf = get_model()
    # Extremely large positive input (CPU 10,000%)
    extreme_high = [10000.0] * len(clf.feature_names)
    prob_high, pred_high = clf.predict_one(extreme_high)
    assert math.isfinite(prob_high)
    assert prob_high > 0.99
    assert pred_high == 1

    # Extremely large negative input
    extreme_low = [-10000.0] * len(clf.feature_names)
    prob_low, pred_low = clf.predict_one(extreme_low)
    assert math.isfinite(prob_low)
    assert prob_low < 0.01
    assert pred_low == 0


# ===========================================================================
# 6. Specific Metric Anomaly Classification Tests
# ===========================================================================

def test_inference_normal_observation():
    """A baseline normal observation must produce low anomaly probability and class 0."""
    clf = get_model()
    # Normal ICU server observation
    normal_metrics = {"cpu_usage": 32.0, "memory_usage": 52.0, "disk_usage": 42.0, "latency_ms": 12.0}
    # Preceding normal history
    history = [normal_metrics for _ in range(15)]
    feat_res = extract_features_for_observation(normal_metrics, history)

    prob, pred = clf.predict_one(feat_res["features"])
    assert pred == 0, f"Normal observation misclassified as anomaly (prob={prob})"
    assert prob < clf.threshold


def test_inference_cpu_spike_anomaly():
    """A CPU spike (95%) against a 32% baseline must be classified as an anomaly."""
    clf = get_model()
    spike_metrics = {"cpu_usage": 95.0, "memory_usage": 52.0, "disk_usage": 42.0, "latency_ms": 14.0}
    baseline_history = [{"cpu_usage": 32.0, "memory_usage": 52.0, "disk_usage": 42.0, "latency_ms": 12.0} for _ in range(15)]
    feat_res = extract_features_for_observation(spike_metrics, baseline_history)

    prob, pred = clf.predict_one(feat_res["features"])
    assert pred == 1, f"CPU spike was not detected (prob={prob})"
    assert prob >= clf.threshold


def test_inference_memory_spike_anomaly():
    """A memory spike (96%) against a 52% baseline must be classified as an anomaly."""
    clf = get_model()
    spike_metrics = {"cpu_usage": 32.0, "memory_usage": 96.0, "disk_usage": 42.0, "latency_ms": 15.0}
    baseline_history = [{"cpu_usage": 32.0, "memory_usage": 52.0, "disk_usage": 42.0, "latency_ms": 12.0} for _ in range(15)]
    feat_res = extract_features_for_observation(spike_metrics, baseline_history)

    prob, pred = clf.predict_one(feat_res["features"])
    assert pred == 1, f"Memory spike was not detected (prob={prob})"
    assert prob >= clf.threshold


def test_inference_disk_pressure_anomaly():
    """A disk pressure spike (98%) against a 42% baseline must be classified as an anomaly."""
    clf = get_model()
    spike_metrics = {"cpu_usage": 32.0, "memory_usage": 52.0, "disk_usage": 98.0, "latency_ms": 14.0}
    baseline_history = [{"cpu_usage": 32.0, "memory_usage": 52.0, "disk_usage": 42.0, "latency_ms": 12.0} for _ in range(15)]
    feat_res = extract_features_for_observation(spike_metrics, baseline_history)

    prob, pred = clf.predict_one(feat_res["features"])
    assert pred == 1, f"Disk pressure was not detected (prob={prob})"
    assert prob >= clf.threshold


def test_inference_latency_spike_anomaly():
    """A latency spike (350ms) against a 12ms baseline must be classified as an anomaly."""
    clf = get_model()
    spike_metrics = {"cpu_usage": 32.0, "memory_usage": 52.0, "disk_usage": 42.0, "latency_ms": 350.0}
    baseline_history = [{"cpu_usage": 32.0, "memory_usage": 52.0, "disk_usage": 42.0, "latency_ms": 12.0} for _ in range(15)]
    feat_res = extract_features_for_observation(spike_metrics, baseline_history)

    prob, pred = clf.predict_one(feat_res["features"])
    assert pred == 1, f"Latency spike was not detected (prob={prob})"
    assert prob >= clf.threshold


def test_inference_combined_resource_contention():
    """Simultaneous CPU, Memory, and Latency spikes must yield high anomaly probability."""
    clf = get_model()
    spike_metrics = {"cpu_usage": 92.0, "memory_usage": 94.0, "disk_usage": 45.0, "latency_ms": 400.0}
    baseline_history = [{"cpu_usage": 32.0, "memory_usage": 52.0, "disk_usage": 42.0, "latency_ms": 12.0} for _ in range(15)]
    feat_res = extract_features_for_observation(spike_metrics, baseline_history)

    prob, pred = clf.predict_one(feat_res["features"])
    assert pred == 1
    assert prob > 0.90, f"Combined anomaly should have very high probability, got {prob}"


# ===========================================================================
# 7. FastAPI ML Endpoints Integration Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_api_model_info():
    """GET /api/v1/ml/model-info returns valid model metadata, features, and weights."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/ml/model-info")
        assert res.status_code == 200
        data = res.json()
        assert data["model_type"] == "LogisticRegressionBinaryClassifier"
        assert data["feature_count"] == 14
        assert "cpu_usage" in data["weights"]
        assert "latency_modified_zscore" in data["weights"]
        assert "classification_threshold" in data


@pytest.mark.asyncio
async def test_api_model_evaluation():
    """GET /api/v1/ml/evaluation returns train, validation, and test split metrics."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/ml/evaluation")
        assert res.status_code == 200
        data = res.json()
        assert "evaluation_metrics" in data
        metrics = data["evaluation_metrics"]
        assert "train" in metrics
        assert "validation" in metrics
        assert "test" in metrics
        assert metrics["train"]["accuracy"] >= 0.95
        assert metrics["test"]["accuracy"] >= 0.90


@pytest.mark.asyncio
async def test_api_model_reload():
    """POST /api/v1/ml/reload reloads model from disk and returns OK status."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/ml/reload")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "OK"
        assert "threshold" in data


@pytest.mark.asyncio
async def test_api_predict_endpoint():
    """POST /api/v1/ml/predict calculates anomaly probability and top contributing features."""
    # Seed baseline history into test database for srv_ml_01
    db_path = config.DB_PATH
    con = sqlite3.connect(str(db_path))
    now = datetime.now(timezone.utc)
    for i in range(10):
        ts = (now - timedelta(minutes=20 - i)).isoformat()
        m = json.dumps({"cpu_usage": 32.0, "memory_usage": 52.0, "disk_usage": 42.0, "latency_ms": 12.0})
        con.execute(
            "INSERT INTO telemetry_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            (f"hist_ml_{i}", TEST_TENANT_ID, "srv_ml_01", ts, m, TEST_COLLECTOR_ID, 10 + i, "v1.0", "h", ts),
        )
    con.commit()
    con.close()

    event = {
        "event_id": "evt_ml_pred_1",
        "tenant_id": TEST_TENANT_ID,
        "server_id": "srv_ml_01",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "metrics": {
            "cpu_usage": 96.0,
            "memory_usage": 52.0,
            "disk_usage": 42.0,
            "latency_ms": 12.0,
        },
    }
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/ml/predict", json=event)
        assert res.status_code == 200
        data = res.json()
        assert data["server_id"] == "srv_ml_01"
        assert "anomaly_probability" in data
        assert "predicted_class" in data
        assert data["predicted_class"] == 1
        assert len(data["top_contributing_features"]) >= 1


@pytest.mark.asyncio
async def test_e2e_ingestion_triggers_ml_prediction():
    """POST /api/v1/ingest automatically triggers ML inference without changing API contract."""
    now_utc = datetime.now(timezone.utc).isoformat()
    event = {
        "event_id": "evt_ml_e2e_1",
        "tenant_id": TEST_TENANT_ID,
        "server_id": "srv_e2e_icu",
        "timestamp_utc": now_utc,
        "metrics": {
            "cpu_usage": 94.0,
            "memory_usage": 45.0,
            "disk_usage": 50.0,
            "latency_ms": 12.0,
        },
        "policy_version": "v1.0",
    }
    payload_hash = compute_payload_hash(event)
    receipt = {
        "event_id": "evt_ml_e2e_1",
        "tenant_id": TEST_TENANT_ID,
        "payload_hash": payload_hash,
        "collector_id": TEST_COLLECTOR_ID,
        "sequence_number": 800,
        "policy_version": "v1.0",
        "algorithm": "Ed25519",
    }
    sig_bytes = TEST_KEY.sign(canonical_receipt_bytes(receipt))
    receipt["signature"] = base64.b64encode(sig_bytes).decode("utf-8")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/ingest", json={"event": event, "receipt": receipt})
        assert res.status_code == 201
        assert res.json()["status"] == "ACCEPTED"
        assert res.json()["event_id"] == "evt_ml_e2e_1"
