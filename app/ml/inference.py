"""DATACAT Live Inference Module for Logistic Regression Anomaly Detection.

Handles:
  - Loading and caching the trained model from JSON.
  - Querying preceding historical observations for the target server from SQLite.
  - Extracting the 14 causal features using app.ml.features.
  - Applying stored standardisation parameters.
  - Calculating anomaly probability and binary classification.
  - Generating explainable feature attribution (top contributing features).

Guarantees:
  - Operates strictly on verified telemetry.
  - Uses only preceding observations (zero temporal leakage).
  - No retraining during live inference.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

import aiosqlite

from app.ml.features import (
    FEATURE_NAMES,
    extract_features_for_observation,
)
from app.ml.logistic_regression import (
    LogisticRegressionBinaryClassifier,
)

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parent.parent / "models" / "logistic_regression_model.json"
)

_cached_model: Optional[LogisticRegressionBinaryClassifier] = None


def get_model(
    model_path: Optional[Path | str] = None,
) -> LogisticRegressionBinaryClassifier:
    """Returns cached model instance or loads from disk on demand."""
    global _cached_model
    if _cached_model is not None and model_path is None:
        return _cached_model

    path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
    if not path.exists():
        # Check secondary location
        fallback = Path(__file__).resolve().parent.parent.parent / "backend" / "models" / "logistic_regression_model.json"
        if fallback.exists():
            path = fallback
        else:
            raise FileNotFoundError(f"Trained Logistic Regression model not found at {path}")

    _cached_model = LogisticRegressionBinaryClassifier.load(path)
    logger.info("Loaded Logistic Regression model v%s from %s", _cached_model.model_version, path)
    return _cached_model


def reload_model(model_path: Optional[Path | str] = None) -> LogisticRegressionBinaryClassifier:
    """Forces reload of model from disk."""
    global _cached_model
    _cached_model = None
    return get_model(model_path)


async def predict_telemetry_event(
    db: aiosqlite.Connection,
    verified_event: dict[str, Any],
    model: Optional[LogisticRegressionBinaryClassifier] = None,
) -> dict[str, Any]:
    """Runs ML inference on a single verified telemetry event.

    Args:
        db: open database connection to retrieve preceding historical telemetry.
        verified_event: event dict with 'server_id', 'tenant_id', 'event_id', 'metrics'.
        model: optional preloaded model instance.

    Returns:
        dict with probability, predicted_class, features_used, top_contributors.
    """
    classifier = model or get_model()

    event_id = verified_event["event_id"]
    tenant_id = verified_event["tenant_id"]
    server_id = verified_event["server_id"]
    metrics = verified_event.get("metrics", {})

    current_metrics = {
        "cpu_usage": float(metrics.get("cpu_usage", 0.0)),
        "memory_usage": float(metrics.get("memory_usage", 0.0)),
        "disk_usage": float(metrics.get("disk_usage", 0.0)),
        "latency_ms": float(metrics.get("latency_ms", 0.0)),
    }

    # 1. Fetch preceding observations for this server (strictly prior to current event)
    preceding_history = await _fetch_preceding_metrics(
        db, tenant_id=tenant_id, server_id=server_id, exclude_event_id=event_id, limit=30
    )

    # 2. Fetch preceding anomaly flags for persistence indicator
    preceding_flags = await _fetch_preceding_anomaly_flags(
        db, tenant_id=tenant_id, server_id=server_id, limit=5
    )

    # 3. Extract 14 causal features using identical logic
    feat_res = extract_features_for_observation(
        current_metrics=current_metrics,
        preceding_history=preceding_history,
        preceding_anomaly_flags=preceding_flags,
    )
    feature_vector = feat_res["features"]
    feature_dict = feat_res["feature_dict"]

    # 4. Standardize and Predict
    x_std = classifier.standardizer.transform_one(feature_vector)
    prob, pred = classifier.predict_one_standardized(x_std)

    # 5. Calculate feature impact: contribution = w_j * x_std_j
    contributions = []
    for j, fname in enumerate(classifier.feature_names):
        w = classifier.weights[j]
        val_std = x_std[j]
        impact = round(w * val_std, 4)
        contributions.append({
            "feature": fname,
            "raw_value": feature_dict[fname],
            "standardized_value": val_std,
            "weight": w,
            "linear_contribution": impact,
        })

    # Sort by absolute impact descending
    contributions.sort(key=lambda c: abs(c["linear_contribution"]), reverse=True)

    return {
        "server_id": server_id,
        "tenant_id": tenant_id,
        "event_id": event_id,
        "anomaly_probability": prob,
        "predicted_class": pred,
        "is_anomaly": pred == 1,
        "classification_threshold": classifier.threshold,
        "model_version": classifier.model_version,
        "features_used": feature_dict,
        "top_contributing_features": contributions[:5],
        "metadata": feat_res["metadata"],
    }


async def _fetch_preceding_metrics(
    db: aiosqlite.Connection,
    tenant_id: str,
    server_id: str,
    exclude_event_id: str,
    limit: int = 30,
) -> list[dict[str, float]]:
    """Fetches up to limit preceding metric dicts for a server, ordered chronologically ascending."""
    query = """
    SELECT metrics FROM telemetry_events
    WHERE tenant_id = ? AND server_id = ? AND event_id != ?
    ORDER BY timestamp_utc DESC
    LIMIT ?;
    """
    history_desc: list[dict[str, float]] = []
    async with db.execute(query, (tenant_id, server_id, exclude_event_id, limit)) as cur:
        rows = await cur.fetchall()
        for r in rows:
            try:
                m = json.loads(r[0])
                history_desc.append({k: float(v) for k, v in m.items()})
            except Exception:
                pass

    # Reverse so list is chronological ascending
    history_desc.reverse()
    return history_desc


async def _fetch_preceding_anomaly_flags(
    db: aiosqlite.Connection,
    tenant_id: str,
    server_id: str,
    limit: int = 5,
) -> list[bool]:
    """Fetches recent anomaly flags for persistence indicator calculation."""
    query = """
    SELECT is_anomaly FROM statistical_analysis_records
    WHERE tenant_id = ? AND server_id = ?
    ORDER BY event_timestamp_utc DESC
    LIMIT ?;
    """
    flags_desc: list[bool] = []
    async with db.execute(query, (tenant_id, server_id, limit)) as cur:
        rows = await cur.fetchall()
        for r in rows:
            flags_desc.append(bool(r[0]))

    flags_desc.reverse()
    return flags_desc
