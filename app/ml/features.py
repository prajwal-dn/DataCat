"""DATACAT Feature Engineering Module for Anomaly Classification.

Computes 14 causal features from raw telemetry metrics and historical baselines:
  - 4 Raw features: cpu_usage, memory_usage, disk_usage, latency_ms
  - 4 Statistical features: cpu_modified_zscore, memory_modified_zscore,
                           disk_modified_zscore, latency_modified_zscore
  - 4 Dynamic change features: cpu_change, memory_change, disk_change, latency_change
  - 2 Aggregate features: abnormal_metric_count, persistence_indicator

Causal Guarantees:
  - All historical context is strictly preceding the current observation (t < current).
  - Current observation is never included in its own baseline.
  - Zero future data leakage.
  - Exact same feature calculation logic shared between offline training and live inference.
"""

from __future__ import annotations

import math
import statistics
from typing import Any, Optional

FEATURE_NAMES = [
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "latency_ms",
    "cpu_modified_zscore",
    "memory_modified_zscore",
    "disk_modified_zscore",
    "latency_modified_zscore",
    "cpu_change",
    "memory_change",
    "disk_change",
    "latency_change",
    "abnormal_metric_count",
    "persistence_indicator",
]

MONITORED_METRICS = ["cpu_usage", "memory_usage", "disk_usage", "latency_ms"]

# Minimum scale regularizers (epsilon) to prevent division by zero in zero-MAD cases
DEFAULT_MIN_MAD_SCALE = {
    "cpu_usage": 1.0,
    "memory_usage": 1.0,
    "disk_usage": 0.5,
    "latency_ms": 2.0,
}

# Operational fallback thresholds when history is sparse
DEFAULT_FALLBACK_THRESHOLDS = {
    "cpu_usage": 85.0,
    "memory_usage": 85.0,
    "disk_usage": 90.0,
    "latency_ms": 150.0,
}

MODIFIED_Z_THRESHOLD = 3.5
ROLLING_WINDOW_SIZE = 30
PERSISTENCE_LOOKBACK = 5


def compute_modified_zscore(
    value: float,
    history: list[float],
    metric_name: str,
    min_mad_scale: Optional[dict[str, float]] = None,
) -> tuple[float, Optional[float], Optional[float], bool]:
    """Computes Modified Z-score (Iglewicz & Hoaglin 1993) using only past observations.

    Returns:
        (modified_zscore, median, mad, is_warmup)
    """
    scales = min_mad_scale or DEFAULT_MIN_MAD_SCALE
    min_mad = scales.get(metric_name, 1.0)

    if not history:
        # Zero prior history: warmup observation
        return 0.0, None, None, True

    n = len(history)
    median = statistics.median(history)
    abs_devs = [abs(x - median) for x in history]
    mad = statistics.median(abs_devs)
    effective_mad = max(mad, min_mad)

    # Modified Z-score: 0.6745 * (x - median) / effective_mad
    mz = 0.6745 * (value - median) / effective_mad

    is_warmup = n < 5
    return round(mz, 6), round(median, 4), round(mad, 4), is_warmup


def extract_features_for_observation(
    current_metrics: dict[str, float],
    preceding_history: list[dict[str, float]],
    preceding_anomaly_flags: Optional[list[bool]] = None,
    min_mad_scale: Optional[dict[str, float]] = None,
    fallback_thresholds: Optional[dict[str, float]] = None,
) -> dict[str, Any]:
    """Extracts the 14-dimensional feature vector for a single observation.

    Args:
        current_metrics: dict containing cpu_usage, memory_usage, disk_usage, latency_ms.
        preceding_history: list of prior metric dicts for this server, sorted chronologically ascending.
                           Length should be at most ROLLING_WINDOW_SIZE.
        preceding_anomaly_flags: list of bools indicating whether each preceding observation was anomalous.
        min_mad_scale: optional overrides for minimum scale per metric.
        fallback_thresholds: optional operational threshold overrides.

    Returns:
        dict containing:
          - "features": list[float] matching FEATURE_NAMES order
          - "feature_dict": dict[str, float] mapping feature name to value
          - "metadata": diagnostic info (sample_count, is_warmup, etc.)
    """
    fallbacks = fallback_thresholds or DEFAULT_FALLBACK_THRESHOLDS

    # 1. Raw values
    cpu = float(current_metrics.get("cpu_usage", 0.0))
    mem = float(current_metrics.get("memory_usage", 0.0))
    disk = float(current_metrics.get("disk_usage", 0.0))
    lat = float(current_metrics.get("latency_ms", 0.0))

    # 2. Extract preceding metric series for rolling baseline
    # Only keep the most recent ROLLING_WINDOW_SIZE preceding samples
    recent_history = preceding_history[-ROLLING_WINDOW_SIZE:] if preceding_history else []
    sample_count = len(recent_history)

    cpu_hist = [float(h["cpu_usage"]) for h in recent_history if "cpu_usage" in h]
    mem_hist = [float(h["memory_usage"]) for h in recent_history if "memory_usage" in h]
    disk_hist = [float(h["disk_usage"]) for h in recent_history if "disk_usage" in h]
    lat_hist = [float(h["latency_ms"]) for h in recent_history if "latency_ms" in h]

    # 3. Modified Z-scores
    cpu_mz, cpu_med, cpu_mad, cpu_warm = compute_modified_zscore(cpu, cpu_hist, "cpu_usage", min_mad_scale)
    mem_mz, mem_med, mem_mad, mem_warm = compute_modified_zscore(mem, mem_hist, "memory_usage", min_mad_scale)
    disk_mz, disk_med, disk_mad, disk_warm = compute_modified_zscore(disk, disk_hist, "disk_usage", min_mad_scale)
    lat_mz, lat_med, lat_mad, lat_warm = compute_modified_zscore(lat, lat_hist, "latency_ms", min_mad_scale)

    is_warmup = sample_count < 5

    # 4. First-order temporal changes: x_t - x_{t-1}
    if recent_history:
        prev = recent_history[-1]
        cpu_change = round(cpu - float(prev.get("cpu_usage", cpu)), 6)
        mem_change = round(mem - float(prev.get("memory_usage", mem)), 6)
        disk_change = round(disk - float(prev.get("disk_usage", disk)), 6)
        lat_change = round(lat - float(prev.get("latency_ms", lat)), 6)
    else:
        cpu_change = 0.0
        mem_change = 0.0
        disk_change = 0.0
        lat_change = 0.0

    # 5. Abnormal metric count for current event
    # Count metrics exceeding statistical threshold or fallback limits
    abnormal_count = 0
    if abs(cpu_mz) > MODIFIED_Z_THRESHOLD or (cpu_warm and cpu > fallbacks["cpu_usage"]):
        abnormal_count += 1
    if abs(mem_mz) > MODIFIED_Z_THRESHOLD or (mem_warm and mem > fallbacks["memory_usage"]):
        abnormal_count += 1
    if abs(disk_mz) > MODIFIED_Z_THRESHOLD or (disk_warm and disk > fallbacks["disk_usage"]):
        abnormal_count += 1
    if abs(lat_mz) > MODIFIED_Z_THRESHOLD or (lat_warm and lat > fallbacks["latency_ms"]):
        abnormal_count += 1

    # 6. Persistence indicator
    # Number of anomalous observations in the preceding PERSISTENCE_LOOKBACK window
    persistence_indicator = 0.0
    if preceding_anomaly_flags:
        recent_flags = preceding_anomaly_flags[-PERSISTENCE_LOOKBACK:]
        persistence_indicator = float(sum(1 for f in recent_flags if f))
    elif recent_history:
        # If explicit anomaly flags are not supplied, deduce from recent history's abnormal metric counts
        # (used in self-contained streaming)
        lookback_slice = recent_history[-PERSISTENCE_LOOKBACK:]
        for prev_item in lookback_slice:
            p_cpu = float(prev_item.get("cpu_usage", 0.0))
            p_mem = float(prev_item.get("memory_usage", 0.0))
            p_disk = float(prev_item.get("disk_usage", 0.0))
            p_lat = float(prev_item.get("latency_ms", 0.0))
            if (p_cpu > fallbacks["cpu_usage"] or p_mem > fallbacks["memory_usage"]
                    or p_disk > fallbacks["disk_usage"] or p_lat > fallbacks["latency_ms"]):
                persistence_indicator += 1.0

    feature_dict = {
        "cpu_usage": cpu,
        "memory_usage": mem,
        "disk_usage": disk,
        "latency_ms": lat,
        "cpu_modified_zscore": cpu_mz,
        "memory_modified_zscore": mem_mz,
        "disk_modified_zscore": disk_mz,
        "latency_modified_zscore": lat_mz,
        "cpu_change": cpu_change,
        "memory_change": mem_change,
        "disk_change": disk_change,
        "latency_change": lat_change,
        "abnormal_metric_count": float(abnormal_count),
        "persistence_indicator": persistence_indicator,
    }

    feature_vector = [feature_dict[name] for name in FEATURE_NAMES]

    return {
        "features": feature_vector,
        "feature_dict": feature_dict,
        "metadata": {
            "sample_count": sample_count,
            "is_warmup": is_warmup,
            "medians": {"cpu": cpu_med, "mem": mem_med, "disk": disk_med, "lat": lat_med},
            "mads": {"cpu": cpu_mad, "mem": mem_mad, "disk": disk_mad, "lat": lat_mad},
        },
    }


def extract_features_from_chronological_series(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Extracts causal features for a sequence of observations ordered chronologically.

    Ensures zero temporal leakage: record i only sees observations 0 to i-1.

    Args:
        records: list of dicts with 'cpu_usage', 'memory_usage', 'disk_usage', 'latency_ms',
                 and optionally 'is_anomaly'.

    Returns:
        list of feature dicts (same length as records), each containing
        'features', 'feature_dict', 'is_anomaly', 'timestamp_utc', etc.
    """
    extracted = []
    history: list[dict[str, float]] = []
    anomaly_flags: list[bool] = []

    for r in records:
        metrics = {
            "cpu_usage": float(r["cpu_usage"]),
            "memory_usage": float(r["memory_usage"]),
            "disk_usage": float(r["disk_usage"]),
            "latency_ms": float(r["latency_ms"]),
        }

        feat_res = extract_features_for_observation(
            current_metrics=metrics,
            preceding_history=history,
            preceding_anomaly_flags=anomaly_flags,
        )

        item = {
            "timestamp_utc": r.get("timestamp_utc", ""),
            "server_id": r.get("server_id", ""),
            "features": feat_res["features"],
            "feature_dict": feat_res["feature_dict"],
            "metadata": feat_res["metadata"],
        }
        if "is_anomaly" in r:
            item["is_anomaly"] = int(r["is_anomaly"])
        if "anomaly_type" in r:
            item["anomaly_type"] = r["anomaly_type"]

        extracted.append(item)

        # Append current observation to history for subsequent steps
        history.append(metrics)

        # Track anomaly flag for persistence indicator
        # (in training, if is_anomaly is present, we use it or deduce it)
        is_anom = int(r.get("is_anomaly", 0)) == 1 if "is_anomaly" in r else (feat_res["feature_dict"]["abnormal_metric_count"] > 0)
        anomaly_flags.append(is_anom)

    return extracted
