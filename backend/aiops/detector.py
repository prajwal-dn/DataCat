"""
Anomaly Detection Module.
Combines static thresholds and robust statistical baseline detection (Median & MAD).
"""
import statistics
from typing import Any, Dict, List, Optional

# Configurable static thresholds
STATIC_THRESHOLDS: Dict[str, Dict[str, float]] = {
    "cpu_usage": {"high": 90.0, "critical": 98.0},
    "memory_usage": {"high": 90.0, "critical": 98.0},
    "disk_usage": {"high": 90.0, "critical": 98.0},
    "network_latency_ms": {"high": 300.0, "critical": 1000.0},
    "packet_loss_pct": {"high": 5.0, "critical": 20.0},
    "failed_login_count": {"high": 10.0, "critical": 20.0},
}

# Minimum variance protection deltas for MAD calculations
MINIMUM_DELTAS: Dict[str, float] = {
    "cpu_usage": 15.0,
    "memory_usage": 15.0,
    "disk_usage": 15.0,
    "network_latency_ms": 100.0,
    "packet_loss_pct": 2.0,
    "failed_login_count": 5.0,
}

# Historical sample limits
MIN_HISTORICAL_SAMPLES = 8
MAX_HISTORICAL_SAMPLES = 30


class AnomalySignal:
    def __init__(
        self,
        event_id: str,
        source_host: str,
        metric_name: str,
        observed_value: float,
        baseline_or_threshold: float,
        severity: str,
        detection_method: str,
        explanation: str,
        ingested_at: str,
    ):
        self.event_id = event_id
        self.source_host = source_host
        self.metric_name = metric_name
        self.observed_value = round(observed_value, 2)
        self.baseline_or_threshold = round(baseline_or_threshold, 2)
        self.severity = severity  # MEDIUM, HIGH, CRITICAL
        self.detection_method = detection_method
        self.explanation = explanation
        self.ingested_at = ingested_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "source_host": self.source_host,
            "metric_name": self.metric_name,
            "observed_value": self.observed_value,
            "baseline_or_threshold": self.baseline_or_threshold,
            "severity": self.severity,
            "detection_method": self.detection_method,
            "explanation": self.explanation,
            "ingested_at": self.ingested_at,
        }


def compute_mad_upper_bound(history: List[float], min_delta: float) -> Optional[float]:
    """
    Calculate upper boundary using Median + max(3 * 1.4826 * MAD, min_delta).
    Requires at least MIN_HISTORICAL_SAMPLES.
    """
    if len(history) < MIN_HISTORICAL_SAMPLES:
        return None

    samples = history[-MAX_HISTORICAL_SAMPLES:]
    med = statistics.median(samples)
    mad = statistics.median([abs(x - med) for x in samples])
    upper_bound = med + max(3 * 1.4826 * mad, min_delta)
    return upper_bound


def evaluate_metric(
    event_id: str,
    source_host: str,
    metric_name: str,
    value: float,
    history: List[float],
    ingested_at: str,
) -> Optional[AnomalySignal]:
    """
    Evaluate a metric against both static thresholds and historical baseline.
    Returns an AnomalySignal if anomalous, else None.
    """
    thresholds = STATIC_THRESHOLDS.get(metric_name)
    static_severity: Optional[str] = None
    static_limit: float = 0.0

    if thresholds:
        if value >= thresholds["critical"]:
            static_severity = "CRITICAL"
            static_limit = thresholds["critical"]
        elif value >= thresholds["high"]:
            static_severity = "HIGH"
            static_limit = thresholds["high"]

    min_delta = MINIMUM_DELTAS.get(metric_name, 10.0)
    mad_upper_bound = compute_mad_upper_bound(history, min_delta)
    is_statistical_anomaly = mad_upper_bound is not None and value > mad_upper_bound

    # If neither triggered, reading is normal
    if not static_severity and not is_statistical_anomaly:
        return None

    # Determine severity and explanation
    if static_severity == "CRITICAL":
        severity = "CRITICAL"
        detection_method = "static_threshold" if not is_statistical_anomaly else "combined"
        explanation = (
            f"{metric_name.replace('_', ' ').title()} reached critical level of {value:.1f} "
            f"(threshold: {static_limit:.1f})."
        )
        baseline = static_limit

    elif static_severity == "HIGH":
        severity = "HIGH"
        detection_method = "static_threshold" if not is_statistical_anomaly else "combined"
        explanation = (
            f"{metric_name.replace('_', ' ').title()} crossed high warning threshold at {value:.1f} "
            f"(threshold: {static_limit:.1f})."
        )
        baseline = static_limit

    else:
        # Statistical anomaly without crossing static high threshold
        severity = "MEDIUM"
        detection_method = "statistical_mad"
        explanation = (
            f"{metric_name.replace('_', ' ').title()} deviated significantly from host baseline: "
            f"observed {value:.1f} vs expected upper limit of {mad_upper_bound:.1f}."
        )
        baseline = mad_upper_bound if mad_upper_bound is not None else 0.0

    return AnomalySignal(
        event_id=event_id,
        source_host=source_host,
        metric_name=metric_name,
        observed_value=value,
        baseline_or_threshold=baseline,
        severity=severity,
        detection_method=detection_method,
        explanation=explanation,
        ingested_at=ingested_at,
    )
