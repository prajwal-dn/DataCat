"""DATACAT AIOps Detection Configuration Loader.

Reads config/aiops_thresholds.yaml and exposes a typed, validated config object.
Falls back to safe built-in defaults if the file is missing or invalid.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "aiops_thresholds.yaml"


class DetectionConfig:
    """Typed wrapper around aiops_thresholds.yaml values."""

    def __init__(self, raw: dict[str, Any]) -> None:
        sd = raw.get("statistical_detection", {})
        p = raw.get("persistence", {})
        bp = raw.get("baseline_protection", {})
        al = raw.get("alert_suppression", {})
        ic = raw.get("incident_correlation", {})

        # Statistical detection parameters
        self.min_samples_for_baseline: int = int(sd.get("min_samples_for_baseline", 10))
        self.rolling_window_size: int = int(sd.get("rolling_window_size", 30))
        self.modified_zscore_threshold: float = float(sd.get("modified_zscore_threshold", 3.5))

        self.critical_absolute_thresholds: dict[str, float] = {
            k: float(v)
            for k, v in sd.get("critical_absolute_thresholds", {
                "cpu_usage": 95.0,
                "memory_usage": 95.0,
                "disk_usage": 97.0,
                "latency_ms": 1000.0,
            }).items()
        }

        self.min_mad_scale: dict[str, float] = {
            k: float(v)
            for k, v in sd.get("min_mad_scale", {
                "cpu_usage": 1.0,
                "memory_usage": 1.0,
                "disk_usage": 0.5,
                "latency_ms": 2.0,
            }).items()
        }

        self.direction: dict[str, str] = sd.get("direction", {
            "cpu_usage": "high_only",
            "memory_usage": "high_only",
            "disk_usage": "high_only",
            "latency_ms": "high_only",
        })

        self.fallback_thresholds: dict[str, float] = {
            k: float(v)
            for k, v in sd.get("fallback_thresholds", {
                "cpu_usage": 85.0,
                "memory_usage": 85.0,
                "disk_usage": 90.0,
                "latency_ms": 150.0,
            }).items()
        }

        self.severity_bands: dict[str, float] = {
            k: float(v)
            for k, v in sd.get("severity_bands", {
                "medium_z": 3.5,
                "high_z": 6.0,
                "critical_z": 10.0,
            }).items()
        }

        self.fallback_severity_bands: dict[str, float] = {
            k: float(v)
            for k, v in sd.get("fallback_severity_bands", {
                "medium_excess": 0.0,
                "high_excess": 5.0,
                "critical_excess": 15.0,
            }).items()
        }

        # Persistence parameters
        self.consecutive_anomaly_window: int = int(p.get("consecutive_anomaly_window", 3))
        self.persistence_lookback_count: int = int(p.get("persistence_lookback_count", 5))
        self.persistence_trigger_count: int = int(p.get("persistence_trigger_count", 3))
        self.persistence_critical_override: int = int(p.get("persistence_critical_override", 5))

        # Baseline protection
        self.exclude_anomalies_from_baseline: bool = bool(bp.get("exclude_anomalies_from_baseline", True))
        self.max_anomaly_contamination_ratio: float = float(bp.get("max_anomaly_contamination_ratio", 0.5))

        # Alert suppression
        self.suppression_window_seconds: int = int(al.get("suppression_window_seconds", 120))

        # Incident correlation
        self.correlation_window_seconds: int = int(ic.get("correlation_window_seconds", 300))

        # Decision fusion parameters
        df = raw.get("decision_fusion", {})
        self.high_prob_threshold: float = float(df.get("high_prob_threshold", 0.50))
        self.low_prob_threshold: float = float(df.get("low_prob_threshold", 0.20))
        self.escalate_on_persistence: bool = bool(df.get("escalate_on_persistence", True))
        self.persistence_escalate_count: int = int(df.get("persistence_escalate_count", 3))

        # Health classification parameters
        hc = raw.get("health_classification", {})
        self.stale_threshold_seconds: int = int(hc.get("stale_threshold_seconds", 180))
        self.cpu_fair: float = float(hc.get("cpu_fair", 75.0))
        self.cpu_poor: float = float(hc.get("cpu_poor", 90.0))
        self.memory_fair: float = float(hc.get("memory_fair", 75.0))
        self.memory_poor: float = float(hc.get("memory_poor", 90.0))
        self.disk_fair: float = float(hc.get("disk_fair", 85.0))
        self.disk_poor: float = float(hc.get("disk_poor", 95.0))
        self.latency_fair: float = float(hc.get("latency_fair", 100.0))
        self.latency_poor: float = float(hc.get("latency_poor", 200.0))

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "DetectionConfig":
        """Load configuration from YAML. Falls back to built-in defaults on any error."""
        path = config_path or _DEFAULT_CONFIG_PATH
        if _YAML_AVAILABLE and path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    raw = yaml.safe_load(f) or {}
                logger.info("AIOps detection config loaded from %s", path)
                return cls(raw)
            except Exception as exc:
                logger.warning("Failed to parse %s: %s — using built-in defaults", path, exc)
        else:
            if not _YAML_AVAILABLE:
                logger.warning("PyYAML not available — using built-in detection defaults")
            else:
                logger.warning("AIOps config file not found at %s — using built-in defaults", path)
        return cls({})
