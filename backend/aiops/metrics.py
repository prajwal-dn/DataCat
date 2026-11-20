"""
Metric extraction, alias resolution, and strict validation.
Extracts metrics from event.payload (including nested payload.metrics)
and normalizes to canonical names.
"""
import math
from typing import Any, Dict, Optional

# Canonical metric names and their allowed alias keys
METRIC_ALIASES: Dict[str, list[str]] = {
    "cpu_usage": ["cpu_usage", "cpu_pct", "cpu_percent"],
    "memory_usage": ["memory_usage", "memory_pct", "memory_percent", "ram_usage", "ram_pct"],
    "disk_usage": ["disk_usage", "disk_pct", "disk_percent"],
    "network_latency_ms": ["network_latency_ms", "latency_ms", "response_time_ms"],
    "packet_loss_pct": ["packet_loss_pct", "packet_loss"],
    "failed_login_count": ["failed_login_count", "failed_logins"],
}

# Explicitly excluded keys that might be mistaken for percentage or canonical metrics
EXCLUDED_KEYS = {"mem_mb", "memory_mb", "ram_mb", "disk_gb", "disk_mb", "cpu_cores", "cpu_count"}


def _is_valid_number(val: Any) -> bool:
    """Check that value is a real finite number and strictly not a boolean."""
    if val is None or type(val) is bool:
        return False
    if not isinstance(val, (int, float)):
        return False
    if math.isnan(val) or math.isinf(val):
        return False
    return True


def _validate_metric_value(canonical_name: str, val: float) -> Optional[float]:
    """Validate bounds for percentage and counter metrics."""
    # Percentage metrics must be within [0, 100]
    if canonical_name in {"cpu_usage", "memory_usage", "disk_usage", "packet_loss_pct"}:
        if 0.0 <= val <= 100.0:
            return float(val)
        return None

    # Latency and failed logins must be non-negative
    if canonical_name in {"network_latency_ms", "failed_login_count"}:
        if val >= 0.0:
            return float(val)
        return None

    return float(val)


def extract_metrics(payload: Any) -> Dict[str, float]:
    """
    Extract and normalize supported metrics from event payload.
    Supports both direct keys and nested 'metrics' sub-dictionary.
    """
    if not isinstance(payload, dict):
        return {}

    # Gather search dicts: direct payload and nested metrics dict (nested takes precedence or supplements)
    sources = []
    if "metrics" in payload and isinstance(payload["metrics"], dict):
        sources.append(payload["metrics"])
    sources.append(payload)

    extracted: Dict[str, float] = {}

    for canonical_name, aliases in METRIC_ALIASES.items():
        for source in sources:
            found = False
            for alias in aliases:
                if alias in source:
                    # Ignore keys that match excluded patterns
                    if alias.lower() in EXCLUDED_KEYS:
                        continue
                    val = source[alias]
                    if _is_valid_number(val):
                        validated = _validate_metric_value(canonical_name, float(val))
                        if validated is not None:
                            extracted[canonical_name] = validated
                            found = True
                            break
            if found:
                break

    return extracted
