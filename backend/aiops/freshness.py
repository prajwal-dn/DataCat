"""
Telemetry freshness evaluation for DATACAT AIOps.
Evaluates time elapsed since latest server-side ingested_at timestamp against configurable thresholds:
- Fresh: < 2 minutes (< 120s)
- Stale: 2 - 10 minutes (120s - 600s)
- Very stale: > 10 minutes (> 600s)
"""
from datetime import datetime, timezone
from typing import Optional, Tuple

from backend.config import FRESHNESS_FRESH_MAX_SECONDS, FRESHNESS_STALE_MAX_SECONDS


def parse_timestamp(ts: Optional[str]) -> Optional[datetime]:
    """Parse ISO 8601 string into a timezone-aware UTC datetime."""
    if not ts or not isinstance(ts, str):
        return None
    try:
        clean_ts = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def calculate_age_seconds(
    ts: Optional[str],
    now: Optional[datetime] = None,
) -> Optional[float]:
    """Calculate age in seconds between now (UTC) and the provided timestamp."""
    dt = parse_timestamp(ts)
    if dt is None:
        return None
    current_time = now or datetime.now(timezone.utc)
    delta = (current_time - dt).total_seconds()
    return max(0.0, delta)


def evaluate_freshness(
    ts: Optional[str],
    now: Optional[datetime] = None,
    fresh_max_seconds: int = FRESHNESS_FRESH_MAX_SECONDS,
    stale_max_seconds: int = FRESHNESS_STALE_MAX_SECONDS,
) -> Tuple[str, Optional[float]]:
    """
    Evaluate telemetry freshness category and age in seconds.
    Categories:
    - 'no_data': timestamp missing or unparseable
    - 'fresh': age < fresh_max_seconds (default < 120s / 2m)
    - 'stale': fresh_max_seconds <= age <= stale_max_seconds (default 2m - 10m)
    - 'very_stale': age > stale_max_seconds (default > 10m)
    """
    if not ts:
        return "no_data", None

    age = calculate_age_seconds(ts, now=now)
    if age is None:
        return "no_data", None

    if age < fresh_max_seconds:
        category = "fresh"
    elif age <= stale_max_seconds:
        category = "stale"
    else:
        category = "very_stale"

    return category, age


def determine_health_status(
    metric_health: str,
    telemetry_freshness: str,
) -> str:
    """
    Determine overall infrastructure health status combining metric health and telemetry freshness.
    Rules:
    - If metric_health is 'no_data' or telemetry_freshness is 'no_data' -> 'no_data'
    - If metric_health is 'critical' -> 'critical'
    - If metric_health is 'degraded' -> 'degraded'
    - If metric_health is 'healthy':
        - If telemetry_freshness is 'fresh' -> 'healthy'
        - If telemetry_freshness is 'stale' -> 'stale'
        - If telemetry_freshness is 'very_stale' -> 'very_stale'
    """
    if metric_health == "no_data" or telemetry_freshness == "no_data":
        return "no_data"
    if metric_health == "critical":
        return "critical"
    if metric_health == "degraded":
        return "degraded"
    # metric_health is healthy
    if telemetry_freshness == "fresh":
        return "healthy"
    elif telemetry_freshness == "stale":
        return "stale"
    else:
        return "very_stale"
