"""Health classification and incident correlation service for DATACAT Tier 2."""
from datetime import datetime, timezone
import json
from typing import Any, Optional

# Configurable health thresholds
HEALTH_THRESHOLDS = {
    "cpu": {"good": 60.0, "fair": 75.0, "poor": 90.0},
    "memory": {"good": 60.0, "fair": 75.0, "poor": 90.0},
    "disk": {"good": 70.0, "fair": 85.0, "poor": 95.0},
    "latency": {"good": 50.0, "fair": 100.0, "poor": 200.0},
    "stale_seconds": 180,  # 3 minutes without verified telemetry = POOR
}


def parse_iso_utc(ts_str: str) -> Optional[datetime]:
    """Parses an ISO 8601 UTC timestamp safely."""
    try:
        normalized = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def evaluate_server_health(
    metrics: dict[str, float],
    timestamp_utc: str,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Evaluates the 4-tier health state (EXCELLENT, GOOD, FAIR, POOR).

    Handles staleness: Old healthy readings are NEVER displayed as currently healthy.
    """
    now_dt = now or datetime.now(timezone.utc)
    event_dt = parse_iso_utc(timestamp_utc)

    # 1. Check for stale telemetry
    if event_dt is None:
        return {
            "health_status": "POOR",
            "health_reason": "Invalid or missing timestamp in telemetry",
            "is_stale": True,
            "seconds_ago": 999999,
        }

    seconds_ago = max(0.0, (now_dt - event_dt).total_seconds())
    stale_limit = HEALTH_THRESHOLDS["stale_seconds"]

    if seconds_ago > stale_limit:
        mins = int(seconds_ago // 60)
        return {
            "health_status": "POOR",
            "health_reason": f"Telemetry stale: last received {mins}m {int(seconds_ago % 60)}s ago (>{stale_limit}s limit)",
            "is_stale": True,
            "seconds_ago": round(seconds_ago, 1),
        }

    cpu = float(metrics.get("cpu_usage", 0.0))
    mem = float(metrics.get("memory_usage", 0.0))
    disk = float(metrics.get("disk_usage", 0.0))
    latency = float(metrics.get("latency_ms", 0.0))

    # 2. Check for POOR (Critical)
    critical_reasons = []
    if cpu >= HEALTH_THRESHOLDS["cpu"]["poor"]:
        critical_reasons.append(f"Critical CPU usage: {cpu:.1f}% (>= {HEALTH_THRESHOLDS['cpu']['poor']}%)")
    if mem >= HEALTH_THRESHOLDS["memory"]["poor"]:
        critical_reasons.append(f"Critical memory usage: {mem:.1f}% (>= {HEALTH_THRESHOLDS['memory']['poor']}%)")
    if disk >= HEALTH_THRESHOLDS["disk"]["poor"]:
        critical_reasons.append(f"Critical disk space usage: {disk:.1f}% (>= {HEALTH_THRESHOLDS['disk']['poor']}%)")
    if latency >= HEALTH_THRESHOLDS["latency"]["poor"]:
        critical_reasons.append(f"High network latency: {latency:.1f}ms (>= {HEALTH_THRESHOLDS['latency']['poor']}ms)")

    if critical_reasons:
        return {
            "health_status": "POOR",
            "health_reason": "; ".join(critical_reasons),
            "is_stale": False,
            "seconds_ago": round(seconds_ago, 1),
        }

    # 3. Check for FAIR (Needs Attention)
    fair_reasons = []
    if cpu >= HEALTH_THRESHOLDS["cpu"]["fair"]:
        fair_reasons.append(f"Elevated CPU usage: {cpu:.1f}%")
    if mem >= HEALTH_THRESHOLDS["memory"]["fair"]:
        fair_reasons.append(f"Elevated memory usage: {mem:.1f}%")
    if disk >= HEALTH_THRESHOLDS["disk"]["fair"]:
        fair_reasons.append(f"Elevated disk usage: {disk:.1f}%")
    if latency >= HEALTH_THRESHOLDS["latency"]["fair"]:
        fair_reasons.append(f"Elevated latency: {latency:.1f}ms")

    if fair_reasons:
        return {
            "health_status": "FAIR",
            "health_reason": "; ".join(fair_reasons),
            "is_stale": False,
            "seconds_ago": round(seconds_ago, 1),
        }

    # 4. Check for GOOD (Minor Deviations)
    good_reasons = []
    if cpu >= HEALTH_THRESHOLDS["cpu"]["good"]:
        good_reasons.append(f"Moderate CPU usage: {cpu:.1f}%")
    if mem >= HEALTH_THRESHOLDS["memory"]["good"]:
        good_reasons.append(f"Moderate memory usage: {mem:.1f}%")
    if disk >= HEALTH_THRESHOLDS["disk"]["good"]:
        good_reasons.append(f"Moderate disk usage: {disk:.1f}%")
    if latency >= HEALTH_THRESHOLDS["latency"]["good"]:
        good_reasons.append(f"Moderate latency: {latency:.1f}ms")

    if good_reasons:
        return {
            "health_status": "GOOD",
            "health_reason": "; ".join(good_reasons),
            "is_stale": False,
            "seconds_ago": round(seconds_ago, 1),
        }

    # 5. EXCELLENT (Nominal)
    return {
        "health_status": "EXCELLENT",
        "health_reason": f"Nominal baseline (CPU: {cpu:.1f}%, Mem: {mem:.1f}%, Latency: {latency:.1f}ms)",
        "is_stale": False,
        "seconds_ago": round(seconds_ago, 1),
    }


def correlate_incidents(
    servers_health: list[dict[str, Any]],
    recent_failures: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Generates explainable operational and cryptographic incidents with remediation steps."""
    incidents = []
    now_utc = datetime.now(timezone.utc).isoformat()

    # Telemetry-based server incidents
    for s in servers_health:
        server_id = s["server_id"]
        tenant_id = s["tenant_id"]
        status = s["health_status"]
        metrics = s["metrics"]
        seconds_ago = s.get("seconds_ago", 0)

        if s.get("is_stale"):
            incidents.append({
                "incident_id": f"INC-STALE-{server_id}",
                "server_id": server_id,
                "tenant_id": tenant_id,
                "title": "Hospital Telemetry Stream Loss (Stale Data)",
                "severity": "CRITICAL",
                "detection_timestamp": now_utc,
                "contributing_metrics": {"seconds_since_last_event": seconds_ago},
                "explanation": f"Server {server_id} has not emitted verified operational telemetry for {seconds_ago}s. Tier 1 collector or local network may be down.",
                "recommendations": [
                    "Verify Tier 1 daemon is running on hospital host.",
                    "Check network egress connectivity from customer environment.",
                    "Inspect local hospital firewall logs for dropped outbound port 8000 connections.",
                ],
            })
            continue

        if metrics.get("cpu_usage", 0) >= HEALTH_THRESHOLDS["cpu"]["poor"]:
            incidents.append({
                "incident_id": f"INC-CPU-{server_id}",
                "server_id": server_id,
                "tenant_id": tenant_id,
                "title": "Compute Saturation / High CPU Utilization",
                "severity": "CRITICAL",
                "detection_timestamp": now_utc,
                "contributing_metrics": {"cpu_usage": metrics["cpu_usage"]},
                "explanation": f"CPU usage sustained at {metrics['cpu_usage']}%, exceeding safe operational ceiling of {HEALTH_THRESHOLDS['cpu']['poor']}%.",
                "recommendations": [
                    "Review top active processes on server.",
                    "Check for runaway batch compute or unindexed database queries.",
                    "Scale compute allocation or restart saturated worker services.",
                ],
            })

        if metrics.get("memory_usage", 0) >= HEALTH_THRESHOLDS["memory"]["poor"]:
            incidents.append({
                "incident_id": f"INC-MEM-{server_id}",
                "server_id": server_id,
                "tenant_id": tenant_id,
                "title": "Memory Depletion / OOM Risk",
                "severity": "HIGH",
                "detection_timestamp": now_utc,
                "contributing_metrics": {"memory_usage": metrics["memory_usage"]},
                "explanation": f"RAM usage critical at {metrics['memory_usage']}%. Approaching kernel Out-Of-Memory termination threshold.",
                "recommendations": [
                    "Inspect system heap dumps and resident memory size (RSS).",
                    "Audit hospital application caches and clear expired memory pools.",
                ],
            })

        if metrics.get("latency_ms", 0) >= HEALTH_THRESHOLDS["latency"]["poor"]:
            incidents.append({
                "incident_id": f"INC-LAT-{server_id}",
                "server_id": server_id,
                "tenant_id": tenant_id,
                "title": "High Network & System Latency",
                "severity": "MEDIUM",
                "detection_timestamp": now_utc,
                "contributing_metrics": {"latency_ms": metrics["latency_ms"]},
                "explanation": f"Network latency is elevated at {metrics['latency_ms']}ms, exceeding acceptable service-level threshold.",
                "recommendations": [
                    "Inspect hospital network switchboard and Gateway routing.",
                    "Check for bandwidth saturation or packet drops on local telemetry interfaces.",
                ],
            })

    # Cryptographic verification failure incidents
    if recent_failures:
        failure_count = len(recent_failures)
        reasons = list({f.get("failure_reason", "Verification rejected") for f in recent_failures})
        incidents.append({
            "incident_id": f"INC-SEC-{recent_failures[0].get('collector_id', 'ALL')}",
            "server_id": "Tier 1 Ingestion Boundary",
            "tenant_id": recent_failures[0].get("tenant_id", "GLOBAL"),
            "title": f"Cryptographic Verification Rejections ({failure_count} Events)",
            "severity": "HIGH",
            "detection_timestamp": now_utc,
            "contributing_metrics": {"rejected_events_count": failure_count},
            "explanation": f"Detected {failure_count} rejected ingestion attempt(s). Common rejection triggers: {', '.join(reasons[:2])}.",
            "recommendations": [
                "Verify Tier 1 Ed25519 private key matches public key registered in config/collectors.yaml.",
                "Check for canonical JSON payload tampering or replay attack sequence violations.",
                "Inspect local clock synchronization (NTP) on collector host.",
            ],
        })

    return incidents
