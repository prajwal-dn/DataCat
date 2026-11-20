"""
Incident Correlation Module.
Groups related temporal anomalies for the same host within a 5-minute window.
Does not claim correlation proves causation.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from backend.aiops.detector import AnomalySignal
from backend.aiops.recommendations import generate_recommendation

WINDOW_SECONDS = 300  # 5-minute correlation window

SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}


def _parse_timestamp(ts_str: str) -> float:
    """Parse ISO UTC string to epoch seconds."""
    try:
        clean = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        return dt.timestamp()
    except Exception:
        return 0.0


def _build_incident_title(host: str, metrics: List[str], max_sev: str) -> str:
    """Create a concise, professional title based on anomalous metrics."""
    m_set = set(metrics)
    if "cpu_usage" in m_set and "memory_usage" in m_set:
        return f"Resource Exhaustion on {host}"
    if "network_latency_ms" in m_set and "packet_loss_pct" in m_set:
        return f"Network Path Degradation on {host}"
    if "failed_login_count" in m_set:
        return f"Authentication Anomaly on {host}"
    if "disk_usage" in m_set:
        return f"Storage Capacity Warning on {host}"
    if "network_latency_ms" in m_set:
        return f"Service Latency Spike on {host}"
    if "cpu_usage" in m_set:
        return f"CPU Utilization Spike on {host}"
    if "memory_usage" in m_set:
        return f"Memory Pressure on {host}"
    return f"Infrastructure Anomaly on {host}"


def correlate_anomalies(signals: List[AnomalySignal]) -> List[Dict[str, Any]]:
    """
    Correlate anomaly signals per host within a 5-minute sliding window.
    Signals from different hosts are strictly separated.
    """
    if not signals:
        return []

    # 1. Group signals strictly by source_host
    host_groups: Dict[str, List[AnomalySignal]] = {}
    for s in signals:
        host_groups.setdefault(s.source_host, []).append(s)

    incidents: List[Dict[str, Any]] = []

    # 2. Window correlation per host
    for host, host_signals in host_groups.items():
        # Sort chronologically by server-generated ingested_at
        sorted_signals = sorted(host_signals, key=lambda s: _parse_timestamp(s.ingested_at))

        current_cluster: List[AnomalySignal] = []
        cluster_start_epoch: float = 0.0
        cluster_last_epoch: float = 0.0

        for sig in sorted_signals:
            sig_epoch = _parse_timestamp(sig.ingested_at)

            if not current_cluster:
                current_cluster = [sig]
                cluster_start_epoch = sig_epoch
                cluster_last_epoch = sig_epoch
            else:
                # If signal falls within 5 minutes of the cluster's active window
                if (sig_epoch - cluster_last_epoch) <= WINDOW_SECONDS:
                    current_cluster.append(sig)
                    cluster_last_epoch = sig_epoch
                else:
                    # Flush previous cluster into an incident
                    incidents.append(_cluster_to_incident(host, current_cluster))
                    current_cluster = [sig]
                    cluster_start_epoch = sig_epoch
                    cluster_last_epoch = sig_epoch

        if current_cluster:
            incidents.append(_cluster_to_incident(host, current_cluster))

    # Sort incidents by severity (CRITICAL first), then by most recent last_seen
    return sorted(
        incidents,
        key=lambda inc: (SEVERITY_ORDER.get(inc["severity"], 0), inc["last_seen"]),
        reverse=True,
    )


def _cluster_to_incident(host: str, cluster: List[AnomalySignal]) -> Dict[str, Any]:
    """Convert an anomaly cluster into a structured explainable incident record."""
    # Compute highest severity
    highest_sev = "MEDIUM"
    max_rank = 1
    for s in cluster:
        rank = SEVERITY_ORDER.get(s.severity, 1)
        if rank > max_rank:
            max_rank = rank
            highest_sev = s.severity

    metrics = [s.metric_name for s in cluster]
    unique_event_ids = sorted(list({s.event_id for s in cluster}))

    first_seen = cluster[0].ingested_at
    last_seen = cluster[-1].ingested_at

    title = _build_incident_title(host, metrics, highest_sev)

    # Evidence summary
    evidence = [
        f"{s.metric_name}: {s.observed_value} (threshold/baseline: {s.baseline_or_threshold}, {s.severity})"
        for s in cluster
    ]

    recommendation = generate_recommendation(metrics)

    explanation = (
        f"{len(cluster)} correlated anomaly signal(s) observed on host '{host}' within a 5-minute window. "
        "Temporal correlation indicates simultaneous occurrence; further root-cause investigation is recommended."
    )

    return {
        "incident_id": f"inc-{uuid.uuid4().hex[:12]}",
        "source_host": host,
        "severity": highest_sev,
        "title": title,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "signal_count": len(cluster),
        "contributing_signals": [s.to_dict() for s in cluster],
        "unique_event_ids": unique_event_ids,
        "evidence": evidence,
        "explanation": explanation,
        "suggested_recommendation": recommendation,
    }
