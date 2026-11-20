"""
Explainable Recommendations Engine.
Generates deterministic, actionable diagnostic guidance based on observed anomalies.
Recommendations are suggestions, not automatic interventions.
"""
from typing import List, Set

METRIC_RECOMMENDATIONS = {
    "cpu_usage": "Inspect resource-intensive processes, recent deployments and scaling capacity.",
    "memory_usage": "Investigate memory-intensive processes and possible memory leaks.",
    "disk_usage": "Inspect growing logs, temporary files and disk capacity.",
    "network_latency_ms": "Check database response times, application dependencies and service latency.",
    "packet_loss_pct": "Inspect network interfaces, connectivity and network routes.",
    "failed_login_count": "Review aggregated authentication failure patterns and account-protection controls.",
}


def generate_recommendation(metrics: List[str]) -> str:
    """
    Generate an explainable diagnostic recommendation for a set of anomalous metrics.
    Combines multi-metric patterns when relevant infrastructure behaviors co-occur.
    """
    metric_set: Set[str] = set(metrics)

    # 1. Resource Exhaustion pattern: CPU + Memory (+ Latency)
    if "cpu_usage" in metric_set and "memory_usage" in metric_set:
        if "network_latency_ms" in metric_set:
            return (
                "CPU and memory utilization increased while application latency also rose. "
                "This may indicate resource exhaustion under heavy workload. "
                "Investigate high-resource processes, database connection pool limits, and capacity scaling."
            )
        return (
            "Concurrent CPU and memory pressure observed. "
            "Inspect top process resource consumption, recent software rollouts, and background worker jobs."
        )

    # 2. Network Degradation pattern: Latency + Packet Loss
    if "network_latency_ms" in metric_set and "packet_loss_pct" in metric_set:
        return (
            "Network latency and packet loss elevated simultaneously. "
            "This suggests network interface saturation or routing hop degradation. "
            "Inspect NIC errors, upstream network switches, and provider connectivity."
        )

    # 3. Storage Pressure pattern: Disk + (CPU or Memory)
    if "disk_usage" in metric_set and ("cpu_usage" in metric_set or "memory_usage" in metric_set):
        return (
            "Storage capacity is constrained while compute resources are under load. "
            "Check for runaway logging, uncompressed temporary dumps, and verify write queue health."
        )

    # 4. Security / Access pattern
    if "failed_login_count" in metric_set:
        if len(metric_set) > 1:
            return (
                "Elevated authentication failures observed alongside resource anomalies. "
                "Review auth rate limiting, IP origins, and check whether connection spikes correlate with auth load."
            )
        return METRIC_RECOMMENDATIONS["failed_login_count"]

    # 5. Single metric or fallback to clear composition
    parts = [METRIC_RECOMMENDATIONS[m] for m in metrics if m in METRIC_RECOMMENDATIONS]
    if parts:
        return " ".join(parts)

    return "Review host monitoring telemetry and inspect recent infrastructure configuration changes."
