"""
Pydantic response models for AIOps Intelligence endpoints.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class LatestHostMetric(BaseModel):
    source_host: str
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    network_latency_ms: Optional[float] = None
    packet_loss_pct: Optional[float] = None
    failed_login_count: Optional[float] = None
    latest_timestamp: str


class AnomalyItem(BaseModel):
    event_id: str
    source_host: str
    metric_name: str
    observed_value: float
    baseline_or_threshold: float
    severity: str
    detection_method: str
    explanation: str
    ingested_at: str


class IncidentItem(BaseModel):
    incident_id: str
    source_host: str
    severity: str
    title: str
    first_seen: str
    last_seen: str
    signal_count: int
    contributing_signals: List[Dict[str, Any]]
    unique_event_ids: List[str]
    evidence: List[str]
    explanation: str
    suggested_recommendation: str


class AIOpsOverviewResponse(BaseModel):
    tenant_id: str
    health_status: str  # healthy | degraded | critical | no_data
    hosts_monitored: int
    events_analyzed: int
    anomaly_count: int
    correlated_incident_count: int
    generated_at: str
    latest_metrics: List[LatestHostMetric]
    anomalies: List[AnomalyItem]
    incidents: List[IncidentItem]
