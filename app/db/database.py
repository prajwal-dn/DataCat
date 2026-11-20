"""aiosqlite database connection manager and schema initialization."""
import logging
from pathlib import Path
from typing import Optional
import aiosqlite

import app.config as config

logger = logging.getLogger(__name__)

INIT_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS collectors (
    collector_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    public_key_path TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    last_seen_seq INTEGER NOT NULL DEFAULT 0,
    created_at_utc TEXT NOT NULL,
    last_heartbeat_utc TEXT
);

CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    server_id TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    metrics TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL,
    policy_version TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    ingested_at_utc TEXT NOT NULL,
    PRIMARY KEY (tenant_id, event_id),
    UNIQUE (collector_id, sequence_number),
    FOREIGN KEY (collector_id) REFERENCES collectors(collector_id)
);

CREATE INDEX IF NOT EXISTS idx_telemetry_events_collector_seq 
    ON telemetry_events(collector_id, sequence_number);

CREATE INDEX IF NOT EXISTS idx_telemetry_events_tenant_server 
    ON telemetry_events(tenant_id, server_id);

CREATE INDEX IF NOT EXISTS idx_telemetry_events_ingested 
    ON telemetry_events(ingested_at_utc);

CREATE TABLE IF NOT EXISTS verification_records (
    verification_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    status TEXT NOT NULL,
    structure_valid INTEGER NOT NULL,
    collector_registered INTEGER NOT NULL,
    tenant_matched INTEGER NOT NULL,
    hash_matched INTEGER NOT NULL,
    signature_valid INTEGER NOT NULL,
    duplicate_check_passed INTEGER NOT NULL,
    sequence_valid INTEGER NOT NULL,
    sequence_number INTEGER NOT NULL,
    computed_hash TEXT NOT NULL,
    receipt_hash TEXT NOT NULL,
    failure_reason TEXT,
    verified_at_utc TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verification_records_event 
    ON verification_records(tenant_id, event_id);

CREATE TABLE IF NOT EXISTS audit_records (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    tenant_id TEXT,
    collector_id TEXT,
    event_id TEXT,
    details TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_records_time 
    ON audit_records(timestamp_utc);

CREATE TABLE IF NOT EXISTS anomalies (
    anomaly_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    server_id TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    observed_value REAL NOT NULL,
    expected_baseline REAL NOT NULL,
    severity TEXT NOT NULL,
    detection_timestamp TEXT NOT NULL,
    explanation TEXT NOT NULL,
    event_id TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN'
);

CREATE INDEX IF NOT EXISTS idx_anomalies_server 
    ON anomalies(tenant_id, server_id, detection_timestamp);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    server_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    detection_timestamp TEXT NOT NULL,
    contributing_metrics TEXT NOT NULL,
    explanation TEXT NOT NULL,
    recommendations TEXT NOT NULL,
    correlated_anomalies_count INTEGER NOT NULL DEFAULT 1,
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status 
    ON incidents(tenant_id, status, detection_timestamp);

-- ============================================================
-- Statistical Anomaly Detection Engine (MAD / Modified Z-score)
-- ============================================================

CREATE TABLE IF NOT EXISTS statistical_analysis_records (
    analysis_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    server_id TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    current_value REAL NOT NULL,
    baseline_median REAL,
    mad REAL,
    modified_zscore REAL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    is_anomaly INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'NORMAL',
    detection_reason TEXT NOT NULL,
    persistence_count INTEGER NOT NULL DEFAULT 0,
    statistical_context_status TEXT NOT NULL,
    event_timestamp_utc TEXT NOT NULL,
    stored_at_utc TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_stat_records_server_metric
    ON statistical_analysis_records(tenant_id, server_id, metric_name, event_timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_stat_records_anomaly
    ON statistical_analysis_records(tenant_id, server_id, is_anomaly, stored_at_utc);

CREATE INDEX IF NOT EXISTS idx_stat_records_event
    ON statistical_analysis_records(event_id, tenant_id);

-- ============================================================
-- Unified AIOps Decision Pipeline & Health Transitions
-- ============================================================

CREATE TABLE IF NOT EXISTS aiops_decisions (
    decision_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    server_id TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    statistical_status TEXT NOT NULL,
    statistical_scores TEXT NOT NULL,
    abnormal_metrics TEXT NOT NULL,
    logistic_regression_probability REAL NOT NULL,
    logistic_regression_prediction INTEGER NOT NULL,
    model_version TEXT NOT NULL,
    persistence_status TEXT NOT NULL,
    final_anomaly_decision TEXT NOT NULL,
    severity TEXT NOT NULL,
    contributing_signals TEXT NOT NULL,
    explanation TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_aiops_decisions_server
    ON aiops_decisions(tenant_id, server_id, timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_aiops_decisions_status
    ON aiops_decisions(tenant_id, final_anomaly_decision, severity);

CREATE TABLE IF NOT EXISTS health_state_transitions (
    transition_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    server_id TEXT NOT NULL,
    previous_state TEXT NOT NULL,
    current_state TEXT NOT NULL,
    reason TEXT NOT NULL,
    transition_timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_health_transitions_server
    ON health_state_transitions(tenant_id, server_id, transition_timestamp);
"""


async def get_db_connection(db_path: Optional[Path] = None) -> aiosqlite.Connection:
    """Returns an open aiosqlite connection with row factory configured."""
    target_path = db_path or config.DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    db = await aiosqlite.connect(target_path)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA foreign_keys = ON;")
    return db


async def init_db(db_path: Optional[Path] = None) -> None:
    """Initializes tables and indexes using parameterless script execution."""
    target_path = db_path or config.DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(target_path) as db:
        await db.executescript(INIT_SQL)
        await db.commit()
    logger.info("Database schema initialized at %s", target_path)
