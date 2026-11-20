"""Parameterized SQL database operations for collectors, events, verifications, audit, dashboard, and AIOps."""
from datetime import datetime, timezone
import json
import logging
from typing import Any, Optional
import aiosqlite

logger = logging.getLogger(__name__)


async def sync_collector_to_db(
    db: aiosqlite.Connection,
    collector_id: str,
    tenant_id: str,
    public_key_path: str,
    status: str,
    now_utc: str,
) -> None:
    """Upserts a registered collector into the collectors table."""
    query = """
    INSERT INTO collectors (collector_id, tenant_id, public_key_path, status, last_seen_seq, created_at_utc)
    VALUES (?, ?, ?, ?, 0, ?)
    ON CONFLICT(collector_id) DO UPDATE SET
        tenant_id = excluded.tenant_id,
        public_key_path = excluded.public_key_path,
        status = excluded.status;
    """
    await db.execute(query, (collector_id, tenant_id, public_key_path, status, now_utc))
    await db.commit()


async def get_collector_from_db(
    db: aiosqlite.Connection, collector_id: str
) -> Optional[dict[str, Any]]:
    """Retrieves collector metadata by ID."""
    query = "SELECT * FROM collectors WHERE collector_id = ?;"
    async with db.execute(query, (collector_id,)) as cursor:
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_existing_event(
    db: aiosqlite.Connection, tenant_id: str, event_id: str
) -> Optional[dict[str, Any]]:
    """Checks whether an event with tenant_id and event_id already exists."""
    query = "SELECT event_id, tenant_id, payload_hash, sequence_number FROM telemetry_events WHERE tenant_id = ? AND event_id = ?;"
    async with db.execute(query, (tenant_id, event_id)) as cursor:
        row = await cursor.fetchone()
        return dict(row) if row else None


async def is_sequence_number_used(
    db: aiosqlite.Connection, collector_id: str, sequence_number: int
) -> bool:
    """Checks if a sequence number has already been used by the collector."""
    query = "SELECT 1 FROM telemetry_events WHERE collector_id = ? AND sequence_number = ? LIMIT 1;"
    async with db.execute(query, (collector_id, sequence_number)) as cursor:
        row = await cursor.fetchone()
        return row is not None


async def insert_telemetry_event_transaction(
    db: aiosqlite.Connection,
    event_data: dict[str, Any],
    receipt_data: dict[str, Any],
    ingested_at_utc: str,
    verification_record: dict[str, Any],
) -> None:
    """Inserts verified telemetry, updates collector sequence, and stores audit records atomically."""
    metrics_json = json.dumps(event_data["metrics"], separators=(",", ":"))

    insert_event_sql = """
    INSERT INTO telemetry_events (
        event_id, tenant_id, server_id, timestamp_utc, metrics,
        collector_id, sequence_number, policy_version, payload_hash, ingested_at_utc
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """

    update_collector_sql = """
    UPDATE collectors
    SET last_seen_seq = MAX(last_seen_seq, ?),
        last_heartbeat_utc = ?
    WHERE collector_id = ?;
    """

    insert_verification_sql = """
    INSERT INTO verification_records (
        verification_id, event_id, tenant_id, collector_id, status,
        structure_valid, collector_registered, tenant_matched, hash_matched,
        signature_valid, duplicate_check_passed, sequence_valid, sequence_number,
        computed_hash, receipt_hash, failure_reason, verified_at_utc
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """

    insert_audit_sql = """
    INSERT INTO audit_records (
        timestamp_utc, event_type, severity, tenant_id, collector_id, event_id, details
    ) VALUES (?, ?, ?, ?, ?, ?, ?);
    """

    audit_details = json.dumps(
        {
            "server_id": event_data["server_id"],
            "sequence_number": receipt_data["sequence_number"],
            "payload_hash": receipt_data["payload_hash"],
        },
        separators=(",", ":"),
    )

    await db.execute(
        insert_event_sql,
        (
            event_data["event_id"],
            event_data["tenant_id"],
            event_data["server_id"],
            event_data["timestamp_utc"],
            metrics_json,
            receipt_data["collector_id"],
            receipt_data["sequence_number"],
            event_data["policy_version"],
            receipt_data["payload_hash"],
            ingested_at_utc,
        ),
    )

    await db.execute(
        update_collector_sql,
        (
            receipt_data["sequence_number"],
            ingested_at_utc,
            receipt_data["collector_id"],
        ),
    )

    await db.execute(
        insert_verification_sql,
        (
            verification_record["verification_id"],
            verification_record["event_id"],
            verification_record["tenant_id"],
            verification_record["collector_id"],
            verification_record["status"],
            verification_record["structure_valid"],
            verification_record["collector_registered"],
            verification_record["tenant_matched"],
            verification_record["hash_matched"],
            verification_record["signature_valid"],
            verification_record["duplicate_check_passed"],
            verification_record["sequence_valid"],
            verification_record["sequence_number"],
            verification_record["computed_hash"],
            verification_record["receipt_hash"],
            verification_record.get("failure_reason"),
            verification_record["verified_at_utc"],
        ),
    )

    await db.execute(
        insert_audit_sql,
        (
            ingested_at_utc,
            "INGEST_ACCEPTED",
            "INFO",
            event_data["tenant_id"],
            receipt_data["collector_id"],
            event_data["event_id"],
            audit_details,
        ),
    )

    await db.commit()


async def record_verification_failure(
    db: aiosqlite.Connection,
    verification_record: dict[str, Any],
    failure_type: str,
    details: Optional[dict[str, Any]] = None,
) -> None:
    """Records a verification rejection in verification_records and audit_records."""
    insert_verification_sql = """
    INSERT INTO verification_records (
        verification_id, event_id, tenant_id, collector_id, status,
        structure_valid, collector_registered, tenant_matched, hash_matched,
        signature_valid, duplicate_check_passed, sequence_valid, sequence_number,
        computed_hash, receipt_hash, failure_reason, verified_at_utc
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """

    insert_audit_sql = """
    INSERT INTO audit_records (
        timestamp_utc, event_type, severity, tenant_id, collector_id, event_id, details
    ) VALUES (?, ?, ?, ?, ?, ?, ?);
    """

    sanitized_details = json.dumps(details or {}, separators=(",", ":"))

    await db.execute(
        insert_verification_sql,
        (
            verification_record["verification_id"],
            verification_record.get("event_id", "UNKNOWN"),
            verification_record.get("tenant_id", "UNKNOWN"),
            verification_record.get("collector_id", "UNKNOWN"),
            "FAILED",
            verification_record.get("structure_valid", 0),
            verification_record.get("collector_registered", 0),
            verification_record.get("tenant_matched", 0),
            verification_record.get("hash_matched", 0),
            verification_record.get("signature_valid", 0),
            verification_record.get("duplicate_check_passed", 0),
            verification_record.get("sequence_valid", 0),
            verification_record.get("sequence_number", 0),
            verification_record.get("computed_hash", ""),
            verification_record.get("receipt_hash", ""),
            verification_record.get("failure_reason", failure_type),
            verification_record["verified_at_utc"],
        ),
    )

    await db.execute(
        insert_audit_sql,
        (
            verification_record["verified_at_utc"],
            failure_type,
            "WARNING",
            verification_record.get("tenant_id"),
            verification_record.get("collector_id"),
            verification_record.get("event_id"),
            sanitized_details,
        ),
    )

    await db.commit()


# ==============================================================================
# Dashboard Query Functions
# ==============================================================================

async def get_all_tenants(db: aiosqlite.Connection) -> list[str]:
    """Retrieves list of distinct tenant IDs."""
    query = """
    SELECT DISTINCT tenant_id FROM (
        SELECT tenant_id FROM collectors
        UNION
        SELECT tenant_id FROM telemetry_events
    ) ORDER BY tenant_id ASC;
    """
    async with db.execute(query) as cursor:
        rows = await cursor.fetchall()
        return [row[0] for row in rows if row[0]]


async def get_dashboard_overview_data(
    db: aiosqlite.Connection, tenant_id: Optional[str] = None
) -> dict[str, Any]:
    """Aggregates high-level telemetry and collector counts."""
    coll_filter = "WHERE tenant_id = ?" if tenant_id else ""
    event_filter = "WHERE tenant_id = ?" if tenant_id else ""
    verif_filter = "WHERE tenant_id = ?" if tenant_id else ""
    params = (tenant_id,) if tenant_id else ()

    coll_sql = f"SELECT collector_id, status, last_heartbeat_utc FROM collectors {coll_filter};"
    async with db.execute(coll_sql, params) as cursor:
        collectors = await cursor.fetchall()

    total_collectors = len(collectors)
    online_count = 0
    offline_count = 0
    now_ts = datetime.now(timezone.utc)

    for c in collectors:
        c_status = c["status"]
        hb = c["last_heartbeat_utc"]
        if c_status == "ACTIVE" and hb:
            try:
                hb_dt = datetime.fromisoformat(hb.replace("Z", "+00:00"))
                if (now_ts - hb_dt).total_seconds() <= 180:
                    online_count += 1
                    continue
            except Exception:
                pass
        offline_count += 1

    event_sql = f"SELECT COUNT(*) FROM telemetry_events {event_filter};"
    async with db.execute(event_sql, params) as cursor:
        row = await cursor.fetchone()
        verified_events = row[0] if row else 0

    verif_sql = f"""
    SELECT 
        COUNT(*) as total_v,
        SUM(CASE WHEN status = 'VERIFIED' THEN 1 ELSE 0 END) as verified_v,
        SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed_v
    FROM verification_records {verif_filter};
    """
    async with db.execute(verif_sql, params) as cursor:
        row = await cursor.fetchone()
        total_verifications = row[0] or 0
        rejected_events = row[2] or 0

    return {
        "total_collectors": total_collectors,
        "online_collectors": online_count,
        "offline_collectors": offline_count,
        "total_events": total_verifications if total_verifications > 0 else verified_events,
        "verified_events": verified_events,
        "rejected_events": rejected_events,
    }


async def get_latest_server_telemetry_list(
    db: aiosqlite.Connection, tenant_id: Optional[str] = None
) -> list[dict[str, Any]]:
    """Returns the most recent verified event for each monitored server."""
    filter_clause = "WHERE tenant_id = ?" if tenant_id else ""
    params = (tenant_id,) if tenant_id else ()

    query = f"""
    WITH RankedEvents AS (
        SELECT 
            event_id, tenant_id, server_id, timestamp_utc, metrics,
            collector_id, sequence_number, policy_version, payload_hash, ingested_at_utc,
            ROW_NUMBER() OVER(PARTITION BY server_id ORDER BY timestamp_utc DESC) as rn
        FROM telemetry_events
        {filter_clause}
    )
    SELECT * FROM RankedEvents WHERE rn = 1 ORDER BY server_id ASC;
    """
    async with db.execute(query, params) as cursor:
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["metrics"] = json.loads(d["metrics"])
            except Exception:
                d["metrics"] = {}
            result.append(d)
        return result


async def get_collectors_monitoring_list(
    db: aiosqlite.Connection, tenant_id: Optional[str] = None
) -> list[dict[str, Any]]:
    """Retrieves all collectors with accepted and rejected event counters."""
    filter_clause = "WHERE c.tenant_id = ?" if tenant_id else ""
    params = (tenant_id,) if tenant_id else ()

    query = f"""
    SELECT 
        c.collector_id,
        c.tenant_id,
        c.public_key_path,
        c.status,
        c.last_seen_seq,
        c.created_at_utc,
        c.last_heartbeat_utc,
        (SELECT COUNT(*) FROM telemetry_events e WHERE e.collector_id = c.collector_id) as accepted_events,
        (SELECT COUNT(*) FROM verification_records v WHERE v.collector_id = c.collector_id AND v.status = 'FAILED') as failed_verifications
    FROM collectors c
    {filter_clause}
    ORDER BY c.collector_id ASC;
    """
    now_ts = datetime.now(timezone.utc)

    async with db.execute(query, params) as cursor:
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            hb = d["last_heartbeat_utc"]
            is_online = False
            if d["status"] == "ACTIVE" and hb:
                try:
                    hb_dt = datetime.fromisoformat(hb.replace("Z", "+00:00"))
                    is_online = (now_ts - hb_dt).total_seconds() <= 180
                except Exception:
                    is_online = False
            d["is_online"] = is_online
            result.append(d)
        return result


async def get_recent_verification_records(
    db: aiosqlite.Connection, tenant_id: Optional[str] = None, limit: int = 50
) -> list[dict[str, Any]]:
    """Retrieves recent verification records for security audit inspection."""
    filter_clause = "WHERE tenant_id = ?" if tenant_id else ""
    params = (tenant_id, limit) if tenant_id else (limit,)

    query = f"""
    SELECT * FROM verification_records
    {filter_clause}
    ORDER BY verified_at_utc DESC
    LIMIT ?;
    """
    async with db.execute(query, params) as cursor:
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_recent_telemetry_events(
    db: aiosqlite.Connection,
    tenant_id: Optional[str] = None,
    server_id: Optional[str] = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Retrieves recent verified telemetry events with optional filters."""
    clauses = []
    params = []
    if tenant_id:
        clauses.append("tenant_id = ?")
        params.append(tenant_id)
    if server_id:
        clauses.append("server_id = ?")
        params.append(server_id)

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)

    query = f"""
    SELECT event_id, tenant_id, server_id, timestamp_utc, metrics,
           collector_id, sequence_number, policy_version, payload_hash, ingested_at_utc
    FROM telemetry_events
    {where_sql}
    ORDER BY timestamp_utc DESC
    LIMIT ?;
    """
    async with db.execute(query, tuple(params)) as cursor:
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["metrics"] = json.loads(d["metrics"])
            except Exception:
                d["metrics"] = {}
            result.append(d)
        return result


async def get_server_metric_history(
    db: aiosqlite.Connection,
    server_id: str,
    tenant_id: Optional[str] = None,
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Retrieves ordered time-series metric points for a specific server."""
    filter_sql = "WHERE server_id = ?"
    params = [server_id]
    if tenant_id:
        filter_sql += " AND tenant_id = ?"
        params.append(tenant_id)

    params.append(limit)
    query = f"""
    SELECT timestamp_utc, metrics, sequence_number
    FROM (
        SELECT timestamp_utc, metrics, sequence_number
        FROM telemetry_events
        {filter_sql}
        ORDER BY timestamp_utc DESC
        LIMIT ?
    )
    ORDER BY timestamp_utc ASC;
    """
    async with db.execute(query, tuple(params)) as cursor:
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["metrics"] = json.loads(d["metrics"])
            except Exception:
                d["metrics"] = {}
            result.append(d)
        return result


# ==============================================================================
# AIOps Queries: Anomalies, Incidents, and Recommendations
# ==============================================================================

async def get_anomalies_list(
    db: aiosqlite.Connection,
    tenant_id: Optional[str] = None,
    server_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Retrieves list of detected anomalies from database."""
    clauses = []
    params = []
    if tenant_id:
        clauses.append("tenant_id = ?")
        params.append(tenant_id)
    if server_id:
        clauses.append("server_id = ?")
        params.append(server_id)
    if severity:
        clauses.append("severity = ?")
        params.append(severity.upper())

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)

    query = f"""
    SELECT anomaly_id, tenant_id, server_id, metric_name, observed_value,
           expected_baseline, severity, detection_timestamp, explanation, event_id, status
    FROM anomalies
    {where_sql}
    ORDER BY detection_timestamp DESC
    LIMIT ?;
    """
    async with db.execute(query, tuple(params)) as cursor:
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_incidents_list(
    db: aiosqlite.Connection,
    tenant_id: Optional[str] = None,
    server_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Retrieves list of correlated incidents from database."""
    clauses = []
    params = []
    if tenant_id:
        clauses.append("tenant_id = ?")
        params.append(tenant_id)
    if server_id:
        clauses.append("server_id = ?")
        params.append(server_id)
    if status:
        clauses.append("status = ?")
        params.append(status.upper())

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)

    query = f"""
    SELECT incident_id, tenant_id, server_id, title, severity, status,
           detection_timestamp, contributing_metrics, explanation, recommendations,
           correlated_anomalies_count, created_at_utc, updated_at_utc
    FROM incidents
    {where_sql}
    ORDER BY detection_timestamp DESC
    LIMIT ?;
    """
    async with db.execute(query, tuple(params)) as cursor:
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["contributing_metrics"] = json.loads(d["contributing_metrics"])
            except Exception:
                pass
            try:
                d["recommendations"] = json.loads(d["recommendations"])
            except Exception:
                pass
            result.append(d)
        return result


async def get_incident_by_id(
    db: aiosqlite.Connection, incident_id: str
) -> Optional[dict[str, Any]]:
    """Retrieves a single incident by its ID."""
    query = """
    SELECT incident_id, tenant_id, server_id, title, severity, status,
           detection_timestamp, contributing_metrics, explanation, recommendations,
           correlated_anomalies_count, created_at_utc, updated_at_utc
    FROM incidents
    WHERE incident_id = ?;
    """
    async with db.execute(query, (incident_id,)) as cursor:
        row = await cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["contributing_metrics"] = json.loads(d["contributing_metrics"])
        except Exception:
            pass
        try:
            d["recommendations"] = json.loads(d["recommendations"])
        except Exception:
            pass
        return d


async def get_recommendations_list(
    db: aiosqlite.Connection, tenant_id: Optional[str] = None, limit: int = 20
) -> list[dict[str, Any]]:
    """Retrieves explainable recommendations across recent incidents."""
    incidents = await get_incidents_list(db, tenant_id=tenant_id, status="OPEN", limit=limit)
    recommendations = []
    for inc in incidents:
        rec_data = inc.get("recommendations")
        if isinstance(rec_data, dict):
            recommendations.append({
                "incident_id": inc["incident_id"],
                "server_id": inc["server_id"],
                "tenant_id": inc["tenant_id"],
                "severity": inc["severity"],
                "title": inc["title"],
                "detected_at": inc["detection_timestamp"],
                **rec_data
            })
    return recommendations
