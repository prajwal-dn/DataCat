"""
Database layer — aiosqlite connection and schema definition.

Design:
- `events`: Stores accepted, fully-verified events with UNIQUE(tenant_id, event_id).
  Payload is guaranteed non-null.
- `rejection_audit`: Stores sanitized rejection metadata only.
  Never stores raw payloads, signatures, or untrusted public keys.
- `trusted_keys`: Stores pre-registered collector public keys mapped by tenant_id.
"""
import aiosqlite
from backend.config import DB_PATH

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS trusted_keys (
    tenant_id       TEXT NOT NULL PRIMARY KEY,
    public_key_b64  TEXT NOT NULL,
    collector_name  TEXT,
    registered_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id        TEXT NOT NULL,
    event_id         TEXT NOT NULL,
    timestamp        TEXT NOT NULL,
    source_host      TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    payload          TEXT NOT NULL,
    privacy_tags     TEXT,
    hash_verified    INTEGER NOT NULL DEFAULT 1,
    sig_verified     INTEGER NOT NULL DEFAULT 1,
    ingested_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE(tenant_id, event_id)
);

CREATE TABLE IF NOT EXISTS rejection_audit (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id        TEXT NOT NULL,
    event_id         TEXT NOT NULL,
    timestamp        TEXT,
    source_host      TEXT,
    event_type       TEXT,
    rejected_reason  TEXT NOT NULL,
    rejected_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_events_tenant_event ON events(tenant_id, event_id);
CREATE INDEX IF NOT EXISTS idx_events_tenant_ingested ON events(tenant_id, ingested_at);
CREATE INDEX IF NOT EXISTS idx_rejection_tenant_rejected ON rejection_audit(tenant_id, rejected_at);
"""


async def init_db() -> None:
    """Create tables if they do not exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(_DDL)
        await db.commit()


def get_db_path() -> str:
    return DB_PATH
