"""
Database layer — aiosqlite connection, schema definition, and token authentication helpers.

Design:
- `events`: Stores accepted, fully-verified events with UNIQUE(tenant_id, event_id).
  Payload is guaranteed non-null.
- `rejection_audit`: Stores sanitized rejection metadata only.
  Never stores raw payloads, signatures, or untrusted public keys.
- `trusted_keys`: Stores pre-registered collector public keys mapped by tenant_id.
- `tenant_tokens`: Stores hashed API tokens for dashboard authorization per tenant.
"""
import hashlib
import hmac
import aiosqlite
from typing import Optional
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

CREATE TABLE IF NOT EXISTS tenant_tokens (
    token_hash      TEXT NOT NULL PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
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
CREATE INDEX IF NOT EXISTS idx_tokens_tenant ON tenant_tokens(tenant_id);
"""


def hash_token(token: str) -> str:
    """Return SHA-256 hash of API token for secure storage."""
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


async def init_db() -> None:
    """Create tables if they do not exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(_DDL)
        await db.commit()


async def register_tenant_token(tenant_id: str, raw_token: str) -> None:
    """Register an API token for a tenant in the database."""
    t_hash = hash_token(raw_token)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO tenant_tokens (token_hash, tenant_id)
            VALUES (?, ?)
            ON CONFLICT(token_hash) DO UPDATE SET tenant_id = excluded.tenant_id
            """,
            (t_hash, tenant_id),
        )
        await db.commit()


async def get_tenant_for_token(raw_token: str) -> Optional[str]:
    """Retrieve the tenant_id associated with an API token, if valid."""
    if not raw_token:
        return None
    t_hash = hash_token(raw_token)
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT tenant_id FROM tenant_tokens WHERE token_hash = ?",
            (t_hash,),
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None


def get_db_path() -> str:
    return DB_PATH
