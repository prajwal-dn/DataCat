"""
POST /api/v1/ingest — telemetry event ingestion with full verification pipeline.

Pipeline:
  1. Payload size enforcement: MAX_PAYLOAD_BYTES limit check
  2. Header consistency check: X-Tenant-ID must match body.tenant_id
  3. Trusted key lookup: tenant_id must exist in trusted_keys table
  4. Public key verification: receipt.public_key must match registered key
  5. SHA-256 canonical hash verification
  6. Ed25519 signature verification: domain-separated DATACAT-INGEST-V1 prefix
  7. Duplicate detection: (tenant_id, event_id) pre-check
  8. Store accepted event: insert into events table under UNIQUE(tenant_id, event_id)

Rejection privacy:
  Rejections are stored exclusively in rejection_audit with strictly sanitized metadata.
  Raw payloads, signatures, and untrusted keys are NEVER stored in rejection records
  or written to persistent application logs.
"""
import json
import logging
import re
import aiosqlite
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from backend.config import DB_PATH, MAX_PAYLOAD_BYTES
from backend.models import IngestRequest, IngestAccepted, IngestRejected
from backend.verification.hash_verify import verify_hash
from backend.verification.signature_verify import verify_signature, keys_match
from backend.verification.dedup import is_duplicate

logger = logging.getLogger("datacat.ingest")
router = APIRouter()

# Strict sanitization patterns for rejection audit metadata
_SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")
_SAFE_HOST_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,64}$")
_SAFE_TYPE_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,64}$")


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sanitize_identifier(value: Optional[str], pattern: re.Pattern, default: str) -> str:
    """Sanitize identifiers to prevent log/audit poisoning or unconstrained storage."""
    if not value or not isinstance(value, str):
        return default
    cleaned = value.strip()
    if pattern.match(cleaned):
        return cleaned
    filtered = re.sub(r"[^a-zA-Z0-9._\-]", "", cleaned)[:64]
    return filtered if filtered else default


async def _get_registered_key(tenant_id: str) -> Optional[str]:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT public_key_b64 FROM trusted_keys WHERE tenant_id = ?",
            (tenant_id,),
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None


async def _store_rejection(
    tenant_id: str,
    event_id: Optional[str],
    source_host: Optional[str],
    event_type: Optional[str],
    timestamp: Optional[str],
    reason: str,
) -> None:
    """
    Store sanitized rejection metadata only in rejection_audit table.
    Database errors are explicitly logged without leaking sensitive payloads.
    """
    sanitized_event_id = _sanitize_identifier(event_id, _SAFE_ID_RE, "unknown_event")
    sanitized_tenant_id = _sanitize_identifier(tenant_id, _SAFE_ID_RE, "unknown_tenant")
    sanitized_host = _sanitize_identifier(source_host, _SAFE_HOST_RE, "unknown_host")
    sanitized_type = _sanitize_identifier(event_type, _SAFE_TYPE_RE, "unknown_type")
    sanitized_ts = timestamp if (timestamp and isinstance(timestamp, str) and len(timestamp) <= 35) else None

    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                INSERT INTO rejection_audit
                    (tenant_id, event_id, timestamp, source_host, event_type, rejected_reason, rejected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sanitized_tenant_id,
                    sanitized_event_id,
                    sanitized_ts,
                    sanitized_host,
                    sanitized_type,
                    reason,
                    _now_utc(),
                ),
            )
            await db.commit()
    except Exception as exc:
        logger.error(
            "Failed to record rejection audit for tenant_id=%s, reason=%s: %s",
            sanitized_tenant_id,
            reason,
            type(exc).__name__,
        )


async def _store_accepted(req: IngestRequest) -> str:
    """Insert into events table. Raises aiosqlite.IntegrityError on concurrent duplicate."""
    ingested_at = _now_utc()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("BEGIN IMMEDIATE")
        try:
            await db.execute(
                """
                INSERT INTO events
                    (tenant_id, event_id, timestamp, source_host, event_type,
                     payload, privacy_tags, hash_verified, sig_verified, ingested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, ?)
                """,
                (
                    req.tenant_id,
                    req.event.event_id,
                    req.event.timestamp,
                    req.event.source_host,
                    req.event.event_type,
                    json.dumps(req.event.payload),
                    json.dumps(req.event.privacy_tags),
                    ingested_at,
                ),
            )
            await db.commit()
        except Exception:
            await db.rollback()
            raise
    return ingested_at


@router.post("/ingest", status_code=202)
async def ingest_event(
    request: Request,
    body: IngestRequest,
    x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-ID"),
):
    # Enforce streaming payload byte limit directly
    raw_body = await request.body()
    if len(raw_body) > MAX_PAYLOAD_BYTES:
        await _store_rejection(
            tenant_id=body.tenant_id,
            event_id=body.event.event_id,
            source_host=body.event.source_host,
            event_type=body.event.event_type,
            timestamp=body.event.timestamp,
            reason="payload_too_large",
        )
        return JSONResponse(
            status_code=413,
            content=IngestRejected(
                reason="payload_too_large",
                detail=f"Request body exceeds {MAX_PAYLOAD_BYTES} bytes limit",
            ).model_dump(),
        )

    evt = body.event
    rcpt = body.receipt

    # 1. Enforce tenant identity consistency with X-Tenant-ID header
    if not x_tenant_id or x_tenant_id != body.tenant_id:
        await _store_rejection(
            tenant_id=body.tenant_id,
            event_id=evt.event_id,
            source_host=evt.source_host,
            event_type=evt.event_type,
            timestamp=evt.timestamp,
            reason="tenant_mismatch",
        )
        return JSONResponse(
            status_code=400,
            content=IngestRejected(
                reason="tenant_mismatch",
                detail="X-Tenant-ID header must be present and match body tenant_id",
            ).model_dump(),
        )

    # 2. Check trusted public key registry
    registered_key = await _get_registered_key(body.tenant_id)
    if registered_key is None:
        await _store_rejection(
            tenant_id=body.tenant_id,
            event_id=evt.event_id,
            source_host=evt.source_host,
            event_type=evt.event_type,
            timestamp=evt.timestamp,
            reason="unknown_collector",
        )
        return JSONResponse(
            status_code=400,
            content=IngestRejected(
                reason="unknown_collector",
                detail=f"No registered public key for tenant_id={body.tenant_id}",
            ).model_dump(),
        )

    # 3. Request public key match
    if not keys_match(rcpt.public_key, registered_key):
        await _store_rejection(
            tenant_id=body.tenant_id,
            event_id=evt.event_id,
            source_host=evt.source_host,
            event_type=evt.event_type,
            timestamp=evt.timestamp,
            reason="untrusted_key",
        )
        return JSONResponse(
            status_code=400,
            content=IngestRejected(
                reason="untrusted_key",
                detail="receipt.public_key does not match registered trusted key",
            ).model_dump(),
        )

    # 4. SHA-256 hash verification
    event_dict = evt.model_dump()
    if not verify_hash(event_dict, rcpt.payload_hash):
        await _store_rejection(
            tenant_id=body.tenant_id,
            event_id=evt.event_id,
            source_host=evt.source_host,
            event_type=evt.event_type,
            timestamp=evt.timestamp,
            reason="hash_mismatch",
        )
        return JSONResponse(
            status_code=400,
            content=IngestRejected(
                reason="hash_mismatch",
                detail="Computed hash does not match receipt.payload_hash",
            ).model_dump(),
        )

    # 5. Ed25519 signature verification (domain separated)
    if not verify_signature(
        tenant_id=body.tenant_id,
        payload_hash_hex=rcpt.payload_hash,
        signature_b64=rcpt.signature,
        registered_pubkey_b64=registered_key,
    ):
        await _store_rejection(
            tenant_id=body.tenant_id,
            event_id=evt.event_id,
            source_host=evt.source_host,
            event_type=evt.event_type,
            timestamp=evt.timestamp,
            reason="invalid_signature",
        )
        return JSONResponse(
            status_code=400,
            content=IngestRejected(
                reason="invalid_signature",
                detail="Ed25519 signature verification failed",
            ).model_dump(),
        )

    # 6. Duplicate detection pre-check
    if await is_duplicate(body.tenant_id, evt.event_id):
        await _store_rejection(
            tenant_id=body.tenant_id,
            event_id=evt.event_id,
            source_host=evt.source_host,
            event_type=evt.event_type,
            timestamp=evt.timestamp,
            reason="duplicate_event",
        )
        return JSONResponse(
            status_code=409,
            content=IngestRejected(
                reason="duplicate_event",
                detail="event_id already ingested for this tenant",
            ).model_dump(),
        )

    # 7. Store accepted event with DB constraint handling
    try:
        ingested_at = await _store_accepted(body)
    except aiosqlite.IntegrityError:
        await _store_rejection(
            tenant_id=body.tenant_id,
            event_id=evt.event_id,
            source_host=evt.source_host,
            event_type=evt.event_type,
            timestamp=evt.timestamp,
            reason="duplicate_event",
        )
        return JSONResponse(
            status_code=409,
            content=IngestRejected(
                reason="duplicate_event",
                detail="event_id already ingested for this tenant (concurrent duplicate)",
            ).model_dump(),
        )

    return IngestAccepted(
        event_id=evt.event_id,
        hash_verified=True,
        signature_verified=True,
        duplicate=False,
        stored_at=ingested_at,
    )
