"""
POST /api/v1/ingest — telemetry event ingestion with full verification pipeline.

Pipeline:
  1. Header consistency check: X-Tenant-ID must be present and match body.tenant_id
  2. Trusted key lookup: tenant_id must exist in trusted_keys table
  3. Public key verification: receipt.public_key must match registered key
  4. SHA-256 canonical hash verification
  5. Ed25519 signature verification: domain-separated DATACAT-INGEST-V1 prefix
  6. Duplicate detection: (tenant_id, event_id) pre-check
  7. Store accepted event: insert into events table under UNIQUE(tenant_id, event_id)

Rejection privacy:
  Rejections are stored exclusively in rejection_audit with sanitized metadata.
  Raw payloads, signatures, and untrusted keys are never stored in rejection records
  or written to persistent application logs.
"""
import json
import aiosqlite
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Header, Response
from fastapi.responses import JSONResponse

from backend.config import DB_PATH
from backend.models import IngestRequest, IngestAccepted, IngestRejected
from backend.verification.hash_verify import verify_hash
from backend.verification.signature_verify import verify_signature, keys_match
from backend.verification.dedup import is_duplicate

router = APIRouter()


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    event_id: str,
    source_host: Optional[str],
    event_type: Optional[str],
    timestamp: Optional[str],
    reason: str,
) -> None:
    """Store sanitized rejection metadata only in rejection_audit table."""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                INSERT INTO rejection_audit
                    (tenant_id, event_id, timestamp, source_host, event_type, rejected_reason, rejected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    event_id,
                    timestamp,
                    source_host,
                    event_type,
                    reason,
                    _now_utc(),
                ),
            )
            await db.commit()
    except Exception:
        pass


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
    body: IngestRequest,
    x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-ID"),
):
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
