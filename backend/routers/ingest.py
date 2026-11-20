"""
POST /api/v1/ingest — telemetry event ingestion with full verification pipeline.

Verification pipeline (in order):
  1. Schema validation        (Pydantic — automatic)
  2. X-Tenant-ID header check (must match body tenant_id)
  3. Trusted key lookup       (DB — reject if tenant not registered)
  4. Public key match check   (request key must equal registered key)
  5. SHA-256 hash verification
  6. Ed25519 signature verification (using REGISTERED key, tenant-bound message)
  7. Duplicate detection      (pre-check + DB UNIQUE constraint)
  8. Store event              (payload=NULL on rejection for privacy)

Privacy rule: rejected events are stored with ONLY metadata — never the payload.
"""
import json
import aiosqlite

from datetime import datetime, timezone
from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import JSONResponse
from typing import Optional

from backend.config import DB_PATH
from backend.models import IngestRequest, IngestAccepted, IngestRejected
from backend.verification.hash_verify import verify_hash
from backend.verification.signature_verify import verify_signature, keys_match
from backend.verification.dedup import is_duplicate

router = APIRouter()


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _get_registered_key(tenant_id: str) -> Optional[str]:
    """Fetch the registered public key for a tenant. Returns None if not found."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT public_key_b64 FROM trusted_keys WHERE tenant_id = ?",
            (tenant_id,),
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None


async def _store_rejection(
    event_id: str,
    tenant_id: str,
    source_host: str,
    event_type: str,
    timestamp: str,
    reason: str,
    hash_verified: bool,
    sig_verified: bool,
) -> None:
    """
    Store rejection metadata only. payload is intentionally omitted (privacy rule).
    If a duplicate causes IntegrityError here we silently ignore — the original
    record already exists.
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                INSERT OR IGNORE INTO events
                    (event_id, tenant_id, timestamp, source_host, event_type,
                     payload, privacy_tags, status, hash_verified, sig_verified,
                     rejected_reason, ingested_at)
                VALUES (?, ?, ?, ?, ?, NULL, NULL, 'rejected', ?, ?, ?, ?)
                """,
                (
                    event_id, tenant_id, timestamp, source_host, event_type,
                    int(hash_verified), int(sig_verified),
                    reason, _now_utc(),
                ),
            )
            await db.commit()
    except Exception:
        pass  # Best-effort; never let storage failure mask the actual rejection response


async def _store_accepted(req: IngestRequest) -> str:
    """
    Store a fully verified event. Returns the ingested_at timestamp.
    Raises aiosqlite.IntegrityError on duplicate (concurrent race condition).
    """
    ingested_at = _now_utc()
    async with aiosqlite.connect(DB_PATH) as db:
        # BEGIN IMMEDIATE acquires a write lock immediately, preventing races
        await db.execute("BEGIN IMMEDIATE")
        try:
            await db.execute(
                """
                INSERT INTO events
                    (event_id, tenant_id, timestamp, source_host, event_type,
                     payload, privacy_tags, status, hash_verified, sig_verified,
                     rejected_reason, ingested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'accepted', 1, 1, NULL, ?)
                """,
                (
                    req.event.event_id,
                    req.tenant_id,
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
    # ── Step 1: Header/body tenant_id consistency ──────────────────────────
    if x_tenant_id and x_tenant_id != body.tenant_id:
        raise HTTPException(
            status_code=400,
            detail={
                "status": "rejected",
                "reason": "tenant_mismatch",
                "detail": "X-Tenant-ID header does not match body tenant_id",
            },
        )

    evt = body.event
    rcpt = body.receipt

    # ── Step 2: Trusted key registry lookup ───────────────────────────────
    registered_key = await _get_registered_key(body.tenant_id)
    if registered_key is None:
        return JSONResponse(
            status_code=400,
            content=IngestRejected(
                reason="unknown_collector",
                detail=f"No registered public key for tenant_id={body.tenant_id}",
            ).model_dump(),
        )

    # ── Step 3: Public key match (request key must equal registered key) ──
    if not keys_match(rcpt.public_key, registered_key):
        await _store_rejection(
            evt.event_id, body.tenant_id, evt.source_host, evt.event_type,
            evt.timestamp, "untrusted_key", False, False,
        )
        return JSONResponse(
            status_code=400,
            content=IngestRejected(
                reason="untrusted_key",
                detail="receipt.public_key does not match the registered trusted key for this tenant",
            ).model_dump(),
        )

    # ── Step 4: SHA-256 hash verification ─────────────────────────────────
    event_dict = evt.model_dump()
    hash_ok = verify_hash(event_dict, rcpt.payload_hash)
    if not hash_ok:
        await _store_rejection(
            evt.event_id, body.tenant_id, evt.source_host, evt.event_type,
            evt.timestamp, "hash_mismatch", False, False,
        )
        return JSONResponse(
            status_code=400,
            content=IngestRejected(
                reason="hash_mismatch",
                detail="Computed hash does not match receipt.payload_hash",
            ).model_dump(),
        )

    # ── Step 5: Ed25519 signature verification (tenant-bound) ─────────────
    sig_ok = verify_signature(
        tenant_id=body.tenant_id,
        payload_hash_hex=rcpt.payload_hash,
        signature_b64=rcpt.signature,
        registered_pubkey_b64=registered_key,
    )
    if not sig_ok:
        await _store_rejection(
            evt.event_id, body.tenant_id, evt.source_host, evt.event_type,
            evt.timestamp, "invalid_signature", True, False,
        )
        return JSONResponse(
            status_code=400,
            content=IngestRejected(
                reason="invalid_signature",
                detail="Ed25519 signature verification failed",
            ).model_dump(),
        )

    # ── Step 6: Duplicate detection (pre-check) ───────────────────────────
    if await is_duplicate(evt.event_id):
        return JSONResponse(
            status_code=409,
            content=IngestRejected(
                reason="duplicate_event",
                detail="event_id already ingested",
            ).model_dump(),
        )

    # ── Step 7: Store accepted event (DB UNIQUE constraint catches races) ──
    try:
        ingested_at = await _store_accepted(body)
    except aiosqlite.IntegrityError:
        # Concurrent duplicate slipped past the pre-check
        return JSONResponse(
            status_code=409,
            content=IngestRejected(
                reason="duplicate_event",
                detail="event_id already ingested (concurrent submission)",
            ).model_dump(),
        )

    return IngestAccepted(
        event_id=evt.event_id,
        hash_verified=True,
        signature_verified=True,
        duplicate=False,
        stored_at=ingested_at,
    )
