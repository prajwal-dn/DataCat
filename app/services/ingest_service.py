"""Core Ingestion Service implementing the zero-trust 9-step verification pipeline."""
from datetime import datetime, timezone
import logging
from typing import Any, Tuple
import uuid
import sqlite3
import aiosqlite
from pydantic import ValidationError

from app.core.crypto import (
    canonical_receipt_bytes,
    compute_payload_hash,
    verify_ed25519_signature,
)
from app.core.registry import registry
from app.core.schemas import IngestionRequest, SignedReceipt, TelemetryEvent
from app.db.queries import (
    get_existing_event,
    insert_telemetry_event_transaction,
    is_sequence_number_used,
    record_verification_failure,
)

logger = logging.getLogger(__name__)


class IngestionService:
    """Orchestrates zero-trust validation, cryptographic verification, and safe storage."""

    @staticmethod
    async def process_ingest(
        db: aiosqlite.Connection, raw_payload: dict[str, Any]
    ) -> Tuple[int, dict[str, Any]]:
        """Executes the complete 9-step validation pipeline.

        Returns (http_status_code, response_body).
        """
        now_utc = datetime.now(timezone.utc).isoformat()
        verification_id = str(uuid.uuid4())

        # Step 1: Validate request structure & strict extra field rejection
        try:
            req_model = IngestionRequest.model_validate(raw_payload)
            # Validate event fields strictly
            event_model = TelemetryEvent.model_validate(req_model.event)
            # Validate receipt fields strictly
            receipt_model = SignedReceipt.model_validate(req_model.receipt)
        except ValidationError as ve:
            # Format clean error without disclosing internal structures
            errors = [f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}" for err in ve.errors()]
            verification_rec = {
                "verification_id": verification_id,
                "event_id": str(raw_payload.get("event", {}).get("event_id", "UNKNOWN")),
                "tenant_id": str(raw_payload.get("event", {}).get("tenant_id", "UNKNOWN")),
                "collector_id": str(raw_payload.get("receipt", {}).get("collector_id", "UNKNOWN")),
                "structure_valid": 0,
                "verified_at_utc": now_utc,
            }
            await record_verification_failure(
                db, verification_rec, "INVALID_SCHEMA", {"errors": errors[:3]}
            )
            return 400, {
                "status": "INVALID_SCHEMA",
                "message": "Request payload failed schema validation",
                "errors": errors,
            }

        # Original dicts preserved for cryptographic operations
        raw_event = req_model.event
        raw_receipt = req_model.receipt

        event_id = event_model.event_id
        tenant_id = event_model.tenant_id
        collector_id = receipt_model.collector_id
        sequence_number = receipt_model.sequence_number
        policy_version = event_model.policy_version
        receipt_hash = receipt_model.payload_hash

        verification_rec = {
            "verification_id": verification_id,
            "event_id": event_id,
            "tenant_id": tenant_id,
            "collector_id": collector_id,
            "sequence_number": sequence_number,
            "receipt_hash": receipt_hash,
            "computed_hash": "",
            "structure_valid": 1,
            "collector_registered": 0,
            "tenant_matched": 0,
            "hash_matched": 0,
            "signature_valid": 0,
            "duplicate_check_passed": 0,
            "sequence_valid": 0,
            "verified_at_utc": now_utc,
        }

        # Step 2: Validate event and receipt consistency
        if receipt_model.event_id != event_id or receipt_model.tenant_id != tenant_id or receipt_model.policy_version != policy_version:
            verification_rec["failure_reason"] = "Inconsistency between event and receipt envelope"
            await record_verification_failure(
                db,
                verification_rec,
                "INVALID_SCHEMA",
                {"reason": "event and receipt metadata mismatch"},
            )
            return 400, {
                "status": "INVALID_SCHEMA",
                "message": "Inconsistent identifiers between event and receipt envelope",
            }

        # Step 3: Identify registered collector
        collector = registry.get(collector_id)
        if not collector or not collector.active:
            verification_rec["collector_registered"] = 0
            verification_rec["failure_reason"] = f"Collector '{collector_id}' unknown or inactive"
            await record_verification_failure(
                db, verification_rec, "UNKNOWN_COLLECTOR"
            )
            return 403, {
                "status": "UNKNOWN_COLLECTOR",
                "message": "Collector is not registered or is inactive",
            }
        verification_rec["collector_registered"] = 1

        # Step 4: Verify collector and tenant relationship
        if collector.tenant_id != tenant_id:
            verification_rec["tenant_matched"] = 0
            verification_rec["failure_reason"] = f"Collector does not belong to tenant '{tenant_id}'"
            await record_verification_failure(
                db, verification_rec, "TENANT_MISMATCH"
            )
            return 403, {
                "status": "TENANT_MISMATCH",
                "message": "Tenant mismatch between event and collector registration",
            }
        verification_rec["tenant_matched"] = 1

        # Step 5: Recalculate SHA-256 of canonical event representation
        computed_hash = compute_payload_hash(raw_event)
        verification_rec["computed_hash"] = computed_hash

        if computed_hash.lower() != receipt_hash.lower():
            verification_rec["hash_matched"] = 0
            verification_rec["failure_reason"] = "Payload hash mismatch"
            await record_verification_failure(
                db, verification_rec, "HASH_MISMATCH"
            )
            return 400, {
                "status": "HASH_MISMATCH",
                "message": "Computed SHA-256 payload hash does not match receipt",
            }
        verification_rec["hash_matched"] = 1

        # Step 6: Verify Ed25519 signature
        canonical_receipt = canonical_receipt_bytes(raw_receipt)
        is_sig_valid = verify_ed25519_signature(
            collector.public_key,
            receipt_model.signature,
            canonical_receipt,
        )

        if not is_sig_valid:
            verification_rec["signature_valid"] = 0
            verification_rec["failure_reason"] = "Ed25519 signature verification failed"
            await record_verification_failure(
                db, verification_rec, "INVALID_SIGNATURE"
            )
            return 401, {
                "status": "INVALID_SIGNATURE",
                "message": "Ed25519 digital signature verification failed",
            }
        verification_rec["signature_valid"] = 1

        # Step 7: Duplicate and sequence constraints
        # Case A & B: Check if event_id already exists for this tenant
        existing_event = await get_existing_event(db, tenant_id, event_id)
        if existing_event:
            if existing_event["payload_hash"].lower() == receipt_hash.lower():
                # Case A: Same event ID and same verified hash -> Idempotent DUPLICATE response
                logger.info("Idempotent duplicate event received: %s", event_id)
                return 200, {
                    "status": "DUPLICATE",
                    "message": "Event already ingested with identical payload hash",
                    "event_id": event_id,
                }
            else:
                # Case B: Same event ID and different hash -> Reject conflicting payload
                verification_rec["duplicate_check_passed"] = 0
                verification_rec["failure_reason"] = "Conflicting payload hash for existing event_id"
                await record_verification_failure(
                    db, verification_rec, "DUPLICATE_CONFLICT"
                )
                return 409, {
                    "status": "DUPLICATE_CONFLICT",
                    "message": "Event ID already exists with conflicting payload hash",
                    "event_id": event_id,
                }
        verification_rec["duplicate_check_passed"] = 1

        # Case C: Same collector sequence number reused
        seq_used = await is_sequence_number_used(db, collector_id, sequence_number)
        if seq_used:
            verification_rec["sequence_valid"] = 0
            verification_rec["failure_reason"] = f"Sequence number {sequence_number} already used"
            await record_verification_failure(
                db, verification_rec, "SEQUENCE_CONFLICT"
            )
            return 409, {
                "status": "SEQUENCE_CONFLICT",
                "message": f"Sequence number {sequence_number} already used for this collector",
            }
        verification_rec["sequence_valid"] = 1

        # Case D: Legitimate out-of-order event is accepted since it passed duplicate and sequence uniqueness checks

        # Step 8: Store verified event atomically in database
        verification_rec["status"] = "VERIFIED"
        try:
            await insert_telemetry_event_transaction(
                db,
                event_data=raw_event,
                receipt_data=raw_receipt,
                ingested_at_utc=now_utc,
                verification_record=verification_rec,
            )
        except (aiosqlite.IntegrityError, sqlite3.IntegrityError) as ie:
            # Concurrent duplicate race: another worker committed the event in parallel
            logger.info("Concurrent submission caught IntegrityError: %s", ie)
            existing_event = await get_existing_event(db, tenant_id, event_id)
            if existing_event and existing_event["payload_hash"].lower() == receipt_hash.lower():
                return 200, {
                    "status": "DUPLICATE",
                    "message": "Event already ingested with identical payload hash",
                    "event_id": event_id,
                }
            return 409, {
                "status": "SEQUENCE_CONFLICT",
                "message": "Sequence or event uniqueness constraint collision",
            }
        except Exception as e:
            logger.error("Database transaction error while storing event: %s", e)
            return 500, {
                "status": "DATABASE_ERROR",
                "message": "Failed to safely persist verified telemetry event",
            }

        # Step 8b: Execute Unified AIOps Decision Pipeline (Statistical + ML + Fusion + Health)
        try:
            from app.core.unified_aiops import UnifiedAIOpsPipeline
            await UnifiedAIOpsPipeline.process_verified_event(db, raw_event)
        except Exception as e:
            logger.error("Unified AIOps pipeline error (non-fatal): %s", e)

        # Step 8c: Trigger legacy AIOps engine for incident correlation compatibility
        try:
            from app.core.aiops import AIOpsEngine
            await AIOpsEngine.analyze_event(db, raw_event)
        except Exception as e:
            logger.error("AIOps incident correlator error (non-fatal): %s", e)

        # Step 9: Return ingestion status
        return 201, {
            "status": "ACCEPTED",
            "message": "Telemetry event successfully verified and ingested",
            "event_id": event_id,
        }
