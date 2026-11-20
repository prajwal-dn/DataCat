"""
Ed25519 signing for the DataCat Collector.

Implements the exact signing contract from docs/api-contract.md:

  Domain-separated message:
      f"DATACAT-INGEST-V1:{tenant_id}:{payload_hash_hex.lower()}"  →  UTF-8 bytes

  Canonical hash:
      json.dumps(event_dict, sort_keys=True, separators=(',',':'), ensure_ascii=False)
      → encode UTF-8 → SHA-256 → hex string

Both sides (collector and backend) MUST use these identical byte sequences.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

logger = logging.getLogger("datacat.collector.signing")

DOMAIN_SEPARATOR = "DATACAT-INGEST-V1"


# ── Canonical hash ────────────────────────────────────────────────────────────

def canonical_hash(event_dict: Dict[str, Any]) -> str:
    """
    Return hex-encoded SHA-256 of the canonical JSON encoding of event_dict.
    Keys are sorted alphabetically; no extra whitespace; UTF-8 encoded.

    This MUST match backend/verification/hash_verify.py exactly.
    """
    canonical = json.dumps(event_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── Domain-separated signing message ─────────────────────────────────────────

def signing_message(tenant_id: str, payload_hash_hex: str) -> bytes:
    """
    Return the deterministic domain-separated UTF-8 bytes to sign.
    Format: DATACAT-INGEST-V1:{tenant_id}:{payload_hash_hex.lower()}
    """
    return f"{DOMAIN_SEPARATOR}:{tenant_id}:{payload_hash_hex.lower()}".encode("utf-8")


# ── Public key export ─────────────────────────────────────────────────────────

def public_key_b64(private_key: Ed25519PrivateKey) -> str:
    """Return the base64-encoded raw 32-byte public key for the given private key."""
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


# ── Full signing pipeline ─────────────────────────────────────────────────────

def sign_event(
    event_dict: Dict[str, Any],
    tenant_id: str,
    private_key: Ed25519PrivateKey,
) -> Tuple[str, str, str, str]:
    """
    Compute the canonical hash and Ed25519 signature for an event dict.

    Args:
        event_dict:  The ``event`` object (before wrapping in the ingest envelope).
        tenant_id:   The collector's tenant UUID.
        private_key: The loaded Ed25519 private key.

    Returns:
        (payload_hash_hex, signature_b64, pubkey_b64, signed_at_iso)
    """
    payload_hash = canonical_hash(event_dict)
    message = signing_message(tenant_id, payload_hash)
    sig_bytes = private_key.sign(message)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
    pub_b64 = public_key_b64(private_key)
    signed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    logger.debug(
        "Signed event tenant=%s hash=%s sig=%s…",
        tenant_id,
        payload_hash[:16],
        sig_b64[:16],
    )
    return payload_hash, sig_b64, pub_b64, signed_at


def build_ingest_payload(
    event_dict: Dict[str, Any],
    tenant_id: str,
    private_key: Ed25519PrivateKey,
) -> Dict[str, Any]:
    """
    Wrap an event dict in the full ingest envelope matching the API contract.

    Returns the dict ready to POST to POST /api/v1/ingest.
    """
    payload_hash, sig_b64, pub_b64, signed_at = sign_event(event_dict, tenant_id, private_key)

    return {
        "tenant_id": tenant_id,
        "event": event_dict,
        "receipt": {
            "payload_hash": payload_hash,
            "signature": sig_b64,
            "public_key": pub_b64,
            "signed_at": signed_at,
        },
    }
