"""
Ed25519 signature verification with domain-separated tenant-bound signing.

Signing specification:
  Domain separation prefix: DATACAT-INGEST-V1:
  Deterministic message format:
    f"DATACAT-INGEST-V1:{tenant_id}:{payload_hash}".encode("utf-8")

Security rules:
- Backend verifies using the registered public key for tenant_id from trusted_keys.
- The public key provided in receipt is verified for exact match against trusted_keys.
- Any verification failure or bad key encoding returns False.
"""
import base64
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN_SEPARATOR = "DATACAT-INGEST-V1"


def compute_signing_message(tenant_id: str, payload_hash_hex: str) -> bytes:
    """Return the deterministic domain-separated byte message to sign or verify."""
    return f"{DOMAIN_SEPARATOR}:{tenant_id}:{payload_hash_hex.lower()}".encode("utf-8")


def _load_public_key(pubkey_b64: str) -> Optional[Ed25519PublicKey]:
    """Decode a base64 Ed25519 public key. Returns None on decode/type errors."""
    try:
        raw = base64.b64decode(pubkey_b64)
        if len(raw) != 32:
            return None
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        return None


def verify_signature(
    tenant_id: str,
    payload_hash_hex: str,
    signature_b64: str,
    registered_pubkey_b64: str,
) -> bool:
    """
    Verify Ed25519 signature against registered trusted public key using
    domain-separated, tenant-bound message.
    """
    public_key = _load_public_key(registered_pubkey_b64)
    if public_key is None:
        return False

    try:
        sig_bytes = base64.b64decode(signature_b64)
    except Exception:
        return False

    message = compute_signing_message(tenant_id, payload_hash_hex)

    try:
        public_key.verify(sig_bytes, message)
        return True
    except (InvalidSignature, Exception):
        return False


def keys_match(request_pubkey_b64: str, registered_pubkey_b64: str) -> bool:
    """Constant-time comparison between request key and registered key."""
    import hmac as _hmac
    try:
        a = base64.b64decode(request_pubkey_b64)
        b = base64.b64decode(registered_pubkey_b64)
        return _hmac.compare_digest(a, b)
    except Exception:
        return False
