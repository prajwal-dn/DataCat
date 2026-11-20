"""
Ed25519 signature verification.

Security model:
- The backend NEVER trusts the public key supplied in the request body.
- It looks up the REGISTERED trusted key for the tenant from the database.
- It then validates that receipt.public_key matches the registered key
  (so the collector knows which key to present, but cannot substitute one).
- Verification is performed against the registered key.

Tenant-binding (security fix applied here):
  The signed message is: f"{tenant_id}:{payload_hash}".encode('utf-8')
  NOT just bytes.fromhex(payload_hash).
  This binds the signature to a specific tenant, preventing cross-tenant replay.

  >>> NOTE FOR TEAMMATE: The collector must sign this combined message,
  >>> NOT just the raw hash bytes. See docs/api-contract.md amendment section.
"""
import base64
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _load_public_key(pubkey_b64: str) -> Optional[Ed25519PublicKey]:
    """Decode a base64 Ed25519 public key. Returns None on any decode error."""
    try:
        raw = base64.b64decode(pubkey_b64)
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
    Verify an Ed25519 signature.

    Args:
        tenant_id:            The tenant UUID from the request.
        payload_hash_hex:     Hex-encoded SHA-256 from receipt.payload_hash.
        signature_b64:        Base64-encoded signature from receipt.signature.
        registered_pubkey_b64: The trusted public key fetched from DB (NOT from request).

    Returns:
        True if signature is valid, False otherwise.
    """
    public_key = _load_public_key(registered_pubkey_b64)
    if public_key is None:
        return False

    try:
        sig_bytes = base64.b64decode(signature_b64)
    except Exception:
        return False

    # Tenant-bound message: prevents cross-tenant replay attacks
    message = f"{tenant_id}:{payload_hash_hex}".encode("utf-8")

    try:
        public_key.verify(sig_bytes, message)
        return True
    except (InvalidSignature, Exception):
        return False


def keys_match(request_pubkey_b64: str, registered_pubkey_b64: str) -> bool:
    """
    Check that the public key presented in the request matches the registered key.
    Uses constant-time comparison to prevent timing side-channels.
    """
    import hmac as _hmac
    try:
        a = base64.b64decode(request_pubkey_b64)
        b = base64.b64decode(registered_pubkey_b64)
        return _hmac.compare_digest(a, b)
    except Exception:
        return False
