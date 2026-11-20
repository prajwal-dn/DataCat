"""Cryptographic utilities for canonical JSON serialization, SHA-256 hashing, and Ed25519 verification."""
import base64
import hashlib
import json
from pathlib import Path
from typing import Any
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Fields included in canonical receipt for Ed25519 signature verification
RECEIPT_SIGNATURE_FIELDS = [
    "algorithm",
    "collector_id",
    "event_id",
    "payload_hash",
    "policy_version",
    "sequence_number",
    "tenant_id",
]


def canonical_json_bytes(data: Any) -> bytes:
    """Canonical JSON serialization conforming to the DATACAT specification.

    - Keys sorted deterministically
    - Compact separators (',', ':') without whitespace
    - UTF-8 encoding
    - NaN/Infinity prohibited
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def compute_payload_hash(event_data: dict[str, Any]) -> str:
    """Calculates the SHA-256 hex digest of canonical event JSON representation."""
    serialized = canonical_json_bytes(event_data)
    return hashlib.sha256(serialized).hexdigest()


def canonical_receipt_bytes(receipt_data: dict[str, Any]) -> bytes:
    """Serializes the receipt fields covered by the Ed25519 signature."""
    signed_payload = {
        field: receipt_data[field]
        for field in RECEIPT_SIGNATURE_FIELDS
        if field in receipt_data
    }
    return canonical_json_bytes(signed_payload)


def load_ed25519_public_key_from_pem_file(key_path: Path | str) -> ed25519.Ed25519PublicKey:
    """Loads an Ed25519 public key from a PEM file."""
    path = Path(key_path)
    if not path.is_file():
        raise FileNotFoundError(f"Public key file not found: {path}")

    pem_bytes = path.read_bytes()
    public_key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError(f"Key in {path} is not an Ed25519 public key")
    return public_key


def verify_ed25519_signature(
    public_key: ed25519.Ed25519PublicKey,
    signature_base64: str,
    data_bytes: bytes,
) -> bool:
    """Verifies a base64-encoded Ed25519 digital signature over the provided data bytes."""
    try:
        signature = base64.b64decode(signature_base64)
        public_key.verify(signature, data_bytes)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False
