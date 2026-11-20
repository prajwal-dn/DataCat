"""
SHA-256 canonical hash verification.

Canonical JSON rule (from docs/api-contract.md):
    json.dumps(event_dict, sort_keys=True, separators=(',',':'), ensure_ascii=False)
    → encode UTF-8 → SHA-256 → hex string

This module is used by BOTH the ingest router and the test suite.
"""
import hashlib
import hmac
import json


def canonical_hash(event_dict: dict) -> str:
    """Return hex-encoded SHA-256 of the canonical JSON encoding of event_dict."""
    canonical = json.dumps(event_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_hash(event_dict: dict, expected_hex: str) -> bool:
    """
    Return True if the canonical hash of event_dict matches expected_hex.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    computed = canonical_hash(event_dict)
    try:
        return hmac.compare_digest(computed, expected_hex.lower())
    except TypeError:
        return False

