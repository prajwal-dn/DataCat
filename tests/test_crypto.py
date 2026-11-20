"""Unit tests for cryptographic verification, canonical JSON serialization, and Ed25519 signatures."""
import base64
import json
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from app.core.crypto import (
    canonical_json_bytes,
    canonical_receipt_bytes,
    compute_payload_hash,
    verify_ed25519_signature,
)


def test_canonical_json_formatting():
    # Keys should be sorted and whitespace stripped
    obj1 = {"b": 2, "a": 1, "nested": {"z": 9, "m": 5}}
    obj2 = {"nested": {"m": 5, "z": 9}, "a": 1, "b": 2}
    assert canonical_json_bytes(obj1) == canonical_json_bytes(obj2)
    assert canonical_json_bytes(obj1) == b'{"a":1,"b":2,"nested":{"m":5,"z":9}}'


def test_compute_payload_hash_deterministic():
    event = {
        "event_id": "evt_001",
        "tenant_id": "tenant_a",
        "server_id": "srv_01",
        "timestamp_utc": "2026-11-20T16:00:00Z",
        "metrics": {"cpu_usage": 45.5, "memory_usage": 60.0, "disk_usage": 70.0, "latency_ms": 12.3},
        "policy_version": "v1.0",
    }
    h1 = compute_payload_hash(event)
    # Permuting keys in dictionary should produce the exact same hash
    event_permuted = {
        "policy_version": "v1.0",
        "metrics": {"latency_ms": 12.3, "disk_usage": 70.0, "memory_usage": 60.0, "cpu_usage": 45.5},
        "timestamp_utc": "2026-11-20T16:00:00Z",
        "server_id": "srv_01",
        "tenant_id": "tenant_a",
        "event_id": "evt_001",
    }
    h2 = compute_payload_hash(event_permuted)
    assert h1 == h2
    assert len(h1) == 64


def test_ed25519_signature_lifecycle():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    receipt_data = {
        "event_id": "evt_001",
        "tenant_id": "tenant_a",
        "payload_hash": "a" * 64,
        "collector_id": "collector_01",
        "sequence_number": 1,
        "policy_version": "v1.0",
        "algorithm": "Ed25519",
        "signature": "ignored_in_signing",
    }

    canonical_data = canonical_receipt_bytes(receipt_data)
    sig_raw = private_key.sign(canonical_data)
    sig_b64 = base64.b64encode(sig_raw).decode("utf-8")

    # Verification should succeed
    assert verify_ed25519_signature(public_key, sig_b64, canonical_data) is True

    # Tampered sequence number should fail
    tampered_receipt = dict(receipt_data, sequence_number=2)
    tampered_bytes = canonical_receipt_bytes(tampered_receipt)
    assert verify_ed25519_signature(public_key, sig_b64, tampered_bytes) is False
