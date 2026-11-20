"""
DataCat Collector Test Suite.

Tests for:
  - Privacy engine: PII stripping, allowlist enforcement, size rejection, suppression.
  - Signing: canonical hash, domain-separated message, signature correctness.
  - Telemetry normalizer: collection and normalization.
  - Transmission: mock backend responses (accepted, rejected, duplicate, timeout).
  - Integration: full pipeline from raw metrics to ingest envelope.

NOTE: The fixture is named `collector_keypair` (not `ed25519_keypair`) to avoid
      a scope conflict with the session-scoped `ed25519_keypair` defined in conftest.py
      for the backend integration tests.
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ── Module imports ───────────────────────────────────────────────────────────
from collector.privacy.engine import (
    apply_privacy_policy,
    filter_payload,
    reject_if_too_large,
)
from collector.signing.signer import (
    build_ingest_payload,
    canonical_hash,
    public_key_b64,
    sign_event,
    signing_message,
)
from collector.telemetry.normalizer import collect_normalized_telemetry, normalize_metrics
from collector.transport.sender import TransmissionResult, transmit


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def collector_keypair():
    """Generate a fresh Ed25519 private key for each collector test."""
    return Ed25519PrivateKey.generate()


@pytest.fixture
def collector_tenant_id():
    """A fresh tenant UUID for each collector test (avoids conftest's session-scoped one)."""
    return str(uuid.uuid4())


@pytest.fixture
def sample_raw_payload():
    return {
        "cpu_pct": 45.2,
        "ram_pct": 72.8,
        "disk_pct": 55.0,
        "latency_ms": 120.5,
        "packet_loss": 0.5,
        "failed_logins": 2,
        "os_type": "Linux",
        "collector_version": "1.0.0",
    }


@pytest.fixture
def sample_pii_payload():
    return {
        "cpu_pct": 45.2,
        "username": "john_doe",          # PII — must be stripped
        "email": "john@example.com",     # PII — must be stripped
        "password": "s3cr3t",            # PII — must be stripped
        "api_key": "tok_live_abc123",    # PII — must be stripped
        "ip_address": "192.168.1.100",   # PII — must be stripped
        "ram_pct": 60.0,
        "disk_pct": 42.0,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Privacy Engine Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPrivacyEngineFiltering:

    def test_clean_payload_passes_unmodified(self, sample_raw_payload):
        """A fully allowlisted payload with no PII should pass with 'clean' tag."""
        filtered, tags = filter_payload(sample_raw_payload)
        assert "cpu_pct" in filtered
        assert "ram_pct" in filtered
        assert "latency_ms" in filtered
        assert "clean" in tags or "fields_allowlisted" in tags

    def test_pii_fields_are_stripped(self, sample_pii_payload):
        """PII fields (username, email, password, api_key, ip_address) must be removed."""
        filtered, tags = filter_payload(sample_pii_payload)
        assert "username" not in filtered
        assert "email" not in filtered
        assert "password" not in filtered
        assert "api_key" not in filtered
        assert "ip_address" not in filtered
        # Permitted fields must survive
        assert "cpu_pct" in filtered
        assert "ram_pct" in filtered
        assert "pii_removed" in tags

    def test_non_allowlisted_fields_are_dropped(self):
        """Unknown / non-allowlisted fields must be silently dropped."""
        payload = {
            "cpu_pct": 50.0,
            "process_list": ["nginx", "sshd"],   # not allowlisted
            "arbitrary_custom": "some_value",    # not allowlisted
            "ram_pct": 70.0,
        }
        filtered, tags = filter_payload(payload)
        assert "process_list" not in filtered
        assert "arbitrary_custom" not in filtered
        assert "cpu_pct" in filtered
        assert "ram_pct" in filtered
        assert "fields_allowlisted" in tags

    def test_boolean_values_are_dropped(self):
        """Boolean field values must be rejected (avoid True→1.0 misinterpretation)."""
        payload = {"cpu_pct": True, "ram_pct": 50.0}
        filtered, tags = filter_payload(payload)
        assert "cpu_pct" not in filtered
        assert "ram_pct" in filtered

    def test_empty_payload_causes_suppression(self):
        """An entirely empty payload must be suppressed locally."""
        filtered_payload, tags, suppressed = apply_privacy_policy({})
        assert suppressed is True
        assert filtered_payload == {}

    def test_all_pii_filtered_causes_suppression(self):
        """If all fields are PII and nothing survives filtering, suppress the event."""
        all_pii = {
            "username": "alice",
            "email": "alice@example.com",
            "password": "hunter2",
        }
        filtered_payload, tags, suppressed = apply_privacy_policy(all_pii)
        assert suppressed is True
        assert filtered_payload == {}

    def test_nested_metrics_object_flattened(self):
        """Nested 'metrics' object should be recursively filtered and flattened."""
        payload = {
            "cpu_pct": 30.0,
            "metrics": {
                "ram_pct": 65.0,
                "disk_pct": 42.0,
                "secret_token": "tok_xyz",   # PII inside nested dict
            },
        }
        filtered, tags = filter_payload(payload)
        assert "cpu_pct" in filtered
        assert "ram_pct" in filtered
        assert "disk_pct" in filtered
        assert "secret_token" not in filtered

    def test_process_args_stripped_as_pii(self):
        """process_args may contain secrets — must be blocked."""
        payload = {"cpu_pct": 55.0, "process_args": "--password hunter2"}
        filtered, tags = filter_payload(payload)
        assert "process_args" not in filtered

    def test_non_dict_input_causes_suppression(self):
        """Non-dict input to filter_payload must return empty + tags."""
        filtered, tags = filter_payload("not-a-dict")
        assert filtered == {}
        assert "pii_removed" in tags


class TestPrivacyEngineSizeRejection:

    def test_oversized_payload_is_rejected(self):
        """Payload exceeding MAX_PAYLOAD_BYTES must be flagged for suppression."""
        with patch("collector.privacy.engine.MAX_PAYLOAD_BYTES", 10):
            result = reject_if_too_large({"cpu_pct": 50.0})
        assert result is True

    def test_normal_payload_not_rejected(self, sample_raw_payload):
        """Normal-sized payloads must not be rejected."""
        result = reject_if_too_large(sample_raw_payload)
        assert result is False


class TestPrivacyPolicyPipeline:

    def test_full_pipeline_clean_payload(self, sample_raw_payload):
        """Full pipeline with a clean payload produces filtered dict and suppress=False."""
        filtered, tags, suppressed = apply_privacy_policy(sample_raw_payload)
        assert suppressed is False
        assert len(filtered) > 0
        assert "cpu_pct" in filtered or "cpu_usage" in filtered

    def test_full_pipeline_pii_stripped_not_suppressed(self, sample_pii_payload):
        """PII is stripped but surviving permitted fields prevent suppression."""
        filtered, tags, suppressed = apply_privacy_policy(sample_pii_payload)
        assert suppressed is False
        assert "username" not in filtered
        assert "cpu_pct" in filtered
        assert "pii_removed" in tags


# ═══════════════════════════════════════════════════════════════════════════════
# Signing Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestCanonicalHash:

    def test_canonical_hash_is_deterministic(self):
        """Same dict always produces same SHA-256 hash."""
        event = {"event_id": "abc", "payload": {"cpu_pct": 45.0}, "source_host": "h1"}
        h1 = canonical_hash(event)
        h2 = canonical_hash(event)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex = 64 chars

    def test_canonical_hash_sorts_keys(self):
        """Dict key order must NOT affect the hash — keys must be sorted."""
        e1 = {"b": 2, "a": 1}
        e2 = {"a": 1, "b": 2}
        assert canonical_hash(e1) == canonical_hash(e2)

    def test_canonical_hash_matches_contract_spec(self):
        """Hash must match the api-contract.md formula exactly."""
        event = {"key": "value"}
        expected_canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        expected_hash = hashlib.sha256(expected_canonical.encode("utf-8")).hexdigest()
        assert canonical_hash(event) == expected_hash

    def test_different_values_produce_different_hashes(self):
        e1 = {"cpu_pct": 45.0}
        e2 = {"cpu_pct": 46.0}
        assert canonical_hash(e1) != canonical_hash(e2)


class TestSigningMessage:

    def test_signing_message_format(self):
        """Domain-separated message must follow DATACAT-INGEST-V1:{tid}:{hash} format."""
        tid = "tenant-123"
        h = "abcdef01" * 8
        msg = signing_message(tid, h)
        assert msg == f"DATACAT-INGEST-V1:{tid}:{h}".encode("utf-8")

    def test_signing_message_lowercases_hash(self):
        """Hash in signing message must always be lowercase."""
        tid = "tenant-456"
        h_upper = "ABCDEF01" * 8
        msg = signing_message(tid, h_upper)
        assert h_upper.lower().encode() in msg

    def test_signing_message_matches_backend_contract(self):
        """
        Message format must EXACTLY match backend/verification/signature_verify.py:
        DATACAT-INGEST-V1:{tenant_id}:{payload_hash_hex.lower()}
        """
        tid = "00000000-0000-0000-0000-000000000001"
        h = "deadbeef" * 8
        expected = f"DATACAT-INGEST-V1:{tid}:{h}".encode("utf-8")
        assert signing_message(tid, h) == expected


class TestSignEvent:

    def test_sign_event_returns_valid_signature(self, collector_keypair, collector_tenant_id):
        """sign_event must produce a valid Ed25519 signature verifiable by the same key."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": "2026-11-21T00:00:00Z",
            "source_host": "test-host",
            "event_type": "system.metrics",
            "payload": {"cpu_pct": 55.0},
            "privacy_tags": ["clean"],
        }

        payload_hash, sig_b64, pub_b64, signed_at = sign_event(event, collector_tenant_id, collector_keypair)

        # Verify: reconstruct message and verify sig with public key
        message = signing_message(collector_tenant_id, payload_hash)
        raw_pub = base64.b64decode(pub_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(raw_pub)
        sig_bytes = base64.b64decode(sig_b64)

        # Must not raise InvalidSignature
        pub_key.verify(sig_bytes, message)

    def test_sign_event_hash_matches_canonical_hash(self, collector_keypair, collector_tenant_id):
        """payload_hash returned by sign_event must equal canonical_hash of event dict."""
        event = {
            "event_id": "evt-01",
            "timestamp": "2026-11-21T00:00:00Z",
            "source_host": "h1",
            "event_type": "test",
            "payload": {"cpu_pct": 42.0},
            "privacy_tags": ["clean"],
        }
        payload_hash, _, _, _ = sign_event(event, collector_tenant_id, collector_keypair)
        assert payload_hash == canonical_hash(event)

    def test_different_tenant_id_produces_different_signature(self, collector_keypair):
        """Tenant-bound signature: different tenant_id → different signature bytes."""
        event = {
            "event_id": "evt-01",
            "timestamp": "2026-11-21T00:00:00Z",
            "source_host": "h1",
            "event_type": "test",
            "payload": {"cpu_pct": 42.0},
            "privacy_tags": ["clean"],
        }
        _, sig1, _, _ = sign_event(event, "tenant-aaa", collector_keypair)
        _, sig2, _, _ = sign_event(event, "tenant-bbb", collector_keypair)
        assert sig1 != sig2

    def test_build_ingest_payload_structure(self, collector_keypair, collector_tenant_id):
        """build_ingest_payload must return complete API-contract-compliant envelope."""
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": "2026-11-21T00:00:00Z",
            "source_host": "h1",
            "event_type": "system.metrics",
            "payload": {"cpu_pct": 50.0},
            "privacy_tags": ["clean"],
        }
        envelope = build_ingest_payload(event, collector_tenant_id, collector_keypair)

        assert envelope["tenant_id"] == collector_tenant_id
        assert envelope["event"] == event
        assert "receipt" in envelope
        receipt = envelope["receipt"]
        assert "payload_hash" in receipt
        assert "signature" in receipt
        assert "public_key" in receipt
        assert "signed_at" in receipt
        # payload_hash must be a 64-char hex string (SHA-256)
        assert len(receipt["payload_hash"]) == 64
        bytes.fromhex(receipt["payload_hash"])  # must be valid hex


# ═══════════════════════════════════════════════════════════════════════════════
# Telemetry Normalizer Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTelemetryNormalizer:

    def test_normalize_metrics_passthrough(self):
        """normalize_metrics is a passthrough for already-canonical field names."""
        raw = {"cpu_pct": 55.0, "ram_pct": 70.0, "disk_pct": 42.0}
        result = normalize_metrics(raw)
        assert result == raw

    def test_collect_normalized_returns_dict(self):
        """collect_normalized_telemetry must return a non-empty dict."""
        result = collect_normalized_telemetry()
        assert isinstance(result, dict)
        assert len(result) >= 1

    def test_normalized_output_has_no_pii(self):
        """Normalized telemetry must not contain fields in the PII blocklist."""
        from collector.config import PII_FIELD_BLOCKLIST
        result = collect_normalized_telemetry()
        for blocked in PII_FIELD_BLOCKLIST:
            # No field name should contain a PII identifier
            matching = [k for k in result.keys() if blocked in k.lower()]
            assert matching == [], f"PII field '{blocked}' found in normalized output: {matching}"

    def test_numeric_values_only_in_normalized(self):
        """All metric values in normalized output should be numeric or basic strings."""
        result = collect_normalized_telemetry()
        for key, val in result.items():
            assert isinstance(val, (int, float, str)), (
                f"Field '{key}' has unexpected type {type(val)}"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# Transmission Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTransmission:

    def _make_envelope(self, tenant_id: str) -> Dict[str, Any]:
        return {
            "tenant_id": tenant_id,
            "event": {
                "event_id": str(uuid.uuid4()),
                "timestamp": "2026-11-21T00:00:00Z",
                "source_host": "test-host",
                "event_type": "system.metrics",
                "payload": {"cpu_pct": 50.0},
                "privacy_tags": ["clean"],
            },
            "receipt": {
                "payload_hash": "a" * 64,
                "signature": base64.b64encode(b"\x00" * 64).decode(),
                "public_key": base64.b64encode(b"\x01" * 32).decode(),
                "signed_at": "2026-11-21T00:00:00Z",
            },
        }

    def test_accepted_response_returns_success(self, collector_tenant_id):
        """202 response must produce success=True TransmissionResult."""
        envelope = self._make_envelope(collector_tenant_id)
        mock_resp = MagicMock()
        mock_resp.status_code = 202
        mock_resp.json.return_value = {
            "status": "accepted",
            "event_id": envelope["event"]["event_id"],
            "stored_at": "2026-11-21T00:00:00Z",
        }

        with patch("collector.transport.sender.httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_class.return_value = mock_client

            result = transmit(envelope, collector_tenant_id)

        assert result.success is True
        assert result.status_code == 202
        assert result.backend_stored_at == "2026-11-21T00:00:00Z"

    def test_duplicate_409_returns_failure(self, collector_tenant_id):
        """409 Conflict must produce success=False with 'duplicate_event' reason."""
        envelope = self._make_envelope(collector_tenant_id)
        mock_resp = MagicMock()
        mock_resp.status_code = 409
        mock_resp.json.return_value = {"status": "rejected", "reason": "duplicate_event"}

        with patch("collector.transport.sender.httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_class.return_value = mock_client

            result = transmit(envelope, collector_tenant_id)

        assert result.success is False
        assert result.status_code == 409
        assert result.response_reason == "duplicate_event"

    def test_rejection_400_returns_failure(self, collector_tenant_id):
        """400 rejection (hash/signature) must produce success=False."""
        envelope = self._make_envelope(collector_tenant_id)
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.json.return_value = {"status": "rejected", "reason": "hash_mismatch"}

        with patch("collector.transport.sender.httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_class.return_value = mock_client

            result = transmit(envelope, collector_tenant_id)

        assert result.success is False
        assert result.status_code == 400
        assert result.response_reason == "hash_mismatch"

    def test_timeout_returns_failure(self, collector_tenant_id):
        """Network timeout must produce success=False with error='timeout'."""
        import httpx as _httpx
        envelope = self._make_envelope(collector_tenant_id)

        with patch("collector.transport.sender.httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = _httpx.TimeoutException("timed out")
            mock_client_class.return_value = mock_client

            result = transmit(envelope, collector_tenant_id)

        assert result.success is False
        assert result.error == "timeout"

    def test_connect_error_returns_failure(self, collector_tenant_id):
        """Connection refused must produce success=False with error='connect_error'."""
        import httpx as _httpx
        envelope = self._make_envelope(collector_tenant_id)

        with patch("collector.transport.sender.httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = _httpx.ConnectError("connection refused")
            mock_client_class.return_value = mock_client

            result = transmit(envelope, collector_tenant_id)

        assert result.success is False
        assert result.error == "connect_error"


# ═══════════════════════════════════════════════════════════════════════════════
# Integration Pipeline Test
# ═══════════════════════════════════════════════════════════════════════════════

class TestFullCollectorPipeline:

    def test_full_pipeline_produces_valid_ingest_envelope(self, collector_keypair, collector_tenant_id):
        """
        Full pipeline: raw metrics → privacy filter → sign → produces valid API-contract envelope.
        The envelope must be verifiable by the backend's hash and signature checks.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        raw_metrics = {
            "cpu_pct": 60.0,
            "ram_pct": 75.0,
            "disk_pct": 42.0,
            "latency_ms": 90.0,
            "packet_loss": 0.0,
            "username": "alice",          # PII — must be stripped by privacy engine
            "password": "hunter2",        # PII — must be stripped by privacy engine
        }

        # Step 1: Privacy filter
        filtered, tags, suppressed = apply_privacy_policy(raw_metrics)
        assert suppressed is False
        assert "username" not in filtered
        assert "password" not in filtered
        assert "cpu_pct" in filtered
        assert "pii_removed" in tags

        # Step 2: Build event dict
        event_dict = {
            "event_id": str(uuid.uuid4()),
            "timestamp": "2026-11-21T00:00:00Z",
            "source_host": "integration-test-host",
            "event_type": "system.metrics",
            "payload": filtered,
            "privacy_tags": tags,
        }

        # Step 3: Sign
        envelope = build_ingest_payload(event_dict, collector_tenant_id, collector_keypair)

        # Step 4: Verify envelope structure
        assert envelope["tenant_id"] == collector_tenant_id
        assert envelope["event"]["payload"] == filtered
        assert envelope["event"]["privacy_tags"] == tags

        receipt = envelope["receipt"]
        payload_hash = receipt["payload_hash"]
        sig_b64 = receipt["signature"]
        pub_b64 = receipt["public_key"]

        # Step 5: Verify hash matches backend formula
        expected_hash = canonical_hash(event_dict)
        assert payload_hash == expected_hash

        # Step 6: Verify signature using the public key (backend would do this)
        message = signing_message(collector_tenant_id, payload_hash)
        raw_pub = base64.b64decode(pub_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(raw_pub)
        sig_bytes = base64.b64decode(sig_b64)
        pub_key.verify(sig_bytes, message)   # raises InvalidSignature if wrong

    def test_pipeline_suppresses_all_pii_payload(self):
        """A payload containing only PII must be suppressed — no envelope built."""
        all_pii = {
            "username": "bob",
            "email": "bob@corp.example",
            "api_key": "sk-prod-secret",
            "env_vars": "KEY=val PASS=xyz",
        }
        _, _, suppressed = apply_privacy_policy(all_pii)
        assert suppressed is True
