# DataCat API Contract v1.0

> **Shared document — do not modify without both parties agreeing.**
> Last updated: 2026-11-20

---

## Transport

- Protocol: HTTPS (HTTP for local dev)
- Base URL: `http://localhost:8000` (dev) / `https://api.datacat.io` (prod)
- Content-Type: `application/json`
- Auth: `X-Tenant-ID` header (UUID string) on all requests

---

## Endpoints

### 1. POST /api/v1/ingest

Collector sends a verified telemetry event plus its cryptographic receipt.

#### Request Body

```json
{
  "tenant_id": "uuid-string",
  "event": {
    "event_id": "uuid-string",
    "timestamp": "ISO-8601 UTC string",
    "source_host": "string",
    "event_type": "string",
    "payload": {
      "arbitrary": "json object — telemetry data"
    },
    "privacy_tags": ["pii_removed", "aggregated"]
  },
  "receipt": {
    "payload_hash": "hex-encoded SHA-256 of canonical JSON of event object",
    "signature": "base64-encoded Ed25519 signature over payload_hash bytes",
    "public_key": "base64-encoded Ed25519 public key (32 bytes)",
    "signed_at": "ISO-8601 UTC string"
  }
}
```

**Canonical JSON rule:** `event` object is serialized with keys sorted alphabetically, no extra whitespace, UTF-8 encoded, then SHA-256 hashed. This is what `payload_hash` covers.

#### Response — 202 Accepted (success)

```json
{
  "status": "accepted",
  "event_id": "uuid-string",
  "hash_verified": true,
  "signature_verified": true,
  "duplicate": false,
  "stored_at": "ISO-8601 UTC string"
}
```

#### Response — 400 Bad Request (hash mismatch)

```json
{
  "status": "rejected",
  "reason": "hash_mismatch",
  "detail": "Computed hash does not match receipt.payload_hash"
}
```

#### Response — 400 Bad Request (invalid signature)

```json
{
  "status": "rejected",
  "reason": "invalid_signature",
  "detail": "Ed25519 signature verification failed"
}
```

#### Response — 409 Conflict (duplicate)

```json
{
  "status": "rejected",
  "reason": "duplicate_event",
  "detail": "event_id already ingested"
}
```

#### Response — 422 Unprocessable (bad schema)

Standard FastAPI validation error.

---

### 2. GET /api/v1/events

Returns stored events for dashboard display.

#### Query Parameters

| Param       | Type    | Default | Description                        |
|-------------|---------|---------|------------------------------------|
| `tenant_id` | string  | —       | Filter by tenant (optional)        |
| `status`    | string  | all     | `accepted` / `rejected` / `all`    |
| `limit`     | integer | 50      | Max results                        |
| `offset`    | integer | 0       | Pagination offset                  |

#### Response — 200 OK

```json
{
  "total": 123,
  "events": [
    {
      "event_id": "uuid-string",
      "tenant_id": "uuid-string",
      "timestamp": "ISO-8601 UTC",
      "source_host": "string",
      "event_type": "string",
      "status": "accepted",
      "hash_verified": true,
      "signature_verified": true,
      "rejected_reason": null,
      "ingested_at": "ISO-8601 UTC"
    }
  ]
}
```

---

### 3. GET /api/v1/stats

Aggregate counts for dashboard summary cards.

#### Query Parameters

| Param       | Type   | Default | Description          |
|-------------|--------|---------|----------------------|
| `tenant_id` | string | —       | Filter (optional)    |

#### Response — 200 OK

```json
{
  "total_events": 500,
  "accepted": 480,
  "rejected": 20,
  "duplicate_rejections": 5,
  "hash_failures": 8,
  "signature_failures": 7,
  "tenants_active": 3,
  "last_event_at": "ISO-8601 UTC"
}
```

---

### 4. GET /api/v1/incidents

Events flagged as anomalies or policy violations.

#### Response — 200 OK

```json
{
  "incidents": [
    {
      "event_id": "uuid-string",
      "tenant_id": "uuid-string",
      "incident_type": "signature_failure | hash_mismatch | duplicate | privacy_violation",
      "timestamp": "ISO-8601 UTC",
      "source_host": "string",
      "detail": "human-readable reason"
    }
  ]
}
```

---

### 5. GET /api/v1/health

Platform health check.

#### Response — 200 OK

```json
{
  "status": "ok",
  "version": "1.0.0",
  "db": "connected",
  "uptime_seconds": 3600
}
```

---

## Canonical JSON Specification (for hash computation)

```python
import json, hashlib

def canonical_hash(event_dict: dict) -> str:
    canonical = json.dumps(event_dict, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()
```

Both collector and backend MUST use this exact function.

---

## Ed25519 Signing Specification

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64, hashlib

# Signing (collector side)
payload_hash_bytes = bytes.fromhex(payload_hash_hex)
signature_bytes = private_key.sign(payload_hash_bytes)
signature_b64 = base64.b64encode(signature_bytes).decode()

# Verifying (backend side)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature

public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
try:
    public_key.verify(base64.b64decode(signature_b64), bytes.fromhex(payload_hash_hex))
    # valid
except InvalidSignature:
    # reject
```

