# DataCat Collector — Tier 1

**Local telemetry collector with privacy enforcement and Ed25519 signing.**

The collector runs on each monitored host. It:
1. Collects system telemetry via `psutil`.
2. Applies a strict allowlist-driven privacy filter that removes all PII before any data leaves the host.
3. Signs each approved event with an Ed25519 private key using the shared domain-separated contract.
4. Transmits the signed envelope to the DataCat SaaS backend.

---

## Prerequisites

- Python 3.11+
- `pip install -r collector/requirements.txt`

```
cryptography>=42.0.0
httpx>=0.27.0
psutil>=5.9.0
python-dotenv>=1.0.0
```

---

## Setup

### 1 — Generate the collector keypair

```bash
python collector/signing/keygen.py
```

This writes:
- `keys/collector_private.pem` — **never commit this file** (gitignored)
- `keys/collector.pub` — base64-encoded public key (safe to share with backend admin)

### 2 — Register the public key with the backend

The backend admin runs (once per collector):

```bash
python backend/seed_trusted_key.py \
  --tenant-id <your-tenant-uuid> \
  --pub-key-file keys/collector.pub \
  --collector-name my-host-01
```

The public key must be registered before any events can be accepted.

### 3 — Configure the collector

Create a `.env` file at the repo root (**never commit this file**):

```env
DATACAT_TENANT_ID=<your-tenant-uuid>
DATACAT_BACKEND_URL=http://localhost:8000
DATACAT_PRIVATE_KEY_PATH=keys/collector_private.pem
DATACAT_SOURCE_HOST=my-host-01
DATACAT_COLLECTION_INTERVAL=30
```

All settings can also be passed as environment variables directly.

---

## Running the Collector

### Send one event immediately

```bash
python -m collector.collector --once
```

Expected output on success:

```
✓ Event accepted by backend: event_id=<uuid> stored_at=2026-11-21T...Z
```

### Run continuously (every `DATACAT_COLLECTION_INTERVAL` seconds)

```bash
python -m collector.collector
```

Press `Ctrl+C` to stop.

---

## Project Structure

```
collector/
├── __init__.py
├── collector.py          # Main entry point
├── config.py             # Configuration (env vars, PII blocklist, thresholds)
├── requirements.txt
├── README.md             # This file
├── privacy/
│   ├── __init__.py
│   └── engine.py         # Allowlist filter, PII stripping, size rejection
├── signing/
│   ├── __init__.py
│   ├── keygen.py         # Ed25519 keypair generation
│   └── signer.py         # Canonical hash, signing message, envelope builder
├── telemetry/
│   ├── __init__.py
│   └── normalizer.py     # psutil-based metric collection and normalisation
└── transport/
    ├── __init__.py
    └── sender.py         # HTTP transmission to backend ingest API
```

---

## Privacy Guarantees

| Guarantee | Implementation |
|-----------|---------------|
| Allowlist-only fields transmitted | `PERMITTED_METRIC_FIELDS` in `engine.py` |
| PII field names blocked | `PII_FIELD_BLOCKLIST` substring match in `config.py` |
| Boolean values rejected | Prevents `True → 1.0` metric misinterpretation |
| Oversized payloads suppressed locally | `MAX_PAYLOAD_BYTES` = 900 KB |
| All-PII events suppressed (never transmitted) | `apply_privacy_policy()` returns `suppressed=True` |
| Raw payload content never logged | `logging.info/debug` only logs field names, never values |

---

## Signing Contract

The signing specification exactly matches `backend/verification/signature_verify.py`:

```
canonical_json = json.dumps(event_dict, sort_keys=True, separators=(',',':'), ensure_ascii=False)
payload_hash   = SHA-256(canonical_json.encode("utf-8")).hexdigest()
signing_message = f"DATACAT-INGEST-V1:{tenant_id}:{payload_hash.lower()}".encode("utf-8")
signature      = Ed25519PrivateKey.sign(signing_message)  # raw 64-byte sig, base64-encoded
```

Both sides must use **identical** byte sequences. Any deviation causes signature verification failure.

---

## Running Tests

Collector unit tests live in `tests/test_collector.py` alongside the backend tests.

```bash
# Collector tests only
python -m pytest tests/test_collector.py -v

# Full test suite (backend + collector)
python -m pytest tests/ -v
```

Expected: **84 passed** (49 backend + 35 collector).

---

## Security Notes

- **Never commit** `keys/collector_private.pem` or `.env`. Both are gitignored.
- The backend only accepts events signed with a pre-registered public key.
- Supplying a different public key in the `receipt.public_key` field is rejected.
- The signing message binds `tenant_id` cryptographically — a key registered for tenant A cannot forge events for tenant B.
