"""
pytest fixtures shared across all test modules.

Generates a real Ed25519 keypair for every test session.
No mocking of cryptographic operations.
Uses a temporary SQLite database (never the production DB).
"""
import asyncio
import base64
import json
import hashlib
import os
import tempfile
import uuid

import aiosqlite
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import AsyncClient, ASGITransport

# Point to temp DB before importing app modules
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()
os.environ["DATACAT_DB_PATH"] = _tmp_db.name

# Now import app (uses env var for DB path)
from backend.main import app
from backend.database import init_db, DB_PATH
from backend.verification.hash_verify import canonical_hash


# ── Key generation ───────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def ed25519_keypair():
    """Generate a fresh Ed25519 keypair for the test session."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode()
    return private_key, pub_b64


@pytest.fixture(scope="session")
def tenant_id():
    return str(uuid.uuid4())


# ── Database bootstrap ───────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_db(ed25519_keypair, tenant_id):
    """Init schema and seed trusted key once per test session."""
    await init_db()
    _, pub_b64 = ed25519_keypair
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO trusted_keys (tenant_id, public_key_b64, collector_name) VALUES (?, ?, ?)",
            (tenant_id, pub_b64, "test-collector"),
        )
        await db.commit()


# ── HTTP client ──────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def client():
    """Async HTTPX client backed by the FastAPI app (no real server needed)."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ── Event builder helper ─────────────────────────────────────────────────────

def build_valid_event(
    private_key: Ed25519PrivateKey,
    pub_b64: str,
    tenant_id: str,
    event_id: str = None,
    event_type: str = "cpu_usage",
    tamper_hash: bool = False,
    tamper_signature: bool = False,
    wrong_tenant_in_sig: str = None,
) -> dict:
    """
    Build a fully valid ingest request dict, optionally with deliberate flaws.
    Uses the same canonical hash and tenant-bound signing spec as the backend.
    """
    event_id = event_id or str(uuid.uuid4())
    event = {
        "event_id": event_id,
        "timestamp": "2026-11-20T14:00:00Z",
        "source_host": "test-host-01",
        "event_type": event_type,
        "payload": {"cpu_pct": 42.5, "mem_mb": 1024},
        "privacy_tags": ["pii_removed"],
    }

    payload_hash = canonical_hash(event)

    if tamper_hash:
        payload_hash = "00" * 32  # all zeros

    # Tenant-bound message: "{tenant_id}:{payload_hash}"
    signing_tenant = wrong_tenant_in_sig or tenant_id
    message = f"{signing_tenant}:{payload_hash}".encode("utf-8")

    if tamper_signature:
        signature_b64 = base64.b64encode(b"\x00" * 64).decode()
    else:
        sig_bytes = private_key.sign(message)
        signature_b64 = base64.b64encode(sig_bytes).decode()

    return {
        "tenant_id": tenant_id,
        "event": event,
        "receipt": {
            "payload_hash": payload_hash,
            "signature": signature_b64,
            "public_key": pub_b64,
            "signed_at": "2026-11-20T14:00:01Z",
        },
    }
