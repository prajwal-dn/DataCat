"""
pytest fixtures shared across all test modules.

Generates a real Ed25519 keypair for every test session.
Uses a temporary SQLite database.
Follows the domain-separated tenant-bound signing specification:
  DATACAT-INGEST-V1:{tenant_id}:{payload_hash}
"""
import base64
import os
import tempfile
import uuid

import aiosqlite
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import AsyncClient, ASGITransport

_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()
os.environ["DATACAT_DB_PATH"] = _tmp_db.name

from backend.main import app
from backend.database import init_db, DB_PATH, register_tenant_token
from backend.verification.hash_verify import canonical_hash
from backend.verification.signature_verify import compute_signing_message


@pytest.fixture(scope="session")
def ed25519_keypair():
    """Generate a fresh Ed25519 keypair for test session."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode()
    return private_key, pub_b64


@pytest.fixture(scope="session")
def tenant_id():
    return str(uuid.uuid4())


@pytest.fixture(scope="session")
def tenant_token():
    return "test-dashboard-token-secret"


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_db(ed25519_keypair, tenant_id, tenant_token):
    """Init schema and register trusted key and token for the test session."""
    await init_db()
    _, pub_b64 = ed25519_keypair
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO trusted_keys (tenant_id, public_key_b64, collector_name) VALUES (?, ?, ?)",
            (tenant_id, pub_b64, "test-collector"),
        )
        await db.commit()

    await register_tenant_token(tenant_id, tenant_token)


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


def build_valid_event(
    private_key: Ed25519PrivateKey,
    pub_b64: str,
    tenant_id: str,
    event_id: str = None,
    event_type: str = "cpu_usage",
    tamper_hash: bool = False,
    tamper_signature: bool = False,
    wrong_tenant_in_sig: str = None,
    wrong_pubkey_b64: str = None,
    source_host: str = "test-host-01",
    custom_payload: dict = None,
) -> dict:
    """
    Build a valid ingest request dict with domain-separated signature.
    """
    event_id = event_id or str(uuid.uuid4())
    event = {
        "event_id": event_id,
        "timestamp": "2026-11-20T14:00:00Z",
        "source_host": source_host,
        "event_type": event_type,
        "payload": custom_payload if custom_payload is not None else {"cpu_pct": 42.5, "mem_mb": 1024},
        "privacy_tags": ["pii_removed"],
    }

    payload_hash = canonical_hash(event)

    if tamper_hash:
        payload_hash = "00" * 32

    signing_tenant = wrong_tenant_in_sig or tenant_id
    message = compute_signing_message(signing_tenant, payload_hash)

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
            "public_key": wrong_pubkey_b64 or pub_b64,
            "signed_at": "2026-11-20T14:00:01Z",
        },
    }
