"""
seed_trusted_key.py — One-time setup helper.

Registers a collector's Ed25519 public key and optional dashboard API token into the database.
Run this BEFORE any collector sends events to the backend.

Usage:
    python backend/seed_trusted_key.py \\
        --tenant-id  <uuid>              \\
        --pubkey-b64 <base64-encoded-key>  \\
        --api-token  <secret-dashboard-token> \\
        --name       "My Collector"
"""
import argparse
import asyncio
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import aiosqlite
from backend.config import DB_PATH
from backend.database import init_db, register_tenant_token


async def seed(tenant_id: str, pubkey_b64: str, name: str, api_token: str) -> None:
    await init_db()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO trusted_keys (tenant_id, public_key_b64, collector_name)
            VALUES (?, ?, ?)
            ON CONFLICT(tenant_id) DO UPDATE SET
                public_key_b64 = excluded.public_key_b64,
                collector_name = excluded.collector_name,
                registered_at  = strftime('%Y-%m-%dT%H:%M:%SZ','now')
            """,
            (tenant_id, pubkey_b64.strip(), name),
        )
        await db.commit()

    await register_tenant_token(tenant_id, api_token)

    print(f"[OK] Registered public key for tenant={tenant_id} (name='{name}')")
    print(f"[OK] Registered dashboard API token for tenant={tenant_id}")
    print(f"     Token: {api_token}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Register a trusted collector public key and API token")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--pubkey-b64", default=None, help="Base64 public key string")
    parser.add_argument("--pubkey-file", default=None, help="File containing base64 public key")
    parser.add_argument("--api-token", default=None, help="Dashboard API token (generated if omitted)")
    parser.add_argument("--name", default="default-collector")
    args = parser.parse_args()

    if args.pubkey_b64:
        key = args.pubkey_b64
    elif args.pubkey_file:
        key = Path(args.pubkey_file).read_text().strip()
    else:
        parser.error("Provide either --pubkey-b64 or --pubkey-file")

    token = args.api_token or secrets.token_urlsafe(32)
    asyncio.run(seed(args.tenant_id, key, args.name, token))


if __name__ == "__main__":
    main()
