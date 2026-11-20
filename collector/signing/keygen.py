"""
Ed25519 key generation for the DataCat Collector.

Generates a new Ed25519 keypair:
  - Private key: written to keys/collector_private.pem  (NEVER committed)
  - Public key:  written to keys/collector.pub           (safe to share with backend)

Usage:
    python collector/signing/keygen.py

After running this script, register the public key with the backend:
    python backend/seed_trusted_key.py --tenant-id <UUID> --pub-key-file keys/collector.pub
"""
import base64
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def generate_keypair(keys_dir: Path = Path("keys")) -> tuple[str, str]:
    """
    Generate an Ed25519 keypair and write both halves to disk.

    Returns:
        (private_pem_path, public_b64_path) as string paths
    """
    keys_dir.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serialize private key — PEM PKCS8 format, unencrypted
    private_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    private_path = keys_dir / "collector_private.pem"
    private_path.write_bytes(private_pem)

    # Serialize public key — raw 32 bytes encoded as base64
    public_raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_b64 = base64.b64encode(public_raw).decode("ascii")
    public_path = keys_dir / "collector.pub"
    public_path.write_text(public_b64, encoding="utf-8")

    return str(private_path), str(public_path)


def load_private_key(pem_path: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    pem_bytes = Path(pem_path).read_bytes()
    key = load_pem_private_key(pem_bytes, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"Expected Ed25519PrivateKey, got {type(key)}")
    return key


if __name__ == "__main__":
    priv, pub = generate_keypair()
    print("\nDataCat Ed25519 keypair generated.")
    print(f"  Private key (NEVER commit): {priv}")
    print(f"  Public key  (share with backend): {pub}")
    print("\nNext step: register the public key with the backend.")
    print("  python backend/seed_trusted_key.py --tenant-id <UUID> --pub-key-file", pub)
