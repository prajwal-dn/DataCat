"""
DataCat Collector Configuration.

All tuneable values live here — override via environment variables or .env file.
Never commit secrets or private keys.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file if present (not committed)
load_dotenv(Path(__file__).parent.parent / ".env")

# ── Identity ────────────────────────────────────────────────────────────────
TENANT_ID: str = os.getenv("DATACAT_TENANT_ID", "")
COLLECTOR_NAME: str = os.getenv("DATACAT_COLLECTOR_NAME", "default-collector")

# Source host reported in every event (defaults to system hostname)
import socket
SOURCE_HOST: str = os.getenv("DATACAT_SOURCE_HOST", socket.gethostname())

# ── Backend connection ───────────────────────────────────────────────────────
BACKEND_URL: str = os.getenv("DATACAT_BACKEND_URL", "http://localhost:8000")
INGEST_ENDPOINT: str = f"{BACKEND_URL}/api/v1/ingest"
HEALTH_ENDPOINT: str = f"{BACKEND_URL}/api/v1/health"

# HTTP timeout for ingest requests (seconds)
HTTP_TIMEOUT: float = float(os.getenv("DATACAT_HTTP_TIMEOUT", "10.0"))

# ── Signing key path ─────────────────────────────────────────────────────────
# Private key is never committed — stored locally only.
# Generate with:  python collector/signing/keygen.py
PRIVATE_KEY_PATH: str = os.getenv(
    "DATACAT_PRIVATE_KEY_PATH",
    str(Path(__file__).parent.parent / "keys" / "collector_private.pem"),
)

# ── Collection behaviour ─────────────────────────────────────────────────────
# Interval between telemetry collection cycles (seconds)
COLLECTION_INTERVAL: float = float(os.getenv("DATACAT_COLLECTION_INTERVAL", "30.0"))

# ── Privacy thresholds ───────────────────────────────────────────────────────
# CPU / memory / disk usage percentages considered sensitive (> value → not suppressed by value alone)
# Fields listed here are ALWAYS stripped before transmission (PII / sensitive identifiers)
PII_FIELD_BLOCKLIST: list = [
    "username",
    "user",
    "email",
    "password",
    "token",
    "secret",
    "api_key",
    "access_key",
    "private_key",
    "ssn",
    "credit_card",
    "phone",
    "address",
    "ip_address",   # raw IPs stripped; aggregated stats retained
    "mac_address",
    "hostname_full",
    "pid_list",
    "process_args", # command-line arguments may expose secrets
    "env_vars",
]

# Maximum payload size the collector will transmit (bytes)
MAX_PAYLOAD_BYTES: int = int(os.getenv("DATACAT_MAX_PAYLOAD_BYTES", str(900 * 1024)))

