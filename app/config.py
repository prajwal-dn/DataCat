"""Application configuration module for DATACAT Tier 2 SaaS."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DB_PATH = Path(os.getenv("DATACAT_DB_PATH", str(BASE_DIR / "datacat.db")))
COLLECTORS_CONFIG_PATH = Path(
    os.getenv("DATACAT_COLLECTORS_CONFIG", str(BASE_DIR / "config" / "collectors.yaml"))
)
KEYS_DIR = BASE_DIR / "keys"

# API details
API_V1_STR = "/api/v1"
PROJECT_NAME = "DATACAT Tier 2 SaaS Platform"
VERSION = "0.1.0"
