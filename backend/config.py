"""
DataCat backend configuration.
All tuneable values live here — no magic strings scattered across modules.
"""
import os
from pathlib import Path

# Repository root (one level above this file)
ROOT_DIR = Path(__file__).parent.parent

# SQLite database path (overridable via env for tests)
DB_PATH: str = os.getenv("DATACAT_DB_PATH", str(ROOT_DIR / "datacat.db"))

# Application metadata
APP_VERSION = "1.0.0"
APP_TITLE = "DataCat SaaS Platform"

# Ingest limits
MAX_PAYLOAD_BYTES = 1_048_576  # 1 MB hard limit on raw request body

# Telemetry Freshness Thresholds (in seconds)
# Fresh: < 2 minutes (120s)
# Stale: 2 to 10 minutes (120s - 600s)
# Very Stale: > 10 minutes (> 600s)
FRESHNESS_FRESH_MAX_SECONDS = int(os.getenv("DATACAT_FRESHNESS_FRESH_MAX_SECONDS", "120"))
FRESHNESS_STALE_MAX_SECONDS = int(os.getenv("DATACAT_FRESHNESS_STALE_MAX_SECONDS", "600"))

# Dashboard
EVENTS_DEFAULT_LIMIT = 50
EVENTS_MAX_LIMIT = 500

