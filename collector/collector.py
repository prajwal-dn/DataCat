"""
DataCat Collector — Main Entry Point.

Full pipeline per collection cycle:
  1. Collect raw system metrics via telemetry.normalizer.
  2. Apply privacy engine: strip PII, enforce allowlist, check size.
  3. If suppressed locally → log and skip (never transmit).
  4. Build event dict with required API-contract fields.
  5. Sign event with Ed25519 private key (domain-separated, tenant-bound).
  6. Transmit signed envelope to backend POST /api/v1/ingest.
  7. Log result (without echoing payload contents).

Usage:
    # One-shot (send one event and exit)
    python -m collector.collector --once

    # Continuous (collect every COLLECTION_INTERVAL seconds)
    python -m collector.collector

Environment variables (or .env):
    DATACAT_TENANT_ID           UUID of the tenant
    DATACAT_PRIVATE_KEY_PATH    Path to Ed25519 private key PEM
    DATACAT_BACKEND_URL         Backend base URL (default: http://localhost:8000)
    DATACAT_COLLECTION_INTERVAL Seconds between collection cycles (default: 30)
    DATACAT_SOURCE_HOST         Hostname to report (default: system hostname)
    DATACAT_COLLECTOR_NAME      Collector identifier (default: default-collector)
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from collector.config import (
    BACKEND_URL,
    COLLECTION_INTERVAL,
    COLLECTOR_NAME,
    INGEST_ENDPOINT,
    PRIVATE_KEY_PATH,
    SOURCE_HOST,
    TENANT_ID,
)
from collector.privacy.engine import apply_privacy_policy
from collector.signing.keygen import load_private_key
from collector.signing.signer import build_ingest_payload
from collector.telemetry.normalizer import collect_normalized_telemetry
from collector.transport.sender import transmit

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("datacat.collector")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_once(private_key, tenant_id: str, event_type: str = "system.metrics") -> bool:
    """
    Execute a single collection + privacy + sign + transmit cycle.
    Returns True if event was successfully transmitted, False otherwise.
    """
    # 1. Collect
    raw_metrics = collect_normalized_telemetry()
    logger.debug("Collected %d raw metric fields.", len(raw_metrics))

    # 2. Privacy filter
    filtered_payload, privacy_tags, suppressed = apply_privacy_policy(raw_metrics)
    if suppressed:
        logger.info(
            "Event suppressed by privacy engine (tags=%s). No data transmitted.",
            privacy_tags,
        )
        return False

    logger.info(
        "Privacy engine approved event. tags=%s retained_fields=%d",
        privacy_tags,
        len(filtered_payload),
    )

    # 3. Build event dict (matches API contract EventPayload schema)
    event_id = str(uuid.uuid4())
    event_dict = {
        "event_id": event_id,
        "timestamp": _now_iso(),
        "source_host": SOURCE_HOST,
        "event_type": event_type,
        "payload": filtered_payload,
        "privacy_tags": privacy_tags,
    }

    # 4. Sign
    ingest_envelope = build_ingest_payload(event_dict, tenant_id, private_key)

    # 5. Transmit
    result = transmit(ingest_envelope, tenant_id=tenant_id, backend_url=INGEST_ENDPOINT)

    if result.success:
        logger.info(
            "✓ Event accepted by backend: event_id=%s stored_at=%s",
            result.event_id,
            result.backend_stored_at,
        )
        return True
    else:
        logger.warning(
            "✗ Event rejected or failed: event_id=%s status=%d reason=%s error=%s",
            result.event_id,
            result.status_code,
            result.response_reason,
            result.error,
        )
        return False


def main():
    parser = argparse.ArgumentParser(description="DataCat Collector")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Collect and transmit one event, then exit.",
    )
    parser.add_argument(
        "--event-type",
        default="system.metrics",
        help="Event type label (default: system.metrics)",
    )
    args = parser.parse_args()

    # Validate required configuration
    if not TENANT_ID:
        logger.error(
            "DATACAT_TENANT_ID is not set. "
            "Set it in .env or as an environment variable."
        )
        sys.exit(1)

    if not Path(PRIVATE_KEY_PATH).exists():
        logger.error(
            "Private key not found at %s. "
            "Generate a keypair with: python collector/signing/keygen.py",
            PRIVATE_KEY_PATH,
        )
        sys.exit(1)

    try:
        private_key = load_private_key(PRIVATE_KEY_PATH)
    except Exception as exc:
        logger.error("Failed to load private key: %s", exc)
        sys.exit(1)

    logger.info(
        "DataCat Collector starting. tenant=%s host=%s backend=%s interval=%ss",
        TENANT_ID,
        SOURCE_HOST,
        BACKEND_URL,
        COLLECTION_INTERVAL,
    )

    if args.once:
        success = run_once(private_key, TENANT_ID, event_type=args.event_type)
        sys.exit(0 if success else 1)

    # Continuous collection loop
    while True:
        try:
            run_once(private_key, TENANT_ID, event_type=args.event_type)
        except KeyboardInterrupt:
            logger.info("Collector stopped by user.")
            break
        except Exception as exc:
            logger.error("Unexpected error in collection cycle: %s", exc)

        logger.debug("Sleeping %ss until next collection.", COLLECTION_INTERVAL)
        time.sleep(COLLECTION_INTERVAL)


if __name__ == "__main__":
    main()

