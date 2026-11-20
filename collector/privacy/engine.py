"""
Privacy Engine — DataCat Tier 1.

Responsibilities:
  1. Strip PII / sensitive fields from raw telemetry before signing or transmitting.
  2. Reject events that exceed permitted size (privacy by omission).
  3. Annotate surviving events with privacy_tags describing applied transforms.
  4. Never transmit rejected/filtered raw data to the SaaS backend.

Design principles:
  - Allowlist-driven: only explicitly declared metric fields are retained.
  - Blocklist-driven for field names: any field matching PII_FIELD_BLOCKLIST is stripped.
  - Non-numeric / unknown fields are dropped; structured telemetry only.
  - Privacy decisions are logged locally; no sensitive data flows out.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Tuple

from collector.config import MAX_PAYLOAD_BYTES, PII_FIELD_BLOCKLIST

logger = logging.getLogger("datacat.collector.privacy")

# ── Allowlisted metric field canonical names ─────────────────────────────────
# Only these aggregated, non-identifying metrics are permitted to be transmitted.
PERMITTED_METRIC_FIELDS: set = {
    # CPU
    "cpu_usage",
    "cpu_pct",
    "cpu_count",
    "load_avg_1m",
    "load_avg_5m",
    "load_avg_15m",
    # Memory (percentages and byte counts only — not process-level maps)
    "memory_usage",
    "ram_pct",
    "mem_pct",
    "mem_total_mb",
    "mem_available_mb",
    "mem_used_mb",
    "swap_pct",
    # Disk (aggregated — not per-file or per-process)
    "disk_usage",
    "disk_pct",
    "disk_free_gb",
    "disk_total_gb",
    "disk_read_mb_s",
    "disk_write_mb_s",
    # Network (rates and latency — not raw packet contents)
    "network_latency_ms",
    "latency_ms",
    "response_time_ms",
    "packet_loss_pct",
    "packet_loss",
    "net_sent_mb_s",
    "net_recv_mb_s",
    "net_errors",
    # Security (counts only)
    "failed_login_count",
    "failed_logins",
    "auth_failures",
    "port_scan_count",
    # Application health (non-identifying counters)
    "error_rate_pct",
    "request_count",
    "request_latency_ms",
    "queue_depth",
    "thread_count",
    "open_file_descriptors",
    "gc_pause_ms",
    # Event metadata (safe strings)
    "event_type",
    "source",
    "collector_version",
    "os_type",
    "kernel_version",
}


def _is_pii_field(field_name: str) -> bool:
    """Return True if the field name matches any PII blocklist entry (case-insensitive)."""
    lower = field_name.lower()
    return any(blocked in lower for blocked in PII_FIELD_BLOCKLIST)


def _is_permitted_field(field_name: str) -> bool:
    """Return True if the field name is in the allowlisted metric set."""
    return field_name.lower() in PERMITTED_METRIC_FIELDS


def filter_payload(raw_payload: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Apply privacy filtering to a raw telemetry payload dict.

    Returns:
        (filtered_payload, privacy_tags)

    Privacy tags applied:
        "pii_removed"       — at least one PII field was stripped
        "fields_allowlisted" — unknown / non-allowlisted fields were dropped
        "clean"             — no modifications required
    """
    if not isinstance(raw_payload, dict):
        logger.warning("Privacy engine received non-dict payload; rejecting entirely.")
        return {}, ["pii_removed", "fields_allowlisted"]

    filtered: Dict[str, Any] = {}
    pii_stripped = False
    fields_dropped = False

    for key, value in raw_payload.items():
        if _is_pii_field(key):
            logger.info("Privacy: stripped PII field '%s'", key)
            pii_stripped = True
            continue

        # Accept the field — only retain scalar numeric / string values
        if isinstance(value, bool):
            # Booleans are uninformative metrics — drop silently
            fields_dropped = True
            continue
        elif isinstance(value, dict):
            # Recurse for nested metric objects (allowlist applied recursively inside).
            # The parent key itself does not need to be on the allowlist; its children do.
            if _is_pii_field(key):
                logger.info("Privacy: stripped PII nested object '%s'", key)
                pii_stripped = True
                continue
            sub_filtered, _ = filter_payload(value)
            filtered.update(sub_filtered)
            if sub_filtered:
                fields_dropped = True  # mark that parent key was absorbed
        elif not _is_permitted_field(key):
            logger.debug("Privacy: dropped non-allowlisted field '%s'", key)
            fields_dropped = True
        elif isinstance(value, (int, float, str)):
            filtered[key] = value
        else:
            logger.debug("Privacy: dropped field '%s' with unsupported type %s", key, type(value).__name__)
            fields_dropped = True

    tags: List[str] = []
    if pii_stripped:
        tags.append("pii_removed")
    if fields_dropped:
        tags.append("fields_allowlisted")
    if not tags:
        tags.append("clean")

    return filtered, tags


def reject_if_too_large(payload: Dict[str, Any]) -> bool:
    """
    Return True if the serialised payload exceeds MAX_PAYLOAD_BYTES.
    The event must be suppressed locally — never transmitted to the backend.
    """
    try:
        size = len(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        if size > MAX_PAYLOAD_BYTES:
            logger.warning(
                "Privacy: payload size %d bytes exceeds limit %d — event suppressed locally.",
                size,
                MAX_PAYLOAD_BYTES,
            )
            return True
    except Exception:
        return True
    return False


def apply_privacy_policy(
    raw_payload: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[str], bool]:
    """
    Full privacy policy pipeline.

    Returns:
        (filtered_payload, privacy_tags, should_suppress)

    If should_suppress is True the event must NOT be transmitted.
    """
    filtered, tags = filter_payload(raw_payload)

    if not filtered:
        logger.info("Privacy: all fields filtered; event suppressed locally.")
        return {}, tags + (["suppressed"] if "suppressed" not in tags else []), True

    if reject_if_too_large(filtered):
        return {}, tags + ["suppressed"], True

    return filtered, tags, False
