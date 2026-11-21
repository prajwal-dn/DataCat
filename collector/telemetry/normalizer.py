"""
Telemetry Normalizer — DataCat Collector.

Collects raw system metrics via psutil, normalises field names to the
canonical set understood by both the privacy engine and the backend AIOps engine.

Field name contract (must match backend/aiops/metrics.py aliases):
  cpu_pct             → cpu_usage (AIOps alias: "cpu_pct")
  ram_pct             → memory_usage (AIOps alias: "ram_pct")
  disk_pct            → disk_usage (AIOps alias: "disk_percent")
  latency_ms          → network_latency_ms (AIOps alias: "latency_ms")
  packet_loss         → packet_loss_pct (AIOps alias: "packet_loss")
  failed_logins       → failed_login_count (AIOps alias: "failed_logins")

The normalised dict is passed through the privacy engine before signing.
"""
from __future__ import annotations

import logging
import platform
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from collector.config import (
    LATENCY_PROBE_ENABLED,
    LATENCY_PROBE_HOST,
    LATENCY_PROBE_PORT,
    LATENCY_PROBE_TIMEOUT,
)

logger = logging.getLogger("datacat.collector.telemetry")

# Optional psutil — gracefully absent in minimal environments
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False
    logger.warning("psutil not installed — using stub telemetry; install psutil for real metrics.")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Latency probe ─────────────────────────────────────────────────────────────

def _probe_latency_ms(
    target_host: str = LATENCY_PROBE_HOST,
    port: int = LATENCY_PROBE_PORT,
    timeout: float = LATENCY_PROBE_TIMEOUT,
) -> Optional[float]:
    """
    Measure TCP connection latency to a configured endpoint.
    Returns None if unreachable.

    This measures TCP connect latency, not actual packet loss.
    """
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            t0 = time.monotonic()
            s.connect((target_host, port))
            latency = (time.monotonic() - t0) * 1000.0
            return round(latency, 2)
    except OSError:
        return None


# ── Raw collection ────────────────────────────────────────────────────────────

def collect_system_metrics() -> Dict[str, Any]:
    """
    Collect raw system telemetry.  Returns a dict with canonical field names
    that the privacy engine and AIOps engine both understand.
    """
    if not _PSUTIL_AVAILABLE:
        return _stub_metrics()

    raw: Dict[str, Any] = {}

    # CPU
    try:
        raw["cpu_pct"] = psutil.cpu_percent(interval=0.5)
        load = psutil.getloadavg() if hasattr(psutil, "getloadavg") else (0.0, 0.0, 0.0)
        raw["load_avg_1m"] = round(load[0], 2)
        raw["load_avg_5m"] = round(load[1], 2)
        raw["load_avg_15m"] = round(load[2], 2)
    except Exception as exc:
        logger.debug("CPU metric error: %s", exc)

    # Memory
    try:
        mem = psutil.virtual_memory()
        raw["ram_pct"] = mem.percent
        raw["mem_total_mb"] = round(mem.total / 1_048_576, 1)
        raw["mem_available_mb"] = round(mem.available / 1_048_576, 1)
        raw["mem_used_mb"] = round(mem.used / 1_048_576, 1)
        swap = psutil.swap_memory()
        raw["swap_pct"] = swap.percent
    except Exception as exc:
        logger.debug("Memory metric error: %s", exc)

    # Disk (root partition only — avoid per-path enumeration)
    try:
        disk = psutil.disk_usage("/")
        raw["disk_pct"] = disk.percent
        raw["disk_free_gb"] = round(disk.free / 1_073_741_824, 2)
        raw["disk_total_gb"] = round(disk.total / 1_073_741_824, 2)
        io = psutil.disk_io_counters()
        if io:
            raw["disk_read_mb_s"] = round(io.read_bytes / 1_048_576, 2)
            raw["disk_write_mb_s"] = round(io.write_bytes / 1_048_576, 2)
    except Exception as exc:
        logger.debug("Disk metric error: %s", exc)

    # Network
    try:
        net = psutil.net_io_counters()
        if net:
            raw["net_sent_mb_s"] = round(net.bytes_sent / 1_048_576, 2)
            raw["net_recv_mb_s"] = round(net.bytes_recv / 1_048_576, 2)
            raw["net_errors"] = net.errin + net.errout
    except Exception as exc:
        logger.debug("Network IO metric error: %s", exc)

    # Optional external TCP latency probe (disabled by default)
    if LATENCY_PROBE_ENABLED:
        try:
            lat = _probe_latency_ms()
            if lat is not None:
                raw["latency_ms"] = lat
        except Exception as exc:
            logger.debug("Latency probe error: %s", type(exc).__name__)

    # Misc system counters (non-identifying)
    try:
        raw["thread_count"] = len(psutil.pids())
        raw["open_file_descriptors"] = psutil.Process().num_fds() if hasattr(psutil.Process(), "num_fds") else 0
    except Exception:
        pass

    # Metadata (safe, non-identifying strings)
    raw["os_type"] = platform.system()
    raw["kernel_version"] = platform.release()
    raw["collector_version"] = "1.0.0"

    return raw


def _stub_metrics() -> Dict[str, Any]:
    """Return zero-valued stub metrics when psutil is unavailable."""
    return {
        "cpu_pct": 0.0,
        "ram_pct": 0.0,
        "disk_pct": 0.0,
        "os_type": platform.system(),
        "collector_version": "1.0.0",
    }


# ── Normalisation ─────────────────────────────────────────────────────────────

def normalize_metrics(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize raw telemetry to the canonical field names expected by the backend.
    This is a pure pass-through for already-canonical names.

    The privacy engine will further filter this dict via its allowlist.
    Normalization ensures the collector always uses consistent field names
    regardless of what psutil returns on different OS versions.
    """
    # The raw dict already uses the AIOps-compatible alias names
    # (cpu_pct, ram_pct, disk_pct, latency_ms, packet_loss, etc.)
    # Return as-is — privacy engine handles field filtering.
    return dict(raw)


def collect_normalized_telemetry() -> Dict[str, Any]:
    """
    Convenience function: collect + normalize in one call.
    Returns a normalized dict ready for the privacy engine.
    """
    raw = collect_system_metrics()
    return normalize_metrics(raw)

