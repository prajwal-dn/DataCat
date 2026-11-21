"""
Transmission module — DataCat Collector.

Responsible for POSTing a signed ingest envelope to the backend
POST /api/v1/ingest endpoint.

Design:
  - Single POST per event; no batching (simplest MVP).
  - Validates HTTP response code and parses backend response body.
  - Never retransmits rejected events (privacy rule: rejected data stays local).
  - Logs transmission results without echoing payload contents.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

from collector.config import HTTP_TIMEOUT, INGEST_ENDPOINT

logger = logging.getLogger("datacat.collector.transport")


@dataclass
class TransmissionResult:
    success: bool
    status_code: int
    event_id: str
    response_reason: Optional[str] = None
    backend_stored_at: Optional[str] = None
    error: Optional[str] = None


def transmit(
    ingest_envelope: Dict[str, Any],
    tenant_id: str,
    backend_url: str = INGEST_ENDPOINT,
    timeout: float = HTTP_TIMEOUT,
) -> TransmissionResult:
    """
    POST the signed ingest envelope to the backend.

    Args:
        ingest_envelope: The full payload returned by signing.build_ingest_payload().
        tenant_id:       Tenant UUID, also sent as X-Tenant-ID header.
        backend_url:     Full URL for the ingest endpoint.
        timeout:         HTTP request timeout in seconds.

    Returns:
        TransmissionResult with transmission status and backend metadata.

    Privacy rule:
        On any failure (network, rejection, timeout) the event stays local.
        The raw payload is NEVER logged or re-transmitted after rejection.
    """
    event_id = ingest_envelope.get("event", {}).get("event_id", "unknown")

    headers = {
        "Content-Type": "application/json",
        "X-Tenant-ID": tenant_id,
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(backend_url, json=ingest_envelope, headers=headers)

        body: Dict[str, Any] = {}
        try:
            parsed = resp.json()
            if isinstance(parsed, dict):
                body = parsed
        except Exception:
            pass

        if resp.status_code == 202:
            logger.info(
                "Transmission accepted: event_id=%s stored_at=%s",
                event_id,
                body.get("stored_at"),
            )
            return TransmissionResult(
                success=True,
                status_code=202,
                event_id=event_id,
                backend_stored_at=body.get("stored_at"),
            )

        elif resp.status_code == 409:
            raw_reason = body.get("reason")
            if isinstance(raw_reason, str) and raw_reason.strip():
                reason = raw_reason.strip()
            else:
                reason = "http_409"

            if reason == "duplicate_event":
                logger.info("Transmission duplicate (409): event_id=%s reason=%s", event_id, reason)
            else:
                logger.warning("Transmission conflict (409): event_id=%s reason=%s", event_id, reason)
            return TransmissionResult(
                success=False,
                status_code=409,
                event_id=event_id,
                response_reason=reason,
            )

        else:
            reason = body.get("reason", f"http_{resp.status_code}")
            # Do NOT log body detail — may contain echoed request fragments
            logger.warning(
                "Transmission rejected: event_id=%s status=%d reason=%s",
                event_id,
                resp.status_code,
                reason,
            )
            return TransmissionResult(
                success=False,
                status_code=resp.status_code,
                event_id=event_id,
                response_reason=reason,
            )

    except httpx.TimeoutException:
        logger.warning("Transmission timeout: event_id=%s", event_id)
        return TransmissionResult(
            success=False,
            status_code=0,
            event_id=event_id,
            error="timeout",
        )

    except httpx.ConnectError:
        logger.warning("Transmission connect error: event_id=%s", event_id)
        return TransmissionResult(
            success=False,
            status_code=0,
            event_id=event_id,
            error="connect_error",
        )

    except Exception as exc:
        error_type = type(exc).__name__
        logger.error(
            "Transmission unexpected error: event_id=%s error_type=%s",
            event_id,
            error_type,
        )
        return TransmissionResult(
            success=False,
            status_code=0,
            event_id=event_id,
            error="unexpected_error",
        )

