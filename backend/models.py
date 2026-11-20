"""
Pydantic models — exact field names from docs/api-contract.md.
Do not rename fields without updating the shared contract.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
import uuid


# ---------------------------------------------------------------------------
# Ingest request (POST /api/v1/ingest)
# ---------------------------------------------------------------------------

class EventPayload(BaseModel):
    event_id: str = Field(..., description="UUID identifying this unique event")
    timestamp: str = Field(..., description="ISO-8601 UTC timestamp")
    source_host: str = Field(..., description="Originating host identifier")
    event_type: str = Field(..., description="Category/type of telemetry event")
    payload: Dict[str, Any] = Field(..., description="Arbitrary telemetry data")
    privacy_tags: List[str] = Field(default_factory=list, description="Applied privacy transformations")


class Receipt(BaseModel):
    payload_hash: str = Field(..., description="Hex-encoded SHA-256 of canonical JSON of event object")
    signature: str = Field(..., description="Base64-encoded Ed25519 signature over payload_hash bytes")
    public_key: str = Field(..., description="Base64-encoded Ed25519 public key (32 bytes) — verified against registry")
    signed_at: str = Field(..., description="ISO-8601 UTC timestamp of signing")


class IngestRequest(BaseModel):
    tenant_id: str = Field(..., description="UUID identifying the tenant")
    event: EventPayload
    receipt: Receipt

    @field_validator("tenant_id")
    @classmethod
    def tenant_id_must_be_uuid(cls, v: str) -> str:
        try:
            uuid.UUID(v)
        except ValueError:
            raise ValueError("tenant_id must be a valid UUID")
        return v

    @field_validator("receipt")
    @classmethod
    def payload_hash_must_be_hex(cls, v: Receipt) -> Receipt:
        try:
            bytes.fromhex(v.payload_hash)
        except ValueError:
            raise ValueError("receipt.payload_hash must be a valid hex string")
        return v


# ---------------------------------------------------------------------------
# Ingest responses
# ---------------------------------------------------------------------------

class IngestAccepted(BaseModel):
    status: str = "accepted"
    event_id: str
    hash_verified: bool
    signature_verified: bool
    duplicate: bool
    stored_at: str


class IngestRejected(BaseModel):
    status: str = "rejected"
    reason: str   # hash_mismatch | invalid_signature | duplicate_event | unknown_collector | untrusted_key | tenant_mismatch
    detail: str


# ---------------------------------------------------------------------------
# GET /api/v1/events
# ---------------------------------------------------------------------------

class EventRecord(BaseModel):
    event_id: str
    tenant_id: str
    timestamp: str
    source_host: str
    event_type: str
    status: str
    hash_verified: bool
    signature_verified: bool
    rejected_reason: Optional[str]
    ingested_at: str


class EventsResponse(BaseModel):
    total: int
    events: List[EventRecord]


# ---------------------------------------------------------------------------
# GET /api/v1/stats
# ---------------------------------------------------------------------------

class StatsResponse(BaseModel):
    total_events: int
    accepted: int
    rejected: int
    duplicate_rejections: int
    hash_failures: int
    signature_failures: int
    tenants_active: int
    last_event_at: Optional[str]


# ---------------------------------------------------------------------------
# GET /api/v1/incidents
# ---------------------------------------------------------------------------

class IncidentRecord(BaseModel):
    event_id: str
    tenant_id: str
    incident_type: str   # signature_failure | hash_mismatch | duplicate | unknown_collector | untrusted_key
    timestamp: str
    source_host: str
    detail: str


class IncidentsResponse(BaseModel):
    incidents: List[IncidentRecord]


# ---------------------------------------------------------------------------
# GET /api/v1/health
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    version: str
    db: str
    uptime_seconds: float
