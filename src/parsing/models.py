"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/parsing/models.py

Pydantic v2 data models for the log-parsing pipeline.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from src.config.settings import EventAction, EventCategory

# ── Logging ──────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)


# ── Raw log event ────────────────────────────────────────────────────
class RawLogEvent(BaseModel):
    raw_line: str = Field(..., min_length=1, description="Verbatim log line.")
    host_name: str = Field(default="unknown", description="Originating host.")
    log_source: str = Field(default="unknown", description="Log stream name.")
    ingestion_ts: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC ingestion timestamp.",
    )

    @field_validator("ingestion_ts", mode="before")
    @classmethod
    def _ensure_utc(cls, v: datetime) -> datetime:
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


# ── Normalized (ECS) event ───────────────────────────────────────────
class NormalizedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str = Field(default="")
    dest_ip: str = Field(default="")
    event_category: EventCategory = Field(default=EventCategory.UNKNOWN)
    event_action: EventAction = Field(default=EventAction.UNKNOWN)
    username: str = Field(default="")
    process_name: str = Field(default="")
    log_original: str = Field(..., description="Verbatim raw log line.")
    template_id: int = Field(default=-1)
    template_str: str = Field(default="")
    event_hash: str = Field(default="")
    host_name: str = Field(default="unknown")
    log_source: str = Field(default="unknown")
    suspicion_delta: float = Field(
        default=0.0, description="Behavioral suspicion score from BaselineProfiler."
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def _ensure_utc(cls, v: datetime) -> datetime:
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    def compute_hash(self) -> NormalizedEvent:
        self.event_hash = hashlib.sha256(self.log_original.encode("utf-8")).hexdigest()
        return self


# ── Alert contract model ─────────────────────────────────────────────
class ModelAlert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    severity: str = Field(default="P4")
    attack_type: str = Field(default="anomaly_unknown")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    source_host: str = Field(default="0.0.0.0")
    affected_assets: List[str] = Field(default_factory=list)
    event_hashes: List[str] = Field(default_factory=list)
    model_source: str = Field(default="RuleEngine")
    raw_sequence: List[int] = Field(default_factory=list)
    anomaly_score: float = Field(default=0.0, ge=-1.0, le=0.0)
    xgb_proba: dict = Field(default_factory=dict)


# ── Session model ────────────────────────────────────────────────────
class LogSession(BaseModel):
    session_id: str = Field(default_factory=lambda: str(uuid4()))
    entity_type: str = Field(default="ip")
    entity_id: str = Field(..., description="Entity value (IP/User/Host).")
    start_ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_count: int = Field(default=0)
    template_sequence: List[int] = Field(default_factory=list)
    total_suspicion: float = Field(default=0.0)
    template_counts: dict = Field(default_factory=dict)
    event_hashes: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    dest_ips: List[str] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)
    events: List[NormalizedEvent] = Field(default_factory=list)
