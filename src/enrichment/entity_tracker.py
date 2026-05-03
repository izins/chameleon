"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/enrichment/entity_tracker.py

Persistent memory for entity behaviour across sessions.

WHY THIS EXISTS:
  An attacker who spaces their actions (e.g. 1 failed login Monday,
  1 port scan Wednesday, 1 privilege escalation Friday) will generate
  3 separate sessions, each looking harmless in isolation.

  The EntityTracker solves this by maintaining a cumulative record
  for every entity (IP / user / host) it has ever seen. When the
  enrichment engine processes a new alert, it asks the tracker:
  "What do we already know about this entity?" — and gets back the
  full history of past alerts, cumulative risk score, and MITRE
  technique timeline.

STORAGE:
  In demo mode, we use an in-memory dict backed by a JSON file.
  In production, this would be Redis (hot) + PostgreSQL (cold).
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from src.config.settings import settings
from src.database.db_manager import db  # Import the new DB manager

logger = logging.getLogger(__name__)


# ── Constants ────────────────────────────────────────────────────────
DEFAULT_DECAY_HOURS: int = 168   # 7 days — score decays after this
SCORE_DECAY_FACTOR: float = 0.5  # halve old scores after decay period


# ── Entity Record ────────────────────────────────────────────────────
class EntityRecord(BaseModel):
    """Cumulative record of everything we know about one entity.

    Attributes:
        entity_id: The grouping key (IP, username, or host).
        first_seen: UTC timestamp of the first alert for this entity.
        last_seen: UTC timestamp of the most recent alert.
        cumulative_score: Running risk score (sum of all alert scores).
        alert_count: Total number of alerts received.
        alert_ids: List of alert_id strings for audit trail.
        attack_types: Unique attack types observed.
        mitre_techniques: Unique MITRE ATT&CK technique IDs observed.
        categories: Unique ECS event categories across all alerts.
        source_ips: All source IPs associated with this entity.
    """

    entity_id: str
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    cumulative_score: float = 0.0
    alert_count: int = 0
    alert_ids: List[str] = Field(default_factory=list)
    attack_types: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)


class EntityTracker:
    """Persistent memory that tracks entity behaviour over time.

    This is the solution to the "Low and Slow" attack problem.
    Every alert updates the entity's cumulative record, so even if
    individual sessions look benign, the accumulation of many small
    signals over days or weeks will eventually cross the threshold.

    Args:
        persistence_path: Path to the JSON file for demo persistence.
            If None, uses in-memory only.
    """

    def __init__(self, persistence_path: Optional[str] = None) -> None:
        self._records: Dict[str, EntityRecord] = {}
        self._lock = threading.Lock()
        self._path = Path(persistence_path) if persistence_path else None

        if self._path and self._path.exists():
            self._load_from_disk()

        logger.info(
            "EntityTracker ready — %d entities in memory, persistence=%s",
            len(self._records),
            self._path or "OFF",
        )

    def _load_from_disk(self) -> None:
        """Load entity records from the JSON persistence file."""
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for entity_id, record_data in data.items():
                self._records[entity_id] = EntityRecord(**record_data)
            logger.info("Loaded %d entity records from disk", len(self._records))
        except Exception as exc:
            logger.warning("Could not load entity records: %s", exc)

    def _save_to_disk(self) -> None:
        """Persist entity records to the JSON file."""
        if not self._path:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                eid: rec.model_dump(mode="json")
                for eid, rec in self._records.items()
            }
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, default=str)
        except Exception as exc:
            logger.warning("Could not save entity records: %s", exc)

    def update(
        self,
        entity_id: str,
        alert_id: str,
        score_delta: float,
        attack_type: str = "",
        mitre_technique: str = "",
        categories: Optional[List[str]] = None,
        source_ips: Optional[List[str]] = None,
        severity: str = "UNKNOWN",
        confidence: float = 0.0,
    ) -> EntityRecord:
        """Update or create an entity record with new alert data.

        This is called every time a new alert arrives. It adds the
        score delta to the cumulative score and appends metadata.

        Args:
            entity_id: The entity key.
            alert_id: UUID of the alert.
            score_delta: Risk points to add.
            attack_type: Attack type string.
            mitre_technique: MITRE ATT&CK ID (e.g. "T1110").
            categories: ECS event categories from the alert.
            source_ips: Source IPs from the alert.

        Returns:
            The updated EntityRecord.
        """
        now = datetime.now(timezone.utc)

        with self._lock:
            # 1. In-memory logic (keeps existing functionality)
            if entity_id not in self._records:
                self._records[entity_id] = EntityRecord(entity_id=entity_id)
            rec = self._records[entity_id]

            rec.cumulative_score += score_delta
            rec.alert_count += 1
            rec.last_seen = datetime.now(timezone.utc)
            rec.alert_ids.append(alert_id)
            if attack_type and attack_type not in rec.attack_types:
                rec.attack_types.append(attack_type)
            if mitre_technique and mitre_technique not in rec.mitre_techniques:
                rec.mitre_techniques.append(mitre_technique)
            if categories:
                for cat in categories:
                    if cat not in rec.categories:
                        rec.categories.append(cat)
            if source_ips:
                for ip in source_ips:
                    if ip not in rec.source_ips:
                        rec.source_ips.append(ip)

            # 2. Write to the Hot SQLite Database
            try:
                if attack_type:  # Don't insert empty attack types
                    db.upsert_entity(ip=entity_id, score_delta=score_delta, attack_type=attack_type)
                    db.log_alert(
                        alert_id=alert_id,
                        ip=entity_id,
                        attack_type=attack_type,
                        severity=severity,
                        confidence=confidence,
                    )
            except Exception as e:
                logger.error("Failed to write to hot DB: %s", e)

            # 3. Optional persistence to JSON
            if self._path:
                self._save_to_disk()

            logger.info(
                "Entity %s updated (Hot DB) — score=%.1f  alerts=%d  attack_types=%s",
                entity_id, rec.cumulative_score, rec.alert_count, rec.attack_types
            )
            return rec.model_copy()

    def get(self, entity_id: str) -> Optional[EntityRecord]:
        """Retrieve the record for an entity.

        Args:
            entity_id: The entity key.

        Returns:
            The EntityRecord if it exists, else None.
        """
        with self._lock:
            return self._records.get(entity_id)

    def get_all_above_score(self, threshold: float) -> List[EntityRecord]:
        """Return all entities whose cumulative score exceeds threshold.

        Args:
            threshold: Minimum score to include.

        Returns:
            List of EntityRecords above the threshold.
        """
        with self._lock:
            return [
                rec for rec in self._records.values()
                if rec.cumulative_score >= threshold
            ]

    def decay_scores(self, now: Optional[datetime] = None) -> int:
        """Apply time-based score decay to all entities.

        Entities whose last activity was more than DEFAULT_DECAY_HOURS
        ago get their cumulative score multiplied by SCORE_DECAY_FACTOR.

        Call this periodically (e.g. daily via cron or background thread).

        Args:
            now: Current time (defaults to utcnow).

        Returns:
            Number of entities whose scores were decayed.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        decayed = 0
        decay_threshold = timedelta(hours=DEFAULT_DECAY_HOURS)

        with self._lock:
            for rec in self._records.values():
                if (now - rec.last_seen) > decay_threshold:
                    old_score = rec.cumulative_score
                    rec.cumulative_score *= SCORE_DECAY_FACTOR
                    if old_score != rec.cumulative_score:
                        decayed += 1
                        logger.debug(
                            "Decayed entity %s: %.1f → %.1f",
                            rec.entity_id, old_score, rec.cumulative_score,
                        )
            if decayed:
                self._save_to_disk()

        if decayed:
            logger.info("Decayed scores for %d entities", decayed)
        return decayed

    @property
    def entity_count(self) -> int:
        """Number of entities currently tracked."""
        with self._lock:
            return len(self._records)


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# ---------------------
# 1. Solves the "Low and Slow" attack problem by maintaining cumulative
#    risk scores per entity across days, weeks, or months.
# 2. Bridges the gap between stateless session-based detection and
#    stateful long-term threat tracking.
# 3. Provides the historical context that the enrichment engine and
#    the scoring engine (Phase 3) need to make informed decisions.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os

    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    tracker = EntityTracker()

    logger.info("=" * 60)
    logger.info("ENTITY TRACKER DEMO — Low & Slow attack simulation")
    logger.info("=" * 60)

    # Simulate spaced-out alerts for the same attacker
    tracker.update("192.168.1.100", "alert-001", score_delta=10,
                   attack_type="ssh_bruteforce", mitre_technique="T1110",
                   categories=["authentication"])
    logger.info("  Monday: 1 failed login → score = %.1f",
                tracker.get("192.168.1.100").cumulative_score)

    tracker.update("192.168.1.100", "alert-002", score_delta=20,
                   attack_type="lateral_movement", mitre_technique="T1021",
                   categories=["network"])
    logger.info("  Wednesday: port scan → score = %.1f",
                tracker.get("192.168.1.100").cumulative_score)

    tracker.update("192.168.1.100", "alert-003", score_delta=60,
                   attack_type="privilege_escalation", mitre_technique="T1068",
                   categories=["system"])
    logger.info("  Friday: priv esc → score = %.1f",
                tracker.get("192.168.1.100").cumulative_score)

    rec = tracker.get("192.168.1.100")
    logger.info("")
    logger.info("  FINAL RECORD:")
    logger.info("    Entity:       %s", rec.entity_id)
    logger.info("    Score:        %.1f (THRESHOLD EXCEEDED!)", rec.cumulative_score)
    logger.info("    Alert count:  %d", rec.alert_count)
    logger.info("    Attack types: %s", rec.attack_types)
    logger.info("    MITRE:        %s", rec.mitre_techniques)
    logger.info("    Categories:   %s ← cross-source!", rec.categories)

    logger.info("")
    logger.info("EntityTracker demo complete ✓")
