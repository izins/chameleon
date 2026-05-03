"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/response/isolation_log.py

Immutable audit log for every containment action taken by the system.

CRITICAL RULE: Every isolation action MUST be logged BEFORE execution.
  1. Log intent  → isolation_log.append_action(action)
  2. Execute     → firewall/DB/user lock
  3. Log result  → isolation_log.update_result(action_id, success)

This ensures that even if the execution fails or is interrupted,
we have a complete record of what the system INTENDED to do.

Storage:
  In demo mode → JSON-lines file (data/isolation_actions.jsonl)
  In production → Kafka topic + Elasticsearch + Blockchain (Phase 5)
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from src.config.settings import settings

logger = logging.getLogger(__name__)


# ── Action types ─────────────────────────────────────────────────────
class IsolationActionType(str, Enum):
    """Types of containment actions the system can take."""

    NETWORK_QUARANTINE = "network_quarantine"
    DB_REVOKE = "db_revoke"
    USER_LOCK = "user_lock"
    ALERT_SOC = "alert_soc"
    ELEVATED_MONITORING = "elevated_monitoring"
    LOG_ONLY = "log_only"


class ActionStatus(str, Enum):
    """Status of an isolation action."""

    PENDING = "pending"
    EXECUTED = "executed"
    DRY_RUN = "dry_run"
    FAILED = "failed"


# ── Action record ───────────────────────────────────────────────────
class IsolationAction(BaseModel):
    """A single containment action record.

    Attributes:
        action_id: Unique UUID4 for this action.
        timestamp: When the action was logged (BEFORE execution).
        alert_id: The enriched alert that triggered this action.
        entity_id: Target entity (IP / user / host).
        action_type: What containment action to take.
        severity: Alert severity that triggered the action.
        status: Current status of the action.
        dry_run: Whether this was a dry-run (no real execution).
        risk_score: The risk score that triggered this action.
        details: Human-readable description of the action.
        error: Error message if action failed.
    """

    action_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    alert_id: str = Field(default="")
    entity_id: str = Field(default="")
    action_type: IsolationActionType = Field(
        default=IsolationActionType.LOG_ONLY,
    )
    severity: str = Field(default="P4")
    status: ActionStatus = Field(default=ActionStatus.PENDING)
    dry_run: bool = Field(default=False)
    risk_score: float = Field(default=0.0)
    details: str = Field(default="")
    error: str = Field(default="")


class IsolationLog:
    """Append-only audit log for all isolation actions.

    Thread-safe. Every action is persisted immediately to disk
    in demo mode, or to Kafka/ES in production.

    Args:
        log_path: Path to the JSON-lines audit file.
    """

    def __init__(self, log_path: Optional[str] = None) -> None:
        self._path = Path(
            log_path or str(
                Path(settings.demo_output_file).parent / "isolation_actions.jsonl"
            )
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._actions: List[IsolationAction] = []
        self._lock = threading.Lock()
        logger.info("IsolationLog ready → %s", self._path)

    def append_action(self, action: IsolationAction) -> IsolationAction:
        """Log an action BEFORE it is executed.

        Args:
            action: The isolation action to log.

        Returns:
            The same action (for chaining).
        """
        with self._lock:
            self._actions.append(action)
            self._persist(action)

        logger.info(
            "ACTION LOGGED [%s] → %s on entity=%s  severity=%s  "
            "dry_run=%s  risk=%.1f  status=%s",
            action.action_id[:8],
            action.action_type.value,
            action.entity_id,
            action.severity,
            action.dry_run,
            action.risk_score,
            action.status.value,
        )
        return action

    def update_result(
        self,
        action_id: str,
        success: bool,
        error: str = "",
    ) -> Optional[IsolationAction]:
        """Update the result of an executed action.

        Args:
            action_id: The UUID of the action.
            success: Whether the action succeeded.
            error: Error message if failed.

        Returns:
            The updated action, or None if not found.
        """
        with self._lock:
            for action in self._actions:
                if action.action_id == action_id:
                    if success:
                        action.status = (
                            ActionStatus.DRY_RUN if action.dry_run
                            else ActionStatus.EXECUTED
                        )
                    else:
                        action.status = ActionStatus.FAILED
                        action.error = error
                    self._persist(action)
                    logger.info(
                        "ACTION RESULT [%s] → %s  error=%s",
                        action_id[:8], action.status.value, error or "none",
                    )
                    return action
        return None

    def get_actions_for_entity(self, entity_id: str) -> List[IsolationAction]:
        """Get all actions taken against an entity.

        Args:
            entity_id: The entity key.

        Returns:
            List of IsolationAction records.
        """
        with self._lock:
            return [a for a in self._actions if a.entity_id == entity_id]

    def get_all(self) -> List[IsolationAction]:
        """Get all logged actions.

        Returns:
            List of all IsolationAction records.
        """
        with self._lock:
            return list(self._actions)

    @property
    def action_count(self) -> int:
        """Total number of logged actions."""
        with self._lock:
            return len(self._actions)

    def _persist(self, action: IsolationAction) -> None:
        """Append an action to the JSON-lines file."""
        try:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(action.model_dump_json() + "\n")
        except Exception as exc:
            logger.warning("Failed to persist action: %s", exc)


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Legal requirement: every containment action must be auditable.
# 2. Log BEFORE execute: ensures intent is recorded even on failure.
# 3. Feeds into Phase 5 (Blockchain) for tamper-evident traceability.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os

    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    log = IsolationLog()

    action = IsolationAction(
        alert_id="alert-001", entity_id="192.168.1.100",
        action_type=IsolationActionType.NETWORK_QUARANTINE,
        severity="P1", dry_run=True, risk_score=92.5,
        details="Quarantine host 192.168.1.100 — SSH brute-force detected",
    )
    log.append_action(action)
    log.update_result(action.action_id, success=True)

    logger.info("Actions for 192.168.1.100: %d",
                len(log.get_actions_for_entity("192.168.1.100")))
    logger.info("IsolationLog demo complete ✓")
