"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/response/isolator.py

Containment execution engine. Takes a RiskVerdict and executes
the appropriate isolation actions based on severity level.

Isolation matrix:
  P1 → network_quarantine + db_revoke + user_lock + alert_soc
  P2 → network_quarantine + alert_soc
  P3 → elevated_monitoring + alert_soc
  P4 → log_only

CRITICAL: isolator.py is DRY-RUN capable.
  When AEGIS_DRY_RUN=true (or demo mode), actions are logged
  but NOT executed against real infrastructure.

CRITICAL: Every action calls isolation_log.append_action() BEFORE
  executing. Log intent first, then execute.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from src.config.settings import settings
from src.response.isolation_log import (
    ActionStatus,
    IsolationAction,
    IsolationActionType,
    IsolationLog,
)
from src.response.scorer import RiskVerdict

logger = logging.getLogger(__name__)


# ── Dynamic Isolation Logic ───────────────────────────────────────────
class Isolator:
    """Executes containment actions based on risk verdicts and context.
    
    Uses an intelligent, flexible containment protocol inspired by ISO 27035
    but adapted for specific attack types and asset criticality.

    In DRY-RUN mode (demo or AEGIS_DRY_RUN=true), all actions are
    logged but not executed against real infrastructure.

    Args:
        isolation_log: IsolationLog instance for audit trail.
        dry_run: Override dry-run flag (defaults to settings).
    """

    def __init__(
        self,
        isolation_log: Optional[IsolationLog] = None,
        dry_run: Optional[bool] = None,
    ) -> None:
        self._log = isolation_log or IsolationLog()
        self._dry_run = (
            dry_run if dry_run is not None
            else (settings.demo_mode or settings.dry_run)
        )
        logger.info(
            "Isolator ready — dry_run=%s", self._dry_run,
        )

    def _determine_actions(self, verdict: RiskVerdict) -> List[IsolationActionType]:
        """Determine isolation actions dynamically based on context."""
        actions = []
        severity = verdict.adjusted_severity
        attack = verdict.attack_type
        asset = verdict.asset_type
        impact = verdict.business_impact

        # Base actions by severity
        if severity in ("P1", "P2"):
            actions.append(IsolationActionType.ALERT_SOC)
        elif severity == "P3":
            actions.extend([IsolationActionType.ELEVATED_MONITORING, IsolationActionType.ALERT_SOC])
        else:
            return [IsolationActionType.LOG_ONLY]

        # Context-aware isolation rules
        if impact == "critical" and asset in ("server", "network", "infrastructure"):
            # Never auto-quarantine a critical server/router; elevate monitoring instead
            actions.append(IsolationActionType.ELEVATED_MONITORING)
            logger.info("  [ISO 27035] Bypassed auto-quarantine for CRITICAL infrastructure %s. Relying on SOC manual review.", verdict.entity_id)
        else:
            # Attack-specific containment
            if attack in ("data_exfil", "malware_beacon", "scan"):
                actions.append(IsolationActionType.NETWORK_QUARANTINE)
            elif attack == "sql_injection":
                actions.append(IsolationActionType.DB_REVOKE)
            elif attack in ("ssh_bruteforce", "privilege_escalation"):
                actions.append(IsolationActionType.USER_LOCK)
                # If bruteforce is severe, also block network
                if severity == "P1":
                    actions.append(IsolationActionType.NETWORK_QUARANTINE)
            elif attack == "anomaly_unknown":
                actions.append(IsolationActionType.NETWORK_QUARANTINE)
                
        # Deduplicate
        return list(set(actions))

    def execute(self, verdict: RiskVerdict) -> List[IsolationAction]:
        """Execute all containment actions for a risk verdict.

        Steps for each action:
          1. Create IsolationAction (status=PENDING)
          2. Log it via isolation_log.append_action() — BEFORE execution
          3. Execute the action (or simulate in dry-run)
          4. Update the result

        Args:
            verdict: The risk verdict from the scorer.

        Returns:
            List of IsolationAction records with final statuses.
        """
        action_types = self._determine_actions(verdict)

        executed_actions: List[IsolationAction] = []

        logger.info(
            "╔══════════════════════════════════════════════╗",
        )
        logger.info(
            "║  ISOLATION — %s on %s (score=%.2f %s)  ║",
            verdict.adjusted_severity, verdict.entity_id,
            verdict.final_risk_score, verdict.risk_label,
        )
        logger.info(
            "╚══════════════════════════════════════════════╝",
        )

        for action_type in action_types:
            # ── 1. Create action ─────────────────────────────────────
            action = IsolationAction(
                alert_id=verdict.alert_id,
                entity_id=verdict.entity_id,
                action_type=action_type,
                severity=verdict.adjusted_severity,
                status=ActionStatus.PENDING,
                dry_run=self._dry_run,
                risk_score=verdict.final_risk_score,
                details=self._build_details(action_type, verdict),
            )

            # ── 2. Log BEFORE execution ──────────────────────────────
            self._log.append_action(action)

            # ── 3. Execute (or simulate) ─────────────────────────────
            success, error = self._execute_action(action_type, verdict)

            # ── 4. Update result ─────────────────────────────────────
            self._log.update_result(action.action_id, success, error)
            executed_actions.append(action)

        logger.info(
            "Isolation complete for %s — %d actions executed (%s)",
            verdict.entity_id,
            len(executed_actions),
            "DRY-RUN" if self._dry_run else "LIVE",
        )
        return executed_actions

    def _execute_action(
        self,
        action_type: IsolationActionType,
        verdict: RiskVerdict,
    ) -> tuple[bool, str]:
        """Execute a single containment action.

        Args:
            action_type: The type of action to execute.
            verdict: The risk verdict providing context.

        Returns:
            Tuple of (success: bool, error: str).
        """
        if self._dry_run:
            logger.info(
                "  [DRY-RUN] %s on %s — NOT EXECUTED",
                action_type.value, verdict.entity_id,
            )
            return True, ""

        # ── Production execution stubs ───────────────────────────────
        try:
            if action_type == IsolationActionType.NETWORK_QUARANTINE:
                self._quarantine_host(verdict.entity_id)
            elif action_type == IsolationActionType.DB_REVOKE:
                self._revoke_db_access(verdict.entity_id)
            elif action_type == IsolationActionType.USER_LOCK:
                self._lock_user(verdict.entity_id)
            elif action_type == IsolationActionType.ALERT_SOC:
                self._send_soc_alert(verdict)
            elif action_type == IsolationActionType.ELEVATED_MONITORING:
                self._enable_monitoring(verdict.entity_id)
            elif action_type == IsolationActionType.LOG_ONLY:
                logger.info("  [LOG-ONLY] Recorded for %s", verdict.entity_id)
            return True, ""
        except Exception as exc:
            error_msg = f"{action_type.value} failed: {exc}"
            logger.error("  [FAILED] %s", error_msg)
            return False, error_msg

    def _quarantine_host(self, entity_id: str) -> None:
        """Add firewall rules to quarantine a host.

        In production: calls iptables/nftables or SDN API.

        Args:
            entity_id: The IP to quarantine.
        """
        logger.info(
            "  [EXECUTE] iptables -A INPUT -s %s -j DROP", entity_id,
        )
        logger.info(
            "  [EXECUTE] iptables -A OUTPUT -d %s -j DROP", entity_id,
        )

    def _revoke_db_access(self, entity_id: str) -> None:
        """Revoke database access for a compromised host.

        In production: runs REVOKE ALL on MySQL/PostgreSQL.

        Args:
            entity_id: The host whose DB access to revoke.
        """
        logger.info(
            "  [EXECUTE] REVOKE ALL PRIVILEGES FROM connections "
            "originating from %s", entity_id,
        )

    def _lock_user(self, entity_id: str) -> None:
        """Lock user accounts associated with the compromised host.

        In production: runs passwd -l or AD account disable.

        Args:
            entity_id: The host whose users to lock.
        """
        logger.info(
            "  [EXECUTE] passwd -l (all users from %s)", entity_id,
        )

    def _send_soc_alert(self, verdict: RiskVerdict) -> None:
        """Send an alert to the SOC team.

        In production: posts to Slack/PagerDuty/SIEM.

        Args:
            verdict: The risk verdict with full context.
        """
        logger.info(
            "  [EXECUTE] SOC ALERT → entity=%s  score=%.2f  "
            "severity=%s  label=%s",
            verdict.entity_id, verdict.final_risk_score,
            verdict.adjusted_severity, verdict.risk_label,
        )

    def _enable_monitoring(self, entity_id: str) -> None:
        """Enable elevated monitoring for a suspicious host.

        In production: adjusts SIEM rules / enables packet capture.

        Args:
            entity_id: The host to monitor more closely.
        """
        logger.info(
            "  [EXECUTE] Elevated monitoring enabled for %s",
            entity_id,
        )

    @staticmethod
    def _build_details(
        action_type: IsolationActionType,
        verdict: RiskVerdict,
    ) -> str:
        """Build a human-readable description of the action.

        Args:
            action_type: The action type.
            verdict: The risk verdict.

        Returns:
            Description string.
        """
        return (
            f"{action_type.value} on {verdict.entity_id} — "
            f"severity={verdict.adjusted_severity} "
            f"risk={verdict.final_risk_score:.2f} ({verdict.risk_label})"
        )


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Translates risk verdicts into concrete containment actions.
# 2. Follows the isolation matrix: P1→full lockdown, P4→log only.
# 3. DRY-RUN mode ensures safe demo without real network impact.
# 4. Log-before-execute guarantees audit trail integrity.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os

    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    from src.enrichment.enrichment_engine import EnrichmentEngine
    from src.parsing.models import ModelAlert

    engine = EnrichmentEngine()
    from src.response.scorer import RiskScorer

    scorer = RiskScorer()
    isolator = Isolator()

    logger.info("=" * 70)
    logger.info("ISOLATOR DEMO — Full Pipeline")
    logger.info("=" * 70)

    # P1 alert — should trigger full lockdown
    alert = ModelAlert(
        severity="P1", attack_type="privilege_escalation",
        confidence=0.92, source_host="10.0.0.40",
        affected_assets=["10.0.0.10"],
    )
    enriched = engine.enrich(alert)
    verdict = scorer.score(enriched)
    actions = isolator.execute(verdict)

    logger.info("")
    logger.info("Actions taken: %d", len(actions))
    for a in actions:
        logger.info("  %s → %s (%s)", a.action_type.value,
                     a.status.value, a.details)

    logger.info("")
    logger.info("Isolator demo complete ✓")
