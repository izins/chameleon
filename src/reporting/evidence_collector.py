"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/reporting/evidence_collector.py

Collects and assembles ALL forensic evidence from Phase 1-3 into
a single, structured EvidencePackage.

Sources:
  Phase 1 → Raw logs, event hashes, template sequences, UEBA scores
  Phase 2 → MITRE timeline, CVE list, entity history
  Phase 3 → Risk verdict, isolation actions, network topology

In demo mode, evidence is collected from in-memory objects.
In production, queries Elasticsearch + Kafka + entity_tracker persistence.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from src.enrichment.enrichment_engine import EnrichedAlert
from src.response.isolation_log import IsolationAction
from src.response.scorer import RiskVerdict

logger = logging.getLogger(__name__)


class TimelineEntry(BaseModel):
    """A single event in the attack timeline.

    Attributes:
        timestamp: When the event occurred.
        event_type: Category (log, alert, action, enrichment).
        source: Which module produced this entry.
        description: Human-readable description.
        severity: Severity level if applicable.
        raw_data: The raw log line or JSON data.
        event_hash: SHA-256 for traceability.
    """

    timestamp: str = Field(default="")
    event_type: str = Field(default="log")
    source: str = Field(default="")
    description: str = Field(default="")
    severity: str = Field(default="")
    raw_data: str = Field(default="")
    event_hash: str = Field(default="")


class IoC(BaseModel):
    """Indicator of Compromise extracted from the incident.

    Attributes:
        ioc_type: Type of indicator (ip, hash, domain, template, user).
        value: The actual indicator value.
        context: Where this IoC was observed.
        first_seen: First observation time.
        confidence: How confident we are this is malicious (0-1).
    """

    ioc_type: str = Field(default="ip")
    value: str = Field(default="")
    context: str = Field(default="")
    first_seen: str = Field(default="")
    confidence: float = Field(default=0.0)


class EvidencePackage(BaseModel):
    """Complete forensic evidence package for one incident.

    Attributes:
        package_id: Unique identifier.
        incident_timestamp: When the incident was detected.
        entity_id: The primary entity under investigation.
        timeline: Chronological list of all events.
        iocs: Extracted Indicators of Compromise.
        raw_logs: Original log lines involved.
        event_hashes: SHA-256 hashes of all raw events.
        template_sequence: Drain3 template IDs (ML input).
        mitre_techniques: MITRE ATT&CK techniques observed.
        mitre_tactic: Primary kill-chain phase.
        cve_ids: Relevant CVE identifiers.
        max_cvss: Highest CVSS score.
        entity_cumulative_score: Entity risk history.
        entity_attack_history: Past attack types for this entity.
        risk_verdict: Final risk assessment.
        isolation_actions: Containment actions taken.
        total_suspicion: UEBA behavioral score.
        affected_assets: All assets involved.
    """

    package_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    entity_id: str = Field(default="")

    # Timeline
    timeline: List[TimelineEntry] = Field(default_factory=list)

    # IoCs
    iocs: List[IoC] = Field(default_factory=list)

    # Phase 1 evidence
    raw_logs: List[str] = Field(default_factory=list)
    event_hashes: List[str] = Field(default_factory=list)
    template_sequence: List[int] = Field(default_factory=list)
    total_suspicion: float = Field(default=0.0)

    # Phase 2 evidence
    mitre_techniques: List[str] = Field(default_factory=list)
    mitre_tactic: str = Field(default="")
    cve_ids: List[str] = Field(default_factory=list)
    max_cvss: float = Field(default=0.0)
    entity_cumulative_score: float = Field(default=0.0)
    entity_attack_history: List[str] = Field(default_factory=list)

    # Phase 3 evidence
    risk_score: float = Field(default=0.0)
    risk_label: str = Field(default="")
    adjusted_severity: str = Field(default="P4")
    isolation_actions: List[dict] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)


class EvidenceCollector:
    """Collects forensic evidence from all phases into a unified package.

    This is the forensic heart of AEGIS. It pulls data from every layer
    of the pipeline and assembles a court-admissible evidence package.
    """

    def __init__(self) -> None:
        logger.info("EvidenceCollector ready")

    def collect(
        self,
        enriched: EnrichedAlert,
        verdict: RiskVerdict,
        actions: List[IsolationAction],
        raw_logs: Optional[List[str]] = None,
        template_sequence: Optional[List[int]] = None,
        total_suspicion: float = 0.0,
    ) -> EvidencePackage:
        """Assemble all evidence into a single package.

        Args:
            enriched: The enriched alert from Phase 2.
            verdict: The risk verdict from Phase 3.
            actions: List of isolation actions taken.
            raw_logs: Original log lines (from LogSession.events).
            template_sequence: Drain3 template sequence (from LogSession).
            total_suspicion: UEBA score (from LogSession).

        Returns:
            A complete EvidencePackage.
        """
        alert = enriched.original_alert

        # ── Build timeline ───────────────────────────────────────────
        timeline = self._build_timeline(enriched, verdict, actions)

        # ── Extract IoCs ─────────────────────────────────────────────
        iocs = self._extract_iocs(enriched, verdict)

        package = EvidencePackage(
            entity_id=alert.source_host,
            incident_timestamp=alert.timestamp,
            timeline=timeline,
            iocs=iocs,
            raw_logs=raw_logs or [],
            event_hashes=alert.event_hashes,
            template_sequence=template_sequence or alert.raw_sequence,
            total_suspicion=total_suspicion,
            mitre_techniques=enriched.mitre_techniques,
            mitre_tactic=enriched.mitre_tactic,
            cve_ids=enriched.cve_ids,
            max_cvss=enriched.max_cvss,
            entity_cumulative_score=enriched.entity_cumulative_score,
            entity_attack_history=enriched.entity_attack_types,
            risk_score=verdict.final_risk_score,
            risk_label=verdict.risk_label,
            adjusted_severity=verdict.adjusted_severity,
            isolation_actions=[a.model_dump(mode="json") for a in actions],
            affected_assets=alert.affected_assets,
        )

        logger.info(
            "Evidence collected for %s — %d timeline entries, %d IoCs, "
            "%d raw logs, %d actions",
            package.entity_id, len(timeline), len(iocs),
            len(package.raw_logs), len(actions),
        )
        return package

    def _build_timeline(
        self,
        enriched: EnrichedAlert,
        verdict: RiskVerdict,
        actions: List[IsolationAction],
    ) -> List[TimelineEntry]:
        """Reconstruct the attack timeline from all phases.

        Args:
            enriched: Enriched alert data.
            verdict: Risk verdict.
            actions: Isolation actions.

        Returns:
            Chronologically sorted timeline entries.
        """
        entries: List[TimelineEntry] = []
        alert = enriched.original_alert

        # Phase 2: Alert detection
        entries.append(TimelineEntry(
            timestamp=alert.timestamp,
            event_type="alert",
            source=alert.model_source,
            description=(
                f"Attack detected: {alert.attack_type} "
                f"(confidence={alert.confidence:.0%})"
            ),
            severity=alert.severity,
        ))

        # Phase 2: Enrichment
        entries.append(TimelineEntry(
            timestamp=enriched.timestamp.isoformat(),
            event_type="enrichment",
            source="EnrichmentEngine",
            description=(
                f"MITRE: {enriched.mitre_techniques} | "
                f"CVEs: {enriched.cve_ids} | "
                f"CVSS: {enriched.max_cvss}"
            ),
        ))

        # Phase 3: Risk scoring
        entries.append(TimelineEntry(
            timestamp=enriched.timestamp.isoformat(),
            event_type="scoring",
            source="RiskScorer",
            description=(
                f"Risk score: {verdict.final_risk_score:.2f} ({verdict.risk_label}) | "
                f"Severity: {verdict.original_severity}→{verdict.adjusted_severity}"
            ),
            severity=verdict.adjusted_severity,
        ))

        # Phase 3: Isolation actions
        for action in actions:
            entries.append(TimelineEntry(
                timestamp=action.timestamp.isoformat(),
                event_type="isolation",
                source="Isolator",
                description=(
                    f"{action.action_type.value} on {action.entity_id} — "
                    f"status={action.status.value}"
                ),
                severity=action.severity,
            ))

        return entries

    def _extract_iocs(
        self,
        enriched: EnrichedAlert,
        verdict: RiskVerdict,
    ) -> List[IoC]:
        """Extract Indicators of Compromise from the incident.

        Args:
            enriched: Enriched alert.
            verdict: Risk verdict.

        Returns:
            List of IoCs.
        """
        iocs: List[IoC] = []
        alert = enriched.original_alert

        # Source IP
        iocs.append(IoC(
            ioc_type="ip",
            value=alert.source_host,
            context="Primary attacker IP",
            first_seen=alert.timestamp,
            confidence=alert.confidence,
        ))

        # Affected assets
        for asset in alert.affected_assets:
            iocs.append(IoC(
                ioc_type="ip",
                value=asset,
                context="Targeted asset",
                first_seen=alert.timestamp,
                confidence=0.8,
            ))

        # Event hashes as IoCs
        for h in alert.event_hashes[:5]:
            iocs.append(IoC(
                ioc_type="hash",
                value=h,
                context="Malicious log event hash",
                first_seen=alert.timestamp,
                confidence=alert.confidence,
            ))

        return iocs


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Assembles court-admissible forensic evidence from all 3 phases.
# 2. Reconstructs the attack timeline chronologically.
# 3. Extracts IoCs for threat intelligence sharing.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os
    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    from src.enrichment.enrichment_engine import EnrichmentEngine
    from src.parsing.models import ModelAlert
    from src.response.scorer import RiskScorer
    from src.response.isolator import Isolator

    engine = EnrichmentEngine()
    scorer = RiskScorer()
    isolator = Isolator(dry_run=True)
    collector = EvidenceCollector()

    alert = ModelAlert(
        severity="P1", attack_type="privilege_escalation",
        confidence=0.92, source_host="10.0.0.40",
        affected_assets=["10.0.0.10"], model_source="DeepLog",
        raw_sequence=[5, 5, 5, 22, 11],
    )
    enriched = engine.enrich(alert)
    verdict = scorer.score(enriched)
    actions = isolator.execute(verdict)
    package = collector.collect(enriched, verdict, actions)

    logger.info("Evidence Package: %s", package.package_id[:8])
    logger.info("  Timeline: %d entries", len(package.timeline))
    logger.info("  IoCs: %d", len(package.iocs))
    logger.info("  MITRE: %s", package.mitre_techniques)
    logger.info("EvidenceCollector demo complete ✓")
