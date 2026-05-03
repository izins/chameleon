"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/reporting/report_generator.py

Assembles a complete incident report from all Phase 4 components.
Produces a structured IncidentReport that can be rendered as PDF,
JSON, or displayed in a dashboard.

Orchestrates:
  1. EvidenceCollector → forensic evidence
  2. IncidentAnalyzer → forensic analysis
  3. PlaybookGenerator → IR steps
  4. LegalDZGenerator → CERT-DZ + ANPDP notifications
  5. RegulatoryDB → applicable regulations
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from src.config.settings import settings
from src.enrichment.enrichment_engine import EnrichedAlert
from src.reporting.evidence_collector import EvidenceCollector, EvidencePackage
from src.reporting.incident_analyzer import IncidentAnalysis, IncidentAnalyzer
from src.reporting.legal_dz import (
    ANPDPNotification,
    CERTDZNotification,
    LegalDZGenerator,
)
from src.blockchain.aegis_chain import AegisChain
from src.reporting.playbook import Playbook, PlaybookGenerator
from src.reporting.regulatory_db import RegulatoryDB, RegulatoryMatch
from src.response.isolation_log import IsolationAction
from src.response.scorer import RiskVerdict

logger = logging.getLogger(__name__)


class IncidentReport(BaseModel):
    """Complete incident report combining all Phase 4 outputs.

    Attributes:
        report_id: Unique report identifier.
        generated_at: Report generation timestamp.
        entity_id: Primary entity under investigation.
        severity: Final adjusted severity.
        risk_score: Final composite risk score.
        risk_label: Human-readable risk label.
        evidence: Complete forensic evidence package.
        analysis: Forensic incident analysis.
        playbook: Incident response playbook.
        cert_dz_notification: CERT-DZ legal document.
        anpdp_notification: ANPDP legal document.
        applicable_regulations: Matched regulations.
        executive_summary: One-paragraph summary for executives.
        technical_summary: Detailed technical summary.
    """

    report_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    entity_id: str = Field(default="")
    severity: str = Field(default="P4")
    risk_score: float = Field(default=0.0)
    risk_label: str = Field(default="")

    # Phase 4 components
    evidence: EvidencePackage = Field(default_factory=EvidencePackage)
    analysis: IncidentAnalysis = Field(default_factory=IncidentAnalysis)
    playbook: Playbook = Field(default_factory=Playbook)
    cert_dz_notification: CERTDZNotification = Field(
        default_factory=CERTDZNotification,
    )
    anpdp_notification: ANPDPNotification = Field(
        default_factory=ANPDPNotification,
    )
    applicable_regulations: List[dict] = Field(default_factory=list)

    # Summaries
    executive_summary: str = Field(default="")
    technical_summary: str = Field(default="")


class ReportGenerator:
    """Orchestrates the full report generation pipeline.

    Assembles evidence, analysis, playbook, and legal documents
    into a single IncidentReport.

    Args:
        evidence_collector: EvidenceCollector instance.
        incident_analyzer: IncidentAnalyzer instance.
        playbook_generator: PlaybookGenerator instance.
        legal_generator: LegalDZGenerator instance.
        regulatory_db: RegulatoryDB instance.
    """

    def __init__(
        self,
        evidence_collector: Optional[EvidenceCollector] = None,
        incident_analyzer: Optional[IncidentAnalyzer] = None,
        playbook_generator: Optional[PlaybookGenerator] = None,
        legal_generator: Optional[LegalDZGenerator] = None,
        regulatory_db: Optional[RegulatoryDB] = None,
    ) -> None:
        self._collector = evidence_collector or EvidenceCollector()
        self._analyzer = incident_analyzer or IncidentAnalyzer()
        self._playbook = playbook_generator or PlaybookGenerator()
        self._legal = legal_generator or LegalDZGenerator()
        self._reg_db = regulatory_db or RegulatoryDB()
        self._blockchain = AegisChain()
        logger.info("ReportGenerator ready")

    def generate(
        self,
        enriched: EnrichedAlert,
        verdict: RiskVerdict,
        actions: List[IsolationAction],
        raw_logs: Optional[List[str]] = None,
        template_sequence: Optional[List[int]] = None,
        total_suspicion: float = 0.0,
        affected_persons: int = 0,
    ) -> IncidentReport:
        """Generate a complete incident report.

        Args:
            enriched: Enriched alert from Phase 2.
            verdict: Risk verdict from Phase 3.
            actions: Isolation actions from Phase 3.
            raw_logs: Original log lines.
            template_sequence: Drain3 template sequence.
            total_suspicion: UEBA behavioral score.
            affected_persons: Estimated affected individuals.

        Returns:
            A complete IncidentReport.
        """
        # ── 1. Collect evidence ──────────────────────────────────────
        evidence = self._collector.collect(
            enriched, verdict, actions,
            raw_logs=raw_logs,
            template_sequence=template_sequence,
            total_suspicion=total_suspicion,
        )

        # ── 2. Analyze incident ──────────────────────────────────────
        analysis = self._analyzer.analyze(evidence)

        # ── 3. Generate playbook ─────────────────────────────────────
        playbook = self._playbook.generate(evidence, analysis, verdict)

        # ── 4. Legal documents ───────────────────────────────────────
        cert_dz = self._legal.generate_cert_dz(evidence, analysis, verdict)
        anpdp = self._legal.generate_anpdp(
            evidence, analysis, verdict,
            affected_persons=affected_persons,
        )

        # ── 5. Regulatory matching ───────────────────────────────────
        regulations = self._reg_db.get_applicable(
            attack_type=enriched.original_alert.attack_type,
            data_categories=["personal_data"],
            jurisdictions=["Algeria"],
        )
        reg_dicts = [
            {
                "reg_id": m.regulation.reg_id,
                "name": m.regulation.name,
                "deadline_hours": m.deadline_hours,
                "urgency": m.urgency,
                "penalty": m.regulation.penalty_description[:100],
            }
            for m in regulations
        ]

        # ── 6. Generate summaries ────────────────────────────────────
        executive_summary = self._generate_executive_summary(
            evidence, analysis, verdict,
        )
        technical_summary = self._generate_technical_summary(
            evidence, analysis, verdict, playbook,
        )

        report = IncidentReport(
            entity_id=evidence.entity_id,
            severity=verdict.adjusted_severity,
            risk_score=verdict.final_risk_score,
            risk_label=verdict.risk_label,
            evidence=evidence,
            analysis=analysis,
            playbook=playbook,
            cert_dz_notification=cert_dz,
            anpdp_notification=anpdp,
            applicable_regulations=reg_dicts,
            executive_summary=executive_summary,
            technical_summary=technical_summary,
        )

        # ── 7. Persist report ────────────────────────────────────────
        self._persist_report(report)

        # ── 8. Anchor to Blockchain (Phase 5) ────────────────────────
        tx_id = self._blockchain.anchor_incident_report(report)

        logger.info(
            "INCIDENT REPORT GENERATED — %s entity=%s severity=%s "
            "risk=%.2f steps=%d regulations=%d tx_id=%s",
            report.report_id[:8], report.entity_id,
            report.severity, report.risk_score,
            playbook.total_steps, len(reg_dicts),
            tx_id[:8],
        )
        return report

    def _generate_executive_summary(
        self,
        evidence: EvidencePackage,
        analysis: IncidentAnalysis,
        verdict: RiskVerdict,
    ) -> str:
        """Generate a one-paragraph summary for executives.

        Args:
            evidence: Evidence package.
            analysis: Incident analysis.
            verdict: Risk verdict.

        Returns:
            Executive summary string.
        """
        return (
            f"On {evidence.incident_timestamp}, AEGIS detected a "
            f"{analysis.attack_classification} incident targeting "
            f"{evidence.entity_id}. The attack was classified as "
            f"{verdict.adjusted_severity} with a risk score of "
            f"{evidence.risk_score:.2f}/10 ({evidence.risk_label}). "
            f"{len(evidence.isolation_actions)} containment actions were "
            f"executed. {len(evidence.affected_assets)} additional assets "
            f"were identified as affected. "
            f"MITRE ATT&CK techniques: {', '.join(evidence.mitre_techniques)}. "
            f"Regulatory notifications (CERT-DZ T+24h, ANPDP T+72h) have "
            f"been generated and require immediate submission."
        )

    def _generate_technical_summary(
        self,
        evidence: EvidencePackage,
        analysis: IncidentAnalysis,
        verdict: RiskVerdict,
        playbook: Playbook,
    ) -> str:
        """Generate a detailed technical summary.

        Args:
            evidence: Evidence package.
            analysis: Incident analysis.
            verdict: Risk verdict.
            playbook: Generated playbook.

        Returns:
            Technical summary string.
        """
        lines = [
            f"INCIDENT TECHNICAL SUMMARY — {evidence.package_id[:8]}",
            f"Entity: {evidence.entity_id}",
            f"Classification: {analysis.attack_classification}",
            f"Kill Chain: {analysis.kill_chain_phase}",
            f"Risk Score: {evidence.risk_score:.2f} ({evidence.risk_label})",
            "",
            "── ASSET CONTEXT ──",
            f"Asset Type: {getattr(verdict, 'asset_type', 'unknown')}",
            f"Asset Role: {getattr(verdict, 'asset_role', 'unknown')}",
            f"Business Impact: {getattr(verdict, 'business_impact', 'unknown')}",
            f"Data Classification: {getattr(verdict, 'data_classification', 'unknown')}",
            "",
            "── 5D RISK DECOMPOSITION ──",
            f"D1 Vulnerability (CVSS+EPSS+KEV): {getattr(verdict, 'vuln_component', 0):.2f}",
            f"D2 Asset Criticality:             {getattr(verdict, 'criticality_component', 0):.2f}",
            f"D3 Propagation Risk:              {getattr(verdict, 'propagation_component', 0):.2f}",
            f"D4 Entity History:                {getattr(verdict, 'history_component', 0):.2f}",
            f"D5 Data Sensitivity:              {getattr(verdict, 'data_component', 0):.2f}",
            f"EPSS Score: {getattr(verdict, 'epss_score', 0):.2f}",
            f"CISA KEV: {'YES — actively exploited' if getattr(verdict, 'is_kev', False) else 'No'}",
            f"Sources: {getattr(verdict, 'scoring_sources', [])}",
            "",
            "── ENRICHMENT ──",
            f"CVSS Max: {evidence.max_cvss}",
            f"MITRE: {', '.join(evidence.mitre_techniques)}",
            f"CVEs: {', '.join(evidence.cve_ids)}",
            f"Entity History: score={evidence.entity_cumulative_score:.1f} "
            f"attacks={evidence.entity_attack_history}",
            f"UEBA Suspicion: {evidence.total_suspicion:.1f}",
            f"Template Sequence: {evidence.template_sequence}",
            f"Affected Assets: {evidence.affected_assets}",
            "",
            "── ANALYSIS ──",
            f"Root Cause: {analysis.root_cause_hypothesis}",
            f"Impact: C={analysis.impact.confidentiality} "
            f"I={analysis.impact.integrity} A={analysis.impact.availability}",
            f"Playbook: {playbook.total_steps} steps, "
            f"~{playbook.estimated_total_minutes} minutes",
        ]
        return "\n".join(lines)

    def _persist_report(self, report: IncidentReport) -> None:
        """Save the report to disk.

        Args:
            report: The incident report to persist.
        """
        try:
            output_dir = Path(settings.demo_output_file).parent / "reports"
            output_dir.mkdir(parents=True, exist_ok=True)
            path = output_dir / f"report_{report.report_id[:8]}.json"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(report.model_dump_json(indent=2))
            logger.info("Report persisted → %s", path)
        except Exception as exc:
            logger.warning("Failed to persist report: %s", exc)


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Orchestrates all Phase 4 components into a single IncidentReport.
# 2. Generates executive + technical summaries automatically.
# 3. Persists reports for Phase 5 blockchain integration.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os
    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    from src.enrichment.enrichment_engine import EnrichmentEngine
    from src.parsing.models import ModelAlert
    from src.response.scorer import RiskScorer
    from src.response.isolator import Isolator

    alert = ModelAlert(
        severity="P1", attack_type="privilege_escalation",
        confidence=0.92, source_host="10.0.0.40",
        affected_assets=["10.0.0.10"], model_source="DeepLog",
        raw_sequence=[5, 5, 5, 22, 11],
    )

    enriched = EnrichmentEngine().enrich(alert)
    verdict = RiskScorer().score(enriched)
    actions = Isolator(dry_run=True).execute(verdict)

    generator = ReportGenerator()
    report = generator.generate(
        enriched, verdict, actions, affected_persons=150,
    )

    logger.info("Report: %s", report.report_id[:8])
    logger.info("  Executive: %s", report.executive_summary[:100])
    logger.info("  Playbook: %d steps", report.playbook.total_steps)
    logger.info("  Regulations: %d", len(report.applicable_regulations))
    logger.info("ReportGenerator demo complete ✓")
