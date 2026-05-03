"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/reporting/legal_dz.py

Generates Algerian legal notification documents:
  a) CERT-DZ notification (deadline: T+24h) — Décret 20-05
  b) ANPDP notification (deadline: T+72h) — Loi 18-07

Each document is a structured Pydantic model that can be
serialized to JSON, rendered as PDF, or submitted via API.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from src.reporting.evidence_collector import EvidencePackage
from src.reporting.incident_analyzer import IncidentAnalysis
from src.reporting.regulatory_db import RegulatoryDB
from src.response.scorer import RiskVerdict

logger = logging.getLogger(__name__)


# ── CERT-DZ Notification ────────────────────────────────────────────
class CERTDZNotification(BaseModel):
    """Structured notification for CERT.dz per Décret 20-05.

    Attributes:
        notification_id: Unique identifier.
        generated_at: Generation timestamp.
        deadline: Absolute deadline for submission (T+24h).
        hours_remaining: Hours until deadline.
        organization_name: Reporting organization.
        contact_person: Name and role of contact.
        contact_email: Contact email.
        contact_phone: Contact phone.
        incident_id: AEGIS incident identifier.
        incident_timestamp: When the incident was detected.
        severity_level: P1-P4 severity.
        nature_of_breach: Description of the breach.
        attack_type: Technical attack classification.
        source_ip: Attacker IP address.
        affected_systems: List of affected systems.
        mitre_techniques: MITRE ATT&CK techniques observed.
        containment_measures: Actions taken to contain the incident.
        impact_assessment: CIA impact description.
        evidence_preservation: How evidence was preserved.
        regulatory_reference: Applicable law reference.
        penalties_for_attacker: Legal penalties applicable to the attacker.
        internal_services_to_notify: Internal departments to involve.
        legal_liability_risk: Risk of legal liability for the organization.
    """

    notification_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    deadline: str = Field(default="")
    hours_remaining: float = Field(default=24.0)

    # Organization
    organization_name: str = Field(default="[ORGANISATION]")
    contact_person: str = Field(default="[NOM DU RESPONSABLE]")
    contact_email: str = Field(default="[EMAIL]")
    contact_phone: str = Field(default="[TELEPHONE]")

    # Incident
    incident_id: str = Field(default="")
    incident_timestamp: str = Field(default="")
    severity_level: str = Field(default="P4")
    nature_of_breach: str = Field(default="")
    attack_type: str = Field(default="")
    source_ip: str = Field(default="")
    affected_systems: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    containment_measures: List[str] = Field(default_factory=list)
    impact_assessment: str = Field(default="")
    evidence_preservation: str = Field(default="")
    regulatory_reference: str = Field(
        default="Décret exécutif 20-05 relatif au dispositif national de sécurité des systèmes d'information",
    )
    penalties_for_attacker: str = Field(default="")
    internal_services_to_notify: List[str] = Field(default_factory=list)
    legal_liability_risk: str = Field(default="")


# ── ANPDP Notification ──────────────────────────────────────────────
class ANPDPNotification(BaseModel):
    """Structured notification for ANPDP per Loi 18-07.

    Attributes:
        notification_id: Unique identifier.
        generated_at: Generation timestamp.
        deadline: Absolute deadline for submission (T+72h).
        hours_remaining: Hours until deadline.
        organization_name: Reporting organization.
        contact_person: Primary contact.
        dpo_contact: Data Protection Officer contact.
        incident_id: AEGIS incident identifier.
        incident_timestamp: When the breach was discovered.
        nature_of_breach: Description of the data breach.
        affected_data_categories: Types of personal data affected.
        estimated_persons_affected: Number of individuals impacted.
        data_processing_purpose: Purpose of the data processing.
        likely_consequences: Probable consequences for data subjects.
        containment_measures: Actions taken.
        notification_to_subjects: Whether data subjects were notified.
        regulatory_reference: Applicable law reference.
        fines_for_non_compliance: Potential fines for not reporting.
        data_loss_risk_assessment: Assessment of data loss risks.
        penalties_for_attacker: Penalties applicable to the attacker.
        internal_services_to_notify: Internal departments to involve.
    """

    notification_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    deadline: str = Field(default="")
    hours_remaining: float = Field(default=72.0)

    # Organization
    organization_name: str = Field(default="[ORGANISATION]")
    contact_person: str = Field(default="[NOM DU RESPONSABLE]")
    dpo_contact: str = Field(default="[DPO - NOM ET CONTACT]")

    # Breach details
    incident_id: str = Field(default="")
    incident_timestamp: str = Field(default="")
    nature_of_breach: str = Field(default="")
    affected_data_categories: List[str] = Field(default_factory=list)
    estimated_persons_affected: int = Field(default=0)
    data_processing_purpose: str = Field(default="[BUT DU TRAITEMENT]")
    likely_consequences: str = Field(default="")
    containment_measures: List[str] = Field(default_factory=list)
    notification_to_subjects: bool = Field(default=False)
    regulatory_reference: str = Field(
        default="Loi 18-07 du 10 juin 2018 relative à la protection des personnes physiques "
                "dans le traitement des données à caractère personnel",
    )
    fines_for_non_compliance: str = Field(default="")
    data_loss_risk_assessment: str = Field(default="")
    penalties_for_attacker: str = Field(default="")
    internal_services_to_notify: List[str] = Field(default_factory=list)


class LegalDZGenerator:
    """Generates Algerian legal compliance documents.

    Produces two separate notifications:
      1. CERT-DZ (T+24h) — mandatory for all cyber incidents
      2. ANPDP (T+72h) — mandatory if personal data is involved
    """

    def __init__(self) -> None:
        self._reg_db = RegulatoryDB()
        logger.info("LegalDZGenerator ready")

    def generate_cert_dz(
        self,
        evidence: EvidencePackage,
        analysis: IncidentAnalysis,
        verdict: RiskVerdict,
    ) -> CERTDZNotification:
        """Generate CERT-DZ notification document.

        Args:
            evidence: Forensic evidence package.
            analysis: Incident analysis.
            verdict: Risk verdict.

        Returns:
            Structured CERT-DZ notification.
        """
        now = datetime.now(timezone.utc)
        deadline = now + timedelta(hours=24)

        containment_measures = [
            a.get("action_type", "unknown") + " — " + a.get("status", "unknown")
            for a in evidence.isolation_actions
        ]

        notification = CERTDZNotification(
            deadline=deadline.isoformat(),
            hours_remaining=24.0,
            incident_id=evidence.package_id,
            incident_timestamp=evidence.incident_timestamp,
            severity_level=verdict.adjusted_severity,
            nature_of_breach=(
                f"{analysis.attack_classification} — "
                f"{analysis.kill_chain_phase}"
            ),
            attack_type=analysis.attack_classification,
            source_ip=evidence.entity_id,
            affected_systems=[evidence.entity_id] + evidence.affected_assets,
            mitre_techniques=evidence.mitre_techniques,
            containment_measures=containment_measures,
            impact_assessment=analysis.impact.description,
            evidence_preservation=(
                f"AEGIS Evidence Package {evidence.package_id[:8]} — "
                f"{len(evidence.event_hashes)} event hashes preserved, "
                f"blockchain immutability pending (Phase 5)"
            ),
            penalties_for_attacker=self._assess_attacker_penalties(analysis),
            internal_services_to_notify=["Direction Générale", "Direction Juridique", "RSSI/CISO", "DPO"],
            legal_liability_risk=self._assess_legal_liability(analysis, verdict),
        )

        logger.info(
            "CERT-DZ notification generated — deadline=%s severity=%s",
            deadline.isoformat(), verdict.adjusted_severity,
        )
        return notification

    def generate_anpdp(
        self,
        evidence: EvidencePackage,
        analysis: IncidentAnalysis,
        verdict: RiskVerdict,
        affected_persons: int = 0,
        data_categories: Optional[List[str]] = None,
    ) -> ANPDPNotification:
        """Generate ANPDP notification document.

        Args:
            evidence: Forensic evidence package.
            analysis: Incident analysis.
            verdict: Risk verdict.
            affected_persons: Estimated number of affected individuals.
            data_categories: Categories of personal data compromised.

        Returns:
            Structured ANPDP notification.
        """
        now = datetime.now(timezone.utc)
        deadline = now + timedelta(hours=72)

        if data_categories is None:
            data_categories = self._infer_data_categories(analysis)

        containment_measures = [
            a.get("action_type", "unknown") + " — " + a.get("status", "unknown")
            for a in evidence.isolation_actions
        ]

        consequences = self._assess_consequences(analysis, evidence)

        notification = ANPDPNotification(
            deadline=deadline.isoformat(),
            hours_remaining=72.0,
            incident_id=evidence.package_id,
            incident_timestamp=evidence.incident_timestamp,
            nature_of_breach=(
                f"{analysis.attack_classification} avec impact potentiel "
                f"sur les données personnelles"
            ),
            affected_data_categories=data_categories,
            estimated_persons_affected=affected_persons,
            likely_consequences=consequences,
            containment_measures=containment_measures,
            fines_for_non_compliance=(
                "Amende de 20 000 DA à 200 000 DA et emprisonnement de 2 mois à 2 ans (Art. 47-54). "
                "Interdiction d'exercer possible en cas de négligence grave."
            ),
            data_loss_risk_assessment=analysis.data_at_risk,
            penalties_for_attacker=self._assess_attacker_penalties(analysis),
            internal_services_to_notify=["DPO", "Direction Juridique", "Service Communication"],
        )

        logger.info(
            "ANPDP notification generated — deadline=%s persons=%d categories=%s",
            deadline.isoformat(), affected_persons, data_categories,
        )
        return notification

    def _infer_data_categories(self, analysis: IncidentAnalysis) -> List[str]:
        """Infer affected data categories from the attack analysis.

        Args:
            analysis: Incident analysis.

        Returns:
            List of data category strings.
        """
        categories = []
        data_risk = analysis.data_at_risk.lower()

        if any(w in data_risk for w in ("credential", "password", "key")):
            categories.append("Identifiants et mots de passe")
        if any(w in data_risk for w in ("database", "pii", "personal")):
            categories.append("Données à caractère personnel")
        if any(w in data_risk for w in ("full", "all data")):
            categories.extend([
                "Données à caractère personnel",
                "Données professionnelles",
            ])
        if not categories:
            categories.append("Catégories à déterminer après investigation")
        return categories

    def _assess_consequences(
        self, analysis: IncidentAnalysis, evidence: EvidencePackage,
    ) -> str:
        """Assess likely consequences for data subjects.

        Args:
            analysis: Incident analysis.
            evidence: Evidence package.

        Returns:
            Consequences description string.
        """
        if analysis.impact.confidentiality >= 8:
            return (
                "Risque élevé: possibilité d'usurpation d'identité, "
                "accès non autorisé aux comptes des personnes concernées, "
                "divulgation de données confidentielles."
            )
        if analysis.impact.confidentiality >= 5:
            return (
                "Risque modéré: exposition potentielle de données "
                "personnelles, surveillance recommandée pour les personnes concernées."
            )
        return (
            "Risque faible: impact limité sur les données personnelles. "
            "Investigation en cours pour confirmer l'étendue."
        )

    def _assess_attacker_penalties(self, analysis: IncidentAnalysis) -> str:
        """Assess legal penalties for the attacker under Algerian law."""
        lower_class = analysis.attack_classification.lower()
        if "escalation" in lower_class or "exfil" in lower_class or "injection" in lower_class:
            return (
                "Emprisonnement de 6 mois à 3 ans et amende de 500 000 DA à 2 000 000 DA "
                "(Loi 09-04, Art. 394bis). Peines doublées si atteinte à la défense nationale "
                "ou aux données de l'État."
            )
        return (
            "Emprisonnement de 3 mois à 1 an et amende de 50 000 DA à 100 000 DA "
            "(Loi 09-04) pour accès frauduleux à un système de traitement automatisé."
        )

    def _assess_legal_liability(self, analysis: IncidentAnalysis, verdict: RiskVerdict) -> str:
        """Assess legal liability risk for the organization."""
        if analysis.impact.confidentiality >= 7 or verdict.adjusted_severity in ("P1",):
            return (
                "Risque ÉLEVÉ: Possibilité de mise en cause de la responsabilité pénale du "
                "dirigeant (Loi 09-04, Art. 11) si une négligence grave dans la sécurisation "
                "des systèmes est prouvée. Déclaration immédiate vitale."
            )
        return (
            "Risque MODÉRÉ: Le défaut de notification au CERT-DZ dans les délais impartis "
            "expose l'entité à une amende allant de 1 000 000 DA à 5 000 000 DA."
        )


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Legal compliance: Algeria requires CERT-DZ (T+24h) and ANPDP (T+72h).
# 2. Structured output (Pydantic models) for API/PDF rendering.
# 3. Auto-infers data categories and consequences from analysis.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os
    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    from src.enrichment.enrichment_engine import EnrichmentEngine
    from src.parsing.models import ModelAlert
    from src.response.scorer import RiskScorer
    from src.response.isolator import Isolator
    from src.reporting.evidence_collector import EvidenceCollector
    from src.reporting.incident_analyzer import IncidentAnalyzer

    alert = ModelAlert(
        severity="P1", attack_type="privilege_escalation",
        confidence=0.92, source_host="10.0.0.40",
        affected_assets=["10.0.0.10"], model_source="DeepLog",
    )

    enriched = EnrichmentEngine().enrich(alert)
    verdict = RiskScorer().score(enriched)
    actions = Isolator(dry_run=True).execute(verdict)
    evidence = EvidenceCollector().collect(enriched, verdict, actions)
    analysis = IncidentAnalyzer().analyze(evidence)
    legal = LegalDZGenerator()

    cert = legal.generate_cert_dz(evidence, analysis, verdict)
    anpdp = legal.generate_anpdp(evidence, analysis, verdict, affected_persons=150)

    logger.info("CERT-DZ: deadline=%s severity=%s", cert.deadline, cert.severity_level)
    logger.info("ANPDP: deadline=%s persons=%d", anpdp.deadline, anpdp.estimated_persons_affected)
    logger.info("LegalDZ demo complete ✓")
