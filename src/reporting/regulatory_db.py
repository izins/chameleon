"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/reporting/regulatory_db.py

Database of worldwide and Algerian cybersecurity regulations.

Provides:
  - Notification deadlines per regulation
  - Required report fields per authority
  - Penalty information for non-compliance
  - Automatic matching of incident type → applicable regulations

Regulations covered:
  Algeria:
    - Décret exécutif 20-05 (CERT-DZ, Agence de Sécurité des SI)
    - Loi 18-07 (Protection des données personnelles, ANPDP)
    - Loi 09-04 (Cybercriminalité)
  International:
    - GDPR (EU — if Algerian entity processes EU data)
    - NIS2 Directive (EU critical infrastructure)
    - NIST CSF (US framework, advisory)
    - ISO 27001 (International standard)
    - PCI-DSS (Payment card data)
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class Regulation(BaseModel):
    """A cybersecurity regulation or framework.

    Attributes:
        reg_id: Unique identifier.
        name: Full name of the regulation.
        jurisdiction: Country or region.
        authority: Responsible body.
        notification_deadline_hours: Hours to notify after discovery.
        mandatory: Whether notification is legally mandatory.
        penalty_description: Penalties for non-compliance.
        required_fields: Fields that must appear in the notification.
        applies_to: Data categories that trigger this regulation.
        reference_url: Official documentation URL.
    """

    reg_id: str = Field(default="")
    name: str = Field(default="")
    jurisdiction: str = Field(default="")
    authority: str = Field(default="")
    notification_deadline_hours: int = Field(default=72)
    mandatory: bool = Field(default=True)
    penalty_description: str = Field(default="")
    required_fields: List[str] = Field(default_factory=list)
    applies_to: List[str] = Field(default_factory=list)
    reference_url: str = Field(default="")


class RegulatoryMatch(BaseModel):
    """Result of matching an incident to applicable regulations.

    Attributes:
        regulation: The matched regulation.
        deadline_hours: Hours remaining to notify.
        urgency: Urgency label (IMMEDIATE, URGENT, STANDARD).
        missing_fields: Fields we still need to collect.
    """

    regulation: Regulation
    deadline_hours: int = Field(default=72)
    urgency: str = Field(default="STANDARD")
    missing_fields: List[str] = Field(default_factory=list)


# ── Algerian Regulations ────────────────────────────────────────────
_REG_CERT_DZ = Regulation(
    reg_id="DZ-CERT",
    name="Décret exécutif 20-05 — Notification au CERT.dz",
    jurisdiction="Algeria",
    authority="CERT.dz (Centre de Veille, Détection et Réponse)",
    notification_deadline_hours=24,
    mandatory=True,
    penalty_description=(
        "Amende de 1 000 000 DA à 5 000 000 DA pour défaut de notification. "
        "Responsabilité pénale du dirigeant (Loi 09-04, Art. 11)."
    ),
    required_fields=[
        "incident_id", "timestamp", "nature_of_breach",
        "affected_systems", "source_ip", "attack_type",
        "containment_measures_taken", "contact_person",
        "organization_name", "severity_level",
    ],
    applies_to=["all_incidents"],
    reference_url="https://www.cert.dz/",
)

_REG_ANPDP = Regulation(
    reg_id="DZ-ANPDP",
    name="Loi 18-07 — Protection des données personnelles (ANPDP)",
    jurisdiction="Algeria",
    authority="ANPDP (Autorité Nationale de Protection des Données Personnelles)",
    notification_deadline_hours=72,
    mandatory=True,
    penalty_description=(
        "Emprisonnement de 2 mois à 2 ans et amende de 20 000 DA "
        "à 200 000 DA (Loi 18-07, Art. 47-54). "
        "Interdiction d'exercer pour les cas graves."
    ),
    required_fields=[
        "incident_id", "timestamp", "nature_of_breach",
        "affected_data_categories", "estimated_persons_affected",
        "containment_measures_taken", "contact_person",
        "dpo_contact", "data_processing_purpose",
    ],
    applies_to=["personal_data", "pii", "credentials", "health_data"],
    reference_url="https://www.joradp.dz/",
)

_REG_LOI_09_04 = Regulation(
    reg_id="DZ-CYBER",
    name="Loi 09-04 — Règles relatives à la cybercriminalité",
    jurisdiction="Algeria",
    authority="Parquet / Gendarmerie Nationale / DGSN",
    notification_deadline_hours=48,
    mandatory=True,
    penalty_description=(
        "Emprisonnement de 6 mois à 3 ans (Art. 394bis du Code pénal). "
        "Aggravation si atteinte aux données de l'État ou défense nationale."
    ),
    required_fields=[
        "incident_id", "timestamp", "nature_of_breach",
        "evidence_preservation_method", "source_ip",
        "attack_type", "affected_systems",
    ],
    applies_to=["intrusion", "data_exfil", "privilege_escalation"],
    reference_url="https://www.joradp.dz/",
)

# ── International Regulations ───────────────────────────────────────
_REG_GDPR = Regulation(
    reg_id="EU-GDPR",
    name="General Data Protection Regulation (GDPR)",
    jurisdiction="European Union",
    authority="National DPA (e.g., CNIL for France)",
    notification_deadline_hours=72,
    mandatory=True,
    penalty_description=(
        "Up to €20M or 4% of global annual turnover, "
        "whichever is higher (Art. 83)."
    ),
    required_fields=[
        "incident_id", "timestamp", "nature_of_breach",
        "affected_data_categories", "estimated_persons_affected",
        "likely_consequences", "containment_measures_taken",
        "dpo_contact",
    ],
    applies_to=["personal_data", "pii", "eu_data"],
    reference_url="https://gdpr.eu/",
)

_REG_NIS2 = Regulation(
    reg_id="EU-NIS2",
    name="NIS2 Directive — Network and Information Security",
    jurisdiction="European Union",
    authority="National CSIRT",
    notification_deadline_hours=24,
    mandatory=True,
    penalty_description=(
        "Up to €10M or 2% of global turnover for essential entities. "
        "Management liability for non-compliance."
    ),
    required_fields=[
        "incident_id", "timestamp", "severity_level",
        "affected_services", "cross_border_impact",
        "containment_measures_taken",
    ],
    applies_to=["critical_infrastructure", "essential_services"],
    reference_url="https://digital-strategy.ec.europa.eu/en/policies/nis2-directive",
)

_REG_PCI_DSS = Regulation(
    reg_id="INTL-PCI",
    name="PCI-DSS v4.0 — Payment Card Industry Data Security Standard",
    jurisdiction="International",
    authority="PCI Security Standards Council",
    notification_deadline_hours=24,
    mandatory=True,
    penalty_description=(
        "Fines of $5,000 to $100,000 per month of non-compliance. "
        "Loss of card processing privileges."
    ),
    required_fields=[
        "incident_id", "timestamp", "cardholder_data_exposed",
        "pan_count", "containment_measures_taken",
        "forensic_investigator_assigned",
    ],
    applies_to=["payment_data", "cardholder_data"],
    reference_url="https://www.pcisecuritystandards.org/",
)

_REG_NIST = Regulation(
    reg_id="US-NIST",
    name="NIST Cybersecurity Framework v2.0",
    jurisdiction="United States (advisory)",
    authority="NIST",
    notification_deadline_hours=0,
    mandatory=False,
    penalty_description="Advisory framework — no direct penalties.",
    required_fields=[
        "incident_id", "timestamp", "attack_type", "impact_assessment",
    ],
    applies_to=["all_incidents"],
    reference_url="https://www.nist.gov/cyberframework",
)

# ── Registry ────────────────────────────────────────────────────────
ALL_REGULATIONS: List[Regulation] = [
    _REG_CERT_DZ, _REG_ANPDP, _REG_LOI_09_04,
    _REG_GDPR, _REG_NIS2, _REG_PCI_DSS, _REG_NIST,
]


class RegulatoryDB:
    """Database of cybersecurity regulations for compliance matching.

    Automatically determines which regulations apply to a given
    incident based on data categories and attack type.
    """

    def __init__(self) -> None:
        self._regulations = {r.reg_id: r for r in ALL_REGULATIONS}
        logger.info(
            "RegulatoryDB ready — %d regulations loaded", len(self._regulations),
        )

    def get_applicable(
        self,
        attack_type: str = "",
        data_categories: Optional[List[str]] = None,
        jurisdictions: Optional[List[str]] = None,
    ) -> List[RegulatoryMatch]:
        """Find all regulations applicable to this incident.

        Args:
            attack_type: The type of attack detected.
            data_categories: Categories of data affected.
            jurisdictions: Jurisdictions to consider.

        Returns:
            List of RegulatoryMatch objects, sorted by deadline urgency.
        """
        if data_categories is None:
            data_categories = []
        if jurisdictions is None:
            jurisdictions = ["Algeria"]

        matches: List[RegulatoryMatch] = []

        for reg in self._regulations.values():
            # Jurisdiction filter
            if jurisdictions and reg.jurisdiction not in jurisdictions:
                if reg.jurisdiction not in ("International",):
                    continue

            # Check if regulation applies
            applies = False
            if "all_incidents" in reg.applies_to:
                applies = True
            elif attack_type in reg.applies_to:
                applies = True
            else:
                for cat in data_categories:
                    if cat in reg.applies_to:
                        applies = True
                        break

            if applies:
                urgency = "STANDARD"
                if reg.notification_deadline_hours <= 24:
                    urgency = "IMMEDIATE"
                elif reg.notification_deadline_hours <= 48:
                    urgency = "URGENT"

                matches.append(RegulatoryMatch(
                    regulation=reg,
                    deadline_hours=reg.notification_deadline_hours,
                    urgency=urgency,
                ))

        matches.sort(key=lambda m: m.deadline_hours)
        return matches

    def get_algerian_regulations(self) -> List[Regulation]:
        """Get all Algerian regulations.

        Returns:
            List of Algerian Regulation objects.
        """
        return [
            r for r in self._regulations.values()
            if r.jurisdiction == "Algeria"
        ]

    def get_by_id(self, reg_id: str) -> Optional[Regulation]:
        """Get a regulation by ID.

        Args:
            reg_id: Regulation identifier.

        Returns:
            The Regulation, or None.
        """
        return self._regulations.get(reg_id)


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Single source of truth for regulatory compliance requirements.
# 2. Automatically matches incidents to applicable regulations.
# 3. Covers Algeria (CERT-DZ, ANPDP, Loi 09-04) + international (GDPR,
#    NIS2, PCI-DSS, NIST).
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os
    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    db = RegulatoryDB()

    logger.info("=" * 60)
    logger.info("REGULATORY DB DEMO")
    logger.info("=" * 60)

    matches = db.get_applicable(
        attack_type="data_exfil",
        data_categories=["personal_data"],
        jurisdictions=["Algeria", "European Union"],
    )

    for m in matches:
        logger.info(
            "  [%s] %s → %dh deadline (%s)",
            m.regulation.reg_id, m.regulation.name,
            m.deadline_hours, m.urgency,
        )
        logger.info("    Penalty: %s", m.regulation.penalty_description[:80])

    logger.info("RegulatoryDB demo complete ✓")
