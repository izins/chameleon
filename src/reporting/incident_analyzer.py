"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/reporting/incident_analyzer.py

Forensic analysis engine. Takes an EvidencePackage and produces
a structured IncidentAnalysis with:
  - Attack classification and kill-chain phase mapping
  - Impact assessment (data exposure, asset damage)
  - Root cause hypothesis
  - Dwell time calculation (T0 to T_containment)
  - Attack vector reconstruction
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from src.reporting.evidence_collector import EvidencePackage

logger = logging.getLogger(__name__)


# ── Attack classification database ──────────────────────────────────
_ATTACK_PROFILES: Dict[str, Dict] = {
    "ssh_bruteforce": {
        "classification": "Credential-Based Attack",
        "kill_chain_phase": "Initial Access → Credential Access",
        "typical_vector": "Automated password spraying via SSH",
        "data_risk": "User credentials, SSH keys",
        "lateral_risk": "HIGH — SSH access enables pivot to any reachable host",
        "recommended_investigation": [
            "Check /var/log/auth.log for failed attempts count",
            "Verify if any account was successfully compromised",
            "Audit SSH key additions in ~/.ssh/authorized_keys",
            "Check for new cron jobs or persistence mechanisms",
        ],
    },
    "sql_injection": {
        "classification": "Application-Layer Attack",
        "kill_chain_phase": "Initial Access → Collection",
        "typical_vector": "Malicious SQL via web application input",
        "data_risk": "Database contents, PII, credentials",
        "lateral_risk": "MEDIUM — DB access may allow file read/write via INTO OUTFILE",
        "recommended_investigation": [
            "Review web application logs for injection patterns",
            "Check database query logs for UNION SELECT / DROP / xp_cmdshell",
            "Verify database user privileges (should be least-privilege)",
            "Audit data exfiltration via large SELECT result sets",
        ],
    },
    "lateral_movement": {
        "classification": "Post-Compromise Expansion",
        "kill_chain_phase": "Lateral Movement → Discovery",
        "typical_vector": "Credential reuse, SMB, WMI, SSH pivoting",
        "data_risk": "Access to additional systems and data stores",
        "lateral_risk": "CRITICAL — attacker is actively expanding foothold",
        "recommended_investigation": [
            "Map all hosts contacted by the compromised IP in NetFlow data",
            "Check for new processes on neighboring hosts",
            "Audit authentication logs on all reachable servers",
            "Look for pass-the-hash or token impersonation artifacts",
        ],
    },
    "data_exfil": {
        "classification": "Data Theft",
        "kill_chain_phase": "Collection → Exfiltration",
        "typical_vector": "DNS tunneling, HTTPS POST to C2, cloud storage upload",
        "data_risk": "CRITICAL — data has likely left the network",
        "lateral_risk": "LOW — attacker has what they need",
        "recommended_investigation": [
            "Quantify data volume transferred to external IPs",
            "Check DNS logs for high-entropy subdomain queries (tunneling)",
            "Review outbound HTTPS connections to unknown domains",
            "Identify the data categories that were accessible to the host",
        ],
    },
    "privilege_escalation": {
        "classification": "Privilege Elevation Attack",
        "kill_chain_phase": "Privilege Escalation → Persistence",
        "typical_vector": "Kernel exploit, SUID abuse, sudo misconfiguration",
        "data_risk": "Full system access, all data on host",
        "lateral_risk": "CRITICAL — root access enables any further action",
        "recommended_investigation": [
            "Check for new SUID binaries: find / -perm -4000",
            "Audit /etc/sudoers for recent modifications",
            "Review kernel logs for exploit signatures (dmesg)",
            "Check for rootkit indicators: rkhunter / chkrootkit",
        ],
    },
    "anomaly_unknown": {
        "classification": "Unclassified Behavioral Anomaly",
        "kill_chain_phase": "Unknown — requires manual analysis",
        "typical_vector": "Behavioral deviation detected by UEBA / ML models",
        "data_risk": "Unknown — manual triage required",
        "lateral_risk": "MEDIUM — assume hostile until proven benign",
        "recommended_investigation": [
            "Review the raw log sequence for patterns",
            "Compare entity behavior to historical baseline",
            "Check if the anomaly correlates with known maintenance windows",
            "Escalate to Tier 2 analyst for manual review",
        ],
    },
}


# ── Impact levels ───────────────────────────────────────────────────
class ImpactLevel(BaseModel):
    """Impact assessment for the incident.

    Attributes:
        confidentiality: Impact on data confidentiality (0-10).
        integrity: Impact on data integrity (0-10).
        availability: Impact on system availability (0-10).
        overall: Overall CIA impact score.
        description: Human-readable summary.
    """

    confidentiality: int = Field(default=0, ge=0, le=10)
    integrity: int = Field(default=0, ge=0, le=10)
    availability: int = Field(default=0, ge=0, le=10)
    overall: float = Field(default=0.0)
    description: str = Field(default="")


class IncidentAnalysis(BaseModel):
    """Complete forensic analysis of an incident.

    Attributes:
        analysis_id: Unique analysis identifier.
        timestamp: When the analysis was performed.
        entity_id: The primary entity under investigation.
        attack_classification: Type of attack.
        kill_chain_phase: Where in the kill chain.
        attack_vector: How the attack was conducted.
        root_cause_hypothesis: Best guess at root cause.
        data_at_risk: What data may have been exposed.
        lateral_risk_level: Risk of further spread.
        impact: CIA impact assessment.
        investigation_steps: Recommended forensic steps.
        dwell_time_description: How long attacker was present.
        ioc_summary: Summary of Indicators of Compromise.
        evidence_package_id: Link to the evidence package.
        recommendations: High-level remediation recommendations.
    """

    analysis_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    entity_id: str = Field(default="")
    attack_classification: str = Field(default="")
    kill_chain_phase: str = Field(default="")
    attack_vector: str = Field(default="")
    root_cause_hypothesis: str = Field(default="")
    data_at_risk: str = Field(default="")
    lateral_risk_level: str = Field(default="")
    impact: ImpactLevel = Field(default_factory=ImpactLevel)
    investigation_steps: List[str] = Field(default_factory=list)
    dwell_time_description: str = Field(default="")
    ioc_summary: str = Field(default="")
    evidence_package_id: str = Field(default="")
    recommendations: List[str] = Field(default_factory=list)


class IncidentAnalyzer:
    """Performs forensic analysis on collected evidence.

    Uses attack profiles, MITRE mapping, and risk data to produce
    a structured analysis suitable for incident handlers.
    """

    def __init__(self) -> None:
        logger.info("IncidentAnalyzer ready")

    def analyze(self, evidence: EvidencePackage) -> IncidentAnalysis:
        """Analyze the evidence and produce a forensic report.

        Args:
            evidence: Complete evidence package from EvidenceCollector.

        Returns:
            A structured IncidentAnalysis.
        """
        # ── Determine attack profile ─────────────────────────────────
        attack_type = self._determine_attack_type(evidence)
        profile = _ATTACK_PROFILES.get(attack_type, _ATTACK_PROFILES["anomaly_unknown"])

        # ── Calculate impact ─────────────────────────────────────────
        impact = self._assess_impact(evidence, attack_type)

        # ── Build root cause hypothesis ──────────────────────────────
        root_cause = self._hypothesize_root_cause(evidence, attack_type)

        # ── Build recommendations ────────────────────────────────────
        recommendations = self._build_recommendations(evidence, attack_type)

        # ── IoC summary ──────────────────────────────────────────────
        ioc_summary = self._summarize_iocs(evidence)

        analysis = IncidentAnalysis(
            entity_id=evidence.entity_id,
            attack_classification=profile["classification"],
            kill_chain_phase=profile["kill_chain_phase"],
            attack_vector=profile["typical_vector"],
            root_cause_hypothesis=root_cause,
            data_at_risk=profile["data_risk"],
            lateral_risk_level=profile["lateral_risk"],
            impact=impact,
            investigation_steps=profile["recommended_investigation"],
            dwell_time_description=self._estimate_dwell_time(evidence),
            ioc_summary=ioc_summary,
            evidence_package_id=evidence.package_id,
            recommendations=recommendations,
        )

        logger.info(
            "Incident analyzed: %s — %s (%s) impact=%.1f",
            analysis.entity_id, analysis.attack_classification,
            analysis.kill_chain_phase, analysis.impact.overall,
        )
        return analysis

    def _determine_attack_type(self, evidence: EvidencePackage) -> str:
        """Determine the primary attack type from evidence.

        Args:
            evidence: The evidence package.

        Returns:
            Attack type string.
        """
        if evidence.entity_attack_history:
            # Use the most severe attack type from history
            priority = [
                "privilege_escalation", "data_exfil", "lateral_movement",
                "sql_injection", "ssh_bruteforce", "anomaly_unknown",
            ]
            for at in priority:
                if at in evidence.entity_attack_history:
                    return at
        return "anomaly_unknown"

    def _assess_impact(
        self, evidence: EvidencePackage, attack_type: str,
    ) -> ImpactLevel:
        """Assess CIA impact based on evidence.

        Args:
            evidence: Evidence package.
            attack_type: Determined attack type.

        Returns:
            Impact assessment.
        """
        c, i, a = 3, 2, 1  # Base scores

        if attack_type in ("data_exfil", "sql_injection"):
            c = 9  # High confidentiality impact
        if attack_type == "privilege_escalation":
            c, i = 8, 8  # High C and I
        if attack_type == "lateral_movement":
            c, i, a = 7, 6, 5

        # Adjust by CVSS
        if evidence.max_cvss >= 9.0:
            c = max(c, 9)
            i = max(i, 8)
        elif evidence.max_cvss >= 7.0:
            c = max(c, 7)

        # Adjust by asset count
        if len(evidence.affected_assets) > 3:
            a = max(a, 7)

        overall = round((c + i + a) / 3.0, 1)
        descriptions = {
            (True, True, True): "Critical impact on confidentiality, integrity, and availability",
            (True, True, False): "High impact on confidentiality and integrity",
            (True, False, False): "Primary impact on data confidentiality",
        }
        desc_key = (c >= 7, i >= 7, a >= 7)
        desc = descriptions.get(desc_key, f"CIA scores: C={c} I={i} A={a}")

        return ImpactLevel(
            confidentiality=c, integrity=i, availability=a,
            overall=overall, description=desc,
        )

    def _hypothesize_root_cause(
        self, evidence: EvidencePackage, attack_type: str,
    ) -> str:
        """Generate a root cause hypothesis.

        Args:
            evidence: Evidence package.
            attack_type: Attack type.

        Returns:
            Root cause hypothesis string.
        """
        hypotheses = {
            "ssh_bruteforce": (
                f"Weak or default SSH credentials on {evidence.entity_id}. "
                f"Entity accumulated {evidence.entity_cumulative_score:.0f} "
                f"risk points across {len(evidence.entity_attack_history)} "
                f"attack types, suggesting persistent targeting."
            ),
            "sql_injection": (
                f"Unvalidated user input in web application on {evidence.entity_id}. "
                f"CVSS {evidence.max_cvss:.1f} suggests a known vulnerability "
                f"({', '.join(evidence.cve_ids[:3]) or 'no CVE matched'})."
            ),
            "lateral_movement": (
                f"Credential reuse or token theft from {evidence.entity_id}. "
                f"Attacker pivoted to {len(evidence.affected_assets)} assets. "
                f"MITRE chain: {' → '.join(evidence.mitre_techniques)}."
            ),
            "data_exfil": (
                f"Data exfiltration from {evidence.entity_id}. "
                f"Risk score {evidence.risk_score:.2f} ({evidence.risk_label}). "
                f"Likely using encrypted channel (HTTPS/DNS tunneling)."
            ),
            "privilege_escalation": (
                f"Privilege escalation on {evidence.entity_id} via "
                f"{'known CVE: ' + evidence.cve_ids[0] if evidence.cve_ids else 'unknown exploit'}. "
                f"MITRE: {' → '.join(evidence.mitre_techniques)}."
            ),
        }
        return hypotheses.get(
            attack_type,
            f"Behavioral anomaly on {evidence.entity_id}. "
            f"UEBA suspicion score: {evidence.total_suspicion:.1f}. "
            f"Manual investigation required.",
        )

    def _build_recommendations(
        self, evidence: EvidencePackage, attack_type: str,
    ) -> List[str]:
        """Build remediation recommendations.

        Args:
            evidence: Evidence package.
            attack_type: Attack type.

        Returns:
            List of recommendation strings.
        """
        recs = [
            f"Immediate: Verify containment of {evidence.entity_id}",
            f"Forensic: Preserve disk image and memory dump of {evidence.entity_id}",
        ]
        if evidence.max_cvss >= 7.0:
            recs.append(
                f"Patch: Apply patches for {', '.join(evidence.cve_ids[:3])} "
                f"(CVSS {evidence.max_cvss:.1f})"
            )
        if attack_type == "ssh_bruteforce":
            recs.extend([
                "Enforce MFA on all SSH access",
                "Implement fail2ban or similar rate-limiting",
                "Rotate all SSH keys on affected hosts",
            ])
        elif attack_type == "sql_injection":
            recs.extend([
                "Deploy WAF rules for SQL injection patterns",
                "Audit application code for parameterized queries",
                "Rotate database credentials",
            ])
        elif attack_type in ("lateral_movement", "privilege_escalation"):
            recs.extend([
                "Reset credentials for all accounts on affected hosts",
                "Audit network segmentation policies",
                "Review sudo/admin privilege assignments",
            ])
        if evidence.entity_cumulative_score > 50:
            recs.append(
                f"Threat Intel: Share IoCs for {evidence.entity_id} "
                f"with CERT-DZ and industry ISACs"
            )
            
        # Add dynamic context-aware recommendations (ISO 27035 & SANS inspired)
        # Note: RiskVerdict might not be directly in EvidencePackage in Phase 4.
        # But we can simulate context lookup or assume it's there for future proofing.
        try:
            from src.response.network_graph import NetworkGraph
            graph = NetworkGraph()
            asset_details = graph.get_asset_details(evidence.entity_id)
            asset_type = asset_details.get("asset_type", "unknown")
            impact = asset_details.get("business_impact", "unknown")
            
            if asset_type == "network" or asset_type == "infrastructure":
                recs.append("[SANS Context] Verify routing tables and router firmware integrity")
                recs.append("[SANS Context] Check for unauthorized BGP/OSPF advertisements")
            elif asset_type == "server":
                recs.append("[MITRE D3FEND] Implement Process Isolation and File Integrity Monitoring (FIM)")
                
            if impact == "critical":
                recs.append("[ISO 27035] Initiate executive crisis communication protocols immediately")
                recs.append("[ISO 27035] Activate alternate/DR site if service availability is compromised")
        except Exception as e:
            logger.debug(f"Could not load asset context for recommendations: {e}")

        return recs

    def _estimate_dwell_time(self, evidence: EvidencePackage) -> str:
        """Estimate how long the attacker was present.

        Args:
            evidence: Evidence package.

        Returns:
            Human-readable dwell time description.
        """
        if len(evidence.entity_attack_history) >= 3:
            return (
                f"Multi-stage attack with {len(evidence.entity_attack_history)} "
                f"distinct attack types observed. Likely dwell time: days to weeks."
            )
        elif len(evidence.entity_attack_history) == 2:
            return "Two attack phases observed. Estimated dwell time: hours to days."
        return "Single attack event. Estimated dwell time: minutes to hours."

    def _summarize_iocs(self, evidence: EvidencePackage) -> str:
        """Summarize IoCs for the report.

        Args:
            evidence: Evidence package.

        Returns:
            IoC summary string.
        """
        parts = [f"Primary IP: {evidence.entity_id}"]
        if evidence.affected_assets:
            parts.append(f"Targets: {', '.join(evidence.affected_assets)}")
        if evidence.event_hashes:
            parts.append(f"Event hashes: {len(evidence.event_hashes)} collected")
        if evidence.mitre_techniques:
            parts.append(f"MITRE: {', '.join(evidence.mitre_techniques)}")
        return " | ".join(parts)


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Transforms raw evidence into a structured forensic analysis.
# 2. Provides attack classification, impact assessment, root cause.
# 3. Generates investigation steps for incident handlers.
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
    analyzer = IncidentAnalyzer()

    alert = ModelAlert(
        severity="P1", attack_type="privilege_escalation",
        confidence=0.92, source_host="10.0.0.40",
        affected_assets=["10.0.0.10"], model_source="DeepLog",
        raw_sequence=[5, 5, 5, 22, 11],
    )
    enriched = engine.enrich(alert)
    verdict = scorer.score(enriched)
    actions = isolator.execute(verdict)
    evidence = collector.collect(enriched, verdict, actions)
    analysis = analyzer.analyze(evidence)

    logger.info("Analysis: %s", analysis.attack_classification)
    logger.info("  Kill chain: %s", analysis.kill_chain_phase)
    logger.info("  Impact: %.1f", analysis.impact.overall)
    logger.info("  Root cause: %s", analysis.root_cause_hypothesis)
    logger.info("IncidentAnalyzer demo complete ✓")
