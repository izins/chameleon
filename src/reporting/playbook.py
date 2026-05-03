"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/reporting/playbook.py

Generates structured incident response playbooks for SOC analysts
and incident handlers.

Each playbook is a list of IRStep objects (not raw text) so the
frontend can render them as interactive checklists with status
tracking.

Playbooks are generated per severity level AND per attack type,
combining generic IR procedures with attack-specific technical steps.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from src.reporting.evidence_collector import EvidencePackage
from src.reporting.incident_analyzer import IncidentAnalysis
from src.response.scorer import RiskVerdict

logger = logging.getLogger(__name__)


class StepPriority(str, Enum):
    """Priority of an IR step."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class StepCategory(str, Enum):
    """Category of an IR step."""

    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    FORENSICS = "forensics"
    COMMUNICATION = "communication"
    LEGAL = "legal"
    MONITORING = "monitoring"


class IRStep(BaseModel):
    """A single incident response step.

    Designed to be rendered as a checkbox in the SOC dashboard.

    Attributes:
        step_id: Unique step identifier.
        order: Execution order (1-based).
        category: Step category.
        priority: Step priority.
        title: Short title for the step.
        description: Detailed instructions.
        technical_commands: Shell commands or queries to execute.
        expected_output: What to look for in the results.
        completed: Whether the step has been completed.
        assignee: Who should execute this step.
        estimated_minutes: Estimated time to complete.
    """

    step_id: str = Field(default_factory=lambda: str(uuid4()))
    order: int = Field(default=0)
    category: StepCategory = Field(default=StepCategory.CONTAINMENT)
    priority: StepPriority = Field(default=StepPriority.MEDIUM)
    title: str = Field(default="")
    description: str = Field(default="")
    technical_commands: List[str] = Field(default_factory=list)
    expected_output: str = Field(default="")
    completed: bool = Field(default=False)
    assignee: str = Field(default="SOC Analyst")
    estimated_minutes: int = Field(default=15)


class Playbook(BaseModel):
    """Complete incident response playbook.

    Attributes:
        playbook_id: Unique identifier.
        generated_at: Generation timestamp.
        incident_id: Link to the evidence package.
        entity_id: Primary entity.
        severity: Incident severity.
        attack_type: Attack classification.
        total_steps: Number of steps.
        estimated_total_minutes: Total estimated time.
        steps: Ordered list of IR steps.
    """

    playbook_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    incident_id: str = Field(default="")
    entity_id: str = Field(default="")
    severity: str = Field(default="P4")
    attack_type: str = Field(default="")
    total_steps: int = Field(default=0)
    estimated_total_minutes: int = Field(default=0)
    steps: List[IRStep] = Field(default_factory=list)


class PlaybookGenerator:
    """Generates incident response playbooks.

    Combines:
      1. Generic IR steps based on severity level
      2. Attack-specific technical steps
      3. Evidence-specific commands (using real IPs, CVEs, etc.)
    """

    def __init__(self) -> None:
        logger.info("PlaybookGenerator ready")

    def generate(
        self,
        evidence: EvidencePackage,
        analysis: IncidentAnalysis,
        verdict: RiskVerdict,
    ) -> Playbook:
        """Generate a complete playbook for the incident.

        Args:
            evidence: Forensic evidence package.
            analysis: Incident analysis results.
            verdict: Risk verdict from scorer.

        Returns:
            A structured Playbook with ordered steps.
        """
        steps: List[IRStep] = []
        order = 1

        # ── Phase A: Immediate Containment ───────────────────────────
        containment = self._containment_steps(evidence, verdict)
        for s in containment:
            s.order = order
            order += 1
        steps.extend(containment)

        # ── Phase B: Forensic Collection ─────────────────────────────
        forensics = self._forensic_steps(evidence, analysis)
        for s in forensics:
            s.order = order
            order += 1
        steps.extend(forensics)

        # ── Phase C: Attack-Specific Investigation ───────────────────
        investigation = self._attack_specific_steps(evidence, analysis)
        for s in investigation:
            s.order = order
            order += 1
        steps.extend(investigation)

        # ── Phase D: Eradication ─────────────────────────────────────
        eradication = self._eradication_steps(evidence, analysis)
        for s in eradication:
            s.order = order
            order += 1
        steps.extend(eradication)

        # ── Phase E: Recovery ────────────────────────────────────────
        recovery = self._recovery_steps(evidence)
        for s in recovery:
            s.order = order
            order += 1
        steps.extend(recovery)

        # ── Phase F: Communication & Legal ───────────────────────────
        comms = self._communication_steps(evidence, verdict)
        for s in comms:
            s.order = order
            order += 1
        steps.extend(comms)

        # ── Phase G: Post-Incident Monitoring ────────────────────────
        monitoring = self._monitoring_steps(evidence)
        for s in monitoring:
            s.order = order
            order += 1
        steps.extend(monitoring)

        total_minutes = sum(s.estimated_minutes for s in steps)

        playbook = Playbook(
            incident_id=evidence.package_id,
            entity_id=evidence.entity_id,
            severity=verdict.adjusted_severity,
            attack_type=analysis.attack_classification,
            total_steps=len(steps),
            estimated_total_minutes=total_minutes,
            steps=steps,
        )

        logger.info(
            "Playbook generated: %d steps, ~%d minutes, severity=%s",
            len(steps), total_minutes, verdict.adjusted_severity,
        )
        return playbook

    def _containment_steps(
        self, evidence: EvidencePackage, verdict: RiskVerdict,
    ) -> List[IRStep]:
        """Generate immediate containment steps adapted to asset context.

        ISO 27035 Phase 3 (Response) requires proportional containment.
        We adapt containment to the attack type AND the asset type to
        avoid self-inflicted DoS on critical infrastructure.
        """
        steps: List[IRStep] = []
        asset_type = getattr(verdict, "asset_type", "unknown")
        attack_type = getattr(verdict, "attack_type", "")
        data_class = getattr(verdict, "data_classification", "unknown")

        # ── Asset-aware isolation decision ───────────────────────────
        if asset_type in ("network", "infrastructure"):
            # NEVER auto-quarantine a router or core switch — VLAN shunt instead
            steps.append(IRStep(
                category=StepCategory.CONTAINMENT,
                priority=StepPriority.CRITICAL,
                title=f"[ISO 27035] VLAN shunt {evidence.entity_id} — DO NOT full-quarantine",
                description=(
                    f"CRITICAL INFRASTRUCTURE ({asset_type}). Full quarantine would "
                    f"cause network-wide outage. Move to isolated VLAN for monitoring "
                    f"while maintaining core routing functions."
                ),
                technical_commands=[
                    f"# Switch: set interface {evidence.entity_id} vlan quarantine",
                    f"# Verify routing tables are intact after shunt",
                    f"# Enable port mirroring for forensic capture",
                ],
                expected_output="Device on quarantine VLAN, core routing unaffected",
                assignee="Network Engineer",
                estimated_minutes=15,
            ))
        elif asset_type == "server" and getattr(verdict, "business_impact", "") == "critical":
            # Critical server: micro-segment, don't kill it
            steps.append(IRStep(
                category=StepCategory.CONTAINMENT,
                priority=StepPriority.CRITICAL,
                title=f"Micro-segment {evidence.entity_id} — critical server (partial isolation)",
                description=(
                    f"Business-critical server. Apply micro-segmentation: block all "
                    f"non-essential traffic but keep production services running. "
                    f"Risk: {evidence.risk_score:.2f} ({evidence.risk_label})."
                ),
                technical_commands=[
                    f"iptables -A INPUT -s {evidence.entity_id} -p tcp --dport 22 -j DROP",
                    f"iptables -A INPUT -s {evidence.entity_id} -p tcp --dport 3306 -j DROP",
                    f"# Keep HTTP/HTTPS open if production web server",
                ],
                expected_output="Non-essential ports blocked, production traffic flows",
                assignee="Security Engineer",
                estimated_minutes=10,
            ))
        else:
            # Standard host (workstation, non-critical server): full quarantine
            steps.append(IRStep(
                category=StepCategory.CONTAINMENT,
                priority=StepPriority.CRITICAL,
                title=f"Full network quarantine of {evidence.entity_id}",
                description=(
                    f"Standard asset ({asset_type}). Full network isolation is safe. "
                    f"Risk score: {evidence.risk_score:.2f} ({evidence.risk_label})."
                ),
                technical_commands=[
                    f"iptables -A INPUT -s {evidence.entity_id} -j DROP",
                    f"iptables -A OUTPUT -d {evidence.entity_id} -j DROP",
                    f"ping -c 1 {evidence.entity_id}  # should fail if quarantined",
                ],
                expected_output="All traffic to/from host blocked",
                assignee="SOC L1",
                estimated_minutes=5,
            ))

        # ── Attack-specific containment ──────────────────────────────
        if attack_type == "sql_injection":
            steps.append(IRStep(
                category=StepCategory.CONTAINMENT,
                priority=StepPriority.CRITICAL,
                title="Revoke database access from compromised endpoint",
                description=(
                    "SQL Injection detected. Revoke all DB privileges from "
                    f"{evidence.entity_id} immediately. This is more precise than "
                    "network quarantine for application-layer attacks."
                ),
                technical_commands=[
                    f"REVOKE ALL PRIVILEGES ON *.* FROM connections WHERE host='{evidence.entity_id}';",
                    "# Deploy WAF emergency rule: block UNION/SELECT patterns",
                ],
                assignee="DBA",
                estimated_minutes=10,
            ))
        elif attack_type == "ssh_bruteforce":
            steps.append(IRStep(
                category=StepCategory.CONTAINMENT,
                priority=StepPriority.HIGH,
                title="Lock targeted user accounts + add IP to SSH deny list",
                description=(
                    f"SSH brute-force from {evidence.entity_id}. Lock targeted "
                    f"accounts and add source IP to DenyUsers / fail2ban."
                ),
                technical_commands=[
                    f"fail2ban-client set sshd banip {evidence.entity_id}",
                    "# Lock any compromised accounts: passwd -l <user>",
                ],
                assignee="IAM Team",
                estimated_minutes=10,
            ))
        elif attack_type == "data_exfil":
            steps.append(IRStep(
                category=StepCategory.CONTAINMENT,
                priority=StepPriority.CRITICAL,
                title="Block all outbound traffic from compromised host",
                description=(
                    f"Data exfiltration in progress. Block ALL outbound from "
                    f"{evidence.entity_id} at perimeter firewall AND proxy."
                ),
                technical_commands=[
                    f"iptables -A OUTPUT -s {evidence.entity_id} -j DROP",
                    f"# Proxy: block {evidence.entity_id} at Squid/BlueCoat",
                    "# Check DNS logs for tunneling indicators",
                ],
                assignee="Network Engineer",
                estimated_minutes=5,
            ))

        # ── Data sensitivity escalation ──────────────────────────────
        if data_class in ("restricted", "confidential"):
            steps.append(IRStep(
                category=StepCategory.CONTAINMENT,
                priority=StepPriority.CRITICAL,
                title=f"[ISO 27035] Data breach protocol — {data_class} data at risk",
                description=(
                    f"The compromised asset handles {data_class} data. "
                    f"Initiate data breach containment protocol: identify all "
                    f"data stores accessible from {evidence.entity_id} and verify integrity."
                ),
                technical_commands=[
                    "# Audit file access logs for last 48 hours",
                    "# Check database query logs for bulk SELECT/export operations",
                ],
                assignee="DPO / Security Engineer",
                estimated_minutes=20,
            ))

        # ── P1/P2: Disable accounts ─────────────────────────────────
        if verdict.adjusted_severity in ("P1", "P2"):
            steps.append(IRStep(
                category=StepCategory.CONTAINMENT,
                priority=StepPriority.CRITICAL,
                title="Disable compromised accounts",
                description=(
                    "Lock all user accounts that were active on "
                    f"{evidence.entity_id} during the incident window."
                ),
                technical_commands=[
                    "# List active sessions: who | last",
                    "# Lock accounts: passwd -l <username>",
                    "# AD: Disable-ADAccount -Identity <user>",
                ],
                assignee="IAM Team",
                estimated_minutes=15,
            ))
        return steps

    def _forensic_steps(
        self, evidence: EvidencePackage, analysis: IncidentAnalysis,
    ) -> List[IRStep]:
        """Generate forensic evidence collection steps."""
        return [
            IRStep(
                category=StepCategory.FORENSICS,
                priority=StepPriority.HIGH,
                title="Capture volatile evidence (memory + processes)",
                description=(
                    f"Capture RAM dump and running processes on {evidence.entity_id} "
                    f"BEFORE any remediation. This evidence is volatile."
                ),
                technical_commands=[
                    f"# Memory dump: ssh {evidence.entity_id} 'sudo dd if=/dev/mem of=/tmp/memdump.raw'",
                    f"# Processes: ssh {evidence.entity_id} 'ps auxww > /tmp/processes.txt'",
                    f"# Network: ssh {evidence.entity_id} 'netstat -tulpn > /tmp/netstat.txt'",
                    f"# Open files: ssh {evidence.entity_id} 'lsof -i > /tmp/lsof.txt'",
                ],
                expected_output="4 evidence files collected and preserved",
                assignee="Forensic Analyst",
                estimated_minutes=30,
            ),
            IRStep(
                category=StepCategory.FORENSICS,
                priority=StepPriority.HIGH,
                title="Preserve disk image",
                description="Create a forensic disk image for offline analysis.",
                technical_commands=[
                    f"# dd if=/dev/sda of=/forensics/{evidence.entity_id}_disk.img bs=4M",
                    f"# sha256sum /forensics/{evidence.entity_id}_disk.img > checksum.txt",
                ],
                assignee="Forensic Analyst",
                estimated_minutes=60,
            ),
            IRStep(
                category=StepCategory.FORENSICS,
                priority=StepPriority.MEDIUM,
                title="Collect AEGIS evidence hashes",
                description=(
                    f"Verify {len(evidence.event_hashes)} event hashes from AEGIS. "
                    f"MITRE techniques: {', '.join(evidence.mitre_techniques)}. "
                    f"Template sequence: {evidence.template_sequence[:10]}..."
                ),
                technical_commands=[
                    f"# AEGIS Evidence Package ID: {evidence.package_id}",
                    f"# Total suspicion (UEBA): {evidence.total_suspicion:.1f}",
                    f"# Entity cumulative score: {evidence.entity_cumulative_score:.1f}",
                ],
                assignee="SOC L2",
                estimated_minutes=15,
            ),
        ]

    def _attack_specific_steps(
        self, evidence: EvidencePackage, analysis: IncidentAnalysis,
    ) -> List[IRStep]:
        """Generate steps specific to the attack type."""
        steps: List[IRStep] = []
        for i, step_text in enumerate(analysis.investigation_steps):
            steps.append(IRStep(
                category=StepCategory.FORENSICS,
                priority=StepPriority.HIGH,
                title=f"Investigation: {step_text[:60]}",
                description=step_text,
                assignee="SOC L2",
                estimated_minutes=20,
            ))
        return steps

    def _eradication_steps(
        self, evidence: EvidencePackage, analysis: IncidentAnalysis,
    ) -> List[IRStep]:
        """Generate eradication steps."""
        steps = [
            IRStep(
                category=StepCategory.ERADICATION,
                priority=StepPriority.HIGH,
                title="Remove attacker persistence mechanisms",
                description=(
                    "Check for backdoors, cron jobs, SSH keys, and "
                    "rootkits installed by the attacker."
                ),
                technical_commands=[
                    f"ssh {evidence.entity_id} 'crontab -l'",
                    f"ssh {evidence.entity_id} 'find / -name authorized_keys -exec cat {{}} \\;'",
                    f"ssh {evidence.entity_id} 'find / -perm -4000 -type f 2>/dev/null'",
                    "rkhunter --check --skip-keypress",
                ],
                assignee="Security Engineer",
                estimated_minutes=30,
            ),
        ]
        if evidence.cve_ids:
            steps.append(IRStep(
                category=StepCategory.ERADICATION,
                priority=StepPriority.CRITICAL,
                title=f"Patch vulnerabilities: {', '.join(evidence.cve_ids[:3])}",
                description=(
                    f"Apply patches for CVSS {evidence.max_cvss:.1f} vulnerabilities. "
                    f"CVEs: {', '.join(evidence.cve_ids)}."
                ),
                technical_commands=[
                    "apt update && apt upgrade -y  # Debian/Ubuntu",
                    "yum update -y                 # RHEL/CentOS",
                ],
                assignee="Sysadmin",
                estimated_minutes=45,
            ))
        return steps

    def _recovery_steps(self, evidence: EvidencePackage) -> List[IRStep]:
        """Generate recovery steps."""
        return [
            IRStep(
                category=StepCategory.RECOVERY,
                priority=StepPriority.MEDIUM,
                title="Restore from clean backup",
                description=(
                    f"If {evidence.entity_id} was fully compromised, "
                    f"restore from last known-good backup."
                ),
                technical_commands=[
                    "# Verify backup integrity before restore",
                    f"# rsync -av /backups/{evidence.entity_id}/ /",
                ],
                assignee="Sysadmin",
                estimated_minutes=60,
            ),
            IRStep(
                category=StepCategory.RECOVERY,
                priority=StepPriority.MEDIUM,
                title="Rotate all credentials",
                description="Reset passwords, API keys, SSH keys, and DB credentials.",
                technical_commands=[
                    "passwd <affected_users>",
                    "ssh-keygen -t ed25519  # regenerate SSH keys",
                    "ALTER USER 'app'@'%' IDENTIFIED BY '<new_password>';",
                ],
                assignee="IAM Team",
                estimated_minutes=30,
            ),
        ]

    def _communication_steps(
        self, evidence: EvidencePackage, verdict: RiskVerdict,
    ) -> List[IRStep]:
        """Generate communication and legal steps."""
        steps = [
            IRStep(
                category=StepCategory.COMMUNICATION,
                priority=StepPriority.HIGH,
                title="Notify SOC Manager and CISO",
                description=(
                    f"Escalate incident to management. Severity: {verdict.adjusted_severity}. "
                    f"Risk: {evidence.risk_score:.2f} ({evidence.risk_label})."
                ),
                assignee="SOC Lead",
                estimated_minutes=10,
            ),
        ]
        if verdict.adjusted_severity in ("P1", "P2"):
            steps.append(IRStep(
                category=StepCategory.LEGAL,
                priority=StepPriority.CRITICAL,
                title="Notify CERT-DZ within 24 hours",
                description=(
                    "Legal obligation: Décret 20-05 requires notification "
                    "to CERT.dz within 24h of incident discovery."
                ),
                assignee="Legal / Compliance",
                estimated_minutes=30,
            ))
            steps.append(IRStep(
                category=StepCategory.LEGAL,
                priority=StepPriority.HIGH,
                title="Notify ANPDP within 72 hours (if PII affected)",
                description=(
                    "Loi 18-07: If personal data was compromised, "
                    "ANPDP must be notified within 72 hours."
                ),
                assignee="DPO",
                estimated_minutes=45,
            ))
        return steps

    def _monitoring_steps(self, evidence: EvidencePackage) -> List[IRStep]:
        """Generate post-incident monitoring steps."""
        return [
            IRStep(
                category=StepCategory.MONITORING,
                priority=StepPriority.MEDIUM,
                title="Enable enhanced monitoring (30 days)",
                description=(
                    f"Set elevated monitoring rules for {evidence.entity_id} "
                    f"and all {len(evidence.affected_assets)} affected assets "
                    f"for a minimum of 30 days post-incident."
                ),
                technical_commands=[
                    f"# SIEM: Add watchlist for {evidence.entity_id}",
                    "# IDS: Lower alert thresholds for affected subnet",
                ],
                assignee="SOC L1",
                estimated_minutes=15,
            ),
            IRStep(
                category=StepCategory.MONITORING,
                priority=StepPriority.LOW,
                title="Schedule post-incident review",
                description="Lessons learned meeting within 5 business days.",
                assignee="SOC Manager",
                estimated_minutes=60,
            ),
        ]


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Generates structured IR playbooks as IRStep objects (not raw text).
# 2. Combines severity-based + attack-specific + evidence-based steps.
# 3. Includes real commands, IPs, CVEs for immediate action.
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
        raw_sequence=[5, 5, 5, 22, 11],
    )

    enriched = EnrichmentEngine().enrich(alert)
    verdict = RiskScorer().score(enriched)
    actions = Isolator(dry_run=True).execute(verdict)
    evidence = EvidenceCollector().collect(enriched, verdict, actions)
    analysis = IncidentAnalyzer().analyze(evidence)
    playbook = PlaybookGenerator().generate(evidence, analysis, verdict)

    logger.info("Playbook: %d steps, ~%d min", playbook.total_steps,
                playbook.estimated_total_minutes)
    for s in playbook.steps:
        logger.info("  [%d] [%s] %s — %s (%d min)",
                     s.order, s.priority.value, s.category.value,
                     s.title, s.estimated_minutes)
    logger.info("Playbook demo complete ✓")
