"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/response/iso27035_tracker.py

ISO 27035 Process Tracker — Tracks every incident through the 5 phases
of the ISO 27035 Information Security Incident Management lifecycle.

The 5 phases (ISO 27035-2:2023):
  Phase 1: DETECTION & REPORTING
  Phase 2: ASSESSMENT & DECISION
  Phase 3: RESPONSE (Containment, Eradication, Recovery)
  Phase 4: LESSONS LEARNED
  Phase 5: DOCUMENTATION & CLOSURE

Every phase records:
  - Status (pending / in_progress / completed / skipped)
  - Start and end timestamps
  - Input data (what fed into this phase)
  - Output data (what this phase produced)
  - Operator/module responsible
  - Compliance notes (ISO 27035 clause references)

This module is the single source of truth for incident lifecycle state.
The SOC dashboard API reads from here to show real-time phase progression.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from src.config.settings import settings

logger = logging.getLogger(__name__)


# ── Phase Definitions ────────────────────────────────────────────────

class ISOPhase(str, Enum):
    """The 5 phases of ISO 27035 incident management."""
    DETECTION = "Phase 1: Detection & Reporting"
    ASSESSMENT = "Phase 2: Assessment & Decision"
    RESPONSE = "Phase 3: Response"
    LESSONS = "Phase 4: Lessons Learned"
    CLOSURE = "Phase 5: Documentation & Closure"


class PhaseStatus(str, Enum):
    """Status of an individual phase."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


# ── ISO 27035 Clause References ──────────────────────────────────────

_ISO_CLAUSES = {
    ISOPhase.DETECTION: {
        "clause": "ISO 27035-2:2023 §7.2",
        "title": "Detection and Reporting",
        "requirements": [
            "Monitor information security events from multiple sources",
            "Correlate events to identify potential incidents",
            "Ensure initial reporting within defined SLA",
            "Preserve volatile evidence at point of detection",
        ],
    },
    ISOPhase.ASSESSMENT: {
        "clause": "ISO 27035-2:2023 §7.3",
        "title": "Assessment and Decision",
        "requirements": [
            "Classify the incident by type and severity",
            "Assess business impact (confidentiality, integrity, availability)",
            "Determine if escalation is required",
            "Verify the incident is not a false positive",
            "Assign incident handler based on classification",
        ],
    },
    ISOPhase.RESPONSE: {
        "clause": "ISO 27035-2:2023 §7.4",
        "title": "Responses",
        "sub_phases": {
            "containment": {
                "clause": "§7.4.2",
                "title": "Immediate Containment",
                "requirements": [
                    "Isolate affected systems proportionally",
                    "Preserve evidence before containment actions",
                    "Minimize business disruption during containment",
                ],
            },
            "eradication": {
                "clause": "§7.4.3",
                "title": "Eradication",
                "requirements": [
                    "Remove threat actor access and persistence",
                    "Patch exploited vulnerabilities",
                    "Verify removal with integrity checks",
                ],
            },
            "recovery": {
                "clause": "§7.4.4",
                "title": "Recovery",
                "requirements": [
                    "Restore systems from clean backups",
                    "Rotate all potentially compromised credentials",
                    "Verify system integrity before returning to production",
                    "Implement enhanced monitoring for recurrence",
                ],
            },
        },
    },
    ISOPhase.LESSONS: {
        "clause": "ISO 27035-2:2023 §7.5",
        "title": "Lessons Learned",
        "requirements": [
            "Conduct post-incident review within 5 business days",
            "Identify root cause and contributing factors",
            "Document improvements to detection and response",
            "Update incident response procedures",
        ],
    },
    ISOPhase.CLOSURE: {
        "clause": "ISO 27035-2:2023 §7.6",
        "title": "Documentation and Closure",
        "requirements": [
            "Complete incident report with full timeline",
            "Archive all evidence with cryptographic integrity",
            "Submit regulatory notifications (CERT-DZ T+24h, ANPDP T+72h)",
            "Obtain management sign-off for incident closure",
        ],
    },
}


# ── Data Models ──────────────────────────────────────────────────────

class PhaseData(BaseModel):
    """Captured data for a single ISO 27035 phase.

    Stores the inputs, outputs, timing, and compliance state
    for one phase of the incident lifecycle.
    """
    phase: str = Field(default="")
    status: str = Field(default=PhaseStatus.PENDING.value)
    iso_clause: str = Field(default="")
    iso_title: str = Field(default="")

    started_at: Optional[str] = Field(default=None)
    completed_at: Optional[str] = Field(default=None)
    duration_seconds: Optional[float] = Field(default=None)

    operator: str = Field(default="AEGIS-AUTO")
    module: str = Field(default="")

    # What fed into this phase
    inputs: Dict[str, Any] = Field(default_factory=dict)
    # What this phase produced
    outputs: Dict[str, Any] = Field(default_factory=dict)
    # Sub-phases (for Phase 3: Response)
    sub_phases: Dict[str, "PhaseData"] = Field(default_factory=dict)

    # Compliance
    requirements: List[str] = Field(default_factory=list)
    requirements_met: List[str] = Field(default_factory=list)
    compliance_notes: List[str] = Field(default_factory=list)


class ISOIncidentRecord(BaseModel):
    """Complete ISO 27035 lifecycle record for one incident.

    This is the master record that the SOC dashboard reads from.
    """
    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    entity_id: str = Field(default="")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    last_updated: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )

    # Current phase
    current_phase: str = Field(default=ISOPhase.DETECTION.value)
    overall_status: str = Field(default="active")

    # All 5 phases
    phases: Dict[str, PhaseData] = Field(default_factory=dict)

    # Summary fields for quick dashboard display
    severity: str = Field(default="P4")
    attack_type: str = Field(default="unknown")
    risk_score: float = Field(default=0.0)
    risk_label: str = Field(default="INFO")
    total_phases_completed: int = Field(default=0)
    total_phases: int = Field(default=5)


# ── ISO 27035 Process Tracker ────────────────────────────────────────

class ISO27035Tracker:
    """Tracks incidents through the full ISO 27035 lifecycle.

    Usage:
        tracker = ISO27035Tracker()
        record = tracker.create_incident("192.168.1.100")
        tracker.start_phase(record.incident_id, ISOPhase.DETECTION, ...)
        tracker.complete_phase(record.incident_id, ISOPhase.DETECTION, ...)
    """

    def __init__(self) -> None:
        self._records: Dict[str, ISOIncidentRecord] = {}
        self._output_dir = Path(settings.demo_output_file).parent / "iso27035"
        self._output_dir.mkdir(parents=True, exist_ok=True)
        logger.info("ISO27035Tracker ready — 5-phase lifecycle tracking active")

    def create_incident(self, entity_id: str) -> ISOIncidentRecord:
        """Create a new ISO 27035 incident lifecycle record.

        Initializes all 5 phases with their ISO clause references
        and compliance requirements.

        Args:
            entity_id: The primary entity (IP/host) under investigation.

        Returns:
            A new ISOIncidentRecord with all phases initialized.
        """
        record = ISOIncidentRecord(entity_id=entity_id)

        # Initialize all 5 phases
        for phase in ISOPhase:
            clause_info = _ISO_CLAUSES[phase]
            phase_data = PhaseData(
                phase=phase.value,
                iso_clause=clause_info["clause"],
                iso_title=clause_info["title"],
                requirements=clause_info.get("requirements", []),
            )

            # Initialize sub-phases for Phase 3 (Response)
            if phase == ISOPhase.RESPONSE:
                for sub_name, sub_info in clause_info.get("sub_phases", {}).items():
                    phase_data.sub_phases[sub_name] = PhaseData(
                        phase=f"Phase 3.{sub_name}",
                        iso_clause=sub_info["clause"],
                        iso_title=sub_info["title"],
                        requirements=sub_info.get("requirements", []),
                    )

            record.phases[phase.value] = phase_data

        self._records[record.incident_id] = record
        self._persist(record)

        logger.info(
            "ISO 27035 incident created: %s entity=%s",
            record.incident_id[:8], entity_id,
        )
        return record

    def start_phase(
        self,
        incident_id: str,
        phase: ISOPhase,
        inputs: Dict[str, Any],
        module: str = "AEGIS",
        operator: str = "AEGIS-AUTO",
        sub_phase: Optional[str] = None,
    ) -> None:
        """Mark a phase as in_progress and record its inputs.

        Args:
            incident_id: The incident ID.
            phase: The ISO phase to start.
            inputs: The data that feeds into this phase.
            module: The AEGIS module responsible.
            operator: Human or automated operator.
            sub_phase: Optional sub-phase key (for Phase 3).
        """
        record = self._records.get(incident_id)
        if not record:
            logger.warning("Incident %s not found", incident_id)
            return

        now = datetime.now(timezone.utc).isoformat()

        if sub_phase and phase == ISOPhase.RESPONSE:
            target = record.phases[phase.value].sub_phases.get(sub_phase)
            if target:
                target.status = PhaseStatus.IN_PROGRESS.value
                target.started_at = now
                target.inputs = inputs
                target.module = module
                target.operator = operator
        else:
            target = record.phases[phase.value]
            target.status = PhaseStatus.IN_PROGRESS.value
            target.started_at = now
            target.inputs = inputs
            target.module = module
            target.operator = operator

        record.current_phase = phase.value
        record.last_updated = now
        self._persist(record)

        logger.info(
            "ISO 27035 [%s] %s → IN_PROGRESS (module=%s)",
            incident_id[:8], sub_phase or phase.value, module,
        )

    def complete_phase(
        self,
        incident_id: str,
        phase: ISOPhase,
        outputs: Dict[str, Any],
        requirements_met: Optional[List[str]] = None,
        compliance_notes: Optional[List[str]] = None,
        sub_phase: Optional[str] = None,
    ) -> None:
        """Mark a phase as completed and record its outputs.

        Args:
            incident_id: The incident ID.
            phase: The ISO phase to complete.
            outputs: The data produced by this phase.
            requirements_met: ISO requirements satisfied.
            compliance_notes: Additional compliance observations.
            sub_phase: Optional sub-phase key (for Phase 3).
        """
        record = self._records.get(incident_id)
        if not record:
            logger.warning("Incident %s not found", incident_id)
            return

        now = datetime.now(timezone.utc).isoformat()

        if sub_phase and phase == ISOPhase.RESPONSE:
            target = record.phases[phase.value].sub_phases.get(sub_phase)
        else:
            target = record.phases[phase.value]

        if not target:
            return

        target.status = PhaseStatus.COMPLETED.value
        target.completed_at = now
        target.outputs = outputs

        if requirements_met:
            target.requirements_met = requirements_met
        if compliance_notes:
            target.compliance_notes = compliance_notes

        # Calculate duration
        if target.started_at:
            start = datetime.fromisoformat(target.started_at)
            end = datetime.fromisoformat(now)
            target.duration_seconds = round((end - start).total_seconds(), 3)

        # Update overall progress
        completed = sum(
            1 for p in record.phases.values()
            if p.status == PhaseStatus.COMPLETED.value
        )
        record.total_phases_completed = completed
        record.last_updated = now

        if completed >= 5:
            record.overall_status = "closed"

        self._persist(record)

        logger.info(
            "ISO 27035 [%s] %s → COMPLETED (duration=%.1fs, reqs=%d/%d)",
            incident_id[:8], sub_phase or phase.value,
            target.duration_seconds or 0,
            len(target.requirements_met), len(target.requirements),
        )

    def update_summary(
        self,
        incident_id: str,
        severity: str = "",
        attack_type: str = "",
        risk_score: float = 0.0,
        risk_label: str = "",
    ) -> None:
        """Update the quick-view summary fields on the incident record."""
        record = self._records.get(incident_id)
        if not record:
            return
        if severity:
            record.severity = severity
        if attack_type:
            record.attack_type = attack_type
        if risk_score:
            record.risk_score = risk_score
        if risk_label:
            record.risk_label = risk_label
        self._persist(record)

    def get_record(self, incident_id: str) -> Optional[ISOIncidentRecord]:
        """Get the full ISO 27035 record for an incident."""
        return self._records.get(incident_id)

    def get_all_records(self) -> List[ISOIncidentRecord]:
        """Get all tracked incidents."""
        return list(self._records.values())

    def get_phase_state(
        self, incident_id: str, phase: ISOPhase,
    ) -> Optional[PhaseData]:
        """Get the state of a specific phase."""
        record = self._records.get(incident_id)
        if not record:
            return None
        return record.phases.get(phase.value)

    def to_dashboard_payload(self, incident_id: str) -> Optional[Dict]:
        """Export an incident as a JSON-serializable dashboard payload.

        This is what the SOC dashboard API consumes.
        """
        record = self._records.get(incident_id)
        if not record:
            return None
        return record.model_dump(mode="json")

    def get_all_dashboard_payloads(self) -> List[Dict]:
        """Export all incidents for the dashboard."""
        return [r.model_dump(mode="json") for r in self._records.values()]

    def _persist(self, record: ISOIncidentRecord) -> None:
        """Save the incident record to disk."""
        try:
            path = self._output_dir / f"iso_{record.incident_id[:8]}.json"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(record.model_dump_json(indent=2))
        except Exception as exc:
            logger.warning("Failed to persist ISO record: %s", exc)


# ── Global singleton ─────────────────────────────────────────────────
_tracker: Optional[ISO27035Tracker] = None


def get_iso_tracker() -> ISO27035Tracker:
    """Get or create the global ISO 27035 tracker instance."""
    global _tracker
    if _tracker is None:
        _tracker = ISO27035Tracker()
    return _tracker


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Every incident is tracked through the 5 phases of ISO 27035.
# 2. Each phase records inputs, outputs, timing, and compliance state.
# 3. The SOC dashboard reads from here for real-time phase progression.
# 4. Phase 3 (Response) has sub-phases: Containment, Eradication, Recovery.
# 5. Provides the compliance audit trail that regulators require.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os
    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    tracker = ISO27035Tracker()

    # Simulate a full incident lifecycle
    record = tracker.create_incident("10.0.0.40")

    # Phase 1: Detection
    tracker.start_phase(record.incident_id, ISOPhase.DETECTION, {
        "source": "ML Pipeline (LSTM + XGBoost)",
        "event_count": 47,
        "sessions": 3,
        "raw_logs": "auth.log, syslog, kern.log",
    }, module="kafka_producer.py")

    tracker.complete_phase(record.incident_id, ISOPhase.DETECTION, {
        "alert_id": "abc-123",
        "attack_type": "privilege_escalation",
        "confidence": 0.92,
        "model_source": "Ensemble",
        "mitre_techniques": ["T1068", "T1548"],
    }, requirements_met=[
        "Monitor information security events from multiple sources",
        "Correlate events to identify potential incidents",
    ])

    # Phase 2: Assessment
    tracker.start_phase(record.incident_id, ISOPhase.ASSESSMENT, {
        "enriched_alert_id": "abc-123",
        "max_cvss": 7.8,
        "entity_history_score": 92.0,
    }, module="enrichment_engine.py + verification_gate.py")

    tracker.complete_phase(record.incident_id, ISOPhase.ASSESSMENT, {
        "severity": "P1",
        "risk_score": 7.74,
        "risk_label": "HIGH",
        "gate_verdict": "CONFIRMED",
        "5d_decomposition": {
            "D1_vulnerability": 2.50,
            "D2_asset_criticality": 2.10,
            "D3_propagation": 2.00,
            "D4_history": 0.69,
            "D5_data_sensitivity": 0.45,
        },
        "asset_type": "infrastructure",
        "business_impact": "high",
    }, requirements_met=[
        "Classify the incident by type and severity",
        "Assess business impact (confidentiality, integrity, availability)",
        "Verify the incident is not a false positive",
    ])

    tracker.update_summary(
        record.incident_id,
        severity="P1", attack_type="privilege_escalation",
        risk_score=7.74, risk_label="HIGH",
    )

    # Phase 3: Response (with sub-phases)
    tracker.start_phase(record.incident_id, ISOPhase.RESPONSE, {
        "risk_verdict": "7.74 HIGH",
    }, module="isolator.py", sub_phase="containment")

    tracker.complete_phase(record.incident_id, ISOPhase.RESPONSE, {
        "actions": ["alert_soc", "network_quarantine", "user_lock"],
        "dry_run": True,
        "containment_strategy": "VLAN shunt (infrastructure asset)",
    }, sub_phase="containment", requirements_met=[
        "Isolate affected systems proportionally",
        "Preserve evidence before containment actions",
    ])

    tracker.start_phase(record.incident_id, ISOPhase.RESPONSE, {
        "cve_ids": ["CVE-2024-1086"],
    }, module="playbook.py", sub_phase="eradication")

    tracker.complete_phase(record.incident_id, ISOPhase.RESPONSE, {
        "patches_applied": ["CVE-2024-1086"],
        "persistence_removed": True,
    }, sub_phase="eradication", requirements_met=[
        "Remove threat actor access and persistence",
        "Patch exploited vulnerabilities",
    ])

    # Mark Phase 3 overall as complete
    tracker.complete_phase(record.incident_id, ISOPhase.RESPONSE, {
        "total_actions": 3,
        "playbook_steps": 18,
        "estimated_minutes": 540,
    }, requirements_met=[
        "Isolate affected systems proportionally",
        "Remove threat actor access and persistence",
    ])

    # Phase 4 & 5
    tracker.start_phase(record.incident_id, ISOPhase.LESSONS, {
        "review_scheduled": True,
    }, module="incident_analyzer.py")

    tracker.complete_phase(record.incident_id, ISOPhase.LESSONS, {
        "root_cause": "CVE-2024-1086 nf_tables use-after-free",
        "recommendations": [
            "Update kernel patching SLA to 48h for CRITICAL CVEs",
            "Add EPSS > 0.5 as auto-patch trigger",
        ],
    })

    tracker.start_phase(record.incident_id, ISOPhase.CLOSURE, {
        "report_id": "ffeed7a8",
    }, module="report_generator.py")

    tracker.complete_phase(record.incident_id, ISOPhase.CLOSURE, {
        "report_persisted": True,
        "blockchain_tx": "b4bd9785",
        "cert_dz_notified": True,
        "anpdp_notified": True,
        "management_signoff": "pending",
    }, requirements_met=[
        "Complete incident report with full timeline",
        "Archive all evidence with cryptographic integrity",
        "Submit regulatory notifications (CERT-DZ T+24h, ANPDP T+72h)",
    ])

    # Print the full lifecycle
    final = tracker.get_record(record.incident_id)
    logger.info("=" * 70)
    logger.info("ISO 27035 LIFECYCLE — %s (%s)",
                final.entity_id, final.overall_status)
    logger.info("=" * 70)

    for phase_name, phase_data in final.phases.items():
        status_icon = {
            "completed": "✅",
            "in_progress": "🔄",
            "pending": "⏳",
            "failed": "❌",
        }.get(phase_data.status, "❓")

        logger.info(
            "  %s %s [%s] — %s (%.1fs)",
            status_icon, phase_name, phase_data.iso_clause,
            phase_data.status, phase_data.duration_seconds or 0,
        )
        if phase_data.outputs:
            for k, v in list(phase_data.outputs.items())[:3]:
                logger.info("      → %s: %s", k, v)
        for sub_name, sub_data in phase_data.sub_phases.items():
            sub_icon = "✅" if sub_data.status == "completed" else "⏳"
            logger.info(
                "    %s ├── %s [%s] — %s",
                sub_icon, sub_name, sub_data.iso_clause, sub_data.status,
            )

    logger.info("")
    logger.info("Progress: %d/%d phases completed",
                final.total_phases_completed, final.total_phases)
    logger.info("ISO 27035 tracker demo complete ✓")
