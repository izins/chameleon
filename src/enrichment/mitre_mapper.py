"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/enrichment/mitre_mapper.py

Maps attack types and event patterns to MITRE ATT&CK techniques.

In production, this would query the MITRE ATT&CK STIX database.
For the hackathon, we use a curated local mapping that covers the
attack types defined in settings.AttackType.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from src.config.settings import AttackType

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MitreTechnique:
    """A single MITRE ATT&CK technique reference.

    Attributes:
        technique_id: ATT&CK ID (e.g. "T1110").
        name: Human-readable name.
        tactic: Kill-chain phase (e.g. "Credential Access").
        url: Link to the ATT&CK page.
        severity_weight: Base risk score weight (0-100).
    """

    technique_id: str
    name: str
    tactic: str
    url: str
    severity_weight: float = 50.0


# ── Curated Mapping ──────────────────────────────────────────────────
_ATTACK_TO_MITRE: Dict[str, List[MitreTechnique]] = {
    AttackType.SSH_BRUTEFORCE.value: [
        MitreTechnique(
            "T1110", "Brute Force", "Credential Access",
            "https://attack.mitre.org/techniques/T1110/", 60.0,
        ),
        MitreTechnique(
            "T1110.001", "Password Guessing", "Credential Access",
            "https://attack.mitre.org/techniques/T1110/001/", 50.0,
        ),
    ],
    AttackType.SQL_INJECTION.value: [
        MitreTechnique(
            "T1190", "Exploit Public-Facing Application",
            "Initial Access",
            "https://attack.mitre.org/techniques/T1190/", 80.0,
        ),
    ],
    AttackType.LATERAL_MOVEMENT.value: [
        MitreTechnique(
            "T1021", "Remote Services", "Lateral Movement",
            "https://attack.mitre.org/techniques/T1021/", 70.0,
        ),
        MitreTechnique(
            "T1021.004", "SSH", "Lateral Movement",
            "https://attack.mitre.org/techniques/T1021/004/", 65.0,
        ),
    ],
    AttackType.DATA_EXFIL.value: [
        MitreTechnique(
            "T1041", "Exfiltration Over C2 Channel", "Exfiltration",
            "https://attack.mitre.org/techniques/T1041/", 90.0,
        ),
    ],
    AttackType.PRIVILEGE_ESCALATION.value: [
        MitreTechnique(
            "T1068", "Exploitation for Privilege Escalation",
            "Privilege Escalation",
            "https://attack.mitre.org/techniques/T1068/", 85.0,
        ),
        MitreTechnique(
            "T1548", "Abuse Elevation Control Mechanism",
            "Privilege Escalation",
            "https://attack.mitre.org/techniques/T1548/", 75.0,
        ),
    ],
    AttackType.ANOMALY_UNKNOWN.value: [
        MitreTechnique(
            "T1071", "Application Layer Protocol", "Command and Control",
            "https://attack.mitre.org/techniques/T1071/", 40.0,
        ),
    ],
}


class MitreMapper:
    """Maps attack types to MITRE ATT&CK techniques.

    Args:
        custom_mappings: Optional additional mappings to merge.
    """

    def __init__(
        self, custom_mappings: Optional[Dict[str, List[MitreTechnique]]] = None
    ) -> None:
        self._map = dict(_ATTACK_TO_MITRE)
        if custom_mappings:
            self._map.update(custom_mappings)
        logger.info(
            "MitreMapper ready — %d attack types mapped", len(self._map)
        )

    def lookup(self, attack_type: str) -> List[MitreTechnique]:
        """Get MITRE techniques for an attack type.

        Args:
            attack_type: Attack type string (from ModelAlert).

        Returns:
            List of matching MitreTechnique objects (may be empty).
        """
        techniques = self._map.get(attack_type, [])
        if not techniques:
            logger.debug("No MITRE mapping for attack_type=%s", attack_type)
        return techniques

    def get_primary_technique(self, attack_type: str) -> Optional[MitreTechnique]:
        """Get the highest-severity technique for an attack type.

        Args:
            attack_type: Attack type string.

        Returns:
            The MitreTechnique with the highest severity_weight, or None.
        """
        techniques = self.lookup(attack_type)
        if not techniques:
            return None
        return max(techniques, key=lambda t: t.severity_weight)

    def get_kill_chain_phase(self, attack_type: str) -> str:
        """Get the primary kill-chain tactic for an attack type.

        Args:
            attack_type: Attack type string.

        Returns:
            Tactic name, or "Unknown".
        """
        primary = self.get_primary_technique(attack_type)
        return primary.tactic if primary else "Unknown"


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Every alert gets a MITRE ATT&CK label so analysts can immediately
#    see where the attack sits in the kill chain.
# 2. The severity_weight feeds into the risk scoring engine (Phase 3).
# 3. Accumulating different MITRE techniques for one entity reveals
#    multi-stage attacks (e.g. Credential Access → Lateral Movement →
#    Privilege Escalation → Exfiltration).
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level="DEBUG")

    mapper = MitreMapper()
    for attack in AttackType:
        techniques = mapper.lookup(attack.value)
        primary = mapper.get_primary_technique(attack.value)
        logger.info(
            "  %s → %s (primary: %s, tactic: %s)",
            attack.value,
            [t.technique_id for t in techniques],
            primary.technique_id if primary else "None",
            mapper.get_kill_chain_phase(attack.value),
        )
    logger.info("MitreMapper demo complete ✓")
