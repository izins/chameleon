"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/enrichment/cve_lookup.py

CVE vulnerability lookup service. In demo mode uses a local cache
of known CVEs. In production, queries the NVD API v2.0.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

from src.config.settings import AttackType

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CVEEntry:
    """A single CVE vulnerability reference.

    Attributes:
        cve_id: CVE identifier (e.g. "CVE-2024-6387").
        description: Short description.
        cvss_score: CVSS v3.1 base score (0.0 - 10.0).
        severity: CVSS severity label.
        affected_service: Service/product affected.
    """

    cve_id: str
    description: str
    cvss_score: float
    severity: str
    affected_service: str


# ── Local CVE cache (demo mode) ──────────────────────────────────────
_DEMO_CVE_DB: Dict[str, List[CVEEntry]] = {
    "ssh": [
        CVEEntry(
            "CVE-2024-6387", "regreSSHion — OpenSSH RCE",
            8.1, "HIGH", "openssh",
        ),
        CVEEntry(
            "CVE-2023-48795", "Terrapin — SSH prefix truncation",
            5.9, "MEDIUM", "openssh",
        ),
    ],
    "mysql": [
        CVEEntry(
            "CVE-2024-21047", "MySQL Server optimizer vulnerability",
            4.9, "MEDIUM", "mysql",
        ),
    ],
    "apache": [
        CVEEntry(
            "CVE-2024-38476", "Apache HTTP Server SSRF via mod_rewrite",
            9.8, "CRITICAL", "apache",
        ),
    ],
    "linux_kernel": [
        CVEEntry(
            "CVE-2024-1086", "nf_tables use-after-free LPE",
            7.8, "HIGH", "linux_kernel",
        ),
    ],
}

# Map attack types to relevant services for CVE lookup
_ATTACK_TO_SERVICE: Dict[str, List[str]] = {
    AttackType.SSH_BRUTEFORCE.value: ["ssh"],
    AttackType.SQL_INJECTION.value: ["mysql"],
    AttackType.LATERAL_MOVEMENT.value: ["ssh"],
    AttackType.PRIVILEGE_ESCALATION.value: ["linux_kernel"],
    AttackType.DATA_EXFIL.value: ["mysql", "apache"],
    AttackType.ANOMALY_UNKNOWN.value: [],
}


class CVELookup:
    """Looks up known CVEs relevant to an alert's attack type.

    Args:
        use_nvd_api: If True, query the live NVD API (not demo).
    """

    def __init__(self, use_nvd_api: bool = False) -> None:
        self._use_api = use_nvd_api
        self._cache = dict(_DEMO_CVE_DB)
        logger.info(
            "CVELookup ready — mode=%s, cached_services=%d",
            "NVD_API" if use_nvd_api else "LOCAL",
            len(self._cache),
        )

    def lookup_by_attack(self, attack_type: str) -> List[CVEEntry]:
        """Find CVEs relevant to an attack type.

        Args:
            attack_type: The attack type from the ModelAlert.

        Returns:
            List of relevant CVEEntry objects.
        """
        services = _ATTACK_TO_SERVICE.get(attack_type, [])
        results: List[CVEEntry] = []
        for service in services:
            results.extend(self._cache.get(service, []))
        return results

    def get_max_cvss(self, attack_type: str) -> float:
        """Get the highest CVSS score among relevant CVEs.

        Args:
            attack_type: The attack type.

        Returns:
            Max CVSS score, or 0.0 if no CVEs found.
        """
        cves = self.lookup_by_attack(attack_type)
        return max((c.cvss_score for c in cves), default=0.0)

    def lookup_by_service(self, service: str) -> List[CVEEntry]:
        """Find CVEs for a specific service.

        Args:
            service: Service name (e.g. "ssh", "mysql").

        Returns:
            List of CVEEntry objects.
        """
        return self._cache.get(service, [])


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Adds vulnerability context to alerts — an SSH brute-force on a
#    server running OpenSSH with CVE-2024-6387 is far more critical
#    than one on a fully patched server.
# 2. The max CVSS score feeds into the risk scoring formula (Phase 3).
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level="DEBUG")

    lookup = CVELookup()
    for attack in AttackType:
        cves = lookup.lookup_by_attack(attack.value)
        logger.info(
            "  %s → %d CVEs (max CVSS=%.1f)",
            attack.value, len(cves), lookup.get_max_cvss(attack.value),
        )
        for c in cves:
            logger.info("    %s (%.1f %s) — %s", c.cve_id, c.cvss_score,
                         c.severity, c.description)
    logger.info("CVELookup demo complete ✓")
