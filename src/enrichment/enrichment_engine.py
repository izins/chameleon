"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/enrichment/enrichment_engine.py

The central orchestrator for Phase 2. Takes a raw ModelAlert from the
ML models and produces an EnrichedAlert by:
  1. Looking up MITRE ATT&CK techniques.
  2. Finding relevant CVEs.
  3. Updating the Entity History Tracker (solving spaced events).
  4. Computing an initial risk score.

The output (EnrichedAlert) is what Phase 3 consumes for final scoring
and isolation decisions.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from src.config.settings import settings
from src.enrichment.cve_lookup import CVEEntry, CVELookup
from src.enrichment.entity_tracker import EntityRecord, EntityTracker
from src.enrichment.mitre_mapper import MitreMapper, MitreTechnique
from src.parsing.models import ModelAlert

logger = logging.getLogger(__name__)


# ── Enriched Alert Model ─────────────────────────────────────────────
class EnrichedAlert(BaseModel):
    """A ModelAlert enriched with CVE, MITRE, entity history, and asset context.

    This is the output of Phase 2 and the input for Phase 3 (Scoring).
    Carries the full intelligence picture so every downstream module
    (Scorer, Isolator, Playbook, Report) can make context-aware decisions.
    """

    enriched_id: str = Field(default_factory=lambda: str(uuid4()))
    original_alert: ModelAlert
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    # MITRE ATT&CK enrichment
    mitre_techniques: List[str] = Field(default_factory=list)
    mitre_tactic: str = Field(default="Unknown")
    mitre_severity_weight: float = Field(default=0.0)

    # CVE enrichment
    cve_ids: List[str] = Field(default_factory=list)
    max_cvss: float = Field(default=0.0)

    # Entity history (the "memory" that catches spaced attacks)
    entity_cumulative_score: float = Field(default=0.0)
    entity_alert_count: int = Field(default=0)
    entity_attack_types: List[str] = Field(default_factory=list)
    entity_mitre_timeline: List[str] = Field(default_factory=list)

    # Asset context (Phase 2.5 — carried forward from CMDB/NetworkGraph)
    asset_type: str = Field(default="unknown")
    asset_role: str = Field(default="unknown")
    business_impact: str = Field(default="unknown")
    data_classification: str = Field(default="unknown")
    asset_owner: str = Field(default="unknown")

    # External threat intel summary
    epss_score: float = Field(default=0.0)
    is_kev: bool = Field(default=False)

    # Pre-scoring
    initial_risk_score: float = Field(default=0.0)


# ── Risk score formula ───────────────────────────────────────────────
WEIGHT_CONFIDENCE: float = 30.0
WEIGHT_MITRE: float = 25.0
WEIGHT_CVSS: float = 25.0
WEIGHT_HISTORY: float = 20.0


def _compute_initial_risk(
    confidence: float,
    mitre_weight: float,
    max_cvss: float,
    entity_score: float,
) -> float:
    """Compute a pre-scoring risk estimate (0-100).

    Formula:
        risk = (confidence × 30) + (mitre_weight/100 × 25)
             + (cvss/10 × 25) + min(entity_score/100 × 20, 20)

    Args:
        confidence: ML model confidence (0.0 - 1.0).
        mitre_weight: MITRE severity weight (0 - 100).
        max_cvss: Highest CVSS score (0.0 - 10.0).
        entity_score: Cumulative entity risk score.

    Returns:
        Risk score between 0 and 100.
    """
    risk = (
        (confidence * WEIGHT_CONFIDENCE)
        + (mitre_weight / 100.0 * WEIGHT_MITRE)
        + (max_cvss / 10.0 * WEIGHT_CVSS)
        + min(entity_score / 100.0 * WEIGHT_HISTORY, WEIGHT_HISTORY)
    )
    return round(min(max(risk, 0.0), 100.0), 2)


class EnrichmentEngine:
    """Orchestrates the full enrichment pipeline for Phase 2.

    Args:
        mitre_mapper: MitreMapper instance.
        cve_lookup: CVELookup instance.
        entity_tracker: EntityTracker instance.
    """

    def __init__(
        self,
        mitre_mapper: Optional[MitreMapper] = None,
        cve_lookup: Optional[CVELookup] = None,
        entity_tracker: Optional[EntityTracker] = None,
    ) -> None:
        self._mitre = mitre_mapper or MitreMapper()
        self._cve = cve_lookup or CVELookup()
        self._tracker = entity_tracker or EntityTracker()
        logger.info("EnrichmentEngine ready")

    def enrich(self, alert: ModelAlert) -> EnrichedAlert:
        """Enrich a raw ModelAlert with full context.

        Steps:
          1. MITRE ATT&CK mapping.
          2. CVE lookup.
          3. Entity history update (cumulative score).
          4. Asset context lookup (CMDB / NetworkGraph).
          5. External intel enrichment (EPSS, KEV).
          6. Initial risk score computation.

        Args:
            alert: The raw ModelAlert from the ML models.

        Returns:
            A fully enriched EnrichedAlert.
        """
        # 1. MITRE ATT&CK
        techniques = self._mitre.lookup(alert.attack_type)
        primary = self._mitre.get_primary_technique(alert.attack_type)
        mitre_ids = [t.technique_id for t in techniques]
        mitre_tactic = primary.tactic if primary else "Unknown"
        mitre_weight = primary.severity_weight if primary else 0.0

        # 2. CVE lookup
        cves = self._cve.lookup_by_attack(alert.attack_type)
        cve_ids = [c.cve_id for c in cves]
        max_cvss = self._cve.get_max_cvss(alert.attack_type)

        # 3. Entity history update — THIS SOLVES SPACED EVENTS
        entity_id = alert.source_host
        score_delta = alert.confidence * 100  # Convert confidence to points
        entity_rec = self._tracker.update(
            entity_id=entity_id,
            alert_id=alert.alert_id,
            score_delta=score_delta,
            attack_type=alert.attack_type,
            mitre_technique=mitre_ids[0] if mitre_ids else "",
            categories=[],
            source_ips=alert.affected_assets,
            severity=alert.severity,
            confidence=alert.confidence,
        )

        # 4. Asset context lookup — WHAT is this machine?
        asset_ctx = self._lookup_asset_context(entity_id)

        # 5. External intel enrichment — Is this CVE actively exploited?
        epss_score, is_kev = self._lookup_external_intel(
            alert.attack_type, max_cvss, cve_ids,
        )

        # 6. Compute initial risk score
        initial_risk = _compute_initial_risk(
            confidence=alert.confidence,
            mitre_weight=mitre_weight,
            max_cvss=max_cvss,
            entity_score=entity_rec.cumulative_score,
        )

        enriched = EnrichedAlert(
            original_alert=alert,
            mitre_techniques=mitre_ids,
            mitre_tactic=mitre_tactic,
            mitre_severity_weight=mitre_weight,
            cve_ids=cve_ids,
            max_cvss=max_cvss,
            entity_cumulative_score=entity_rec.cumulative_score,
            entity_alert_count=entity_rec.alert_count,
            entity_attack_types=entity_rec.attack_types,
            entity_mitre_timeline=entity_rec.mitre_techniques,
            asset_type=asset_ctx.get("asset_type", "unknown"),
            asset_role=asset_ctx.get("role", "unknown"),
            business_impact=asset_ctx.get("business_impact", "unknown"),
            data_classification=asset_ctx.get("data_classification", "unknown"),
            asset_owner=asset_ctx.get("owner", "unknown"),
            epss_score=epss_score,
            is_kev=is_kev,
            initial_risk_score=initial_risk,
        )

        logger.info(
            "Enriched alert %s — entity=%s  risk=%.1f  mitre=%s  "
            "cvss=%.1f  entity_score=%.1f  entity_alerts=%d",
            enriched.enriched_id[:8],
            entity_id,
            initial_risk,
            mitre_ids,
            max_cvss,
            entity_rec.cumulative_score,
            entity_rec.alert_count,
        )
        return enriched

    # ── Asset Context Lookup ─────────────────────────────────────────

    def _lookup_asset_context(self, entity_id: str) -> Dict:
        """Query the asset registry (CMDB / NetworkGraph) for machine context.

        In production this queries ServiceNow, GLPI, or a CMDB API.
        In demo mode it reads from NetworkGraph._assets.
        """
        try:
            from src.response.network_graph import NetworkGraph
            graph = NetworkGraph()
            return graph.get_asset_details(entity_id)
        except Exception:
            return {"asset_type": "unknown", "role": "unknown",
                    "business_impact": "unknown", "data_classification": "unknown",
                    "owner": "unknown", "criticality": 5}

    # ── External Intel Enrichment ────────────────────────────────────

    def _lookup_external_intel(
        self, attack_type: str, max_cvss: float, cve_ids: List[str],
    ) -> tuple:
        """Query EPSS and CISA KEV for exploit probability.

        In production: hits https://api.first.org/data/v1/epss
        and https://www.cisa.gov/known-exploited-vulnerabilities-catalog

        Returns:
            Tuple of (epss_score, is_kev).
        """
        # ── CISA KEV simulation ──────────────────────────────────────
        # These CVEs are in the real CISA KEV catalog
        _SIMULATED_KEV = {
            "CVE-2024-6387",   # regreSSHion
            "CVE-2024-38476",  # Apache SSRF
            "CVE-2024-1086",   # nf_tables LPE
        }
        is_kev = bool(set(cve_ids) & _SIMULATED_KEV)

        # ── EPSS simulation ──────────────────────────────────────────
        # EPSS gives a 0-1 probability that a CVE will be exploited
        _EPSS_BY_ATTACK = {
            "data_exfil": 0.82,
            "privilege_escalation": 0.65,
            "sql_injection": 0.58,
            "ssh_bruteforce": 0.42,
            "lateral_movement": 0.55,
            "anomaly_unknown": 0.05,
        }
        epss = _EPSS_BY_ATTACK.get(attack_type, 0.05)

        # Boost EPSS if CVSS is very high
        if max_cvss >= 9.0:
            epss = max(epss, 0.75)

        return round(epss, 2), is_kev


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Transforms a raw ML alert into a context-rich enriched alert.
# 2. Integrates three enrichment sources: MITRE, CVE, Entity History.
# 3. The Entity History Tracker provides the "memory" that catches
#    spaced-out attacks across days or weeks.
# 4. Computes an initial risk score that Phase 3 will refine.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os

    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    logger.info("=" * 70)
    logger.info("ENRICHMENT ENGINE DEMO — Low & Slow attack detection")
    logger.info("=" * 70)

    engine = EnrichmentEngine()

    # Simulate spaced-out alerts from the same attacker
    alerts = [
        ModelAlert(
            severity="P3", attack_type="ssh_bruteforce",
            confidence=0.60, source_host="192.168.1.100",
            affected_assets=["10.0.0.5"], model_source="DeepLog",
            raw_sequence=[5, 5, 5, 22], anomaly_score=-0.3,
        ),
        ModelAlert(
            severity="P3", attack_type="lateral_movement",
            confidence=0.70, source_host="192.168.1.100",
            affected_assets=["10.0.0.5", "10.0.0.6"],
            model_source="IsolationForest", anomaly_score=-0.6,
        ),
        ModelAlert(
            severity="P2", attack_type="privilege_escalation",
            confidence=0.90, source_host="192.168.1.100",
            affected_assets=["10.0.0.5"], model_source="XGBoost",
            xgb_proba={"privilege_escalation": 0.9, "normal": 0.1},
        ),
    ]

    labels = ["Monday (SSH brute-force)", "Wednesday (Lateral move)",
              "Friday (Privilege escalation)"]

    for label, alert in zip(labels, alerts):
        logger.info("")
        logger.info("▶ %s", label)
        enriched = engine.enrich(alert)
        logger.info("  MITRE:         %s (%s)", enriched.mitre_techniques,
                     enriched.mitre_tactic)
        logger.info("  CVEs:          %s (max CVSS=%.1f)", enriched.cve_ids,
                     enriched.max_cvss)
        logger.info("  Entity Score:  %.1f (alerts=%d, types=%s)",
                     enriched.entity_cumulative_score,
                     enriched.entity_alert_count,
                     enriched.entity_attack_types)
        logger.info("  MITRE Timeline: %s ← multi-stage visible!",
                     enriched.entity_mitre_timeline)
        logger.info("  RISK SCORE:    %.1f / 100", enriched.initial_risk_score)

    logger.info("")
    logger.info("Enrichment demo complete ✓")
