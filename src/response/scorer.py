"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/response/scorer.py

Composite risk scoring engine that combines:
  1. CVSS vulnerability score (from Phase 2 CVE lookup)
  2. Asset criticality (from network_graph asset registry)
  3. Propagation score (from network_graph BFS analysis)
  4. Entity history (from Phase 2 EntityTracker)
  5. Baseline suspicion (from Phase 1 UEBA)

Formula (as specified in the architecture):
  risk_score = (cvss_base × 0.4) + (asset_criticality × 0.3)
             + (propagation_score × 0.3)

  where:
    propagation_score = min(10, count(reachable_high_value) × 2.5)

The scorer also handles severity downgrade when ML confidence < 0.6.
"""

from __future__ import annotations

import logging
from typing import Optional

from pydantic import BaseModel, Field

from src.config.settings import Severity
from src.enrichment.enrichment_engine import EnrichedAlert
from src.response.network_graph import NetworkGraph

logger = logging.getLogger(__name__)


# ── Scoring weights (5-dimensional) ──────────────────────────────────
WEIGHT_VULN: float = 0.25          # Vulnerability + EPSS + KEV
WEIGHT_CRITICALITY: float = 0.25   # Asset criticality + type
WEIGHT_PROPAGATION: float = 0.20   # Network BFS propagation
WEIGHT_HISTORY: float = 0.15       # Entity cumulative history
WEIGHT_DATA: float = 0.15          # Data classification sensitivity
PROPAGATION_MULTIPLIER: float = 2.5
PROPAGATION_CAP: float = 10.0
CONFIDENCE_DOWNGRADE_THRESHOLD: float = 0.6

# Data classification sensitivity scoring
_DATA_SENSITIVITY: dict = {
    "public": 1.0,
    "internal": 3.0,
    "confidential": 6.0,
    "restricted": 9.0,
}

# ── Severity ordering for downgrade logic ────────────────────────────
_SEVERITY_ORDER = [Severity.P1, Severity.P2, Severity.P3, Severity.P4]


class RiskVerdict(BaseModel):
    """The output of the risk scoring engine.

    Contains the full 5-dimensional risk decomposition so that
    dashboards, reports, and the isolator can explain WHY the
    score is what it is — not just the final number.
    """

    alert_id: str = Field(default="")
    entity_id: str = Field(default="")
    attack_type: str = Field(default="")
    asset_type: str = Field(default="unknown")
    asset_role: str = Field(default="unknown")
    business_impact: str = Field(default="unknown")
    data_classification: str = Field(default="unknown")
    original_severity: str = Field(default="P4")
    adjusted_severity: str = Field(default="P4")

    # 5-dimensional decomposition
    vuln_component: float = Field(default=0.0)
    criticality_component: float = Field(default=0.0)
    propagation_component: float = Field(default=0.0)
    history_component: float = Field(default=0.0)
    data_component: float = Field(default=0.0)

    # Legacy aliases for backward compat
    cvss_component: float = Field(default=0.0)
    propagation_score: float = Field(default=0.0)
    reachable_high_value: int = Field(default=0)

    # Intel sources
    epss_score: float = Field(default=0.0)
    is_kev: bool = Field(default=False)

    final_risk_score: float = Field(default=0.0)
    risk_label: str = Field(default="LOW")
    requires_isolation: bool = Field(default=False)
    scoring_sources: list = Field(default_factory=list)


def _downgrade_severity(severity: str) -> str:
    """Downgrade severity by one level."""
    try:
        current_idx = _SEVERITY_ORDER.index(Severity(severity))
        new_idx = min(current_idx + 1, len(_SEVERITY_ORDER) - 1)
        return _SEVERITY_ORDER[new_idx].value
    except (ValueError, IndexError):
        return Severity.P4.value


def _risk_label(score: float) -> str:
    """Convert a numeric risk score to a human label."""
    if score >= 8.0:
        return "CRITICAL"
    if score >= 6.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 2.0:
        return "LOW"
    return "INFO"


class RiskScorer:
    """5-Dimensional Contextual Risk Scoring Engine.

    Goes far beyond static CVSS by combining:
      D1: Vulnerability + EPSS + CISA KEV (exploit probability)
      D2: Asset criticality + type (server vs workstation vs router)
      D3: Network propagation risk (BFS to high-value assets)
      D4: Entity history (cumulative alerts over time)
      D5: Data classification sensitivity (public → restricted)

    Every dimension is sourced directly from the EnrichedAlert,
    which carries the full intelligence picture from Phase 2.
    """

    def __init__(
        self, network_graph: Optional[NetworkGraph] = None,
    ) -> None:
        self._graph = network_graph or NetworkGraph()
        logger.info("RiskScorer ready — 5D contextual scoring active")

    def score(self, enriched: EnrichedAlert) -> RiskVerdict:
        """Compute the 5-dimensional composite risk score.

        All context is consumed directly from the EnrichedAlert
        (single source of truth — no redundant queries).

        Args:
            enriched: The enriched alert from Phase 2.

        Returns:
            A RiskVerdict with full scoring decomposition.
        """
        alert = enriched.original_alert
        entity_id = alert.source_host
        attack_type = alert.attack_type
        sources = []

        # ── 1. Severity adjustment ───────────────────────────────────
        original_sev = alert.severity
        adjusted_sev = original_sev
        if alert.confidence < CONFIDENCE_DOWNGRADE_THRESHOLD:
            adjusted_sev = _downgrade_severity(original_sev)
            logger.info(
                "Confidence %.2f < %.2f → severity downgraded %s → %s",
                alert.confidence, CONFIDENCE_DOWNGRADE_THRESHOLD,
                original_sev, adjusted_sev,
            )

        # ── D1: Vulnerability + EPSS + KEV ───────────────────────────
        cvss_base = enriched.max_cvss
        if enriched.is_kev:
            vuln_raw = 10.0
            sources.append("CISA-KEV")
        else:
            vuln_raw = cvss_base + (enriched.epss_score * 5)
            vuln_raw = min(10.0, vuln_raw)
        if enriched.epss_score > 0.1:
            sources.append(f"EPSS({enriched.epss_score:.0%})")
        if cvss_base > 0:
            sources.append(f"CVSS({cvss_base:.1f})")
        vuln_component = vuln_raw * WEIGHT_VULN

        # ── D2: Asset criticality + type ─────────────────────────────
        asset_type = enriched.asset_type
        asset_role = enriched.asset_role
        asset_crit = self._graph.get_asset_criticality(entity_id)

        # Infrastructure multiplier: servers/routers are more critical
        if asset_type in ("server", "network", "infrastructure"):
            asset_crit_adj = min(10.0, asset_crit * 1.2)
            sources.append(f"AssetType({asset_type})")
        else:
            asset_crit_adj = float(asset_crit)

        crit_component = asset_crit_adj * WEIGHT_CRITICALITY

        # ── D3: Propagation risk ─────────────────────────────────────
        hv_assets = self._graph.get_reachable_high_value(entity_id)
        prop_raw = min(PROPAGATION_CAP, len(hv_assets) * PROPAGATION_MULTIPLIER)

        # Worm/scan amplification
        if attack_type in ("scan", "lateral_movement"):
            prop_raw = min(PROPAGATION_CAP, prop_raw * 2.0)

        prop_component = prop_raw * WEIGHT_PROPAGATION
        if hv_assets:
            sources.append(f"Propagation({len(hv_assets)}HV)")

        # ── D4: Entity history ───────────────────────────────────────
        entity_score = enriched.entity_cumulative_score
        entity_alerts = enriched.entity_alert_count
        # Normalize: 200+ cumulative points = max contribution
        history_raw = min(10.0, entity_score / 20.0)
        # Multi-stage escalation: if multiple DIFFERENT attack types seen
        if len(enriched.entity_attack_types) >= 3:
            history_raw = min(10.0, history_raw * 1.5)
            sources.append("MultiStage")
        history_component = history_raw * WEIGHT_HISTORY
        if entity_alerts > 1:
            sources.append(f"History({entity_alerts}alerts)")

        # ── D5: Data classification sensitivity ──────────────────────
        data_class = enriched.data_classification
        data_raw = _DATA_SENSITIVITY.get(data_class, 3.0)
        data_component = data_raw * WEIGHT_DATA
        if data_class in ("confidential", "restricted"):
            sources.append(f"Data({data_class})")

        # ── Final composite score ────────────────────────────────────
        final_score = round(
            vuln_component + crit_component + prop_component
            + history_component + data_component, 2,
        )

        # ── Isolation decision ───────────────────────────────────────
        requires_isolation = adjusted_sev in ("P1", "P2")
        label = _risk_label(final_score)

        verdict = RiskVerdict(
            alert_id=enriched.enriched_id,
            entity_id=entity_id,
            attack_type=attack_type,
            asset_type=asset_type,
            asset_role=asset_role,
            business_impact=enriched.business_impact,
            data_classification=data_class,
            original_severity=original_sev,
            adjusted_severity=adjusted_sev,
            vuln_component=round(vuln_component, 2),
            criticality_component=round(crit_component, 2),
            propagation_component=round(prop_component, 2),
            history_component=round(history_component, 2),
            data_component=round(data_component, 2),
            cvss_component=round(vuln_component, 2),  # backward compat
            propagation_score=round(prop_raw, 2),
            reachable_high_value=len(hv_assets),
            epss_score=enriched.epss_score,
            is_kev=enriched.is_kev,
            final_risk_score=final_score,
            risk_label=label,
            requires_isolation=requires_isolation,
            scoring_sources=sources,
        )

        logger.info(
            "RISK VERDICT [%s] entity=%s (%s/%s) → %.2f (%s)  "
            "D1=%.1f D2=%.1f D3=%.1f D4=%.1f D5=%.1f  "
            "KEV=%s EPSS=%.2f  sources=%s",
            verdict.alert_id[:8], entity_id, asset_type, asset_role,
            final_score, label,
            vuln_component, crit_component, prop_component,
            history_component, data_component,
            enriched.is_kev, enriched.epss_score, sources,
        )
        return verdict


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Implements the composite risk formula from the AEGIS spec.
# 2. Handles severity downgrade for low-confidence alerts.
# 3. Produces the RiskVerdict that drives isolation decisions.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os

    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    from src.enrichment.enrichment_engine import EnrichmentEngine
    from src.parsing.models import ModelAlert

    engine = EnrichmentEngine()
    scorer = RiskScorer()

    logger.info("=" * 60)
    logger.info("RISK SCORER DEMO")
    logger.info("=" * 60)

    alerts = [
        ModelAlert(
            severity="P1", attack_type="privilege_escalation",
            confidence=0.92, source_host="10.0.0.40",
            affected_assets=["10.0.0.10"],
        ),
        ModelAlert(
            severity="P2", attack_type="ssh_bruteforce",
            confidence=0.45, source_host="10.0.0.1",
        ),
        ModelAlert(
            severity="P4", attack_type="anomaly_unknown",
            confidence=0.30, source_host="192.168.1.200",
        ),
    ]

    for alert in alerts:
        enriched = engine.enrich(alert)
        verdict = scorer.score(enriched)
        logger.info(
            "  → %s: score=%.2f (%s) isolate=%s",
            verdict.entity_id, verdict.final_risk_score,
            verdict.risk_label, verdict.requires_isolation,
        )

    logger.info("RiskScorer demo complete ✓")
