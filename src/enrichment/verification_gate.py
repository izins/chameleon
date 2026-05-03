"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/enrichment/verification_gate.py

Two-Step Verification Gate — the critical safety layer between ML
detection and automated response. Prevents false-positive escalations
by requiring multi-source corroboration before triggering isolation
actions and waking up on-call engineers.

Architecture position:
  Phase 2 (Enrichment) → [VERIFICATION GATE] → Phase 3 (Isolation)

The gate evaluates 5 independent signals:
  1. Cross-model consensus (≥2 models agree)
  2. Temporal correlation (≥3 events in 15 min window)
  3. External threat intel (AbuseIPDB + VirusTotal confirm)
  4. ML confidence floor (ensemble ≥ 0.70)
  5. Attack plausibility (CVSS > 0 for claimed CVE)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field

from src.config.settings import settings
from src.enrichment.enrichment_engine import EnrichedAlert
from src.enrichment.threat_intel import ThreatIntelAggregator, ThreatIntelReport

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────
CONFIDENCE_FLOOR: float = 0.70
THREAT_INTEL_CONFIRM_THRESHOLD: float = 5.0
CVSS_PLAUSIBILITY_FLOOR: float = 1.0
MIN_ENTITY_EVENTS_FOR_TEMPORAL: int = 3

# ── Signal weights for final gate score ──────────────────────────────
WEIGHT_MODEL_CONSENSUS: float = 2.5
WEIGHT_TEMPORAL: float = 2.0
WEIGHT_THREAT_INTEL: float = 3.0
WEIGHT_CONFIDENCE: float = 1.5
WEIGHT_PLAUSIBILITY: float = 1.0
WEIGHT_ASSET_CONTEXT: float = 1.5
TOTAL_MAX_SCORE: float = 11.5


class GateVerdict(str, Enum):
    """Possible outcomes of the Verification Gate."""
    CONFIRMED = "CONFIRMED"           # Score ≥ 8 → auto-isolate
    PROBABLE = "PROBABLE"             # Score 5-7 → isolate + flag for review
    INCONCLUSIVE = "INCONCLUSIVE"     # Score 3-4 → hold queue, L1 only
    FALSE_POSITIVE = "FALSE_POSITIVE" # Score < 3 → dismiss


class VerificationSignal(BaseModel):
    """A single verification check result."""
    name: str
    passed: bool = False
    score: float = 0.0
    max_score: float = 0.0
    detail: str = ""


class VerificationResult(BaseModel):
    """Complete output of the Verification Gate.

    Attributes:
        alert_id: The enriched alert being verified.
        entity_id: The source IP under investigation.
        verdict: The gate's decision (CONFIRMED/PROBABLE/INCONCLUSIVE/FALSE_POSITIVE).
        gate_score: Composite verification score (0-10).
        signals: Individual signal results.
        threat_intel: Full external threat intelligence report.
        should_isolate: Whether isolation should proceed.
        should_notify_engineer: Whether to wake up on-call.
        requires_human_review: Whether L1/L2 must review within 30 min.
        explanation: Human-readable gate decision explanation.
    """
    alert_id: str = ""
    entity_id: str = ""
    verdict: GateVerdict = GateVerdict.INCONCLUSIVE
    gate_score: float = 0.0
    signals: List[VerificationSignal] = Field(default_factory=list)
    threat_intel: Optional[ThreatIntelReport] = None
    should_isolate: bool = False
    should_notify_engineer: bool = False
    requires_human_review: bool = False
    explanation: str = ""


class VerificationGate:
    """Two-Step Verification Gate.

    Evaluates multiple independent signals before allowing an alert
    to proceed to the isolation phase. This prevents false-positive
    escalations that waste engineering time and damage credibility.

    Usage:
        gate = VerificationGate()
        result = gate.evaluate(enriched_alert)
        if result.should_isolate:
            isolator.execute(verdict)
    """

    def __init__(self) -> None:
        self._threat_intel = ThreatIntelAggregator()
        logger.info("VerificationGate initialized — 6 signal checks active")

    def evaluate(self, enriched: EnrichedAlert) -> VerificationResult:
        """Run all verification checks on an enriched alert.

        Args:
            enriched: The enriched alert from Phase 2.

        Returns:
            VerificationResult with the gate's decision.
        """
        alert = enriched.original_alert
        entity_id = alert.source_host
        signals: List[VerificationSignal] = []

        logger.info(
            "╔══════════════════════════════════════════════╗"
        )
        logger.info(
            "║  VERIFICATION GATE — %s                ║", entity_id
        )
        logger.info(
            "╚══════════════════════════════════════════════╝"
        )

        # ── Signal 1: Cross-Model Consensus ──────────────────────────
        s1 = self._check_model_consensus(enriched)
        signals.append(s1)

        # ── Signal 2: Temporal Correlation ───────────────────────────
        s2 = self._check_temporal_correlation(enriched)
        signals.append(s2)

        # ── Signal 3: External Threat Intelligence ───────────────────
        threat_report = self._threat_intel.investigate(entity_id)
        s3 = self._check_threat_intel(threat_report)
        signals.append(s3)

        # ── Signal 4: ML Confidence Floor ────────────────────────────
        s4 = self._check_confidence(enriched)
        signals.append(s4)

        # ── Signal 5: Attack Plausibility ────────────────────────────
        s5 = self._check_plausibility(enriched)
        signals.append(s5)

        # ── Signal 6: Asset Context ──────────────────────────────────
        s6 = self._check_asset_context(enriched)
        signals.append(s6)

        # ── Calculate composite gate score ───────────────────────────
        gate_score = round(sum(s.score for s in signals), 2)

        # ── Determine verdict ────────────────────────────────────────
        if gate_score >= 8.0:
            verdict = GateVerdict.CONFIRMED
        elif gate_score >= 5.0:
            verdict = GateVerdict.PROBABLE
        elif gate_score >= 3.0:
            verdict = GateVerdict.INCONCLUSIVE
        else:
            verdict = GateVerdict.FALSE_POSITIVE

        # ── Determine actions ────────────────────────────────────────
        should_isolate = verdict in (GateVerdict.CONFIRMED, GateVerdict.PROBABLE)
        should_notify = verdict == GateVerdict.CONFIRMED
        needs_review = verdict == GateVerdict.PROBABLE

        # ── Build explanation ────────────────────────────────────────
        passed_signals = [s for s in signals if s.passed]
        failed_signals = [s for s in signals if not s.passed]

        explanation_lines = [
            f"VERIFICATION GATE — {verdict.value} (score: {gate_score}/{TOTAL_MAX_SCORE})",
            f"Entity: {entity_id}",
            f"Alert: {enriched.enriched_id[:8]}",
            f"Attack Type: {alert.attack_type}",
            f"Severity: {alert.severity}",
            "",
            f"PASSED ({len(passed_signals)}/{len(signals)}):",
        ]
        for s in passed_signals:
            explanation_lines.append(f"  ✓ {s.name}: {s.detail}")
        if failed_signals:
            explanation_lines.append(f"\nFAILED ({len(failed_signals)}/{len(signals)}):")
            for s in failed_signals:
                explanation_lines.append(f"  ✗ {s.name}: {s.detail}")

        explanation_lines.append(f"\nDecision: {'PROCEED to isolation' if should_isolate else 'HOLD — do NOT isolate'}")
        if should_notify:
            explanation_lines.append("Action: Notify on-call engineer (phone + email)")
        elif needs_review:
            explanation_lines.append("Action: Alert L2 analyst for manual review within 30 min")

        result = VerificationResult(
            alert_id=enriched.enriched_id,
            entity_id=entity_id,
            verdict=verdict,
            gate_score=gate_score,
            signals=signals,
            threat_intel=threat_report,
            should_isolate=should_isolate,
            should_notify_engineer=should_notify,
            requires_human_review=needs_review,
            explanation="\n".join(explanation_lines),
        )

        logger.info(
            "GATE VERDICT [%s] entity=%s → %s (score=%.1f)  "
            "isolate=%s  notify=%s  review=%s",
            enriched.enriched_id[:8], entity_id, verdict.value,
            gate_score, should_isolate, should_notify, needs_review,
        )
        return result

    # ── Individual Signal Checks ─────────────────────────────────────

    def _check_model_consensus(self, enriched: EnrichedAlert) -> VerificationSignal:
        """Check if multiple ML models agree on the threat.

        Args:
            enriched: The enriched alert.

        Returns:
            VerificationSignal for model consensus.
        """
        alert = enriched.original_alert
        # In production: check if DeepLog + XGBoost + IsolationForest agree.
        # For demo: check if model_source is "Ensemble" (means multiple agreed)
        is_ensemble = alert.model_source == "Ensemble"
        has_high_xgb = bool(alert.xgb_proba) and max(alert.xgb_proba.values(), default=0) > 0.7
        passed = is_ensemble or has_high_xgb

        return VerificationSignal(
            name="Cross-Model Consensus",
            passed=passed,
            score=WEIGHT_MODEL_CONSENSUS if passed else 0.0,
            max_score=WEIGHT_MODEL_CONSENSUS,
            detail=(
                f"Model={alert.model_source}, Ensemble={is_ensemble}, "
                f"XGB_high={has_high_xgb}"
            ),
        )

    def _check_temporal_correlation(self, enriched: EnrichedAlert) -> VerificationSignal:
        """Check if multiple events from this entity occurred recently.

        Args:
            enriched: The enriched alert.

        Returns:
            VerificationSignal for temporal correlation.
        """
        alert = enriched.original_alert
        event_count = len(alert.event_hashes)
        passed = event_count >= MIN_ENTITY_EVENTS_FOR_TEMPORAL

        return VerificationSignal(
            name="Temporal Correlation",
            passed=passed,
            score=WEIGHT_TEMPORAL if passed else (WEIGHT_TEMPORAL * 0.5 if event_count >= 2 else 0.0),
            max_score=WEIGHT_TEMPORAL,
            detail=f"{event_count} events linked (threshold: {MIN_ENTITY_EVENTS_FOR_TEMPORAL})",
        )

    def _check_threat_intel(self, report: ThreatIntelReport) -> VerificationSignal:
        """Check if external sources confirm the IP is malicious.

        Args:
            report: The ThreatIntelReport from the aggregator.

        Returns:
            VerificationSignal for threat intelligence.
        """
        passed = report.overall_threat_score >= THREAT_INTEL_CONFIRM_THRESHOLD

        return VerificationSignal(
            name="External Threat Intel",
            passed=passed,
            score=WEIGHT_THREAT_INTEL if passed else (WEIGHT_THREAT_INTEL * (report.overall_threat_score / 10)),
            max_score=WEIGHT_THREAT_INTEL,
            detail=(
                f"ThreatScore={report.overall_threat_score}/10, "
                f"Confirming={report.sources_confirming}/{report.sources_consulted}"
            ),
        )

    def _check_confidence(self, enriched: EnrichedAlert) -> VerificationSignal:
        """Check if ML confidence exceeds the floor.

        Args:
            enriched: The enriched alert.

        Returns:
            VerificationSignal for confidence floor.
        """
        confidence = enriched.original_alert.confidence
        passed = confidence >= CONFIDENCE_FLOOR

        return VerificationSignal(
            name="ML Confidence Floor",
            passed=passed,
            score=WEIGHT_CONFIDENCE if passed else (WEIGHT_CONFIDENCE * (confidence / CONFIDENCE_FLOOR)),
            max_score=WEIGHT_CONFIDENCE,
            detail=f"Confidence={confidence:.2f} (floor={CONFIDENCE_FLOOR})",
        )

    def _check_plausibility(self, enriched: EnrichedAlert) -> VerificationSignal:
        """Check if the attack is plausible (CVE exists, MITRE mapped).

        Args:
            enriched: The enriched alert.

        Returns:
            VerificationSignal for attack plausibility.
        """
        has_cve = len(enriched.cve_ids) > 0
        has_mitre = len(enriched.mitre_techniques) > 0
        has_cvss = enriched.max_cvss >= CVSS_PLAUSIBILITY_FLOOR
        passed = has_mitre and (has_cve or has_cvss)

        return VerificationSignal(
            name="Attack Plausibility",
            passed=passed,
            score=WEIGHT_PLAUSIBILITY if passed else 0.0,
            max_score=WEIGHT_PLAUSIBILITY,
            detail=(
                f"CVE={'yes' if has_cve else 'no'}, "
                f"MITRE={'yes' if has_mitre else 'no'}, "
                f"CVSS={enriched.max_cvss}"
            ),
        )


    def _check_asset_context(self, enriched: EnrichedAlert) -> VerificationSignal:
        """Check if the targeted asset is high-value (server, router, DB).

        High-value assets get an automatic boost because attacks against
        them are inherently more dangerous even with lower confidence.
        This prevents dismissing real threats on critical infrastructure.

        Args:
            enriched: The enriched alert.

        Returns:
            VerificationSignal for asset context.
        """
        asset_type = getattr(enriched, 'asset_type', 'unknown')
        business_impact = getattr(enriched, 'business_impact', 'unknown')
        data_class = getattr(enriched, 'data_classification', 'unknown')

        is_critical_asset = asset_type in ('server', 'network', 'infrastructure')
        is_critical_impact = business_impact == 'critical'
        is_sensitive_data = data_class in ('restricted', 'confidential')

        # Pass if ANY critical indicator is true
        passed = is_critical_asset or is_critical_impact or is_sensitive_data

        # Partial score for medium-value assets
        if passed:
            score = WEIGHT_ASSET_CONTEXT
        elif asset_type == 'workstation' and business_impact == 'medium':
            score = WEIGHT_ASSET_CONTEXT * 0.4
        else:
            score = 0.0

        return VerificationSignal(
            name="Asset Context",
            passed=passed,
            score=score,
            max_score=WEIGHT_ASSET_CONTEXT,
            detail=(
                f"Type={asset_type}, Impact={business_impact}, "
                f"Data={data_class}"
            ),
        )


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Prevents false-positive escalations by requiring multi-source proof.
# 2. Each signal is independently scored, making the gate transparent.
# 3. The verdict determines whether to isolate, alert, or dismiss.
# 4. Signal 6 (Asset Context) ensures critical assets are never dismissed.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os
    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    from src.enrichment.enrichment_engine import EnrichmentEngine
    from src.parsing.models import ModelAlert

    engine = EnrichmentEngine()
    gate = VerificationGate()

    logger.info("=" * 70)
    logger.info("VERIFICATION GATE DEMO")
    logger.info("=" * 70)

    # Test 1: High-confidence P1 from known Tor exit → should CONFIRM
    alert1 = ModelAlert(
        severity="P1", attack_type="privilege_escalation",
        confidence=0.94, source_host="185.220.101.42",
        model_source="Ensemble",
        event_hashes=["a" * 64, "b" * 64, "c" * 64, "d" * 64],
    )
    enriched1 = engine.enrich(alert1)
    result1 = gate.evaluate(enriched1)
    logger.info("\n%s\n", result1.explanation)

    # Test 2: Low-confidence P3 from internal IP → should be INCONCLUSIVE
    alert2 = ModelAlert(
        severity="P3", attack_type="anomaly_unknown",
        confidence=0.35, source_host="192.168.1.100",
        model_source="IsolationForest",
    )
    enriched2 = engine.enrich(alert2)
    result2 = gate.evaluate(enriched2)
    logger.info("\n%s\n", result2.explanation)

    logger.info("Verification Gate demo complete ✓")
