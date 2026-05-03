"""
AEGIS — Phase 3 Response Tests
================================
Tests for: isolation_log, network_graph, scorer, isolator.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

os.environ["AEGIS_DEMO_MODE"] = "true"

from src.config.settings import Severity
from src.enrichment.enrichment_engine import EnrichedAlert, EnrichmentEngine
from src.parsing.models import ModelAlert
from src.response.isolation_log import (
    ActionStatus,
    IsolationAction,
    IsolationActionType,
    IsolationLog,
)
from src.response.network_graph import NetworkGraph
from src.response.scorer import RiskScorer, RiskVerdict, _downgrade_severity, _risk_label
from src.response.isolator import Isolator, ISOLATION_MATRIX


# ═══════════════════════════════════════════════════════════════════════
# 1. ISOLATION LOG TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestIsolationLog:
    def test_append_action(self):
        log = IsolationLog()
        action = IsolationAction(
            entity_id="1.1.1.1",
            action_type=IsolationActionType.NETWORK_QUARANTINE,
        )
        result = log.append_action(action)
        assert result.action_id == action.action_id
        assert log.action_count == 1

    def test_update_result_success(self):
        log = IsolationLog()
        action = IsolationAction(entity_id="2.2.2.2")
        log.append_action(action)
        updated = log.update_result(action.action_id, success=True)
        assert updated is not None
        assert updated.status == ActionStatus.EXECUTED

    def test_update_result_dry_run(self):
        log = IsolationLog()
        action = IsolationAction(entity_id="3.3.3.3", dry_run=True)
        log.append_action(action)
        updated = log.update_result(action.action_id, success=True)
        assert updated.status == ActionStatus.DRY_RUN

    def test_update_result_failure(self):
        log = IsolationLog()
        action = IsolationAction(entity_id="4.4.4.4")
        log.append_action(action)
        updated = log.update_result(
            action.action_id, success=False, error="iptables failed",
        )
        assert updated.status == ActionStatus.FAILED
        assert "iptables" in updated.error

    def test_get_actions_for_entity(self):
        log = IsolationLog()
        log.append_action(IsolationAction(entity_id="5.5.5.5"))
        log.append_action(IsolationAction(entity_id="5.5.5.5"))
        log.append_action(IsolationAction(entity_id="6.6.6.6"))
        assert len(log.get_actions_for_entity("5.5.5.5")) == 2
        assert len(log.get_actions_for_entity("6.6.6.6")) == 1

    def test_unknown_action_returns_none(self):
        log = IsolationLog()
        assert log.update_result("nonexistent", success=True) is None


# ═══════════════════════════════════════════════════════════════════════
# 2. NETWORK GRAPH TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestNetworkGraph:
    def test_neighbors(self):
        g = NetworkGraph()
        neighbors = g.get_neighbors("10.0.0.1")
        assert "10.0.0.5" in neighbors

    def test_reachable(self):
        g = NetworkGraph()
        reachable = g.get_reachable("10.0.0.1")
        assert len(reachable) > 0
        assert "10.0.0.1" not in reachable  # should not include self

    def test_reachable_high_value(self):
        g = NetworkGraph()
        # 10.0.0.40 (jump_host) can reach database, app, backup
        hv = g.get_reachable_high_value("10.0.0.40")
        assert len(hv) >= 2

    def test_unknown_host_default_criticality(self):
        g = NetworkGraph()
        assert g.get_asset_criticality("192.168.1.200") == 5

    def test_known_host_criticality(self):
        g = NetworkGraph()
        assert g.get_asset_criticality("10.0.0.10") == 9  # database

    def test_asset_role(self):
        g = NetworkGraph()
        assert g.get_asset_role("10.0.0.10") == "database"
        assert g.get_asset_role("unknown") == "unknown"

    def test_high_value_assets(self):
        g = NetworkGraph()
        hv = g.get_high_value_assets()
        assert len(hv) >= 3  # app, db, file, jump, backup


# ═══════════════════════════════════════════════════════════════════════
# 3. SCORER TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestScorer:
    def test_basic_scoring(self):
        engine = EnrichmentEngine()
        scorer = RiskScorer()
        alert = ModelAlert(
            severity="P1", attack_type="privilege_escalation",
            confidence=0.92, source_host="10.0.0.40",
        )
        enriched = engine.enrich(alert)
        verdict = scorer.score(enriched)
        assert isinstance(verdict, RiskVerdict)
        assert verdict.final_risk_score > 0
        assert verdict.requires_isolation is True

    def test_severity_downgrade_low_confidence(self):
        engine = EnrichmentEngine()
        scorer = RiskScorer()
        alert = ModelAlert(
            severity="P2", attack_type="ssh_bruteforce",
            confidence=0.45, source_host="10.0.0.1",
        )
        enriched = engine.enrich(alert)
        verdict = scorer.score(enriched)
        assert verdict.adjusted_severity == "P3"  # downgraded
        assert verdict.requires_isolation is False

    def test_p4_no_isolation(self):
        engine = EnrichmentEngine()
        scorer = RiskScorer()
        alert = ModelAlert(
            severity="P4", attack_type="anomaly_unknown",
            confidence=0.30, source_host="192.168.1.200",
        )
        enriched = engine.enrich(alert)
        verdict = scorer.score(enriched)
        assert verdict.requires_isolation is False

    def test_risk_label(self):
        assert _risk_label(9.0) == "CRITICAL"
        assert _risk_label(7.0) == "HIGH"
        assert _risk_label(5.0) == "MEDIUM"
        assert _risk_label(3.0) == "LOW"
        assert _risk_label(1.0) == "INFO"

    def test_downgrade_severity(self):
        assert _downgrade_severity("P1") == "P2"
        assert _downgrade_severity("P2") == "P3"
        assert _downgrade_severity("P3") == "P4"
        assert _downgrade_severity("P4") == "P4"  # can't go lower

    def test_propagation_from_jump_host(self):
        """Jump host should have high propagation score."""
        engine = EnrichmentEngine()
        scorer = RiskScorer()
        alert = ModelAlert(
            severity="P1", attack_type="lateral_movement",
            confidence=0.85, source_host="10.0.0.40",
        )
        enriched = engine.enrich(alert)
        verdict = scorer.score(enriched)
        assert verdict.reachable_high_value >= 2
        assert verdict.propagation_score > 0


# ═══════════════════════════════════════════════════════════════════════
# 4. ISOLATOR TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestIsolator:
    def test_p1_full_lockdown(self):
        """P1 should trigger 4 actions."""
        engine = EnrichmentEngine()
        scorer = RiskScorer()
        isolator = Isolator(dry_run=True)

        alert = ModelAlert(
            severity="P1", attack_type="privilege_escalation",
            confidence=0.92, source_host="10.0.0.40",
        )
        enriched = engine.enrich(alert)
        verdict = scorer.score(enriched)
        actions = isolator.execute(verdict)

        assert len(actions) == 4
        action_types = [a.action_type for a in actions]
        assert IsolationActionType.NETWORK_QUARANTINE in action_types
        assert IsolationActionType.DB_REVOKE in action_types
        assert IsolationActionType.USER_LOCK in action_types
        assert IsolationActionType.ALERT_SOC in action_types

    def test_p4_log_only(self):
        """P4 should only log."""
        engine = EnrichmentEngine()
        scorer = RiskScorer()
        isolator = Isolator(dry_run=True)

        alert = ModelAlert(
            severity="P4", attack_type="anomaly_unknown",
            confidence=0.30, source_host="192.168.1.200",
        )
        enriched = engine.enrich(alert)
        verdict = scorer.score(enriched)
        actions = isolator.execute(verdict)

        assert len(actions) == 1
        assert actions[0].action_type == IsolationActionType.LOG_ONLY

    def test_dry_run_flag(self):
        """All actions in demo mode must be dry-run."""
        isolator = Isolator(dry_run=True)
        engine = EnrichmentEngine()
        scorer = RiskScorer()

        alert = ModelAlert(
            severity="P1", attack_type="ssh_bruteforce",
            confidence=0.9, source_host="10.0.0.5",
        )
        enriched = engine.enrich(alert)
        verdict = scorer.score(enriched)
        actions = isolator.execute(verdict)

        for action in actions:
            assert action.dry_run is True

    def test_log_before_execute(self):
        """Actions must be logged before execution."""
        isolation_log = IsolationLog()
        isolator = Isolator(isolation_log=isolation_log, dry_run=True)
        engine = EnrichmentEngine()
        scorer = RiskScorer()

        alert = ModelAlert(
            severity="P2", attack_type="lateral_movement",
            confidence=0.8, source_host="10.0.0.1",
        )
        enriched = engine.enrich(alert)
        verdict = scorer.score(enriched)
        actions = isolator.execute(verdict)

        # All actions should be in the log
        logged = isolation_log.get_all()
        assert len(logged) == len(actions)

    def test_isolation_matrix_coverage(self):
        """Every severity level should have actions defined."""
        for severity in ["P1", "P2", "P3", "P4"]:
            assert severity in ISOLATION_MATRIX
            assert len(ISOLATION_MATRIX[severity]) >= 1


# ═══════════════════════════════════════════════════════════════════════
# 5. FULL PIPELINE INTEGRATION TEST
# ═══════════════════════════════════════════════════════════════════════

class TestFullPipeline:
    def test_end_to_end(self):
        """Full pipeline: ModelAlert → Enrich → Score → Isolate."""
        engine = EnrichmentEngine()
        scorer = RiskScorer()
        isolation_log = IsolationLog()
        isolator = Isolator(isolation_log=isolation_log, dry_run=True)

        alert = ModelAlert(
            severity="P1", attack_type="privilege_escalation",
            confidence=0.95, source_host="10.0.0.40",
            affected_assets=["10.0.0.10", "10.0.0.50"],
            model_source="DeepLog",
            raw_sequence=[5, 5, 5, 22, 11],
        )

        # Phase 2: Enrich
        enriched = engine.enrich(alert)
        assert enriched.mitre_techniques
        assert enriched.max_cvss > 0

        # Phase 3: Score
        verdict = scorer.score(enriched)
        assert verdict.final_risk_score > 0
        assert verdict.requires_isolation is True

        # Phase 3: Isolate
        actions = isolator.execute(verdict)
        assert len(actions) == 4  # P1 = full lockdown

        # Audit trail
        assert isolation_log.action_count == 4


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
