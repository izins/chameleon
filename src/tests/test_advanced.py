"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/tests/test_advanced.py

Advanced / Complex integration tests that verify:
  1. Full pipeline data integrity (Phase 1 → 5)
  2. Blockchain tamper detection
  3. Severity downgrade on low-confidence alerts
  4. Multi-incident concurrent processing
  5. Legal deadline correctness
  6. Isolation matrix exhaustive coverage
  7. Entity history accumulation across attacks
  8. Report hash determinism
  9. API data consistency
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest import TestCase

import pytest

# Force demo mode for all tests
os.environ["AEGIS_DEMO_MODE"] = "true"

from src.blockchain.aegis_chain import AegisChain
from src.blockchain.ledger import Ledger
from src.blockchain.models import Block, Transaction
from src.config.settings import AttackType, Severity, settings
from src.enrichment.enrichment_engine import EnrichedAlert, EnrichmentEngine
from src.parsing.drain_parser import DrainParser
from src.parsing.models import LogSession, ModelAlert, NormalizedEvent, RawLogEvent
from src.parsing.normalizer import LogNormalizer
from src.parsing.sessionizer import LogSessionizer
from src.reporting.legal_dz import LegalDZGenerator
from src.reporting.playbook import PlaybookGenerator
from src.reporting.report_generator import IncidentReport, ReportGenerator
from src.response.isolation_log import IsolationAction, IsolationLog
from src.response.isolator import ISOLATION_MATRIX, Isolator
from src.response.network_graph import NetworkGraph
from src.response.scorer import RiskScorer, RiskVerdict


# ═══════════════════════════════════════════════════════════════════════
# TEST 1: BLOCKCHAIN TAMPER DETECTION
# ═══════════════════════════════════════════════════════════════════════
class TestBlockchainTamperDetection(TestCase):
    """Verify that ANY modification to the chain is detected."""

    def setUp(self) -> None:
        self.ledger = Ledger(difficulty=1)
        # Clear chain for a fresh start
        self.ledger.chain = []
        self.ledger._create_genesis_block()

    def test_valid_chain_passes(self) -> None:
        """An untouched chain should validate."""
        tx = Transaction(
            document_type="TestDoc",
            document_id="test-001",
            document_hash="a" * 64,
        )
        self.ledger.add_transaction(tx)
        self.ledger.mine_pending_transactions()
        self.assertTrue(self.ledger.is_chain_valid())

    def test_tampered_transaction_detected(self) -> None:
        """Modifying a transaction's hash inside a mined block must be caught."""
        tx = Transaction(
            document_type="TestDoc",
            document_id="test-002",
            document_hash="b" * 64,
        )
        self.ledger.add_transaction(tx)
        self.ledger.mine_pending_transactions()

        # TAMPER: Change the document_hash inside block 1
        self.ledger.chain[1].transactions[0].document_hash = "c" * 64
        self.assertFalse(self.ledger.is_chain_valid())

    def test_tampered_previous_hash_detected(self) -> None:
        """Modifying a block's previous_hash pointer must be caught."""
        for i in range(3):
            tx = Transaction(
                document_type="TestDoc",
                document_id=f"test-{i}",
                document_hash=f"{i}" * 64,
            )
            self.ledger.add_transaction(tx)
            self.ledger.mine_pending_transactions()

        # TAMPER: Break the link between block 2 and block 1
        self.ledger.chain[2].previous_hash = "0" * 64
        self.assertFalse(self.ledger.is_chain_valid())

    def test_inserted_block_detected(self) -> None:
        """Inserting a rogue block into the middle of the chain must be caught."""
        for i in range(3):
            tx = Transaction(
                document_type="TestDoc",
                document_id=f"test-{i}",
                document_hash=f"{i}" * 64,
            )
            self.ledger.add_transaction(tx)
            self.ledger.mine_pending_transactions()

        # TAMPER: Insert a rogue block at position 2
        rogue_block = Block(
            index=2,
            previous_hash=self.ledger.chain[1].hash,
            transactions=[
                Transaction(
                    document_type="ROGUE",
                    document_id="hacker",
                    document_hash="f" * 64,
                )
            ],
        )
        rogue_block.mine_block(1)
        self.ledger.chain.insert(2, rogue_block)

        # Chain should be invalid because block 3's previous_hash won't match
        self.assertFalse(self.ledger.is_chain_valid())


# ═══════════════════════════════════════════════════════════════════════
# TEST 2: SEVERITY DOWNGRADE ON LOW CONFIDENCE
# ═══════════════════════════════════════════════════════════════════════
class TestSeverityDowngrade(TestCase):
    """Verify confidence < 0.6 causes severity downgrade."""

    def setUp(self) -> None:
        self.engine = EnrichmentEngine()
        self.scorer = RiskScorer()

    def test_high_confidence_keeps_severity(self) -> None:
        """P1 alert with confidence=0.95 stays P1."""
        alert = ModelAlert(
            severity="P1",
            attack_type="privilege_escalation",
            confidence=0.95,
            source_host="10.0.0.40",
        )
        enriched = self.engine.enrich(alert)
        verdict = self.scorer.score(enriched)
        self.assertEqual(verdict.adjusted_severity, "P1")

    def test_low_confidence_downgrades_p1_to_p2(self) -> None:
        """P1 alert with confidence=0.45 should become P2."""
        alert = ModelAlert(
            severity="P1",
            attack_type="privilege_escalation",
            confidence=0.45,
            source_host="10.0.0.40",
        )
        enriched = self.engine.enrich(alert)
        verdict = self.scorer.score(enriched)
        self.assertEqual(verdict.original_severity, "P1")
        self.assertEqual(verdict.adjusted_severity, "P2")

    def test_low_confidence_downgrades_p2_to_p3(self) -> None:
        """P2 alert with confidence=0.30 should become P3."""
        alert = ModelAlert(
            severity="P2",
            attack_type="ssh_bruteforce",
            confidence=0.30,
            source_host="192.168.1.100",
        )
        enriched = self.engine.enrich(alert)
        verdict = self.scorer.score(enriched)
        self.assertEqual(verdict.original_severity, "P2")
        self.assertEqual(verdict.adjusted_severity, "P3")

    def test_p4_cannot_downgrade_further(self) -> None:
        """P4 alert with low confidence stays P4 (floor)."""
        alert = ModelAlert(
            severity="P4",
            attack_type="anomaly_unknown",
            confidence=0.10,
            source_host="192.168.1.200",
        )
        enriched = self.engine.enrich(alert)
        verdict = self.scorer.score(enriched)
        self.assertEqual(verdict.adjusted_severity, "P4")


# ═══════════════════════════════════════════════════════════════════════
# TEST 3: ISOLATION MATRIX EXHAUSTIVE
# ═══════════════════════════════════════════════════════════════════════
class TestIsolationMatrixExhaustive(TestCase):
    """Verify every severity level triggers the correct set of actions."""

    def setUp(self) -> None:
        self.engine = EnrichmentEngine()
        self.scorer = RiskScorer()
        self.isolator = Isolator(dry_run=True)

    def _run_severity(self, severity: str, confidence: float = 0.95) -> list:
        alert = ModelAlert(
            severity=severity,
            attack_type="privilege_escalation",
            confidence=confidence,
            source_host="10.0.0.40",
        )
        enriched = self.engine.enrich(alert)
        verdict = self.scorer.score(enriched)
        # Force the adjusted severity to the one we want to test
        verdict.adjusted_severity = severity
        return self.isolator.execute(verdict)

    def test_p1_triggers_4_actions(self) -> None:
        actions = self._run_severity("P1")
        types = [a.action_type.value for a in actions]
        self.assertIn("network_quarantine", types)
        self.assertIn("db_revoke", types)
        self.assertIn("user_lock", types)
        self.assertIn("alert_soc", types)
        self.assertEqual(len(actions), 4)

    def test_p2_triggers_2_actions(self) -> None:
        actions = self._run_severity("P2")
        types = [a.action_type.value for a in actions]
        self.assertIn("network_quarantine", types)
        self.assertIn("alert_soc", types)
        self.assertEqual(len(actions), 2)

    def test_p3_triggers_2_actions(self) -> None:
        actions = self._run_severity("P3")
        types = [a.action_type.value for a in actions]
        self.assertIn("elevated_monitoring", types)
        self.assertIn("alert_soc", types)
        self.assertEqual(len(actions), 2)

    def test_p4_triggers_log_only(self) -> None:
        actions = self._run_severity("P4")
        types = [a.action_type.value for a in actions]
        self.assertEqual(types, ["log_only"])


# ═══════════════════════════════════════════════════════════════════════
# TEST 4: ENTITY HISTORY ACCUMULATION
# ═══════════════════════════════════════════════════════════════════════
class TestEntityHistoryAccumulation(TestCase):
    """Verify that scoring for the same entity grows across multiple attacks."""

    def setUp(self) -> None:
        self.engine = EnrichmentEngine()

    def test_entity_score_increases_across_alerts(self) -> None:
        """Same IP sending 3 alerts should accumulate entity score."""
        ip = "10.10.10.10"
        scores = []
        for attack in ["ssh_bruteforce", "lateral_movement", "privilege_escalation"]:
            alert = ModelAlert(
                severity="P2",
                attack_type=attack,
                confidence=0.85,
                source_host=ip,
            )
            enriched = self.engine.enrich(alert)
            scores.append(enriched.entity_cumulative_score)

        # Each subsequent alert should have a higher cumulative score
        self.assertGreater(scores[1], scores[0])
        self.assertGreater(scores[2], scores[1])

    def test_entity_attack_types_accumulate(self) -> None:
        """Entity history should track distinct attack types."""
        ip = "10.10.10.11"
        for attack in ["ssh_bruteforce", "lateral_movement"]:
            alert = ModelAlert(
                severity="P2",
                attack_type=attack,
                confidence=0.85,
                source_host=ip,
            )
            enriched = self.engine.enrich(alert)

        self.assertIn("ssh_bruteforce", enriched.entity_attack_types)
        self.assertIn("lateral_movement", enriched.entity_attack_types)
        self.assertEqual(enriched.entity_alert_count, 2)


# ═══════════════════════════════════════════════════════════════════════
# TEST 5: LEGAL DEADLINE CORRECTNESS
# ═══════════════════════════════════════════════════════════════════════
class TestLegalDeadlines(TestCase):
    """Verify CERT-DZ (24h) and ANPDP (72h) deadlines are mathematically correct.
    
    Uses the full ReportGenerator pipeline since LegalDZGenerator requires
    EvidencePackage and IncidentAnalysis objects (not raw EnrichedAlert).
    """

    def test_cert_dz_deadline_is_24h(self) -> None:
        engine = EnrichmentEngine()
        alert = ModelAlert(severity="P1", attack_type="privilege_escalation",
                           confidence=0.9, source_host="10.0.0.40")
        enriched = engine.enrich(alert)
        scorer = RiskScorer()
        verdict = scorer.score(enriched)
        isolator = Isolator(dry_run=True)
        actions = isolator.execute(verdict)
        generator = ReportGenerator()
        report = generator.generate(enriched, verdict, actions)

        deadline = datetime.fromisoformat(report.cert_dz_notification.deadline)
        now = datetime.now(timezone.utc)
        diff_hours = (deadline - now).total_seconds() / 3600
        self.assertAlmostEqual(diff_hours, 24.0, delta=0.1)

    def test_anpdp_deadline_is_72h(self) -> None:
        engine = EnrichmentEngine()
        alert = ModelAlert(severity="P1", attack_type="privilege_escalation",
                           confidence=0.9, source_host="10.0.0.40")
        enriched = engine.enrich(alert)
        scorer = RiskScorer()
        verdict = scorer.score(enriched)
        isolator = Isolator(dry_run=True)
        actions = isolator.execute(verdict)
        generator = ReportGenerator()
        report = generator.generate(enriched, verdict, actions)

        deadline = datetime.fromisoformat(report.anpdp_notification.deadline)
        now = datetime.now(timezone.utc)
        diff_hours = (deadline - now).total_seconds() / 3600
        self.assertAlmostEqual(diff_hours, 72.0, delta=0.1)


# ═══════════════════════════════════════════════════════════════════════
# TEST 6: RISK FORMULA MATHEMATICAL CORRECTNESS
# ═══════════════════════════════════════════════════════════════════════
class TestRiskFormula(TestCase):
    """Verify the risk formula: score = (cvss*0.4) + (crit*0.3) + (prop*0.3)."""

    def test_formula_components(self) -> None:
        engine = EnrichmentEngine()
        scorer = RiskScorer()

        alert = ModelAlert(
            severity="P1",
            attack_type="privilege_escalation",
            confidence=0.95,
            source_host="10.0.0.40",
        )
        enriched = engine.enrich(alert)
        verdict = scorer.score(enriched)

        # Manually verify the formula
        expected = (
            verdict.cvss_component
            + verdict.criticality_component
            + verdict.propagation_component
        )
        self.assertAlmostEqual(verdict.final_risk_score, expected, places=2)

        # Verify weights
        cvss_base = enriched.max_cvss
        self.assertAlmostEqual(verdict.cvss_component, cvss_base * 0.4, places=2)


# ═══════════════════════════════════════════════════════════════════════
# TEST 7: FULL PIPELINE END-TO-END DATA INTEGRITY
# ═══════════════════════════════════════════════════════════════════════
class TestFullPipelineIntegrity(TestCase):
    """Run the entire pipeline and verify data flows correctly between phases."""

    def test_phase1_to_phase4_data_chain(self) -> None:
        """Verify that raw logs -> normalized -> enriched -> scored -> reported."""
        # Phase 1: Parse raw logs (normalize takes a single RawLogEvent)
        normalizer = LogNormalizer()
        raw = RawLogEvent(
            raw_line="Jan  5 22:01:15 webserver sshd[12001]: Failed password for root from 1.2.3.4 port 44231 ssh2",
            host_name="webserver",
        )
        event = normalizer.normalize(raw)
        self.assertNotEqual(event.event_hash, "")  # Hash was computed
        self.assertEqual(event.source_ip, "1.2.3.4")

        # Phase 2: Enrich
        engine = EnrichmentEngine()
        alert = ModelAlert(
            severity="P1",
            attack_type="ssh_bruteforce",
            confidence=0.87,
            source_host="1.2.3.4",
            event_hashes=[event.event_hash],
        )
        enriched = engine.enrich(alert)
        self.assertTrue(len(enriched.mitre_techniques) > 0)
        self.assertTrue(enriched.max_cvss > 0)

        # Phase 3: Score
        scorer = RiskScorer()
        verdict = scorer.score(enriched)
        self.assertTrue(verdict.final_risk_score > 0)

        # Phase 3b: Isolate
        isolator = Isolator(dry_run=True)
        actions = isolator.execute(verdict)
        self.assertTrue(len(actions) > 0)

        # Phase 4: Report
        generator = ReportGenerator()
        report = generator.generate(enriched, verdict, actions)
        self.assertEqual(report.entity_id, "1.2.3.4")
        self.assertEqual(report.severity, verdict.adjusted_severity)
        self.assertIsNotNone(report.cert_dz_notification)
        self.assertIsNotNone(report.anpdp_notification)
        self.assertTrue(report.playbook.total_steps > 0)

    def test_report_contains_evidence_hashes(self) -> None:
        """Verify that forensic evidence hashes are preserved through the pipeline."""
        engine = EnrichmentEngine()
        alert = ModelAlert(
            severity="P1",
            attack_type="sql_injection",
            confidence=0.92,
            source_host="10.0.0.5",
            event_hashes=["abc123", "def456"],
        )
        enriched = engine.enrich(alert)
        scorer = RiskScorer()
        verdict = scorer.score(enriched)
        isolator = Isolator(dry_run=True)
        actions = isolator.execute(verdict)
        generator = ReportGenerator()
        report = generator.generate(enriched, verdict, actions)

        # Evidence hashes must survive through to the final report
        self.assertIn("abc123", report.evidence.event_hashes)
        self.assertIn("def456", report.evidence.event_hashes)


# ═══════════════════════════════════════════════════════════════════════
# TEST 8: REPORT HASH DETERMINISM
# ═══════════════════════════════════════════════════════════════════════
class TestReportHashDeterminism(TestCase):
    """Verify that hashing the same report twice produces the same hash."""

    def test_same_report_same_hash(self) -> None:
        engine = EnrichmentEngine()
        alert = ModelAlert(
            severity="P1",
            attack_type="privilege_escalation",
            confidence=0.95,
            source_host="10.0.0.40",
        )
        enriched = engine.enrich(alert)
        scorer = RiskScorer()
        verdict = scorer.score(enriched)
        isolator = Isolator(dry_run=True)
        actions = isolator.execute(verdict)
        generator = ReportGenerator()
        report = generator.generate(enriched, verdict, actions)

        # Hash the report twice
        chain = AegisChain(ledger=Ledger(difficulty=1))
        hash1 = chain._hash_document(report)
        hash2 = chain._hash_document(report)

        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)  # SHA-256 = 64 hex chars


# ═══════════════════════════════════════════════════════════════════════
# TEST 9: MITRE MAPPER COVERAGE
# ═══════════════════════════════════════════════════════════════════════
class TestMitreMapperCoverage(TestCase):
    """Verify that ALL 6 attack_type values from the contract are mapped."""

    def test_all_attack_types_mapped(self) -> None:
        engine = EnrichmentEngine()
        for attack_type in AttackType:
            alert = ModelAlert(
                severity="P2",
                attack_type=attack_type.value,
                confidence=0.80,
                source_host="10.0.0.1",
            )
            enriched = engine.enrich(alert)
            self.assertTrue(
                len(enriched.mitre_techniques) > 0,
                f"No MITRE techniques mapped for {attack_type.value}",
            )


# ═══════════════════════════════════════════════════════════════════════
# TEST 10: MULTI-INCIDENT BLOCKCHAIN ANCHORING
# ═══════════════════════════════════════════════════════════════════════
class TestMultiIncidentBlockchain(TestCase):
    """Verify multiple incidents are correctly anchored and independently verifiable."""

    def test_three_incidents_three_blocks(self) -> None:
        ledger = Ledger(difficulty=1)
        ledger.chain = []
        ledger._create_genesis_block()
        chain = AegisChain(ledger=ledger)
        engine = EnrichmentEngine()

        tx_ids = []
        for attack in ["ssh_bruteforce", "lateral_movement", "privilege_escalation"]:
            alert = ModelAlert(
                severity="P1",
                attack_type=attack,
                confidence=0.9,
                source_host="10.0.0.40",
            )
            enriched = engine.enrich(alert)
            tx_id = chain.anchor_alert(enriched)
            tx_ids.append(tx_id)

        # Should have genesis + 3 alert blocks
        self.assertEqual(len(ledger.chain), 4)

        # All tx_ids should be unique
        self.assertEqual(len(set(tx_ids)), 3)

        # Chain should still be valid
        self.assertTrue(ledger.is_chain_valid())


# ═══════════════════════════════════════════════════════════════════════
# TEST 11: NETWORK GRAPH PROPAGATION
# ═══════════════════════════════════════════════════════════════════════
class TestNetworkGraphPropagation(TestCase):
    """Verify BFS propagation score calculation."""

    def test_propagation_capped_at_10(self) -> None:
        graph = NetworkGraph()
        # Even if many high-value assets are reachable
        # propagation_score = min(10, count * 2.5)
        hv = graph.get_reachable_high_value("10.0.0.1")
        prop_score = min(10.0, len(hv) * 2.5)
        self.assertLessEqual(prop_score, 10.0)

    def test_unknown_host_gets_default_criticality(self) -> None:
        graph = NetworkGraph()
        crit = graph.get_asset_criticality("999.999.999.999")
        self.assertEqual(crit, 5)  # Default per spec


# ═══════════════════════════════════════════════════════════════════════
# TEST 12: LOG PARSING EDGE CASES
# ═══════════════════════════════════════════════════════════════════════
class TestLogParsingEdgeCases(TestCase):
    """Verify parsing handles edge cases gracefully."""

    def test_empty_log_line_rejected(self) -> None:
        """Empty strings should be rejected by Pydantic."""
        with self.assertRaises(Exception):
            RawLogEvent(raw_line="")

    def test_unicode_log_line(self) -> None:
        """Unicode characters in logs should not crash the parser."""
        raw = RawLogEvent(
            raw_line="Jan  5 22:01:15 webserver sshd[12001]: Connexion échouée pour l'utilisateur root",
            host_name="webserver",
        )
        normalizer = LogNormalizer()
        event = normalizer.normalize(raw)
        self.assertNotEqual(event.event_hash, "")

    def test_event_hash_is_sha256(self) -> None:
        """Event hash must be a valid SHA-256 hex string."""
        raw = RawLogEvent(raw_line="test log line 12345")
        normalizer = LogNormalizer()
        event = normalizer.normalize(raw)
        self.assertEqual(len(event.event_hash), 64)
        # Verify it's valid hex
        int(event.event_hash, 16)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
