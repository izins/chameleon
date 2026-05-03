"""
AEGIS — Phase 2 Enrichment Tests
=================================
Tests for: entity_tracker, mitre_mapper, cve_lookup, enrichment_engine.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

os.environ["AEGIS_DEMO_MODE"] = "true"

from src.config.settings import AttackType
from src.enrichment.cve_lookup import CVELookup
from src.enrichment.enrichment_engine import EnrichedAlert, EnrichmentEngine, _compute_initial_risk
from src.enrichment.entity_tracker import EntityRecord, EntityTracker
from src.enrichment.mitre_mapper import MitreMapper
from src.parsing.models import ModelAlert


# ═══════════════════════════════════════════════════════════════════════
# 1. ENTITY TRACKER TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestEntityTracker:
    def test_create_new_entity(self):
        t = EntityTracker()
        rec = t.update("1.1.1.1", "alert-001", score_delta=10)
        assert rec.entity_id == "1.1.1.1"
        assert rec.cumulative_score == 10.0
        assert rec.alert_count == 1

    def test_cumulative_score(self):
        """Spaced events accumulate score over time."""
        t = EntityTracker()
        t.update("1.1.1.1", "a1", 10, attack_type="ssh_bruteforce")
        t.update("1.1.1.1", "a2", 20, attack_type="lateral_movement")
        t.update("1.1.1.1", "a3", 60, attack_type="privilege_escalation")
        rec = t.get("1.1.1.1")
        assert rec.cumulative_score == 90.0
        assert rec.alert_count == 3
        assert len(rec.attack_types) == 3

    def test_separate_entities(self):
        t = EntityTracker()
        t.update("1.1.1.1", "a1", 50)
        t.update("2.2.2.2", "a2", 30)
        assert t.entity_count == 2
        assert t.get("1.1.1.1").cumulative_score == 50
        assert t.get("2.2.2.2").cumulative_score == 30

    def test_mitre_timeline(self):
        t = EntityTracker()
        t.update("1.1.1.1", "a1", 10, mitre_technique="T1110")
        t.update("1.1.1.1", "a2", 20, mitre_technique="T1021")
        t.update("1.1.1.1", "a3", 60, mitre_technique="T1068")
        rec = t.get("1.1.1.1")
        assert rec.mitre_techniques == ["T1110", "T1021", "T1068"]

    def test_no_duplicate_attack_types(self):
        t = EntityTracker()
        t.update("1.1.1.1", "a1", 10, attack_type="ssh_bruteforce")
        t.update("1.1.1.1", "a2", 10, attack_type="ssh_bruteforce")
        assert t.get("1.1.1.1").attack_types == ["ssh_bruteforce"]

    def test_get_above_score(self):
        t = EntityTracker()
        t.update("1.1.1.1", "a1", 90)
        t.update("2.2.2.2", "a2", 10)
        above = t.get_all_above_score(50)
        assert len(above) == 1
        assert above[0].entity_id == "1.1.1.1"

    def test_persistence(self, tmp_path):
        path = str(tmp_path / "entities.json")
        t1 = EntityTracker(persistence_path=path)
        t1.update("5.5.5.5", "a1", 42, attack_type="ssh_bruteforce")
        t2 = EntityTracker(persistence_path=path)
        rec = t2.get("5.5.5.5")
        assert rec is not None
        assert rec.cumulative_score == 42

    def test_unknown_entity_returns_none(self):
        t = EntityTracker()
        assert t.get("9.9.9.9") is None

    def test_score_decay(self):
        from datetime import timedelta
        t = EntityTracker()
        t.update("3.3.3.3", "a1", 100)
        # Simulate 8 days passing (beyond 7-day decay threshold)
        future = datetime.now(timezone.utc) + timedelta(days=8)
        decayed_count = t.decay_scores(now=future)
        assert decayed_count == 1
        rec = t.get("3.3.3.3")
        assert rec.cumulative_score == 50.0  # halved


# ═══════════════════════════════════════════════════════════════════════
# 2. MITRE MAPPER TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestMitreMapper:
    def test_ssh_bruteforce_maps(self):
        m = MitreMapper()
        techs = m.lookup("ssh_bruteforce")
        ids = [t.technique_id for t in techs]
        assert "T1110" in ids

    def test_all_attack_types_mapped(self):
        m = MitreMapper()
        for at in AttackType:
            techs = m.lookup(at.value)
            assert len(techs) >= 1, f"No mapping for {at.value}"

    def test_primary_technique(self):
        m = MitreMapper()
        primary = m.get_primary_technique("privilege_escalation")
        assert primary is not None
        assert primary.severity_weight >= 75

    def test_kill_chain_phase(self):
        m = MitreMapper()
        assert m.get_kill_chain_phase("ssh_bruteforce") == "Credential Access"
        assert m.get_kill_chain_phase("data_exfil") == "Exfiltration"

    def test_unknown_returns_empty(self):
        m = MitreMapper()
        assert m.lookup("totally_fake") == []


# ═══════════════════════════════════════════════════════════════════════
# 3. CVE LOOKUP TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestCVELookup:
    def test_ssh_cves(self):
        c = CVELookup()
        cves = c.lookup_by_attack("ssh_bruteforce")
        ids = [e.cve_id for e in cves]
        assert "CVE-2024-6387" in ids

    def test_max_cvss(self):
        c = CVELookup()
        assert c.get_max_cvss("ssh_bruteforce") == 8.1

    def test_unknown_returns_empty(self):
        c = CVELookup()
        assert c.lookup_by_attack("anomaly_unknown") == []
        assert c.get_max_cvss("anomaly_unknown") == 0.0

    def test_by_service(self):
        c = CVELookup()
        assert len(c.lookup_by_service("ssh")) >= 1


# ═══════════════════════════════════════════════════════════════════════
# 4. ENRICHMENT ENGINE TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestEnrichmentEngine:
    def test_basic_enrichment(self):
        e = EnrichmentEngine()
        alert = ModelAlert(
            severity="P2", attack_type="ssh_bruteforce",
            confidence=0.85, source_host="10.0.0.1",
        )
        enriched = e.enrich(alert)
        assert isinstance(enriched, EnrichedAlert)
        assert "T1110" in enriched.mitre_techniques
        assert enriched.max_cvss > 0
        assert enriched.initial_risk_score > 0
        assert enriched.entity_alert_count == 1

    def test_spaced_events_accumulate(self):
        """THE KEY TEST: 3 spaced alerts from same IP accumulate."""
        e = EnrichmentEngine()

        # Monday: SSH brute-force
        a1 = ModelAlert(attack_type="ssh_bruteforce", confidence=0.6,
                        source_host="192.168.1.100")
        r1 = e.enrich(a1)
        score_after_1 = r1.entity_cumulative_score

        # Wednesday: Lateral movement
        a2 = ModelAlert(attack_type="lateral_movement", confidence=0.7,
                        source_host="192.168.1.100")
        r2 = e.enrich(a2)
        score_after_2 = r2.entity_cumulative_score

        # Friday: Privilege escalation
        a3 = ModelAlert(attack_type="privilege_escalation", confidence=0.9,
                        source_host="192.168.1.100")
        r3 = e.enrich(a3)
        score_after_3 = r3.entity_cumulative_score

        # Scores must be cumulative and increasing
        assert score_after_2 > score_after_1
        assert score_after_3 > score_after_2

        # MITRE timeline must show multi-stage attack
        assert len(r3.entity_mitre_timeline) == 3
        assert r3.entity_alert_count == 3

        # Risk score must be high after accumulation
        assert r3.initial_risk_score > 50

    def test_risk_score_formula(self):
        score = _compute_initial_risk(
            confidence=0.9, mitre_weight=85,
            max_cvss=8.0, entity_score=90,
        )
        assert 70 < score <= 100

    def test_risk_score_bounds(self):
        assert _compute_initial_risk(0, 0, 0, 0) == 0.0
        assert _compute_initial_risk(1, 100, 10, 1000) == 100.0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
