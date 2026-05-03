"""
AEGIS — Phase 4 Reporting Tests
=================================
Tests for: evidence_collector, incident_analyzer, regulatory_db,
           playbook, legal_dz, report_generator.
"""

from __future__ import annotations

import os

import pytest

os.environ["AEGIS_DEMO_MODE"] = "true"

from src.enrichment.enrichment_engine import EnrichmentEngine
from src.parsing.models import ModelAlert
from src.reporting.evidence_collector import EvidenceCollector, EvidencePackage
from src.reporting.incident_analyzer import IncidentAnalyzer, IncidentAnalysis
from src.reporting.legal_dz import LegalDZGenerator
from src.reporting.playbook import PlaybookGenerator, StepCategory
from src.reporting.regulatory_db import RegulatoryDB
from src.reporting.report_generator import IncidentReport, ReportGenerator
from src.response.isolator import Isolator
from src.response.scorer import RiskScorer


# ── Shared fixtures ──────────────────────────────────────────────────
def _make_pipeline():
    """Run full pipeline and return (enriched, verdict, actions)."""
    alert = ModelAlert(
        severity="P1", attack_type="privilege_escalation",
        confidence=0.92, source_host="10.0.0.40",
        affected_assets=["10.0.0.10"], model_source="DeepLog",
        raw_sequence=[5, 5, 5, 22, 11],
    )
    enriched = EnrichmentEngine().enrich(alert)
    verdict = RiskScorer().score(enriched)
    actions = Isolator(dry_run=True).execute(verdict)
    return enriched, verdict, actions


# ═══════════════════════════════════════════════════════════════════════
# 1. EVIDENCE COLLECTOR TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestEvidenceCollector:
    def test_basic_collection(self):
        enriched, verdict, actions = _make_pipeline()
        collector = EvidenceCollector()
        pkg = collector.collect(enriched, verdict, actions)
        assert isinstance(pkg, EvidencePackage)
        assert pkg.entity_id == "10.0.0.40"
        assert len(pkg.timeline) >= 3  # alert + enrichment + scoring + actions
        assert len(pkg.iocs) >= 1

    def test_timeline_has_entries(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        types = [e.event_type for e in pkg.timeline]
        assert "alert" in types
        assert "enrichment" in types
        assert "scoring" in types

    def test_iocs_contain_source_ip(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        ip_iocs = [i for i in pkg.iocs if i.ioc_type == "ip"]
        values = [i.value for i in ip_iocs]
        assert "10.0.0.40" in values

    def test_mitre_evidence(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        assert len(pkg.mitre_techniques) >= 1
        assert pkg.max_cvss > 0


# ═══════════════════════════════════════════════════════════════════════
# 2. INCIDENT ANALYZER TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestIncidentAnalyzer:
    def test_basic_analysis(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        analysis = IncidentAnalyzer().analyze(pkg)
        assert isinstance(analysis, IncidentAnalysis)
        assert analysis.attack_classification != ""
        assert analysis.kill_chain_phase != ""

    def test_impact_assessment(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        analysis = IncidentAnalyzer().analyze(pkg)
        assert analysis.impact.overall > 0
        assert analysis.impact.confidentiality > 0

    def test_investigation_steps(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        analysis = IncidentAnalyzer().analyze(pkg)
        assert len(analysis.investigation_steps) >= 1

    def test_root_cause(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        analysis = IncidentAnalyzer().analyze(pkg)
        assert "10.0.0.40" in analysis.root_cause_hypothesis

    def test_recommendations(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        analysis = IncidentAnalyzer().analyze(pkg)
        assert len(analysis.recommendations) >= 2


# ═══════════════════════════════════════════════════════════════════════
# 3. REGULATORY DB TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestRegulatoryDB:
    def test_algerian_regulations(self):
        db = RegulatoryDB()
        dz = db.get_algerian_regulations()
        assert len(dz) == 3  # CERT-DZ, ANPDP, Loi 09-04

    def test_applicable_regulations(self):
        db = RegulatoryDB()
        matches = db.get_applicable(
            attack_type="data_exfil",
            jurisdictions=["Algeria"],
        )
        assert len(matches) >= 2  # CERT-DZ + Loi 09-04

    def test_cert_dz_deadline(self):
        db = RegulatoryDB()
        reg = db.get_by_id("DZ-CERT")
        assert reg is not None
        assert reg.notification_deadline_hours == 24

    def test_anpdp_deadline(self):
        db = RegulatoryDB()
        reg = db.get_by_id("DZ-ANPDP")
        assert reg is not None
        assert reg.notification_deadline_hours == 72

    def test_gdpr_with_eu_jurisdiction(self):
        db = RegulatoryDB()
        matches = db.get_applicable(
            data_categories=["personal_data"],
            jurisdictions=["Algeria", "European Union"],
        )
        ids = [m.regulation.reg_id for m in matches]
        assert "EU-GDPR" in ids

    def test_urgency_sorting(self):
        db = RegulatoryDB()
        matches = db.get_applicable(jurisdictions=["Algeria"])
        # Sorted by deadline (ascending)
        deadlines = [m.deadline_hours for m in matches]
        assert deadlines == sorted(deadlines)


# ═══════════════════════════════════════════════════════════════════════
# 4. PLAYBOOK TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestPlaybook:
    def test_generate_playbook(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        analysis = IncidentAnalyzer().analyze(pkg)
        playbook = PlaybookGenerator().generate(pkg, analysis, verdict)
        assert playbook.total_steps > 0
        assert playbook.estimated_total_minutes > 0

    def test_steps_ordered(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        analysis = IncidentAnalyzer().analyze(pkg)
        playbook = PlaybookGenerator().generate(pkg, analysis, verdict)
        orders = [s.order for s in playbook.steps]
        assert orders == sorted(orders)

    def test_contains_containment(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        analysis = IncidentAnalyzer().analyze(pkg)
        playbook = PlaybookGenerator().generate(pkg, analysis, verdict)
        cats = [s.category for s in playbook.steps]
        assert StepCategory.CONTAINMENT in cats

    def test_contains_forensics(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        analysis = IncidentAnalyzer().analyze(pkg)
        playbook = PlaybookGenerator().generate(pkg, analysis, verdict)
        cats = [s.category for s in playbook.steps]
        assert StepCategory.FORENSICS in cats

    def test_p1_has_legal_steps(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        analysis = IncidentAnalyzer().analyze(pkg)
        playbook = PlaybookGenerator().generate(pkg, analysis, verdict)
        cats = [s.category for s in playbook.steps]
        assert StepCategory.LEGAL in cats

    def test_technical_commands_present(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        analysis = IncidentAnalyzer().analyze(pkg)
        playbook = PlaybookGenerator().generate(pkg, analysis, verdict)
        steps_with_cmds = [s for s in playbook.steps if s.technical_commands]
        assert len(steps_with_cmds) >= 3


# ═══════════════════════════════════════════════════════════════════════
# 5. LEGAL DZ TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestLegalDZ:
    def test_cert_dz_generation(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        analysis = IncidentAnalyzer().analyze(pkg)
        cert = LegalDZGenerator().generate_cert_dz(pkg, analysis, verdict)
        assert cert.hours_remaining == 24.0
        assert cert.source_ip == "10.0.0.40"
        assert len(cert.mitre_techniques) >= 1

    def test_anpdp_generation(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        analysis = IncidentAnalyzer().analyze(pkg)
        anpdp = LegalDZGenerator().generate_anpdp(
            pkg, analysis, verdict, affected_persons=500,
        )
        assert anpdp.hours_remaining == 72.0
        assert anpdp.estimated_persons_affected == 500

    def test_data_categories_inferred(self):
        enriched, verdict, actions = _make_pipeline()
        pkg = EvidenceCollector().collect(enriched, verdict, actions)
        analysis = IncidentAnalyzer().analyze(pkg)
        anpdp = LegalDZGenerator().generate_anpdp(pkg, analysis, verdict)
        assert len(anpdp.affected_data_categories) >= 1


# ═══════════════════════════════════════════════════════════════════════
# 6. REPORT GENERATOR TESTS (Integration)
# ═══════════════════════════════════════════════════════════════════════

class TestReportGenerator:
    def test_full_report_generation(self):
        enriched, verdict, actions = _make_pipeline()
        generator = ReportGenerator()
        report = generator.generate(enriched, verdict, actions)
        assert isinstance(report, IncidentReport)
        assert report.entity_id == "10.0.0.40"
        assert report.severity == "P1"
        assert report.risk_score > 0
        assert report.playbook.total_steps > 0
        assert len(report.applicable_regulations) >= 1
        assert report.executive_summary != ""
        assert report.technical_summary != ""

    def test_report_contains_all_components(self):
        enriched, verdict, actions = _make_pipeline()
        report = ReportGenerator().generate(enriched, verdict, actions)
        assert report.evidence.entity_id != ""
        assert report.analysis.attack_classification != ""
        assert report.cert_dz_notification.hours_remaining == 24.0
        assert report.anpdp_notification.hours_remaining == 72.0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
