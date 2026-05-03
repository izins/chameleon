"""
AEGIS — FULL PIPELINE INTEGRATION TEST
========================================
Simulates a complete "Low & Slow" SSH brute-force → lateral movement
→ privilege escalation attack WITHOUT real ML models.

The script:
  1. Feeds synthetic raw logs through Phase 1 (Normalizer + UEBA)
  2. Simulates ML model alerts (replacing DeepLog/LogLizer/XGBoost)
  3. Runs Phase 2 enrichment (MITRE + CVE + EntityTracker)
  4. Runs Phase 3 scoring + isolation
  5. Runs Phase 4 forensics + playbook + legal reports
  6. Writes the FULL reports to data/reports/

Usage:
  python -m src.tests.integration_demo
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Environment ──────────────────────────────────────────────────────
os.environ["AEGIS_DEMO_MODE"] = "true"

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)
logger = logging.getLogger("AEGIS_DEMO")

# ── Imports ──────────────────────────────────────────────────────────
from src.config.settings import settings
from src.parsing.models import NormalizedEvent, ModelAlert
from src.parsing.baseline_profiler import BaselineProfiler
from src.parsing.normalizer import LogNormalizer
from src.parsing.sessionizer import LogSessionizer
from src.enrichment.enrichment_engine import EnrichmentEngine
from src.enrichment.entity_tracker import EntityTracker
from src.response.network_graph import NetworkGraph
from src.response.scorer import RiskScorer, RiskVerdict
from src.response.isolator import Isolator
from src.response.isolation_log import IsolationAction, IsolationLog
from src.reporting.evidence_collector import EvidenceCollector
from src.reporting.incident_analyzer import IncidentAnalyzer
from src.reporting.playbook import PlaybookGenerator
from src.reporting.legal_dz import LegalDZGenerator
from src.reporting.regulatory_db import RegulatoryDB
from src.reporting.report_generator import ReportGenerator
from src.blockchain.aegis_chain import AegisChain


# ═══════════════════════════════════════════════════════════════════════
# SYNTHETIC LOG DATA — Simulates a 3-day multi-stage attack
# ═══════════════════════════════════════════════════════════════════════

# Day 1: SSH brute-force reconnaissance (evening hours)
DAY1_LOGS = [
    "Jan  5 22:01:15 webserver sshd[12001]: Failed password for root from 185.220.101.42 port 44231 ssh2",
    "Jan  5 22:01:16 webserver sshd[12002]: Failed password for root from 185.220.101.42 port 44232 ssh2",
    "Jan  5 22:01:17 webserver sshd[12003]: Failed password for admin from 185.220.101.42 port 44233 ssh2",
    "Jan  5 22:01:18 webserver sshd[12004]: Failed password for admin from 185.220.101.42 port 44234 ssh2",
    "Jan  5 22:01:19 webserver sshd[12005]: Failed password for deploy from 185.220.101.42 port 44235 ssh2",
    "Jan  5 22:02:30 webserver sshd[12010]: Accepted password for deploy from 185.220.101.42 port 44280 ssh2",
]

# Day 2: Lateral movement (3 AM — very suspicious)
DAY2_LOGS = [
    "Jan  6 03:15:22 webserver sshd[13001]: Accepted publickey for deploy from 185.220.101.42 port 55001 ssh2",
    "Jan  6 03:15:45 appserver sshd[14001]: Accepted publickey for deploy from 10.0.0.1 port 33001 ssh2",
    "Jan  6 03:16:10 appserver sshd[14002]: Accepted publickey for deploy from 10.0.0.1 port 33002 ssh2",
]

# Day 3: Privilege escalation + data access
DAY3_LOGS = [
    "Jan  7 03:30:00 appserver sshd[15001]: Accepted publickey for deploy from 10.0.0.1 port 44001 ssh2",
    "Jan  7 03:30:15 dbserver mysqld[16001]: Access denied for user 'deploy'@'10.0.0.5' (using password: YES)",
    "Jan  7 03:31:00 dbserver mysqld[16002]: Connect deploy@10.0.0.5 on production_db",
    "Jan  7 03:31:30 appserver sudo: deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
]

ALL_LOGS = DAY1_LOGS + DAY2_LOGS + DAY3_LOGS


def banner(text: str, char: str = "═") -> None:
    """Print a formatted banner."""
    width = 72
    logger.info("")
    logger.info(char * width)
    logger.info(f"  {text}")
    logger.info(char * width)


def section(text: str) -> None:
    """Print a section header."""
    logger.info("")
    logger.info(f"  ┌{'─' * 68}┐")
    logger.info(f"  │  {text:<66}│")
    logger.info(f"  └{'─' * 68}┘")


def main() -> None:
    banner("AEGIS — FULL PIPELINE INTEGRATION TEST", "╔═╗")
    logger.info("  Simulating a 3-day multi-stage attack:")
    logger.info("    Day 1: SSH brute-force → credential compromise")
    logger.info("    Day 2: Lateral movement (web → app server)")
    logger.info("    Day 3: Privilege escalation + DB access")
    logger.info("")

    # Initialize the Blockchain Ledger
    blockchain = AegisChain()
    logger.info("  ⛓️  Blockchain Ledger Initialized")
    logger.info("")

    # ═════════════════════════════════════════════════════════════════
    # PHASE 1 — LOG PARSING + UEBA
    # ═════════════════════════════════════════════════════════════════
    section("PHASE 1 — LOG NORMALIZATION + UEBA BASELINE SCORING")

    normalizer = LogNormalizer()
    profiler = BaselineProfiler()
    sessionizer = LogSessionizer(window_seconds=300, max_events=50)

    all_events: list[NormalizedEvent] = []
    all_sessions = []

    for raw_line in ALL_LOGS:
        try:
            ev = normalizer.normalize_line(raw_line, host="aegis-demo", source="integration_test")
            ev = profiler.score(ev)
            all_events.append(ev)

            closed = sessionizer.process_event(ev)
            if closed:
                all_sessions.append(closed)
        except Exception as exc:
            logger.warning("  Parse error: %s → %s", raw_line[:50], exc)

    # Flush remaining sessions
    remaining = sessionizer.flush_all()
    all_sessions.extend(remaining)

    logger.info("")
    logger.info("  📊 Phase 1 Results:")
    logger.info("  ├─ Raw logs processed:    %d", len(ALL_LOGS))
    logger.info("  ├─ Events normalized:     %d", len(all_events))
    logger.info("  ├─ Sessions created:       %d", len(all_sessions))

    # Show UEBA scores
    logger.info("  │")
    logger.info("  ├─ UEBA Suspicion Scores:")
    for ev in all_events:
        if ev.suspicion_delta > 0:
            logger.info(
                "  │   ⚠️  %.1f pts → %s [%s] %s",
                ev.suspicion_delta, ev.source_ip,
                ev.event_action or "unknown",
                ev.log_original[:60],
            )

    for sess in all_sessions:
        logger.info(
            "  ├─ Session: entity=%s  events=%d  suspicion=%.1f  templates=%s",
            sess.entity_id, len(sess.event_hashes),
            sess.total_suspicion, sess.template_sequence[:5],
        )

    # ═════════════════════════════════════════════════════════════════
    # SIMULATED ML OUTPUT (replacing DeepLog/LogLizer/XGBoost)
    # ═════════════════════════════════════════════════════════════════
    section("SIMULATED ML MODELS (DeepLog + XGBoost + Ensemble)")

    logger.info("  ℹ️  No real ML models available — simulating model-alerts")
    logger.info("  ℹ️  In production, DeepLog/LogLizer/XGBoost consume")
    logger.info("     the normalized-events topic and produce alerts")
    logger.info("")

    # Simulate 3 alerts that the models WOULD produce
    simulated_alerts = [
        ModelAlert(
            severity="P2",
            attack_type="ssh_bruteforce",
            confidence=0.87,
            source_host="185.220.101.42",
            affected_assets=["10.0.0.1"],
            model_source="XGBoost",
            event_hashes=[ev.event_hash for ev in all_events[:6]],
            raw_sequence=[ev.template_id for ev in all_events[:6]],
            xgb_proba={"ssh_bruteforce": 0.87, "anomaly_unknown": 0.13},
        ),
        ModelAlert(
            severity="P2",
            attack_type="lateral_movement",
            confidence=0.78,
            source_host="185.220.101.42",
            affected_assets=["10.0.0.1", "10.0.0.5"],
            model_source="DeepLog",
            event_hashes=[ev.event_hash for ev in all_events[6:9]],
            raw_sequence=[ev.template_id for ev in all_events[6:9]],
            anomaly_score=-0.82,
        ),
        ModelAlert(
            severity="P1",
            attack_type="privilege_escalation",
            confidence=0.94,
            source_host="185.220.101.42",
            affected_assets=["10.0.0.1", "10.0.0.5", "10.0.0.10"],
            model_source="Ensemble",
            event_hashes=[ev.event_hash for ev in all_events[9:]],
            raw_sequence=[ev.template_id for ev in all_events[9:]],
            xgb_proba={"privilege_escalation": 0.94, "lateral_movement": 0.06},
        ),
    ]

    for i, alert in enumerate(simulated_alerts, 1):
        logger.info(
            "  📡 Alert %d: [%s] %s → %s  confidence=%.0f%%  model=%s",
            i, alert.severity, alert.attack_type, alert.source_host,
            alert.confidence * 100, alert.model_source,
        )

    # ═════════════════════════════════════════════════════════════════
    # PHASE 2 — ENRICHMENT
    # ═════════════════════════════════════════════════════════════════
    section("PHASE 2 — ALERT ENRICHMENT (MITRE + CVE + ENTITY HISTORY)")

    enrichment_engine = EnrichmentEngine()
    enriched_alerts = []

    for alert in simulated_alerts:
        enriched = enrichment_engine.enrich(alert)
        enriched_alerts.append(enriched)
        logger.info("")
        logger.info("  🔍 Enriched: %s (%s)", alert.attack_type, alert.severity)
        logger.info("     MITRE Techniques : %s", enriched.mitre_techniques)
        logger.info("     MITRE Tactic     : %s", enriched.mitre_tactic)
        logger.info("     CVEs             : %s", enriched.cve_ids)
        logger.info("     Max CVSS         : %.1f", enriched.max_cvss)
        logger.info("     Entity Score     : %.1f (cumulative)", enriched.entity_cumulative_score)
        logger.info("     Entity Alerts    : %d", enriched.entity_alert_count)
        logger.info("     Attack Timeline  : %s", enriched.entity_attack_types)
        
        # ANCHOR THE ALERT IMMEDIATELY
        blockchain.anchor_alert(enriched)

    # ═════════════════════════════════════════════════════════════════
    # PHASE 3 — RISK SCORING + ISOLATION
    # ═════════════════════════════════════════════════════════════════
    section("PHASE 3 — RISK SCORING + AUTOMATED ISOLATION")

    scorer = RiskScorer()
    isolation_log = IsolationLog()
    isolator = Isolator(isolation_log=isolation_log, dry_run=True)

    all_verdicts: list[RiskVerdict] = []
    all_actions = []

    # Only process the LAST (most severe) alert for isolation
    final_enriched = enriched_alerts[-1]
    verdict = scorer.score(final_enriched)
    all_verdicts.append(verdict)

    logger.info("")
    logger.info("  ⚖️  RISK VERDICT:")
    logger.info("     Entity           : %s", verdict.entity_id)
    logger.info("     Original Severity: %s", verdict.original_severity)
    logger.info("     Adjusted Severity: %s", verdict.adjusted_severity)
    logger.info("     Risk Score       : %.2f / 10", verdict.final_risk_score)
    logger.info("     Risk Label       : %s", verdict.risk_label)
    logger.info("     CVSS Component   : %.2f", verdict.cvss_component)
    logger.info("     Criticality      : %.2f", verdict.criticality_component)
    logger.info("     Propagation      : %.2f (%d high-value targets)",
                verdict.propagation_component, verdict.reachable_high_value)
    logger.info("     Requires Isolation: %s", verdict.requires_isolation)

    actions = isolator.execute(verdict)
    all_actions = actions
    
    # ANCHOR THE ISOLATION ACTIONS IMMEDIATELY
    if actions:
        blockchain.anchor_isolation_actions(final_enriched.enriched_id, actions)

    logger.info("")
    logger.info("  🔒 ISOLATION ACTIONS EXECUTED (DRY-RUN):")
    for a in actions:
        logger.info(
            "     [%s] %s → %s",
            a.action_type.value.upper(),
            a.entity_id,
            a.status.value,
        )

    # ═════════════════════════════════════════════════════════════════
    # PHASE 4 — FORENSICS + PLAYBOOK + LEGAL
    # ═════════════════════════════════════════════════════════════════
    section("PHASE 4 — FORENSIC ANALYSIS + INCIDENT REPORT")

    report_gen = ReportGenerator()
    report = report_gen.generate(
        enriched=final_enriched,
        verdict=verdict,
        actions=actions,
        raw_logs=ALL_LOGS,
        template_sequence=[ev.template_id for ev in all_events],
        total_suspicion=sum(ev.suspicion_delta for ev in all_events),
        affected_persons=250,
    )

    # ── Print the forensic analysis ──────────────────────────────────
    analysis = report.analysis
    logger.info("")
    logger.info("  🔬 FORENSIC ANALYSIS:")
    logger.info("     Classification   : %s", analysis.attack_classification)
    logger.info("     Kill Chain Phase : %s", analysis.kill_chain_phase)
    logger.info("     Attack Vector    : %s", analysis.attack_vector)
    logger.info("     Dwell Time       : %s", analysis.dwell_time_description)
    logger.info("     Data at Risk     : %s", analysis.data_at_risk)
    logger.info("     Lateral Risk     : %s", analysis.lateral_risk_level)
    logger.info("")
    logger.info("     📊 CIA Impact Assessment:")
    logger.info("        Confidentiality : %d/10", analysis.impact.confidentiality)
    logger.info("        Integrity       : %d/10", analysis.impact.integrity)
    logger.info("        Availability    : %d/10", analysis.impact.availability)
    logger.info("        Overall         : %.1f/10", analysis.impact.overall)
    logger.info("")
    logger.info("     🔍 Root Cause Hypothesis:")
    logger.info("        %s", analysis.root_cause_hypothesis)
    logger.info("")
    logger.info("     📋 IoC Summary: %s", analysis.ioc_summary)

    # ── Print the playbook ───────────────────────────────────────────
    playbook = report.playbook
    logger.info("")
    logger.info("  📖 INCIDENT RESPONSE PLAYBOOK")
    logger.info("     Total Steps     : %d", playbook.total_steps)
    logger.info("     Estimated Time  : %d minutes", playbook.estimated_total_minutes)
    logger.info("     Severity        : %s", playbook.severity)
    logger.info("")

    current_category = ""
    for step in playbook.steps:
        if step.category.value != current_category:
            current_category = step.category.value
            logger.info("     ── %s ──", current_category.upper())

        status = "☐"
        priority_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(step.priority.value, "⚪")

        logger.info(
            "     %s %s [Step %d] %s",
            status, priority_icon, step.order, step.title,
        )
        logger.info(
            "        %s  (~%d min, assign: %s)",
            step.description[:80], step.estimated_minutes, step.assignee,
        )
        if step.technical_commands:
            for cmd in step.technical_commands[:2]:
                logger.info("        $ %s", cmd)

    # ── Print legal documents ────────────────────────────────────────
    section("LEGAL NOTIFICATIONS (Algerian Law)")

    cert = report.cert_dz_notification
    logger.info("")
    logger.info("  📜 NOTIFICATION CERT-DZ (Décret 20-05)")
    logger.info("     ⏰ Deadline       : %s", cert.deadline)
    logger.info("     ⏳ Heures restantes: %.0f h", cert.hours_remaining)
    logger.info("     Référence légale : %s", cert.regulatory_reference)
    logger.info("     ID Incident      : %s", cert.incident_id[:8])
    logger.info("     Sévérité         : %s", cert.severity_level)
    logger.info("     Nature           : %s", cert.nature_of_breach)
    logger.info("     IP Source        : %s", cert.source_ip)
    logger.info("     Systèmes affectés: %s", cert.affected_systems)
    logger.info("     MITRE            : %s", cert.mitre_techniques)
    logger.info("     Mesures prises   : %s", cert.containment_measures)
    logger.info("     Impact           : %s", cert.impact_assessment)
    logger.info("     Préservation     : %s", cert.evidence_preservation)
    logger.info("     Risque Légal Org : %s", cert.legal_liability_risk)
    logger.info("     Pénalité Hacker  : %s", cert.penalties_for_attacker)
    logger.info("     Services Internes: %s", ", ".join(cert.internal_services_to_notify))

    anpdp = report.anpdp_notification
    logger.info("")
    logger.info("  📜 NOTIFICATION ANPDP (Loi 18-07)")
    logger.info("     ⏰ Deadline       : %s", anpdp.deadline)
    logger.info("     ⏳ Heures restantes: %.0f h", anpdp.hours_remaining)
    logger.info("     Référence légale : %s", anpdp.regulatory_reference)
    logger.info("     Nature           : %s", anpdp.nature_of_breach)
    logger.info("     Catégories données: %s", anpdp.affected_data_categories)
    logger.info("     Personnes affectées: %d", anpdp.estimated_persons_affected)
    logger.info("     Conséquences     : %s", anpdp.likely_consequences)
    logger.info("     Mesures prises   : %s", anpdp.containment_measures)
    logger.info("     Pertes Données   : %s", anpdp.data_loss_risk_assessment)
    logger.info("     Amendes Non-Conf.: %s", anpdp.fines_for_non_compliance)
    logger.info("     Pénalité Hacker  : %s", anpdp.penalties_for_attacker)
    logger.info("     Services Internes: %s", ", ".join(anpdp.internal_services_to_notify))

    # ── Print applicable regulations ─────────────────────────────────
    logger.info("")
    logger.info("  📋 RÉGLEMENTATIONS APPLICABLES:")
    for reg in report.applicable_regulations:
        logger.info(
            "     [%s] %s — deadline=%dh (%s)",
            reg["reg_id"], reg["name"][:50],
            reg["deadline_hours"], reg["urgency"],
        )
        logger.info("        Pénalité: %s", reg["penalty"][:80])

    # ── Executive summary ────────────────────────────────────────────
    section("EXECUTIVE SUMMARY")
    logger.info("")
    logger.info("  %s", report.executive_summary)

    # ── Technical summary ────────────────────────────────────────────
    section("TECHNICAL SUMMARY")
    logger.info("")
    for line in report.technical_summary.split("\n"):
        logger.info("  %s", line)

    # ── Save full report to file ─────────────────────────────────────
    section("REPORT OUTPUT")

    output_dir = Path(settings.demo_output_file).parent / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    # JSON report
    json_path = output_dir / f"FULL_REPORT_{report.report_id[:8]}.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(report.model_dump_json(indent=2))
    logger.info("  📄 JSON Report → %s", json_path)

    # Human-readable report
    txt_path = output_dir / f"FULL_REPORT_{report.report_id[:8]}.txt"
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write("=" * 72 + "\n")
        fh.write("  AEGIS INCIDENT REPORT\n")
        fh.write("=" * 72 + "\n\n")
        fh.write(f"Report ID    : {report.report_id}\n")
        fh.write(f"Generated    : {report.generated_at}\n")
        fh.write(f"Entity       : {report.entity_id}\n")
        fh.write(f"Severity     : {report.severity}\n")
        fh.write(f"Risk Score   : {report.risk_score:.2f} ({report.risk_label})\n\n")

        fh.write("─" * 72 + "\n")
        fh.write("EXECUTIVE SUMMARY\n")
        fh.write("─" * 72 + "\n")
        fh.write(report.executive_summary + "\n\n")

        fh.write("─" * 72 + "\n")
        fh.write("TECHNICAL SUMMARY\n")
        fh.write("─" * 72 + "\n")
        fh.write(report.technical_summary + "\n\n")

        fh.write("─" * 72 + "\n")
        fh.write("FORENSIC ANALYSIS\n")
        fh.write("─" * 72 + "\n")
        fh.write(f"Classification : {analysis.attack_classification}\n")
        fh.write(f"Kill Chain     : {analysis.kill_chain_phase}\n")
        fh.write(f"Attack Vector  : {analysis.attack_vector}\n")
        fh.write(f"Root Cause     : {analysis.root_cause_hypothesis}\n")
        fh.write(f"Dwell Time     : {analysis.dwell_time_description}\n")
        fh.write(f"Impact (CIA)   : C={analysis.impact.confidentiality} "
                 f"I={analysis.impact.integrity} A={analysis.impact.availability} "
                 f"(overall={analysis.impact.overall})\n\n")

        fh.write("─" * 72 + "\n")
        fh.write("INCIDENT RESPONSE PLAYBOOK\n")
        fh.write("─" * 72 + "\n")
        for step in playbook.steps:
            fh.write(f"\n[Step {step.order}] [{step.priority.value.upper()}] "
                     f"{step.category.value.upper()}\n")
            fh.write(f"  Title   : {step.title}\n")
            fh.write(f"  Detail  : {step.description}\n")
            fh.write(f"  Assignee: {step.assignee} (~{step.estimated_minutes} min)\n")
            if step.technical_commands:
                fh.write("  Commands:\n")
                for cmd in step.technical_commands:
                    fh.write(f"    $ {cmd}\n")

        fh.write("\n" + "─" * 72 + "\n")
        fh.write("LEGAL — NOTIFICATION CERT-DZ (T+24h)\n")
        fh.write("─" * 72 + "\n")
        fh.write(f"Deadline       : {cert.deadline}\n")
        fh.write(f"Référence      : {cert.regulatory_reference}\n")
        fh.write(f"Sévérité       : {cert.severity_level}\n")
        fh.write(f"Nature         : {cert.nature_of_breach}\n")
        fh.write(f"IP Source      : {cert.source_ip}\n")
        fh.write(f"Systèmes       : {cert.affected_systems}\n")
        fh.write(f"MITRE          : {cert.mitre_techniques}\n")
        fh.write(f"Mesures        : {cert.containment_measures}\n")
        fh.write(f"Impact         : {cert.impact_assessment}\n")
        fh.write(f"Preuves        : {cert.evidence_preservation}\n")
        fh.write(f"Risque Légal   : {cert.legal_liability_risk}\n")
        fh.write(f"Pénalité Hacker: {cert.penalties_for_attacker}\n")
        fh.write(f"Services Inters: {', '.join(cert.internal_services_to_notify)}\n")

        fh.write("\n" + "─" * 72 + "\n")
        fh.write("LEGAL — NOTIFICATION ANPDP (T+72h)\n")
        fh.write("─" * 72 + "\n")
        fh.write(f"Deadline       : {anpdp.deadline}\n")
        fh.write(f"Référence      : {anpdp.regulatory_reference}\n")
        fh.write(f"Nature         : {anpdp.nature_of_breach}\n")
        fh.write(f"Données        : {anpdp.affected_data_categories}\n")
        fh.write(f"Personnes      : {anpdp.estimated_persons_affected}\n")
        fh.write(f"Conséquences   : {anpdp.likely_consequences}\n")
        fh.write(f"Pertes Données : {anpdp.data_loss_risk_assessment}\n")
        fh.write(f"Amendes Entité : {anpdp.fines_for_non_compliance}\n")
        fh.write(f"Pénalité Hacker: {anpdp.penalties_for_attacker}\n")
        fh.write(f"Services Inters: {', '.join(anpdp.internal_services_to_notify)}\n")

        fh.write("\n" + "─" * 72 + "\n")
        fh.write("INVESTIGATION STEPS (Attack-Specific)\n")
        fh.write("─" * 72 + "\n")
        for i, step_text in enumerate(analysis.investigation_steps, 1):
            fh.write(f"  {i}. {step_text}\n")

        fh.write("\n" + "─" * 72 + "\n")
        fh.write("RECOMMENDATIONS\n")
        fh.write("─" * 72 + "\n")
        for i, rec in enumerate(analysis.recommendations, 1):
            fh.write(f"  {i}. {rec}\n")

        fh.write("\n" + "=" * 72 + "\n")
        fh.write("  END OF REPORT — AEGIS Adaptive Enterprise Guard\n")
        fh.write("=" * 72 + "\n")

    logger.info("  📄 Text Report → %s", txt_path)

    # ── Final stats ──────────────────────────────────────────────────
    banner("INTEGRATION TEST COMPLETE", "═")
    logger.info("  ✅ Phase 1: %d logs → %d events → %d sessions", len(ALL_LOGS), len(all_events), len(all_sessions))
    logger.info("  ✅ Phase 2: %d alerts enriched (MITRE + CVE + History)", len(enriched_alerts))
    logger.info("  ✅ Phase 3: Risk=%.2f (%s) → %d isolation actions", verdict.final_risk_score, verdict.risk_label, len(actions))
    logger.info("  ✅ Phase 4: %d playbook steps, %d regulations, 2 legal docs", playbook.total_steps, len(report.applicable_regulations))
    logger.info("")
    logger.info("  📁 Reports saved to: %s", output_dir)
    logger.info("")


if __name__ == "__main__":
    main()
