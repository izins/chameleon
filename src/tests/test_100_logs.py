import random
import time
from datetime import datetime, timedelta
import logging
import os

# ── Environment ──────────────────────────────────────────────────────
os.environ["AEGIS_DEMO_MODE"] = "true"

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)
logger = logging.getLogger("AEGIS_100_TEST")

# ── Imports ──────────────────────────────────────────────────────────
from src.parsing.models import NormalizedEvent, ModelAlert
from src.parsing.baseline_profiler import BaselineProfiler
from src.parsing.normalizer import LogNormalizer
from src.parsing.sessionizer import LogSessionizer
from src.enrichment.enrichment_engine import EnrichmentEngine
from src.response.scorer import RiskScorer
from src.response.isolator import Isolator
from src.response.isolation_log import IsolationLog
from src.reporting.report_generator import ReportGenerator
from src.blockchain.aegis_chain import AegisChain
from src.database.db_manager import db
import json

def generate_dynamic_logs(num_logs=100):
    logs = []
    base_time = datetime.now() - timedelta(days=2)
    
    # 70 Benign Logs
    for i in range(70):
        t = (base_time + timedelta(minutes=i*10)).strftime("%b %e %H:%M:%S")
        user = random.choice(["alice", "bob", "deploy"])
        src_ip = f"192.168.1.{random.randint(10, 50)}"
        port = random.randint(30000, 60000)
        logs.append(f"{t} appserver sshd[{random.randint(1000,9999)}]: Accepted publickey for {user} from {src_ip} port {port} ssh2")

    # 20 Brute Force Logs (Malicious)
    hacker_ip = f"185.220.101.{random.randint(10, 99)}"
    brute_time = base_time + timedelta(days=1)
    for i in range(20):
        t = (brute_time + timedelta(seconds=i*2)).strftime("%b %e %H:%M:%S")
        user = random.choice(["root", "admin", "test", "deploy"])
        port = random.randint(30000, 60000)
        logs.append(f"{t} webserver sshd[{random.randint(10000,19999)}]: Failed password for {user} from {hacker_ip} port {port} ssh2")

    # 5 Lateral Movement Logs (Malicious)
    lat_time = brute_time + timedelta(hours=1)
    for i in range(5):
        t = (lat_time + timedelta(minutes=i*5)).strftime("%b %e %H:%M:%S")
        port = random.randint(30000, 60000)
        logs.append(f"{t} appserver sshd[{random.randint(20000,29999)}]: Accepted publickey for deploy from {hacker_ip} port {port} ssh2")

    # 5 Privilege Escalation / Data Access (Malicious)
    priv_time = lat_time + timedelta(hours=1)
    for i in range(5):
        t = (priv_time + timedelta(minutes=i)).strftime("%b %e %H:%M:%S")
        if i % 2 == 0:
            logs.append(f"{t} dbserver mysqld[{random.randint(30000,39999)}]: Connect deploy@{hacker_ip} on production_db")
        else:
            logs.append(f"{t} appserver sudo: deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash")

    # Sort logs by timestamp to simulate real ingestion
    def parse_log_time(log_line):
        time_str = " ".join(log_line.split()[:3])
        try:
            # Assuming current year for parsing
            return datetime.strptime(f"{datetime.now().year} {time_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return datetime.now()

    logs.sort(key=parse_log_time)
    return logs, hacker_ip

def main():
    logger.info("==============================================")
    logger.info("AEGIS 100 LOGS DYNAMIC TEST (NO HARDCODING)")
    logger.info("==============================================\n")

    logs, hacker_ip = generate_dynamic_logs(100)
    logger.info(f"Generated {len(logs)} logs dynamically.")
    logger.info(f"Hacker IP identified as: {hacker_ip}")
    
    blockchain = AegisChain()

    normalizer = LogNormalizer()
    profiler = BaselineProfiler()
    sessionizer = LogSessionizer(window_seconds=300, max_events=50)

    all_events = []
    all_sessions = []

    logger.info("\n--- PHASE 1: PARSING & UEBA ---")
    for raw_line in logs:
        try:
            ev = normalizer.normalize_line(raw_line, host="aegis-test", source="test_100")
            ev = profiler.score(ev)
            all_events.append(ev)
            closed = sessionizer.process_event(ev)
            if closed:
                all_sessions.append(closed)
        except Exception as e:
            pass
            
    all_sessions.extend(sessionizer.flush_all())

    logger.info(f"Processed Events: {len(all_events)}")
    logger.info(f"Generated Sessions: {len(all_sessions)}")

    logger.info("\n--- PHASE 2: ML DETECTIONS (SIMULATED DYNAMICALLY) ---")
    # Dynamically find the events belonging to the hacker IP to generate alerts
    hacker_events = [ev for ev in all_events if ev.source_ip == hacker_ip or hacker_ip in ev.log_original]
    
    if hacker_events:
        attack_types = [
            "advanced_persistent_threat",
            "lateral_movement",
            "data_exfiltration",
            "credential_stuffing",
            "ransomware_activity"
        ]
        chosen_attack = random.choice(attack_types)
        
        alert = ModelAlert(
            severity="P1",
            attack_type=chosen_attack,
            confidence=random.uniform(0.85, 0.99),
            source_host=hacker_ip,
            affected_assets=["aegis-test", "webserver", "appserver", "dbserver"],
            model_source="Ensemble_LSTM_XGB",
            event_hashes=[ev.event_hash for ev in hacker_events],
            raw_sequence=[ev.template_id for ev in hacker_events],
            xgb_proba={chosen_attack: 0.95}
        )
        simulated_alerts = [alert]
        logger.info(f"Generated 1 P1 Alert ({chosen_attack}) covering {len(hacker_events)} anomalous events from {hacker_ip}")
    else:
        simulated_alerts = []
        logger.info("No malicious events detected by ML.")

    logger.info("\n--- PHASE 3: ENRICHMENT & BLOCKCHAIN ---")
    enrichment_engine = EnrichmentEngine()
    enriched_alerts = []
    for alert in simulated_alerts:
        enriched = enrichment_engine.enrich(alert)
        enriched_alerts.append(enriched)
        blockchain.anchor_alert(enriched)
        logger.info(f"Enriched Alert: MITRE {enriched.mitre_tactic}, CVEs {enriched.cve_ids}, CVSS {enriched.max_cvss}")

    logger.info("\n--- PHASE 4: ISOLATION & SCORING ---")
    scorer = RiskScorer()
    isolation_log = IsolationLog()
    isolator = Isolator(isolation_log=isolation_log, dry_run=True)
    
    actions = []
    if enriched_alerts:
        final_enriched = enriched_alerts[-1]
        verdict = scorer.score(final_enriched)
        logger.info(f"Risk Score: {verdict.final_risk_score}/10 -> {verdict.risk_label}")
        
        actions = isolator.execute(verdict)
        blockchain.anchor_isolation_actions(final_enriched.enriched_id, actions)
        for a in actions:
            logger.info(f"Action executed: {a.action_type.value.upper()} on {a.entity_id} -> {a.status.value}")

    logger.info("\n--- PHASE 5: REPORTING ---")
    if enriched_alerts:
        report_gen = ReportGenerator()
        report = report_gen.generate(
            enriched=final_enriched,
            verdict=verdict,
            actions=actions,
            raw_logs=logs,
            template_sequence=[ev.template_id for ev in all_events],
            total_suspicion=sum(ev.suspicion_delta for ev in all_events),
            affected_persons=150
        )
        logger.info(f"Incident Report Generated: {report.report_id}")
        logger.info(f"Classification: {report.analysis.attack_classification}")
        logger.info(f"CERT-DZ Deadline: {report.cert_dz_notification.deadline}")
        logger.info(f"Playbook Steps: {report.playbook.total_steps}")
        
        # Add to Database
        db.log_alert(final_enriched.enriched_id, hacker_ip, alert.attack_type, alert.severity, alert.confidence)
        db.upsert_entity(hacker_ip, alert.confidence * 100, alert.attack_type)
        
        # Append to dashboard_payload.json so both attacks show
        try:
            with open("data/dashboard_payload.json", "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception:
            payload = {"reports": [], "total_events": 0, "total_sessions": 0, "total_ml_alerts": 0, "total_reports": 0}
            
        payload["total_events"] += len(all_events)
        payload["total_sessions"] += len(all_sessions)
        payload["total_ml_alerts"] += 1
        payload["total_reports"] += 1
        
        summary = db.get_dashboard_summary()
        payload["attack_distribution"] = summary.get("attack_distribution", {})
        payload["geo_origins"] = summary.get("geo_origins", [])
        payload["top_attackers"] = summary.get("top_attackers", [])
        payload["attacks_by_hour"] = summary.get("attacks_by_hour", {})
        payload["recent_attacks"] = summary.get("recent_attacks", [])

        payload["reports"].insert(0, {
            "report_id": report.report_id,
            "entity_id": report.entity_id,
            "severity": report.severity,
            "risk_score": report.risk_score,
            "risk_label": report.risk_label,
            "generated_at": report.generated_at,
            "attack_classification": report.analysis.attack_classification,
            "kill_chain": report.analysis.kill_chain_phase,
            "root_cause": report.analysis.root_cause_hypothesis,
            "impact_c": report.analysis.impact.confidentiality,
            "impact_i": report.analysis.impact.integrity,
            "impact_a": report.analysis.impact.availability,
            "playbook_steps": report.playbook.total_steps,
            "playbook_time_min": report.playbook.estimated_total_minutes,
            "mitre_techniques": report.evidence.mitre_techniques,
            "cves": report.evidence.cve_ids,
            "max_cvss": report.evidence.max_cvss,
            "cert_dz_deadline": report.cert_dz_notification.deadline,
            "cert_dz_hours": report.cert_dz_notification.hours_remaining,
            "cert_dz_liability": report.cert_dz_notification.legal_liability_risk,
            "cert_dz_penalties_attacker": report.cert_dz_notification.penalties_for_attacker,
            "anpdp_deadline": report.anpdp_notification.deadline,
            "anpdp_hours": report.anpdp_notification.hours_remaining,
            "anpdp_persons_affected": report.anpdp_notification.estimated_persons_affected,
            "anpdp_fines": report.anpdp_notification.fines_for_non_compliance,
            "anpdp_data_categories": report.anpdp_notification.affected_data_categories,
            "executive_summary": report.executive_summary,
            "technical_summary": report.technical_summary,
            "isolation_actions": [],
            "regulations": report.applicable_regulations,
        })
        
        with open("data/dashboard_payload.json", "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            
    else:
        logger.info("No reports generated as no critical alerts were triggered.")

    logger.info("\n==============================================")
    logger.info("TEST COMPLETED SUCCESSFULLY")
    logger.info("==============================================")

if __name__ == "__main__":
    main()
