"""
AEGIS — NEEDLE IN THE HAYSTACK TEST
=====================================
200 realistic syslog lines. ~190 are normal daily operations.
One SSH brute-force campaign (~10 lines) is buried in the middle.

Goal: Can AEGIS find the single real attack hidden in normal noise?
"""

from __future__ import annotations

import json
import logging
import os
import random
from datetime import datetime, timezone
from pathlib import Path

os.environ["AEGIS_DEMO_MODE"] = "true"
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("HAYSTACK")

from src.config.settings import settings, PROJECT_ROOT
from src.parsing.normalizer import LogNormalizer
from src.parsing.baseline_profiler import BaselineProfiler
from src.parsing.sessionizer import LogSessionizer
from src.ml.ml_detector import MLDetector
from src.enrichment.enrichment_engine import EnrichmentEngine
from src.enrichment.verification_gate import VerificationGate
from src.response.scorer import RiskScorer
from src.response.isolator import Isolator
from src.response.isolation_log import IsolationLog
from src.reporting.report_generator import ReportGenerator
from src.blockchain.aegis_chain import AegisChain
from src.database.db_manager import db
from src.response.iso27035_tracker import ISO27035Tracker, ISOPhase

# ═══════════════════════════════════════════════════════════════════════
# LOG GENERATORS — Normal traffic patterns
# ═══════════════════════════════════════════════════════════════════════

NORMAL_USERS = ["alice", "bob", "charlie", "deploy", "sysadmin", "webmaster"]
INTERNAL_IPS = ["10.0.0.1", "10.0.0.5", "10.0.0.10", "10.0.0.20", "10.0.0.30",
                "10.0.0.50", "10.0.0.100", "192.168.1.10", "192.168.1.20"]
SERVERS = ["webserver", "appserver", "dbserver", "mailserver", "vpngateway", "fileserver"]
SERVICES = ["sshd", "cron", "systemd", "postfix", "nginx"]

def gen_normal_ssh_login(day, hour, minute):
    user = random.choice(NORMAL_USERS)
    ip = random.choice(INTERNAL_IPS)
    srv = random.choice(SERVERS[:3])
    pid = random.randint(10000, 60000)
    port = random.randint(30000, 65000)
    return f"Jan {day:2d} {hour:02d}:{minute:02d}:{random.randint(0,59):02d} {srv} sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2"

def gen_normal_cron(day, hour, minute):
    srv = random.choice(SERVERS)
    pid = random.randint(10000, 60000)
    cmd = random.choice(["/usr/bin/logrotate", "/usr/sbin/ntpdate", "/opt/backup/run.sh",
                          "/usr/bin/certbot renew", "/usr/local/bin/health_check.sh"])
    return f"Jan {day:2d} {hour:02d}:{minute:02d}:{random.randint(0,59):02d} {srv} CRON[{pid}]: (root) CMD ({cmd})"

def gen_normal_systemd(day, hour, minute):
    srv = random.choice(SERVERS)
    unit = random.choice(["nginx.service", "postgresql.service", "redis.service",
                           "docker.service", "sshd.service", "postfix.service"])
    action = random.choice(["Started", "Reloading", "Stopping"])
    return f"Jan {day:2d} {hour:02d}:{minute:02d}:{random.randint(0,59):02d} {srv} systemd[1]: {action} {unit}."

def gen_normal_postfix(day, hour, minute):
    srv = random.choice(["mailserver", "webserver"])
    pid = random.randint(10000, 60000)
    msgid = f"{random.randint(100000,999999)}@{srv}"
    action = random.choice([
        f"to=<user@company.dz>, relay=local, status=sent",
        f"connect from mail.partner.com[{random.randint(50,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}]",
        f"disconnect from mail.partner.com",
    ])
    return f"Jan {day:2d} {hour:02d}:{minute:02d}:{random.randint(0,59):02d} {srv} postfix/smtpd[{pid}]: {msgid}: {action}"

def gen_normal_nginx(day, hour, minute):
    ip = random.choice(INTERNAL_IPS + ["172.16.0.5", "172.16.0.10"])
    status = random.choice([200, 200, 200, 200, 301, 304, 404])
    path = random.choice(["/", "/api/health", "/login", "/dashboard", "/static/main.css",
                           "/api/v1/users", "/favicon.ico"])
    return f"Jan {day:2d} {hour:02d}:{minute:02d}:{random.randint(0,59):02d} webserver nginx[8080]: {ip} - - GET {path} HTTP/1.1 {status}"

def gen_normal_firewall_allow(day, hour, minute):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS)
    port = random.choice([22, 80, 443, 5432, 6379, 8080])
    return f"Jan {day:2d} {hour:02d}:{minute:02d}:{random.randint(0,59):02d} vpngateway kernel: [UFW ALLOW] IN=eth0 OUT= SRC={src} DST={dst} PROTO=TCP DPT={port}"

# ═══════════════════════════════════════════════════════════════════════
# THE ATTACK — SSH brute-force from a single attacker
# ═══════════════════════════════════════════════════════════════════════
ATTACKER_IP = "203.0.113.66"  # Known malicious IP (RFC 5737 documentation range)

def gen_attack_logs():
    """Generate the attack sequence — buried at lines ~95-105."""
    attack = []
    # 8 rapid failed attempts
    for i in range(8):
        user = random.choice(["root", "admin", "root", "root", "deploy", "admin", "postgres", "root"])
        pid = 20000 + i
        port = 55000 + i
        attack.append(
            f"Jan 15 02:31:{10+i:02d} webserver sshd[{pid}]: Failed password for {user} from {ATTACKER_IP} port {port} ssh2"
        )
    # Success after brute-force
    attack.append(
        f"Jan 15 02:32:05 webserver sshd[20010]: Accepted password for deploy from {ATTACKER_IP} port 55100 ssh2"
    )
    # Firewall block on suspicious outbound
    attack.append(
        f"Jan 15 02:32:30 webserver kernel: [UFW BLOCK] IN=eth0 OUT= SRC={ATTACKER_IP} DST=10.0.0.5 PROTO=TCP"
    )
    return attack


def build_200_logs():
    """Build exactly 200 logs: ~190 normal + 10 attack."""
    logs = []
    normal_generators = [
        gen_normal_ssh_login, gen_normal_cron, gen_normal_systemd,
        gen_normal_postfix, gen_normal_nginx, gen_normal_firewall_allow,
    ]

    random.seed(42)  # Reproducible

    # Generate 95 normal logs (Jan 14-15 business hours)
    for i in range(95):
        day = 14 if i < 50 else 15
        hour = random.choice([8, 9, 10, 11, 13, 14, 15, 16, 17])
        minute = random.randint(0, 59)
        gen = random.choice(normal_generators)
        logs.append(gen(day, hour, minute))

    # Insert attack at position 95-104
    attack_logs = gen_attack_logs()
    logs.extend(attack_logs)

    # Generate 95 more normal logs after the attack
    for i in range(200 - len(logs)):
        day = 15
        hour = random.choice([6, 7, 8, 9, 10, 11, 13, 14, 15, 16])
        minute = random.randint(0, 59)
        gen = random.choice(normal_generators)
        logs.append(gen(day, hour, minute))

    return logs[:200], attack_logs


def main():
    logs, attack_lines = build_200_logs()

    logger.info("╔════════════════════════════════════════════════════════════════╗")
    logger.info("║  AEGIS — NEEDLE IN THE HAYSTACK (200 logs, 1 real attack)     ║")
    logger.info("╚════════════════════════════════════════════════════════════════╝")
    logger.info("")
    logger.info("  Total logs:     %d", len(logs))
    logger.info("  Normal logs:    %d (%.0f%%)", len(logs) - len(attack_lines),
                (len(logs) - len(attack_lines)) / len(logs) * 100)
    logger.info("  Attack logs:    %d (%.0f%%) — SSH brute-force from %s",
                len(attack_lines), len(attack_lines) / len(logs) * 100, ATTACKER_IP)
    logger.info("  Attack position: lines 96-105 (buried in the middle)")
    logger.info("")

    # Save logs to a file for the pipeline
    log_file = Path("data/fixtures/haystack_200.log")
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, "w", encoding="utf-8") as f:
        for line in logs:
            f.write(line + "\n")
    logger.info("  Log file saved → %s", log_file)

    # Cache attacker geo
    db.save_geo(ATTACKER_IP, {
        "country": "Russia", "country_code": "RU", "city": "Moscow",
        "latitude": 55.7558, "longitude": 37.6173, "asn": 49505,
        "isp": "Selectel", "is_tor": False, "is_vpn": True,
    })

    # ── PHASE 1: Full pipeline ───────────────────────────────────────
    logger.info("")
    logger.info("  ── PHASE 1: Parsing + UEBA + Sessionizing ──")
    normalizer = LogNormalizer()
    profiler = BaselineProfiler()
    sessionizer = LogSessionizer(window_seconds=300, max_events=50)

    events = []
    sessions = []
    parse_errors = 0

    for raw in logs:
        try:
            ev = normalizer.normalize_line(raw, host="haystack-test", source="200_logs")
            ev = profiler.score(ev)
            events.append(ev)
            closed = sessionizer.process_event(ev)
            if closed:
                sessions.append(closed)
        except Exception:
            parse_errors += 1

    remaining = sessionizer.flush_all()
    sessions.extend(remaining)

    logger.info("    Events parsed:   %d / %d (errors: %d)", len(events), len(logs), parse_errors)
    logger.info("    Sessions:        %d", len(sessions))

    # Show sessions with suspicion
    for s in sessions:
        marker = "🔴" if s.total_suspicion > 2 else "🟢"
        logger.info("    %s Session %s: entity=%-18s events=%d suspicion=%.1f templates=%s",
                     marker, s.session_id[:8], s.entity_id, s.event_count,
                     s.total_suspicion, s.template_sequence[:8])

    # ── PHASE 1.5: ML Detection ──────────────────────────────────────
    logger.info("")
    logger.info("  ── PHASE 1.5: ML Detection (LSTM + XGBoost) ──")
    detector = MLDetector()

    alerts = []
    for session in sessions:
        alert = detector.detect(session)
        is_attacker = ATTACKER_IP in (session.entity_id or "")
        
        # Log all attacker predictions to debug
        if is_attacker:
            seq = detector._prepare_sequence(session.template_sequence)
            lstm_p = detector._run_lstm(seq)
            xgb_c, xgb_p = detector._run_xgboost(seq)
            logger.info("    [DEBUG] Attacker Session: LSTM=%.3f XGB_Class=%s Probas=%s", 
                        lstm_p, xgb_c, xgb_p)

        if alert:
            alerts.append((session, alert))

    logger.info("    Sessions analyzed: %d", len(sessions))
    logger.info("    Alerts fired:      %d", len(alerts))
    logger.info("")

    if not alerts:
        logger.info("    ⚠️  NO ALERTS — the attack was not detected!")
        logger.info("    This indicates the ML models need retraining on this log format.")
    else:
        for session, alert in alerts:
            is_attacker = ATTACKER_IP in (session.entity_id or "")
            marker = "🎯 TARGET" if is_attacker else "   noise"
            logger.info("    %s  entity=%-18s attack=%-18s conf=%.2f model=%s susp=%.1f",
                         marker, alert.source_host, alert.attack_type,
                         alert.confidence, alert.model_source, session.total_suspicion)

    # ── PHASE 2+3+4: Enrichment → Isolation → Reports ────────────────
    logger.info("")
    logger.info("  ── PHASE 2-4: Enrichment → Risk → Reports ──")

    enrichment = EnrichmentEngine()
    gate = VerificationGate()
    scorer = RiskScorer()
    isolator = Isolator(dry_run=True)
    blockchain = AegisChain()
    iso_tracker = ISO27035Tracker()
    iso_tracker = ISO27035Tracker()

    reports = []
    for session, alert in alerts:
        # ── ISO 27035 Phase 1: Detection & Reporting ───────────
        iso_record = iso_tracker.create_incident(alert.source_host)
        iso_id = iso_record.incident_id

        iso_tracker.start_phase(iso_id, ISOPhase.DETECTION, {
            "source": f"ML Pipeline ({alert.model_source})",
            "session_id": session.session_id[:8],
            "event_count": session.event_count,
            "confidence": alert.confidence,
            "attack_type": alert.attack_type,
            "suspicion_score": session.total_suspicion,
        }, module="ml_detector.py")

        iso_tracker.complete_phase(iso_id, ISOPhase.DETECTION, {
            "alert_id": alert.alert_id[:8],
            "attack_type": alert.attack_type,
            "severity": alert.severity,
            "confidence": alert.confidence,
            "model_source": alert.model_source,
            "template_sequence": session.template_sequence[:8],
        }, requirements_met=[
            "Monitor information security events from multiple sources",
            "Correlate events to identify potential incidents",
        ])

        # ── ISO 27035 Phase 2: Assessment & Decision ───────────
        iso_tracker.start_phase(iso_id, ISOPhase.ASSESSMENT, {
            "alert_id": alert.alert_id[:8],
            "enrichment_sources": ["MITRE", "CVE", "EPSS", "KEV", "EntityTracker"],
        }, module="enrichment_engine.py + verification_gate.py + scorer.py")

        enriched = enrichment.enrich(alert)
        verdict = gate.evaluate(enriched)
        risk = scorer.score(enriched)

        iso_tracker.complete_phase(iso_id, ISOPhase.ASSESSMENT, {
            "gate_verdict": verdict.verdict.value,
            "gate_score": verdict.gate_score,
            "risk_score": risk.final_risk_score,
            "risk_label": risk.risk_label,
            "5d_decomposition": {
                "D1_vulnerability": risk.vuln_component,
                "D2_asset_criticality": risk.criticality_component,
                "D3_propagation": risk.propagation_component,
                "D4_entity_history": risk.history_component,
                "D5_data_sensitivity": risk.data_component,
            },
            "mitre_techniques": enriched.mitre_techniques,
            "max_cvss": enriched.max_cvss,
            "epss_score": enriched.epss_score,
            "is_kev": enriched.is_kev,
            "asset_type": enriched.asset_type,
            "business_impact": enriched.business_impact,
        }, requirements_met=[
            "Classify the incident by type and severity",
            "Assess business impact (confidentiality, integrity, availability)",
            "Verify the incident is not a false positive",
        ])

        iso_tracker.update_summary(
            iso_id, severity=alert.severity, attack_type=alert.attack_type,
            risk_score=risk.final_risk_score, risk_label=risk.risk_label,
        )

        # ── ISO 27035 Phase 3: Response ───────────────────────
        iso_tracker.start_phase(iso_id, ISOPhase.RESPONSE, {
            "risk_score": risk.final_risk_score,
            "requires_isolation": risk.requires_isolation,
        }, module="isolator.py", sub_phase="containment")

        actions = isolator.execute(risk)

        iso_tracker.complete_phase(iso_id, ISOPhase.RESPONSE, {
            "actions_count": len(actions),
            "actions": [a.action_type for a in actions],
            "dry_run": True,
        }, sub_phase="containment", requirements_met=[
            "Isolate affected systems proportionally",
            "Preserve evidence before containment actions",
        ])

        # Mark Phase 3 overall complete
        iso_tracker.start_phase(iso_id, ISOPhase.RESPONSE, {
            "containment_done": True,
        }, module="isolator.py")
        iso_tracker.complete_phase(iso_id, ISOPhase.RESPONSE, {
            "total_actions": len(actions),
        })

        db.log_alert(enriched.enriched_id, alert.source_host,
                     alert.attack_type, alert.severity, alert.confidence)
        db.upsert_entity(alert.source_host, alert.confidence * 100, alert.attack_type)
        blockchain.anchor_alert(enriched)
        if actions:
            blockchain.anchor_isolation_actions(enriched.enriched_id, actions)

        # ── ISO 27035 Phase 4: Lessons Learned ─────────────────
        iso_tracker.start_phase(iso_id, ISOPhase.LESSONS, {
            "enriched_alert_id": enriched.enriched_id[:8],
        }, module="incident_analyzer.py")

        report_gen = ReportGenerator()
        report = report_gen.generate(
            enriched=enriched, verdict=risk, actions=actions,
            raw_logs=[l for l in logs if ATTACKER_IP in l] if ATTACKER_IP in alert.source_host else [],
            template_sequence=session.template_sequence,
            total_suspicion=session.total_suspicion,
            affected_persons=50,
        )
        reports.append(report)

        iso_tracker.complete_phase(iso_id, ISOPhase.LESSONS, {
            "root_cause": report.analysis.root_cause_hypothesis,
            "attack_classification": report.analysis.attack_classification,
            "kill_chain_phase": report.analysis.kill_chain_phase,
        }, requirements_met=[
            "Identify root cause and contributing factors",
        ])

        # ── ISO 27035 Phase 5: Documentation & Closure ──────────
        iso_tracker.start_phase(iso_id, ISOPhase.CLOSURE, {
            "report_id": report.report_id[:8],
        }, module="report_generator.py + blockchain")

        iso_tracker.complete_phase(iso_id, ISOPhase.CLOSURE, {
            "report_persisted": True,
            "blockchain_anchored": True,
            "cert_dz_generated": True,
            "anpdp_generated": True,
            "playbook_steps": report.playbook.total_steps,
        }, requirements_met=[
            "Complete incident report with full timeline",
            "Archive all evidence with cryptographic integrity",
            "Submit regulatory notifications (CERT-DZ T+24h, ANPDP T+72h)",
        ])

        is_attacker = ATTACKER_IP in alert.source_host
        marker = "🎯" if is_attacker else "  "
        logger.info("    %s  entity=%-18s gate=%-13s risk=%.1f (%s) isolate=%s",
                     marker, alert.source_host, verdict.verdict.value,
                     risk.final_risk_score, risk.risk_label, risk.requires_isolation)

    # ── Update dashboard payload ─────────────────────────────────────
    summary = db.get_dashboard_summary()
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "test_name": "Needle in the Haystack — 200 logs, 1 attack",
        "scenarios_tested": 1,
        "total_events": len(events),
        "total_sessions": len(sessions),
        "total_ml_alerts": len(alerts),
        "total_reports": len(reports),
        "attack_distribution": summary.get("attack_distribution", {}),
        "severity_distribution": {},
        "verdict_distribution": {},
        "geo_origins": summary.get("geo_origins", []),
        "top_attackers": summary.get("top_attackers", []),
        "attacks_by_hour": summary.get("attacks_by_hour", {}),
        "recent_attacks": summary.get("recent_attacks", []),
        "reports": [],
    }

    for report in reports:
        payload["reports"].append({
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

    # ── FINAL SCORECARD ──────────────────────────────────────────────
    attacker_alerts = [a for _, a in alerts if ATTACKER_IP in a.source_host]
    false_positives = [a for s, a in alerts if ATTACKER_IP not in a.source_host]

    logger.info("")
    logger.info("╔════════════════════════════════════════════════════════════════╗")
    logger.info("║  HAYSTACK RESULTS — DETECTION ACCURACY                        ║")
    logger.info("╚════════════════════════════════════════════════════════════════╝")
    logger.info("")
    logger.info("  📊 Input:       200 logs (%d normal + %d attack)", 200-len(attack_lines), len(attack_lines))
    logger.info("  📊 Sessions:    %d created", len(sessions))
    logger.info("  📊 ML Alerts:   %d total", len(alerts))
    logger.info("")
    logger.info("  🎯 True Positive:    %d (attacker %s detected)", len(attacker_alerts), ATTACKER_IP)
    logger.info("  ⚠️  False Positive:   %d (normal traffic flagged)", len(false_positives))
    logger.info("  🟢 True Negative:    %d (normal sessions not flagged)",
                len(sessions) - len(alerts))
    logger.info("")

    if attacker_alerts:
        logger.info("  ✅ RESULT: ATTACK DETECTED — The needle was found in the haystack!")
    else:
        logger.info("  ❌ RESULT: ATTACK MISSED — ML models need retraining for this format")

    logger.info("")
    logger.info("  Dashboard updated → http://localhost:5000/dashboard")
    logger.info("")


if __name__ == "__main__":
    main()
