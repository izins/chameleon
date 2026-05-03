"""
AEGIS API — Standalone Flask Server
====================================
Self-contained server that reads ALL data directly from JSON files.
No 'src.*' module imports needed — just run: C:\\Python314\\python.exe app.py

Serves all API endpoints needed by the React frontend (Vite proxy on :5173).

Data sources:
  - data/reports/*.json          → Incident reports (41 files)
  - data/blockchain/ledger.json  → Blockchain ledger (36+ blocks)
  - data/network/topology.json   → Network device topology
  - data/iso27035/iso_*.json     → ISO 27035 lifecycle records
  - data/isolation_actions.jsonl → Isolation action log
  - data/aegis_hot.db            → SQLite hot analytics DB
  - data/dashboard_payload.json  → Aggregated dashboard payload
"""

import json
import logging
import os
import sqlite3
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("AEGIS")

# ── Resolve paths ────────────────────────────────────────────────────
# This file lives in: workflow/src/api/app.py
# Project root is:    workflow/
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
REPORTS_DIR = DATA_DIR / "reports"
BLOCKCHAIN_FILE = DATA_DIR / "blockchain" / "ledger.json"
TOPOLOGY_FILE = DATA_DIR / "network" / "topology.json"
ISO_DIR = DATA_DIR / "iso27035"
ISOLATION_FILE = DATA_DIR / "isolation_actions.jsonl"
HOT_DB = DATA_DIR / "aegis_hot.db"
DASHBOARD_PAYLOAD = DATA_DIR / "dashboard_payload.json"


# ═══════════════════════════════════════════════════════════════════════
# DATA LOADING HELPERS (pure JSON, no external imports)
# ═══════════════════════════════════════════════════════════════════════

def load_json(path, default=None):
    if default is None:
        default = []
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def load_jsonl(path):
    if not path.exists():
        return []
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    items.append(json.loads(line))
                except Exception:
                    pass
    return items


def load_all_reports():
    reports = []
    if REPORTS_DIR.exists():
        for f in REPORTS_DIR.glob("*.json"):
            data = load_json(f, default={})
            if data and isinstance(data, dict):
                reports.append(data)
    reports.sort(key=lambda x: x.get("generated_at", ""), reverse=True)
    return reports


def load_blockchain():
    return load_json(BLOCKCHAIN_FILE, default=[])


def load_topology():
    return load_json(TOPOLOGY_FILE, default={})


def load_iso_records():
    records = []
    if ISO_DIR.exists():
        for f in sorted(ISO_DIR.glob("iso_*.json"), reverse=True):
            data = load_json(f, default={})
            if data:
                records.append(data)
    return records


def load_iso_record(prefix):
    if ISO_DIR.exists():
        for f in ISO_DIR.glob(f"iso_{prefix}*.json"):
            data = load_json(f, default={})
            if data:
                return data
    return None


def query_hot_db(sql, params=()):
    """Query the SQLite hot DB for analytics data."""
    if not HOT_DB.exists():
        return []
    try:
        conn = sqlite3.connect(str(HOT_DB))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.warning("DB query failed: %s", e)
        return []


# ═══════════════════════════════════════════════════════════════════════
# FLASK APP
# ═══════════════════════════════════════════════════════════════════════

try:
    from flask import Flask, jsonify, request
    from flask_cors import CORS
except ImportError:
    logger.error("Flask not installed. Run: pip install flask flask-cors")
    raise

app = Flask(__name__)
CORS(app)

# ── Severity mapping ─────────────────────────────────────────────────
SEV_MAP = {"P1": "Critical", "P2": "High", "P3": "Medium", "P4": "Low"}


# ═══════════════════════════════════════════════════════════════════════
# HANDLER ENDPOINTS — Incidents & Playbooks
# (consumed by: Dashboard, Incidents, SOC Analysis, Workflows)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/handler/incidents/active", methods=["GET"])
def get_active_incidents():
    reports = load_all_reports()
    incidents = []
    for r in reports:
        analysis = r.get("analysis", {})
        playbook = r.get("playbook", {}).get("steps", [])
        incidents.append({
            "incident_id": r.get("report_id", ""),
            "date": r.get("generated_at", ""),
            "target_entity": r.get("entity_id", ""),
            "severity": r.get("severity", "P4"),
            "attack_type": r.get("analysis", {}).get("attack_classification", "unknown"),
            "risk_score": r.get("risk_score", 0),
            "risk_label": r.get("risk_label", ""),
            "attack_classification": analysis.get("attack_classification"),
            "root_cause": analysis.get("root_cause_hypothesis"),
            "kill_chain_phase": analysis.get("kill_chain_phase", ""),
            "cves_exploited": analysis.get("cve_exploited", []),
            "mitre_techniques": analysis.get("mitre_techniques", []),
            "playbook_steps": len(playbook),
            "pending_actions": [s for s in playbook if s.get("priority") in ["CRITICAL", "HIGH"]],
        })
    return jsonify({"status": "success", "incidents": incidents})


@app.route("/api/handler/incidents/<report_id>/playbook", methods=["GET"])
def get_playbook(report_id):
    for r in load_all_reports():
        if r.get("report_id", "").startswith(report_id):
            return jsonify({
                "incident_id": report_id,
                "entity_id": r.get("entity_id"),
                "playbook": r.get("playbook", {}),
            })
    return jsonify({"error": "Not found"}), 404


@app.route("/api/handler/isolation/status/<entity_id>", methods=["GET"])
def get_isolation_status(entity_id):
    actions = [a for a in load_jsonl(ISOLATION_FILE) if a.get("entity_id") == entity_id]
    return jsonify({
        "entity_id": entity_id,
        "total_actions": len(actions),
        "actions_log": actions,
    })


# ═══════════════════════════════════════════════════════════════════════
# SOC ENDPOINTS — Alert Feed & Metrics
# (consumed by: LogHistory, Dashboard)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/soc/feed", methods=["GET"])
def get_soc_feed():
    ledger = load_blockchain()
    alerts = []
    for block in reversed(ledger):
        for tx in block.get("transactions", []):
            alerts.append({
                "time": tx.get("timestamp"),
                "tx_id": tx.get("tx_id"),
                "entity_id": tx.get("metadata", {}).get("entity_id", tx.get("document_id")),
                "attack_type": tx.get("metadata", {}).get("attack_classification", "Unknown"),
                "severity": tx.get("metadata", {}).get("severity"),
                "block_index": block.get("index"),
                "document_type": tx.get("document_type"),
            })
    return jsonify({"status": "success", "live_alerts": alerts})


@app.route("/api/soc/metrics", methods=["GET"])
def get_soc_metrics():
    ledger = load_blockchain()
    reports = load_all_reports()
    total_alerts = sum(
        1 for b in ledger for t in b.get("transactions", [])
        if t.get("document_type") in ("EnrichedAlert", "IncidentReport")
    )
    return jsonify({
        "total_blocks": len(ledger),
        "total_alerts": total_alerts,
        "total_incidents": len(reports),
        "system_status": "Healthy (Immutable Mode)",
    })


@app.route("/api/blockchain/ledger", methods=["GET"])
def get_blockchain_ledger():
    """Return the full blockchain ledger for visualization."""
    import hashlib as _hl
    ledger = load_blockchain()

    # Validate chain integrity
    chain_valid = True
    for i in range(1, len(ledger)):
        if ledger[i].get("previous_hash") != ledger[i - 1].get("hash"):
            chain_valid = False
            break

    total_tx = sum(len(b.get("transactions", [])) for b in ledger)

    # Compute per-block summaries for the frontend
    blocks = []
    for b in ledger:
        txs = b.get("transactions", [])
        doc_types = {}
        severities = {}
        entities = set()
        for tx in txs:
            dt = tx.get("document_type", "Unknown")
            doc_types[dt] = doc_types.get(dt, 0) + 1
            meta = tx.get("metadata", {})
            sev = meta.get("severity")
            if sev:
                severities[sev] = severities.get(sev, 0) + 1
            eid = meta.get("entity_id", tx.get("document_id"))
            if eid:
                entities.add(eid)
        blocks.append({
            "index": b.get("index"),
            "timestamp": b.get("timestamp"),
            "hash": b.get("hash", ""),
            "previous_hash": b.get("previous_hash", ""),
            "nonce": b.get("nonce", 0),
            "tx_count": len(txs),
            "transactions": txs,
            "document_types": doc_types,
            "severities": severities,
            "entities": list(entities),
        })

    return jsonify({
        "status": "success",
        "chain_valid": chain_valid,
        "total_blocks": len(ledger),
        "total_transactions": total_tx,
        "genesis_hash": ledger[0].get("hash", "") if ledger else "",
        "latest_hash": ledger[-1].get("hash", "") if ledger else "",
        "blocks": blocks,
    })


@app.route("/api/soc/entity/<entity_id>", methods=["GET"])
def get_entity_profile(entity_id):
    reports = [r for r in load_all_reports() if r.get("entity_id") == entity_id]
    actions = [a for a in load_jsonl(ISOLATION_FILE) if a.get("entity_id") == entity_id]
    max_risk = max((float(r.get("risk_score", 0)) for r in reports), default=0.0)
    return jsonify({
        "entity_id": entity_id,
        "current_risk_score": max_risk,
        "is_isolated": len(actions) > 0,
        "incident_reports": len(reports),
        "isolation_actions": len(actions),
    })


# ═══════════════════════════════════════════════════════════════════════
# ANALYTICS ENDPOINTS — Dashboard Metrics (SQLite Hot DB)
# (consumed by: Dashboard charts, Analytics page)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/analytics/global", methods=["GET"])
def get_global_analytics():
    # Try SQLite first
    entities = query_hot_db("SELECT COUNT(*) as cnt FROM entities")
    alerts = query_hot_db("SELECT COUNT(*) as cnt FROM alerts")
    top_attackers = query_hot_db(
        "SELECT source_ip, COUNT(*) as cnt, MAX(cumulative_score) as score "
        "FROM alerts GROUP BY source_ip ORDER BY cnt DESC LIMIT 10"
    )
    attack_dist = query_hot_db(
        "SELECT attack_type, COUNT(*) as cnt FROM alerts GROUP BY attack_type ORDER BY cnt DESC"
    )
    hourly = query_hot_db(
        "SELECT substr(timestamp, 12, 2) as hour, COUNT(*) as cnt "
        "FROM alerts GROUP BY hour ORDER BY hour"
    )
    geo = query_hot_db(
        "SELECT country, latitude, longitude, COUNT(*) as cnt "
        "FROM geo_origins GROUP BY country ORDER BY cnt DESC LIMIT 20"
    )
    timeline = query_hot_db(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50"
    )

    total_alerts = alerts[0]["cnt"] if alerts else 0
    total_entities = entities[0]["cnt"] if entities else 0

    return jsonify({
        "status": "success",
        "total_alerts_logged": total_alerts,
        "total_entities_tracked": total_entities,
        "top_attackers": top_attackers,
        "attack_distribution": {r["attack_type"]: r["cnt"] for r in attack_dist},
        "attacks_by_hour": {r["hour"]: r["cnt"] for r in hourly},
        "geo_origins": geo,
        "recent_timeline": timeline[:20],
    })


@app.route("/api/analytics/geo", methods=["GET"])
def get_geo():
    geo = query_hot_db(
        "SELECT country, latitude, longitude, isp, is_tor, is_vpn, "
        "cumulative_score, COUNT(*) as attack_count "
        "FROM geo_origins GROUP BY country ORDER BY attack_count DESC"
    )
    return jsonify({"status": "success", "origins": geo})


@app.route("/api/analytics/timeline", methods=["GET"])
def get_timeline():
    limit = min(int(request.args.get("limit", 50)), 200)
    timeline = query_hot_db(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
    )
    return jsonify({"status": "success", "timeline": timeline})


@app.route("/api/analytics/entity/<ip>", methods=["GET"])
def get_entity_detail(ip):
    entity = query_hot_db("SELECT * FROM entities WHERE source_ip = ?", (ip,))
    entity_alerts = query_hot_db(
        "SELECT * FROM alerts WHERE source_ip = ? ORDER BY timestamp DESC", (ip,)
    )
    if not entity:
        return jsonify({"status": "error", "message": f"Entity {ip} not found"}), 404
    return jsonify({"status": "success", "entity": entity[0], "alerts": entity_alerts})


# ═══════════════════════════════════════════════════════════════════════
# LEGAL ENDPOINTS
# (consumed by: LegalDashboard)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/legal/dashboard", methods=["GET"])
def get_legal_dashboard():
    reports = load_all_reports()
    incidents = []
    for r in reports:
        cert = r.get("cert_dz_notification", {})
        anpdp = r.get("anpdp_notification", {})
        incidents.append({
            "incident_id": r.get("report_id", ""),
            "entity_id": r.get("entity_id", ""),
            "severity": SEV_MAP.get(r.get("severity", "P4"), "Low"),
            "attack_type": r.get("analysis", {}).get("attack_classification", "Unknown"),
            "generated_at": r.get("generated_at", ""),
            "risk_score": r.get("risk_score", 0),
            "cert_dz_deadline": cert.get("deadline", ""),
            "cert_dz_hours": cert.get("hours_remaining", 0),
            "anpdp_deadline": anpdp.get("deadline", ""),
            "anpdp_hours": anpdp.get("hours_remaining", 0),
            "legal_liability": cert.get("legal_liability_risk", ""),
            "penalties_attacker": cert.get("penalties_for_attacker", ""),
            "regulations": r.get("applicable_regulations", []),
        })
    return jsonify({
        "status": "success",
        "total_incidents": len(incidents),
        "incidents": incidents[:50],  # cap for performance
    })


@app.route("/api/legal/history/verified", methods=["GET"])
def get_legal_verified():
    ledger = load_blockchain()
    verified = []
    for block in ledger:
        for tx in block.get("transactions", []):
            if tx.get("document_type") == "IncidentReport":
                verified.append({
                    "block_index": block.get("index"),
                    "block_hash": block.get("hash"),
                    "tx_id": tx.get("tx_id"),
                    "document_id": tx.get("document_id"),
                    "timestamp": tx.get("timestamp"),
                    "entity_id": tx.get("metadata", {}).get("entity_id"),
                    "severity": tx.get("metadata", {}).get("severity"),
                    "classification": tx.get("metadata", {}).get("attack_classification"),
                })
    return jsonify({"status": "success", "verified_reports": verified})


@app.route("/api/legal/blockchain/verify/<report_id>", methods=["GET"])
def verify_report(report_id):
    ledger = load_blockchain()
    for block in ledger:
        for tx in block.get("transactions", []):
            if tx.get("document_id", "").startswith(report_id):
                return jsonify({
                    "status": "verified",
                    "block_index": block.get("index"),
                    "block_hash": block.get("hash"),
                    "document_hash": tx.get("document_hash"),
                    "timestamp": tx.get("timestamp"),
                })
    return jsonify({"status": "not_found"}), 404


# ═══════════════════════════════════════════════════════════════════════
# ISO 27035 ENDPOINTS
# (consumed by: SOC Analysis ISO phases)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/iso27035/incidents", methods=["GET"])
def get_iso_incidents():
    records = load_iso_records()
    summaries = []
    for r in records:
        phases_summary = {}
        for pname, pdata in r.get("phases", {}).items():
            phases_summary[pname] = {
                "status": pdata.get("status", "pending"),
                "iso_clause": pdata.get("iso_clause", ""),
                "duration_seconds": pdata.get("duration_seconds"),
            }
        summaries.append({
            "incident_id": r.get("incident_id", ""),
            "entity_id": r.get("entity_id", ""),
            "created_at": r.get("created_at", ""),
            "current_phase": r.get("current_phase", ""),
            "overall_status": r.get("overall_status", ""),
            "severity": r.get("severity", "P4"),
            "attack_type": r.get("attack_type", "unknown"),
            "risk_score": r.get("risk_score", 0),
            "risk_label": r.get("risk_label", "INFO"),
            "total_phases_completed": r.get("total_phases_completed", 0),
            "total_phases": r.get("total_phases", 5),
            "phases": phases_summary,
        })
    return jsonify({"total": len(summaries), "incidents": summaries})


@app.route("/api/iso27035/incident/<incident_id>", methods=["GET"])
def get_iso_incident(incident_id):
    record = load_iso_record(incident_id)
    if not record:
        return jsonify({"error": "Not found"}), 404
    return jsonify(record)


@app.route("/api/iso27035/incident/<incident_id>/phase/<int:phase_num>", methods=["GET"])
def get_iso_phase(incident_id, phase_num):
    record = load_iso_record(incident_id)
    if not record:
        return jsonify({"error": "Not found"}), 404
    phase_map = {
        1: "Phase 1: Detection & Reporting",
        2: "Phase 2: Assessment & Decision",
        3: "Phase 3: Response",
        4: "Phase 4: Lessons Learned",
        5: "Phase 5: Documentation & Closure",
    }
    phase_data = record.get("phases", {}).get(phase_map.get(phase_num, ""))
    if not phase_data:
        return jsonify({"error": "Phase not found"}), 404
    return jsonify({"incident_id": record.get("incident_id"), "phase": phase_data})


@app.route("/api/iso27035/compliance/<incident_id>", methods=["GET"])
def get_iso_compliance(incident_id):
    record = load_iso_record(incident_id)
    if not record:
        return jsonify({"error": "Not found"}), 404
    compliance = []
    for pname, pdata in record.get("phases", {}).items():
        reqs = pdata.get("requirements", [])
        met = pdata.get("requirements_met", [])
        compliance.append({
            "phase": pname,
            "iso_clause": pdata.get("iso_clause", ""),
            "status": pdata.get("status", "pending"),
            "total_requirements": len(reqs),
            "requirements_met": len(met),
        })
    total_reqs = sum(c["total_requirements"] for c in compliance)
    total_met = sum(c["requirements_met"] for c in compliance)
    return jsonify({
        "incident_id": record.get("incident_id"),
        "overall_compliance": f"{total_met}/{total_reqs}",
        "compliance_percentage": round((total_met / total_reqs * 100) if total_reqs else 0, 1),
        "phases": compliance,
    })


# ═══════════════════════════════════════════════════════════════════════
# NETWORK TOPOLOGY ENDPOINTS
# (consumed by: NetworkTopology page)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/network/topology", methods=["GET"])
def get_topology():
    topo = load_topology()
    if not topo:
        return jsonify({"error": "No topology data. Run network scanner first."}), 404
    return jsonify(topo)


@app.route("/api/network/scan", methods=["POST"])
def trigger_scan():
    """Try to run a network scan if the scanner module is available."""
    try:
        import sys
        sys.path.insert(0, str(PROJECT_ROOT))
        from src.response.network_scanner import NetworkScanner
        scanner = NetworkScanner()
        topo = scanner.scan(probe_ports=False)
        return jsonify(topo.model_dump(mode="json"))
    except Exception as e:
        return jsonify({"error": str(e), "message": "Scan failed — topology.json still available"}), 500


# ═══════════════════════════════════════════════════════════════════════
# DASHBOARD AGGREGATE ENDPOINT
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/dashboard", methods=["GET"])
def get_dashboard():
    payload = load_json(DASHBOARD_PAYLOAD, default={})
    if not payload:
        return jsonify({"error": "No dashboard payload. Run integration_demo first."}), 404
    return jsonify(payload)


# ═══════════════════════════════════════════════════════════════════════
# INCIDENT PROGRESS — Save/Load analyst step completion
# ═══════════════════════════════════════════════════════════════════════

PROGRESS_DIR = DATA_DIR / "progress"

@app.route("/api/incidents/progress/<incident_id>", methods=["GET"])
def get_progress(incident_id):
    """Load saved progress for an incident."""
    PROGRESS_DIR.mkdir(exist_ok=True)
    path = PROGRESS_DIR / f"{incident_id}.json"
    data = load_json(path, default={})
    return jsonify({"status": "success", "incident_id": incident_id, "progress": data})


@app.route("/api/incidents/progress/<incident_id>", methods=["POST"])
def save_progress(incident_id):
    """Save analyst's step completion progress."""
    PROGRESS_DIR.mkdir(exist_ok=True)
    path = PROGRESS_DIR / f"{incident_id}.json"

    body = request.get_json(force=True) or {}
    # Merge with existing
    existing = load_json(path, default={})
    existing.update({
        "incident_id": incident_id,
        "completed_steps": body.get("completed_steps", existing.get("completed_steps", {})),
        "notes": body.get("notes", existing.get("notes", "")),
        "analyst": body.get("analyst", existing.get("analyst", "unknown")),
        "last_updated": __import__("datetime").datetime.now().isoformat(),
    })

    with open(path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)

    logger.info("Progress saved for incident %s", incident_id)
    return jsonify({"status": "saved", "incident_id": incident_id})


@app.route("/api/incidents/progress/all/stats", methods=["GET"])
def get_all_progress_stats():
    """Aggregate all saved progress for the dashboard."""
    PROGRESS_DIR.mkdir(exist_ok=True)
    files = list(PROGRESS_DIR.glob("*.json"))

    total_responses = len(files)
    completed = 0
    in_progress = 0
    recent = []

    for f in files:
        data = load_json(f, default={})
        steps = data.get("completed_steps", {})
        done_count = sum(1 for v in steps.values() if v)
        total_count = len(steps) if steps else 0

        pct = round((done_count / max(total_count, 1)) * 100)
        if pct >= 100:
            completed += 1
        elif done_count > 0:
            in_progress += 1

        recent.append({
            "incident_id": data.get("incident_id", f.stem),
            "analyst": data.get("analyst", "unknown"),
            "steps_done": done_count,
            "steps_total": total_count,
            "pct": pct,
            "notes": data.get("notes", ""),
            "last_updated": data.get("last_updated", ""),
        })

    # Sort recent by last_updated descending
    recent.sort(key=lambda x: x.get("last_updated", ""), reverse=True)

    return jsonify({
        "status": "success",
        "total_responses": total_responses,
        "completed": completed,
        "in_progress": in_progress,
        "not_started": max(0, len(load_all_reports()) - total_responses),
        "recent_activity": recent[:10],
    })

# ═══════════════════════════════════════════════════════════════════════
# UNIFIED ATTACK DATABASE
# Single source of truth — consumed by ALL frontend pages
# ═══════════════════════════════════════════════════════════════════════

# ISO 27035 phase mapping by attack type
ISO_PHASE_MAP = {
    "Privilege Elevation Attack": "Phase 3: Response",
    "Data Theft": "Phase 4: Lessons Learned",
    "Credential-Based Attack": "Phase 2: Assessment & Decision",
    "Unclassified Behavioral Anomaly": "Phase 2: Assessment & Decision",
    "Phishing": "Phase 2: Assessment & Decision",
    "Ransomware": "Phase 3: Response",
    "DDoS": "Phase 3: Response",
    "Insider Threat": "Phase 3: Response",
    "Lateral Movement": "Phase 3: Response",
    "Supply Chain Attack": "Phase 1: Detection & Reporting",
    "Zero-Day Exploit": "Phase 3: Response",
}

# Algerian Law references
ALGERIAN_LAW = {
    "loi_18_07": {
        "name": "Loi n° 18-07 du 10 juin 2018",
        "full_title": "Loi relative à la protection des personnes physiques dans le traitement des données à caractère personnel",
        "key_articles": {
            "art_12": {"title": "Obligation de sécurité", "text": "Le responsable du traitement est tenu de prendre toutes les mesures nécessaires pour assurer la sécurité des données et empêcher qu'elles soient endommagées, modifiées ou consultées par des tiers non autorisés."},
            "art_15": {"title": "Notification de violation", "text": "Le responsable du traitement doit notifier toute violation de données à l'autorité nationale dans un délai de 72 heures."},
            "art_38": {"title": "Sanctions pénales", "text": "Est puni d'un emprisonnement de 1 à 5 ans et d'une amende de 1.000.000 DA à 5.000.000 DA, quiconque procède à un traitement de données sans le consentement de la personne concernée."},
            "art_44": {"title": "Transfert international", "text": "Le transfert de données à caractère personnel vers un pays étranger n'est autorisé que si ce pays assure un niveau de protection suffisant."},
            "art_46": {"title": "Responsabilité pénale", "text": "La personne morale peut être déclarée pénalement responsable des infractions prévues par la présente loi."},
        },
        "max_prison": "5 ans",
        "max_fine": "5.000.000 DA",
    },
    "decret_20_05": {
        "name": "Décret exécutif n° 20-05",
        "full_title": "Fixant les conditions et modalités de notification des incidents de cybersécurité au CERT-DZ",
        "notification_deadline_hours": 24,
        "required_fields": [
            "Nature de l'incident",
            "Systèmes affectés",
            "Mesures de confinement prises",
            "Impact estimé",
            "Preuves préservées",
            "Contact responsable",
        ],
    },
    "anpdp": {
        "name": "ANPDP — Autorité Nationale de Protection des Données Personnelles",
        "notification_deadline_hours": 72,
        "required_fields": [
            "Nature de la violation",
            "Catégories de données affectées",
            "Nombre estimé de personnes concernées",
            "Conséquences probables",
            "Mesures correctives prises",
            "Évaluation du risque de perte de données",
        ],
    },
    "code_penal_cyber": {
        "art_394bis": "Accès frauduleux à un système: 3 mois à 1 an prison, 50.000 à 100.000 DA",
        "art_394ter": "Introduction frauduleuse de données: 6 mois à 2 ans prison, 50.000 à 150.000 DA",
        "art_394quater": "Altération de données: 2 mois à 3 ans prison, 1.000.000 à 5.000.000 DA",
    },
}


@app.route("/api/attacks/unified", methods=["GET"])
def get_unified_attacks():
    """Single source of truth for ALL attacks across the platform."""
    reports = load_all_reports()
    ledger = load_blockchain()
    iso_records = load_iso_records()

    # Build blockchain lookup: document_id → block info
    bc_lookup = {}
    for block in ledger:
        for tx in block.get("transactions", []):
            bc_lookup[tx.get("document_id", "")] = {
                "block_index": block.get("index"),
                "block_hash": block.get("hash", "")[:16],
                "tx_id": tx.get("tx_id"),
                "document_hash": tx.get("document_hash"),
                "anchored_at": tx.get("timestamp"),
            }

    # Build ISO lookup: incident_id prefix → record
    iso_lookup = {}
    for rec in iso_records:
        iid = rec.get("incident_id", "")
        iso_lookup[iid[:8]] = rec

    attacks = []
    for r in reports:
        rid = r.get("report_id", "")
        analysis = r.get("analysis", {})
        playbook = r.get("playbook", {})
        cert = r.get("cert_dz_notification", {})
        anpdp = r.get("anpdp_notification", {})
        evidence = r.get("evidence", {})

        attack_type = analysis.get("attack_classification", r.get("analysis", {}).get("attack_classification", "Unknown"))
        iso_phase = ISO_PHASE_MAP.get(attack_type, "Phase 2: Assessment & Decision")

        # Find blockchain anchor
        bc = bc_lookup.get(rid, {})

        # Find ISO record
        iso = iso_lookup.get(rid[:8], {})

        attacks.append({
            "id": rid[:8] if rid else "unknown",
            "report_id": rid,
            "entity_id": r.get("entity_id", ""),
            "severity": r.get("severity", "P4"),
            "severity_label": SEV_MAP.get(r.get("severity", "P4"), "Low"),
            "attack_type": attack_type,
            "risk_score": r.get("risk_score", 0),
            "risk_label": r.get("risk_label", ""),
            "generated_at": r.get("generated_at", ""),

            # Forensic analysis
            "kill_chain": analysis.get("kill_chain_phase", ""),
            "attack_vector": analysis.get("attack_vector", ""),
            "root_cause": analysis.get("root_cause_hypothesis", ""),
            "dwell_time": analysis.get("dwell_time_description", ""),
            "lateral_risk": analysis.get("lateral_risk_level", ""),
            "data_at_risk": analysis.get("data_at_risk", ""),
            "mitre": analysis.get("mitre_techniques", []),
            "cves": analysis.get("cve_exploited", []),
            "ioc_summary": analysis.get("ioc_summary", ""),
            "investigation_steps": analysis.get("investigation_steps", []),
            "recommendations": analysis.get("recommendations", []),

            # Impact
            "impact": {
                "confidentiality": analysis.get("impact", {}).get("confidentiality", 0),
                "integrity": analysis.get("impact", {}).get("integrity", 0),
                "availability": analysis.get("impact", {}).get("availability", 0),
                "overall": analysis.get("impact", {}).get("overall", 0),
            },

            # Playbook
            "playbook_steps": playbook.get("total_steps", 0),
            "playbook_severity": playbook.get("severity", ""),
            "playbook_estimated_minutes": playbook.get("estimated_total_minutes", 0),

            # Legal — CERT-DZ
            "cert_dz": {
                "deadline": cert.get("deadline", ""),
                "hours_remaining": cert.get("hours_remaining", 0),
                "regulatory_reference": cert.get("regulatory_reference", ""),
                "nature_of_breach": cert.get("nature_of_breach", ""),
                "source_ip": cert.get("source_ip", ""),
                "affected_systems": cert.get("affected_systems", ""),
                "containment_measures": cert.get("containment_measures", ""),
                "impact_assessment": cert.get("impact_assessment", ""),
                "evidence_preservation": cert.get("evidence_preservation", ""),
                "legal_liability_risk": cert.get("legal_liability_risk", ""),
                "penalties_for_attacker": cert.get("penalties_for_attacker", ""),
            },

            # Legal — ANPDP
            "anpdp": {
                "deadline": anpdp.get("deadline", ""),
                "hours_remaining": anpdp.get("hours_remaining", 0),
                "regulatory_reference": anpdp.get("regulatory_reference", ""),
                "nature_of_breach": anpdp.get("nature_of_breach", ""),
                "affected_data_categories": anpdp.get("affected_data_categories", ""),
                "estimated_persons_affected": anpdp.get("estimated_persons_affected", 0),
                "likely_consequences": anpdp.get("likely_consequences", ""),
                "data_loss_risk": anpdp.get("data_loss_risk_assessment", ""),
                "fines_for_non_compliance": anpdp.get("fines_for_non_compliance", ""),
            },

            # Blockchain
            "blockchain": bc,
            "blockchain_verified": bool(bc),

            # Regulations
            "regulations": r.get("applicable_regulations", []),

            # ISO 27035
            "iso_phase": iso_phase,
            "iso_record": bool(iso),

            # Executive summary
            "executive_summary": r.get("executive_summary", ""),
            "technical_summary": r.get("technical_summary", ""),
        })

    return jsonify({
        "status": "success",
        "total": len(attacks),
        "attacks": attacks,
        "algerian_law": ALGERIAN_LAW,
    })


@app.route("/api/attacks/<attack_id>", methods=["GET"])
def get_attack_detail(attack_id):
    """Full detail for a single attack — includes raw report data."""
    for r in load_all_reports():
        if r.get("report_id", "").startswith(attack_id):
            return jsonify({"status": "success", "report": r})
    return jsonify({"status": "not_found"}), 404


# ═══════════════════════════════════════════════════════════════════════
# PDF REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/reports/<report_id>/pdf", methods=["GET"])
def generate_pdf(report_id):
    """Generate and serve a PDF incident report."""
    import io
    from datetime import datetime

    # Find the report
    report = None
    for r in load_all_reports():
        if r.get("report_id", "").startswith(report_id):
            report = r
            break

    if not report:
        return jsonify({"error": "Report not found"}), 404

    # Try reportlab, fallback to text-based PDF
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.units import mm

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20*mm, bottomMargin=20*mm)
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle('AegisTitle', parent=styles['Title'], textColor=HexColor('#00e87b'), fontSize=18)
        heading_style = ParagraphStyle('AegisHeading', parent=styles['Heading2'], textColor=HexColor('#38bdf8'), fontSize=13, spaceAfter=6)
        body_style = ParagraphStyle('AegisBody', parent=styles['Normal'], fontSize=10, spaceAfter=4, textColor=HexColor('#333333'))
        label_style = ParagraphStyle('AegisLabel', parent=styles['Normal'], fontSize=9, textColor=HexColor('#666666'))

        analysis = report.get("analysis", {})
        cert = report.get("cert_dz_notification", {})
        anpdp = report.get("anpdp_notification", {})
        playbook = report.get("playbook", {})

        elements = []

        # Title
        elements.append(Paragraph("AEGIS INCIDENT REPORT", title_style))
        elements.append(Spacer(1, 4*mm))

        # Meta
        meta_data = [
            ["Report ID", report.get("report_id", "")[:13]],
            ["Generated", report.get("generated_at", "")[:19]],
            ["Entity", report.get("entity_id", "")],
            ["Severity", f"{report.get('severity', 'P4')} — {SEV_MAP.get(report.get('severity'), 'Low')}"],
            ["Risk Score", f"{report.get('risk_score', 0):.2f} / 10 ({report.get('risk_label', '')})"],
        ]
        meta_table = Table(meta_data, colWidths=[45*mm, 120*mm])
        meta_table.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#666666')),
            ('TEXTCOLOR', (1, 0), (1, -1), HexColor('#111111')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 6*mm))

        # Executive Summary
        elements.append(Paragraph("Executive Summary", heading_style))
        elements.append(Paragraph(report.get("executive_summary", "N/A"), body_style))
        elements.append(Spacer(1, 4*mm))

        # Forensic Analysis
        elements.append(Paragraph("Forensic Analysis", heading_style))
        forensic_data = [
            ["Classification", analysis.get("attack_classification", "")],
            ["Kill Chain Phase", analysis.get("kill_chain_phase", "")],
            ["Attack Vector", analysis.get("attack_vector", "")],
            ["Root Cause", analysis.get("root_cause_hypothesis", "")],
            ["Dwell Time", analysis.get("dwell_time_description", "")],
            ["MITRE Techniques", ", ".join(analysis.get("mitre_techniques", []))],
            ["CVEs Exploited", ", ".join(analysis.get("cve_exploited", []))],
        ]
        f_table = Table(forensic_data, colWidths=[45*mm, 120*mm])
        f_table.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#666666')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(f_table)
        elements.append(Spacer(1, 4*mm))

        # CIA Impact
        impact = analysis.get("impact", {})
        elements.append(Paragraph("CIA Impact Assessment", heading_style))
        cia_data = [
            ["Confidentiality", f"{impact.get('confidentiality', 0)}/10"],
            ["Integrity", f"{impact.get('integrity', 0)}/10"],
            ["Availability", f"{impact.get('availability', 0)}/10"],
            ["Overall", f"{impact.get('overall', 0)}/10"],
        ]
        cia_table = Table(cia_data, colWidths=[45*mm, 30*mm])
        cia_table.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#666666')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(cia_table)
        elements.append(Spacer(1, 4*mm))

        # Playbook
        elements.append(Paragraph(f"Response Playbook ({playbook.get('total_steps', 0)} steps)", heading_style))
        for i, step in enumerate(playbook.get("steps", [])[:10], 1):
            elements.append(Paragraph(
                f"<b>Step {i}:</b> [{step.get('priority', {}).get('value', 'medium').upper()}] {step.get('title', '')} — {step.get('description', '')[:120]}",
                body_style
            ))
        elements.append(Spacer(1, 4*mm))

        # Legal — CERT-DZ
        elements.append(Paragraph("NOTIFICATION CERT-DZ (Décret 20-05) — Délai: 24h", heading_style))
        cert_data = [
            ["Deadline", cert.get("deadline", "")],
            ["Heures restantes", f"{cert.get('hours_remaining', 0)}h"],
            ["Sévérité", cert.get("severity_level", "")],
            ["Nature", cert.get("nature_of_breach", "")],
            ["IP Source", cert.get("source_ip", "")],
            ["Systèmes affectés", cert.get("affected_systems", "")],
            ["Mesures de confinement", cert.get("containment_measures", "")],
            ["Risque légal org.", cert.get("legal_liability_risk", "")],
            ["Pénalité attaquant", cert.get("penalties_for_attacker", "")],
        ]
        c_table = Table(cert_data, colWidths=[50*mm, 115*mm])
        c_table.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#666666')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(c_table)
        elements.append(Spacer(1, 4*mm))

        # Legal — ANPDP
        elements.append(Paragraph("NOTIFICATION ANPDP (Loi 18-07) — Délai: 72h", heading_style))
        anpdp_data = [
            ["Deadline", anpdp.get("deadline", "")],
            ["Nature", anpdp.get("nature_of_breach", "")],
            ["Données affectées", anpdp.get("affected_data_categories", "")],
            ["Personnes concernées", str(anpdp.get("estimated_persons_affected", 0))],
            ["Conséquences", anpdp.get("likely_consequences", "")],
            ["Amendes", anpdp.get("fines_for_non_compliance", "")],
        ]
        a_table = Table(anpdp_data, colWidths=[50*mm, 115*mm])
        a_table.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#666666')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(a_table)
        elements.append(Spacer(1, 6*mm))

        # Blockchain verification
        ledger = load_blockchain()
        for block in ledger:
            for tx in block.get("transactions", []):
                if tx.get("document_id", "").startswith(report_id):
                    elements.append(Paragraph("Blockchain Verification", heading_style))
                    elements.append(Paragraph(f"Block #{block.get('index')} — Hash: {block.get('hash', '')[:32]}...", body_style))
                    elements.append(Paragraph(f"Document Hash: {tx.get('document_hash', '')[:32]}...", body_style))
                    break

        elements.append(Spacer(1, 8*mm))
        elements.append(Paragraph("— END OF REPORT — AEGIS Adaptive Enterprise Guard —", label_style))

        doc.build(elements)
        buf.seek(0)

        from flask import send_file as flask_send_file
        return flask_send_file(
            buf,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"AEGIS_REPORT_{report_id[:8]}.pdf",
        )

    except ImportError:
        # Fallback: serve the JSON report as download
        return jsonify({
            "error": "reportlab not installed. Install with: pip install reportlab",
            "fallback": "json",
            "report": report,
        })


# ═══════════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/health", methods=["GET"])
def health():
    reports = list(REPORTS_DIR.glob("*.json")) if REPORTS_DIR.exists() else []
    ledger = load_blockchain()
    iso = load_iso_records()
    topo = load_topology()
    return jsonify({
        "status": "online",
        "version": "3.0.0-unified",
        "data_sources": {
            "reports": len(reports),
            "blockchain_blocks": len(ledger),
            "iso27035_records": len(iso),
            "topology_devices": topo.get("total_devices", 0),
            "hot_db_exists": HOT_DB.exists(),
            "isolation_log_exists": ISOLATION_FILE.exists(),
        },
        "project_root": str(PROJECT_ROOT),
    })


# ═══════════════════════════════════════════════════════════════════════
# LIVE SIMULATION ENGINE — Hackathon Pitch Demo
# Generates 200 raw logs → enrichment → isolation → report generation
# Uses Server-Sent Events (SSE) for real-time streaming
# ═══════════════════════════════════════════════════════════════════════

import time
import random
import hashlib
import uuid
from datetime import datetime, timedelta

def _sim_id():
    return uuid.uuid4().hex[:8]

# Attack scenario phases with realistic log templates
SIM_PHASES = [
    # Phase 1: Reconnaissance (logs 1-30)
    {
        "phase": "Reconnaissance",
        "mitre": "TA0043",
        "kill_chain": "Reconnaissance",
        "count": 30,
        "templates": [
            "NMAP SYN scan from {src} to {dst}:{port} — {status}",
            "DNS query from {src}: TXT record lookup for {domain}",
            "WHOIS lookup detected from {src} targeting {domain}",
            "Port scan: {src} → {dst} ports 22,80,443,3389,5432 — {n} open",
            "HTTP fingerprinting: {src} → {dst}:80 (Server: {server})",
            "SSL certificate enumeration from {src} on {dst}:443",
            "SNMP community string brute-force from {src} to {dst}",
            "LDAP enumeration attempt from {src} → {dst}:389",
        ],
    },
    # Phase 2: Brute Force / Initial Access (logs 31-80)
    {
        "phase": "Initial Access",
        "mitre": "TA0001",
        "kill_chain": "Delivery",
        "count": 50,
        "templates": [
            "SSH AUTH FAILED: {user}@{dst} from {src} — attempt {n}/50",
            "SSH AUTH FAILED: root@{dst} from {src} — password rejected",
            "RDP brute-force: {src} → {dst}:3389 — {user} — DENIED",
            "SMTP: Phishing email from {email} to {target_email} — attachment: invoice.pdf.exe",
            "HTTP POST {dst}/wp-login.php from {src} — 401 Unauthorized — {user}",
            "FTP AUTH: {user}@{dst} from {src} — FAILED (bad password)",
            "SSH AUTH SUCCESS: {user}@{dst} from {src} — ⚠ ANOMALOUS",
            "Malicious payload download: {src} → {c2}/payload.bin (SHA256: {hash})",
        ],
    },
    # Phase 3: Privilege Escalation (logs 81-120)
    {
        "phase": "Privilege Escalation",
        "mitre": "TA0004",
        "kill_chain": "Exploitation",
        "count": 40,
        "templates": [
            "CRITICAL: CVE-2024-1086 exploit detected on {dst} — local priv esc",
            "Process: {dst} — mimikatz.exe spawned by cmd.exe (PID {pid})",
            "LSASS memory dump detected on {dst} — credential harvesting",
            "New local admin created: svc_backup$ on {dst} by {user}",
            "Sudo escalation: {user} → root on {dst} via CVE-2024-1086",
            "Registry modification: {dst} — HKLM\\SAM\\Domains accessed by {user}",
            "Kerberoasting: SPN query from {dst} for krbtgt service ticket",
            "Token impersonation: {user} → NT AUTHORITY\\SYSTEM on {dst}",
            "UAC bypass: {dst} — eventvwr.exe used for privilege escalation",
        ],
    },
    # Phase 4: Lateral Movement (logs 121-170)
    {
        "phase": "Lateral Movement",
        "mitre": "TA0008",
        "kill_chain": "Command and Control",
        "count": 50,
        "templates": [
            "RDP session: {src} → {dst}:3389 — {user} — ESTABLISHED",
            "PsExec: {src} → {dst} — remote cmd.exe spawned as SYSTEM",
            "SMB: {src} → {dst}:445 — \\\\{dst}\\ADMIN$ accessed by {user}",
            "WMI: {src} → {dst} — remote process creation (powershell.exe)",
            "Pass-the-Hash: NTLM auth from {src} to {dst} — {user} — {hash}",
            "Lateral pivot: SSH tunnel {src}:8080 → {dst}:5432 established",
            "DNS beacon: {dst} → {c2} — encoded payload in TXT record (interval 30s)",
            "C2 heartbeat: {dst} → {c2}:443 — HTTPS POST /api/beacon — 200 OK",
            "Internal scan: {src} sweeping 10.0.0.0/24 — ARP discovery",
        ],
    },
    # Phase 5: Exfiltration (logs 171-200)
    {
        "phase": "Exfiltration",
        "mitre": "TA0010",
        "kill_chain": "Actions on Objectives",
        "count": 30,
        "templates": [
            "DATA STAGING: {dst} — rar.exe creating archive data_{n}.rar ({size}MB)",
            "DNS TUNNEL: {dst} → {c2} — exfil chunk {n}/24 — base64 encoded",
            "HTTPS EXFIL: {dst} → {c2}:443 POST /upload — {size}MB — STATUS 200",
            "FTP UPLOAD: {dst} → {c2}:21 — STOR financial_data_{n}.csv",
            "ICMP TUNNEL: {dst} → {c2} — data exfiltration via oversized ICMP packets",
            "Cloud EXFIL: {dst} → storage.googleapis.com PUT sensitive_{n}.zip",
            "EMAIL EXFIL: {dst} → smtp.{domain} — attachment: backup_{n}.7z ({size}MB)",
            "DLP ALERT: {dst} → {c2} — BLOCKED — classified data pattern match",
        ],
    },
]

ATTACKER_IPS = ["185.220.101.42", "45.155.205.18", "91.219.236.174"]
INTERNAL_IPS = ["10.0.0.10", "10.0.0.20", "10.0.0.30", "10.0.0.40", "10.0.0.50", "10.0.0.60", "10.0.0.70"]
INTERNAL_HOSTS = {"10.0.0.10": "SIEM-AEGIS", "10.0.0.20": "DC-01", "10.0.0.30": "FS-FIN-01", "10.0.0.40": "WS-HR-042", "10.0.0.50": "MAIL-GW", "10.0.0.60": "DB-PROD-01", "10.0.0.70": "WEB-PORTAL"}
C2_DOMAINS = ["c2.darknet.ru", "185.220.101.42", "exfil.onion.link"]
USERS = ["admin", "root", "j.martin", "svc_backup$", "a.benali", "dbadmin"]
DOMAINS = ["cameleon.dz", "aegis-soc.local", "finance.internal"]

def _fill_template(tpl, phase_idx, log_idx):
    src = random.choice(ATTACKER_IPS) if phase_idx < 2 else random.choice(INTERNAL_IPS[:3])
    dst = random.choice(INTERNAL_IPS)
    return tpl.format(
        src=src, dst=dst, port=random.choice([22, 80, 443, 3389, 5432, 8080]),
        status=random.choice(["filtered", "open", "closed"]),
        domain=random.choice(DOMAINS), n=log_idx + 1, user=random.choice(USERS),
        server=random.choice(["Apache/2.4", "nginx/1.24", "IIS/10.0"]),
        email=f"attacker@{random.choice(['mail.ru', 'proton.me'])}",
        target_email=f"{random.choice(USERS)}@cameleon.dz",
        hash=hashlib.sha256(f"sim{log_idx}".encode()).hexdigest()[:12],
        c2=random.choice(C2_DOMAINS), pid=random.randint(1000, 9999),
        size=random.randint(50, 2400),
    )


@app.route("/api/simulation/start", methods=["GET"])
def start_simulation():
    """SSE endpoint — streams 200 raw logs + enrichment + isolation + report."""
    def generate():
        sim_start = datetime.now()
        sim_uuid = _sim_id()
        total_logs = 0
        target_device = "10.0.0.40"  # WS-HR-042 will be the compromised host

        # Start event
        start_data = {"type": "start", "sim_id": sim_uuid, "total_expected": 200, "message": "AEGIS Simulation Engine started — streaming 200 raw logs"}
        yield "data: {}\n\n".format(json.dumps(start_data))
        time.sleep(0.3)

        for phase_idx, phase in enumerate(SIM_PHASES):
            # Phase start event
            phase_data = {"type": "phase", "phase": phase["phase"], "mitre": phase["mitre"], "kill_chain": phase["kill_chain"], "phase_num": phase_idx + 1, "total_phases": 5}
            yield "data: {}\n\n".format(json.dumps(phase_data))
            time.sleep(0.2)

            for i in range(phase["count"]):
                total_logs += 1
                tpl = random.choice(phase["templates"])
                log_line = _fill_template(tpl, phase_idx, i)
                ts = (sim_start + timedelta(seconds=total_logs * 0.15)).strftime("%H:%M:%S.%f")[:-3]
                severity = "CRITICAL" if phase_idx >= 3 else "HIGH" if phase_idx >= 2 else "MEDIUM" if phase_idx >= 1 else "LOW"

                log_event = {
                    "type": "log",
                    "num": total_logs,
                    "timestamp": ts,
                    "severity": severity,
                    "phase": phase["phase"],
                    "mitre": phase["mitre"],
                    "raw": log_line,
                }
                yield "data: {}\n\n".format(json.dumps(log_event))

                # Vary speed: fast during recon, slower during critical phases
                delay = 0.05 if phase_idx == 0 else 0.08 if phase_idx == 1 else 0.12 if phase_idx == 2 else 0.1
                time.sleep(delay)

            # Enrichment event after each phase
            enrich_msg = "AEGIS AI enriched {} logs — mapped to {} ({})".format(phase["count"], phase["mitre"], phase["phase"])
            enrich_data = {"type": "enrichment", "phase": phase["phase"], "mitre": phase["mitre"], "message": enrich_msg, "risk_score": round(2 + phase_idx * 2 + random.random(), 1)}
            yield "data: {}\n\n".format(json.dumps(enrich_data))
            time.sleep(0.3)

            # Isolation event at phase 3 (privilege escalation detected)
            if phase_idx == 2:
                iso_msg = "ISOLATING {} ({}) — threat containment activated".format(INTERNAL_HOSTS[target_device], target_device)
                iso_data = {"type": "isolation", "device_ip": target_device, "hostname": INTERNAL_HOSTS[target_device], "reason": "Privilege escalation detected — CVE-2024-1086 exploit on host", "message": iso_msg}
                yield "data: {}\n\n".format(json.dumps(iso_data))
                time.sleep(0.5)

            # Second isolation at phase 4 (lateral movement to file server)
            if phase_idx == 3:
                iso2_data = {"type": "isolation", "device_ip": "10.0.0.30", "hostname": "FS-FIN-01", "reason": "Lateral movement detected — PsExec + SMB admin share access", "message": "ISOLATING FS-FIN-01 (10.0.0.30) — lateral movement blocked"}
                yield "data: {}\n\n".format(json.dumps(iso2_data))
                time.sleep(0.5)

        # DLP block event
        dlp_data = {"type": "dlp_block", "message": "DLP Policy triggered — exfiltration blocked at 68% completion", "blocked_size": "1.63 GB", "total_size": "2.4 GB"}
        yield "data: {}\n\n".format(json.dumps(dlp_data))
        time.sleep(0.5)

        # Generate attack report
        report_id = "SIM-{}".format(sim_uuid)
        sim_report = {
            "id": report_id,
            "generated_at": datetime.now().isoformat(),
            "attack_type": "Advanced Persistent Threat (APT) — Multi-Stage Intrusion",
            "severity": "P1",
            "risk_score": 9.4,
            "entity_id": target_device,
            "kill_chain": "Full Kill Chain — Recon to Exfiltration",
            "mitre": ["TA0043", "TA0001", "TA0004", "TA0008", "TA0010"],
            "cves": ["CVE-2024-1086"],
            "forensic_analysis": "Multi-stage APT attack detected across {} log events. Attack originated from {}, targeting {}. Privilege escalation via CVE-2024-1086 followed by lateral movement to FS-FIN-01. Data exfiltration attempted (2.4GB) — blocked at 68% by DLP.".format(total_logs, ATTACKER_IPS[0], INTERNAL_HOSTS[target_device]),
            "root_cause": "Unpatched local privilege escalation vulnerability (CVE-2024-1086) on workstation WS-HR-042",
            "attack_vector": "Spear-phishing email with weaponized PDF then CVE-2024-1086 then credential harvesting then lateral movement then data exfiltration",
            "impact": {"confidentiality": 9, "integrity": 7, "availability": 5, "overall": 8.5},
            "recommendations": [
                "Patch CVE-2024-1086 on all endpoints immediately",
                "Implement network segmentation between HR and Finance VLANs",
                "Enable MFA for all administrative accounts",
                "Deploy EDR with behavioral analysis on all workstations",
                "Review and harden GPO policies for lateral movement prevention",
            ],
            "total_logs_analyzed": total_logs,
            "devices_isolated": [target_device, "10.0.0.30"],
            "dwell_time": "1h 14m",
            "status": "contained",
        }

        # Save report
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        report_path = REPORTS_DIR / "{}.json".format(report_id)
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(sim_report, f, indent=2)

        report_event = {"type": "report", "report_id": report_id, "message": "Attack report generated: {}".format(report_id), "report": sim_report}
        yield "data: {}\n\n".format(json.dumps(report_event))
        time.sleep(0.3)

        # Legal/juridique metadata
        legal_data = {
            "cert_dz": {"deadline": "24h", "hours_remaining": 22, "notification_required": True},
            "anpdp": {"deadline": "72h", "hours_remaining": 70, "personal_data_involved": True},
            "loi_18_07": {"articles": ["Art. 12", "Art. 15", "Art. 38", "Art. 44", "Art. 46"]},
            "penal_code": {"articles": ["394bis", "394ter", "394quater"]},
        }

        legal_event = {"type": "legal", "report_id": report_id, "message": "Juridique report generated — Loi 18-07, CERT-DZ, ANPDP mapped", "legal": legal_data}
        yield "data: {}\n\n".format(json.dumps(legal_event))
        time.sleep(0.3)

        # Final summary
        elapsed = (datetime.now() - sim_start).total_seconds()
        complete_event = {"type": "complete", "sim_id": sim_uuid, "total_logs": total_logs, "elapsed_seconds": round(elapsed, 1), "report_id": report_id, "devices_isolated": [target_device, "10.0.0.30"], "message": "Simulation complete — {} logs analyzed in {:.1f}s — {}".format(total_logs, elapsed, report_id)}
        yield "data: {}\n\n".format(json.dumps(complete_event))

    return app.response_class(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Access-Control-Allow-Origin": "*"},
    )


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":

    logger.info("=" * 60)
    logger.info("  AEGIS Flask API — Standalone Server")
    logger.info("  Project root: %s", PROJECT_ROOT)
    logger.info("  Data dir:     %s", DATA_DIR)
    logger.info("")

    # Quick data check
    reports = list(REPORTS_DIR.glob("*.json")) if REPORTS_DIR.exists() else []
    ledger = load_blockchain()
    logger.info("  📊 Reports:    %d files", len(reports))
    logger.info("  ⛓  Blockchain: %d blocks", len(ledger))
    logger.info("  🗺  Topology:   %s", "OK" if TOPOLOGY_FILE.exists() else "MISSING")
    logger.info("  💾 Hot DB:     %s", "OK" if HOT_DB.exists() else "MISSING")
    logger.info("")
    logger.info("  API:  http://localhost:5000/api/health")
    logger.info("  Frontend proxy: Vite :5173 → /api → :5000")
    logger.info("=" * 60)

    app.run(host="0.0.0.0", port=5000, debug=True)

