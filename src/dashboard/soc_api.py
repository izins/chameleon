"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/dashboard/soc_api.py

REST API for the SOC Dashboard — serves ISO 27035 lifecycle data,
incident reports, and risk verdicts for the analyst interface.

Endpoints:
  GET  /api/iso27035/incidents       — All tracked incidents
  GET  /api/iso27035/incident/<id>   — Single incident lifecycle
  GET  /api/iso27035/incident/<id>/phase/<n>  — Phase detail
  GET  /api/incidents                — All incident reports
  GET  /api/health                   — System health
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Dict, List

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder=None)
CORS(app)


# ── Data Directory ───────────────────────────────────────────────────

_DATA_DIR = Path(os.environ.get(
    "AEGIS_DATA_DIR",
    str(Path(__file__).resolve().parent.parent.parent / "data"),
))
_ISO_DIR = _DATA_DIR / "iso27035"
_REPORTS_DIR = _DATA_DIR / "reports"


# ── Helper Functions ─────────────────────────────────────────────────

def _load_iso_records() -> List[Dict]:
    """Load all ISO 27035 incident records from disk."""
    records = []
    if _ISO_DIR.exists():
        for f in sorted(_ISO_DIR.glob("iso_*.json"), reverse=True):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    records.append(json.load(fh))
            except Exception:
                pass
    return records


def _load_iso_record(incident_id_prefix: str) -> Dict | None:
    """Load a single ISO 27035 record by ID prefix."""
    if _ISO_DIR.exists():
        for f in _ISO_DIR.glob(f"iso_{incident_id_prefix}*.json"):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception:
                pass
    return None


def _load_reports() -> List[Dict]:
    """Load all incident reports from disk."""
    reports = []
    if _REPORTS_DIR.exists():
        for f in sorted(_REPORTS_DIR.glob("report_*.json"), reverse=True):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    reports.append(json.load(fh))
            except Exception:
                pass
    return reports


# ── ISO 27035 Lifecycle Endpoints ────────────────────────────────────

@app.route("/api/iso27035/incidents", methods=["GET"])
def get_all_iso_incidents():
    """Get all ISO 27035 tracked incidents with phase summaries."""
    records = _load_iso_records()

    # Build a compact summary for the list view
    summaries = []
    for r in records:
        phases_summary = {}
        for phase_name, phase_data in r.get("phases", {}).items():
            phases_summary[phase_name] = {
                "status": phase_data.get("status", "pending"),
                "iso_clause": phase_data.get("iso_clause", ""),
                "duration_seconds": phase_data.get("duration_seconds"),
                "sub_phases": {
                    k: v.get("status", "pending")
                    for k, v in phase_data.get("sub_phases", {}).items()
                },
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

    return jsonify({
        "total": len(summaries),
        "incidents": summaries,
    })


@app.route("/api/iso27035/incident/<incident_id>", methods=["GET"])
def get_iso_incident(incident_id: str):
    """Get the full ISO 27035 lifecycle for a specific incident.

    Returns all 5 phases with their inputs, outputs, timing,
    compliance requirements, and sub-phases.
    """
    record = _load_iso_record(incident_id)
    if not record:
        return jsonify({"error": f"Incident {incident_id} not found"}), 404
    return jsonify(record)


@app.route("/api/iso27035/incident/<incident_id>/phase/<int:phase_num>",
           methods=["GET"])
def get_iso_phase(incident_id: str, phase_num: int):
    """Get detailed data for a specific phase of an incident.

    Phase numbers:
      1: Detection & Reporting
      2: Assessment & Decision
      3: Response (includes sub-phases)
      4: Lessons Learned
      5: Documentation & Closure
    """
    record = _load_iso_record(incident_id)
    if not record:
        return jsonify({"error": f"Incident {incident_id} not found"}), 404

    phase_map = {
        1: "Phase 1: Detection & Reporting",
        2: "Phase 2: Assessment & Decision",
        3: "Phase 3: Response",
        4: "Phase 4: Lessons Learned",
        5: "Phase 5: Documentation & Closure",
    }
    phase_key = phase_map.get(phase_num)
    if not phase_key:
        return jsonify({"error": f"Invalid phase number {phase_num}"}), 400

    phase_data = record.get("phases", {}).get(phase_key)
    if not phase_data:
        return jsonify({"error": f"Phase {phase_num} not found"}), 404

    return jsonify({
        "incident_id": record.get("incident_id"),
        "entity_id": record.get("entity_id"),
        "phase": phase_data,
    })


# ── Incident Reports Endpoints ──────────────────────────────────────

@app.route("/api/incidents", methods=["GET"])
def get_all_incidents():
    """Get all generated incident reports."""
    reports = _load_reports()
    summaries = []
    for r in reports:
        summaries.append({
            "report_id": r.get("report_id", ""),
            "entity_id": r.get("entity_id", ""),
            "generated_at": r.get("generated_at", ""),
            "severity": r.get("severity", ""),
            "risk_score": r.get("risk_score", 0),
            "risk_label": r.get("risk_label", ""),
            "playbook_steps": len(r.get("playbook", {}).get("steps", [])),
        })
    return jsonify({"total": len(summaries), "incidents": summaries})


@app.route("/api/incident/<report_id>", methods=["GET"])
def get_incident(report_id: str):
    """Get a full incident report by ID prefix."""
    reports = _load_reports()
    for r in reports:
        if r.get("report_id", "").startswith(report_id):
            return jsonify(r)
    return jsonify({"error": f"Report {report_id} not found"}), 404


# ── System Health ────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health_check():
    """System health and status."""
    iso_records = _load_iso_records()
    reports = _load_reports()

    return jsonify({
        "status": "operational",
        "components": {
            "iso27035_tracker": {
                "status": "active",
                "tracked_incidents": len(iso_records),
            },
            "report_generator": {
                "status": "active",
                "total_reports": len(reports),
            },
            "blockchain": {
                "status": "active",
            },
        },
    })


@app.route("/api/iso27035/compliance/<incident_id>", methods=["GET"])
def get_compliance_status(incident_id: str):
    """Get ISO 27035 compliance status for an incident.

    Shows which requirements have been met and which are outstanding.
    """
    record = _load_iso_record(incident_id)
    if not record:
        return jsonify({"error": f"Incident {incident_id} not found"}), 404

    compliance = []
    for phase_name, phase_data in record.get("phases", {}).items():
        reqs = phase_data.get("requirements", [])
        met = phase_data.get("requirements_met", [])
        outstanding = [r for r in reqs if r not in met]

        compliance.append({
            "phase": phase_name,
            "iso_clause": phase_data.get("iso_clause", ""),
            "status": phase_data.get("status", "pending"),
            "total_requirements": len(reqs),
            "requirements_met": len(met),
            "requirements_outstanding": len(outstanding),
            "met": met,
            "outstanding": outstanding,
        })

    total_reqs = sum(c["total_requirements"] for c in compliance)
    total_met = sum(c["requirements_met"] for c in compliance)

    return jsonify({
        "incident_id": record.get("incident_id"),
        "entity_id": record.get("entity_id"),
        "overall_compliance": f"{total_met}/{total_reqs}",
        "compliance_percentage": round(
            (total_met / total_reqs * 100) if total_reqs > 0 else 0, 1,
        ),
        "phases": compliance,
    })


# ── Network Topology Endpoints ───────────────────────────────────────

_NETWORK_DIR = _DATA_DIR / "network"
_STATIC_DIR = Path(__file__).resolve().parent / "static"


@app.route("/api/network/topology", methods=["GET"])
def get_network_topology():
    """Get the full network topology with device classifications.

    Returns all discovered devices, edges, and isolation overlays.
    """
    topo_path = _NETWORK_DIR / "topology.json"
    if topo_path.exists():
        with open(topo_path, "r", encoding="utf-8") as fh:
            return jsonify(json.load(fh))
    return jsonify({"error": "No topology scan found. Run the scanner first."}), 404


@app.route("/api/network/scan", methods=["POST"])
def trigger_network_scan():
    """Trigger a fresh network scan."""
    try:
        from src.response.network_scanner import NetworkScanner
        scanner = NetworkScanner()
        topo = scanner.scan(probe_ports=False)
        return jsonify(topo.model_dump(mode="json"))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Static Frontend ──────────────────────────────────────────────────

@app.route("/topology")
def serve_topology_page():
    """Serve the interactive network topology visualization."""
    return send_from_directory(str(_STATIC_DIR), "topology.html")


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Serves ISO 27035 lifecycle data to the SOC dashboard.
# 2. Provides per-phase drill-down with inputs/outputs/compliance.
# 3. Exposes compliance audit endpoints for regulatory readiness.
# 4. Serves network topology with isolation overlay for visualization.
# 5. Decoupled from the tracker — reads from persisted JSON files.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="INFO")

    logger.info("Starting AEGIS SOC API on http://localhost:5050")
    app.run(host="0.0.0.0", port=5050, debug=True)

