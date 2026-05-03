"""
AEGIS API — ISO 27035 + Network Topology Blueprint
====================================================
Serves ISO lifecycle data and network topology to the frontend.
Mirrors the endpoints from soc_api.py but registered as blueprints
on the main Flask app (port 5000).
"""

import json
from pathlib import Path
from flask import Blueprint, jsonify, request, send_from_directory
from src.config.settings import settings

iso_network_bp = Blueprint("iso_network", __name__)

_DATA_DIR = Path(settings.demo_output_file).parent if hasattr(settings, 'demo_output_file') else Path("data")
_ISO_DIR = _DATA_DIR / "iso27035"
_NETWORK_DIR = _DATA_DIR / "network"
_STATIC_DIR = Path(__file__).resolve().parent.parent.parent / "dashboard" / "static"


def _load_iso_records():
    records = []
    if _ISO_DIR.exists():
        for f in sorted(_ISO_DIR.glob("iso_*.json"), reverse=True):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    records.append(json.load(fh))
            except Exception:
                pass
    return records


def _load_iso_record(prefix):
    if _ISO_DIR.exists():
        for f in _ISO_DIR.glob(f"iso_{prefix}*.json"):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception:
                pass
    return None


# ── ISO 27035 Endpoints ──────────────────────────────────────────────

@iso_network_bp.route("/api/iso27035/incidents", methods=["GET"])
def get_iso_incidents():
    records = _load_iso_records()
    summaries = []
    for r in records:
        phases_summary = {}
        for pname, pdata in r.get("phases", {}).items():
            phases_summary[pname] = {
                "status": pdata.get("status", "pending"),
                "iso_clause": pdata.get("iso_clause", ""),
                "duration_seconds": pdata.get("duration_seconds"),
                "sub_phases": {
                    k: v.get("status", "pending")
                    for k, v in pdata.get("sub_phases", {}).items()
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
    return jsonify({"total": len(summaries), "incidents": summaries})


@iso_network_bp.route("/api/iso27035/incident/<incident_id>", methods=["GET"])
def get_iso_incident(incident_id):
    record = _load_iso_record(incident_id)
    if not record:
        return jsonify({"error": "Not found"}), 404
    return jsonify(record)


@iso_network_bp.route("/api/iso27035/incident/<incident_id>/phase/<int:phase_num>", methods=["GET"])
def get_iso_phase(incident_id, phase_num):
    record = _load_iso_record(incident_id)
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


@iso_network_bp.route("/api/iso27035/compliance/<incident_id>", methods=["GET"])
def get_iso_compliance(incident_id):
    record = _load_iso_record(incident_id)
    if not record:
        return jsonify({"error": "Not found"}), 404
    compliance = []
    for pname, pdata in record.get("phases", {}).items():
        reqs = pdata.get("requirements", [])
        met = pdata.get("requirements_met", [])
        compliance.append({
            "phase": pname, "iso_clause": pdata.get("iso_clause", ""),
            "status": pdata.get("status", "pending"),
            "total_requirements": len(reqs), "requirements_met": len(met),
            "met": met, "outstanding": [r for r in reqs if r not in met],
        })
    total_reqs = sum(c["total_requirements"] for c in compliance)
    total_met = sum(c["requirements_met"] for c in compliance)
    return jsonify({
        "incident_id": record.get("incident_id"),
        "overall_compliance": f"{total_met}/{total_reqs}",
        "compliance_percentage": round((total_met / total_reqs * 100) if total_reqs else 0, 1),
        "phases": compliance,
    })


# ── Network Topology Endpoints ───────────────────────────────────────

@iso_network_bp.route("/api/network/topology", methods=["GET"])
def get_network_topology():
    topo_path = _NETWORK_DIR / "topology.json"
    if topo_path.exists():
        with open(topo_path, "r", encoding="utf-8") as fh:
            return jsonify(json.load(fh))
    return jsonify({"error": "No topology. Run scanner first."}), 404


@iso_network_bp.route("/api/network/scan", methods=["POST"])
def trigger_scan():
    try:
        from src.response.network_scanner import NetworkScanner
        scanner = NetworkScanner()
        topo = scanner.scan(probe_ports=False)
        return jsonify(topo.model_dump(mode="json"))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@iso_network_bp.route("/topology")
def serve_topology():
    return send_from_directory(str(_STATIC_DIR), "topology.html")
