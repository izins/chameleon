"""
AEGIS API — Incident Handler Blueprint
======================================
Role: Incident Handler / L2 Responder
Focus: Technical summary, Actionable Playbooks, Root Cause, Isolation Status.
"""

from flask import Blueprint, jsonify
from src.api.services import DataService

handler_bp = Blueprint("handler", __name__, url_prefix="/api/handler")

@handler_bp.route("/incidents/active", methods=["GET"])
def get_active_incidents():
    reports = DataService.get_all_reports()
    
    technical_view = []
    for r in reports:
        analysis = r.get("analysis", {})
        playbook = r.get("playbook", {}).get("steps", [])
        
        technical_view.append({
            "incident_id": r.get("report_id"),
            "date": r.get("generated_at"),
            "target_entity": r.get("entity_id"),
            "severity": r.get("severity", "P4"),
            "attack_type": r.get("attack_type", "unknown"),
            "risk_score": r.get("risk_score", 0),
            "risk_label": r.get("risk_label", ""),
            "attack_classification": analysis.get("attack_classification"),
            "root_cause": analysis.get("root_cause_hypothesis"),
            "kill_chain_phase": analysis.get("kill_chain_phase", ""),
            "cves_exploited": analysis.get("cve_exploited", []),
            "mitre_techniques": analysis.get("mitre_techniques", []),
            "playbook_steps": len(playbook),
            "pending_actions": [step for step in playbook if step.get("priority") in ["CRITICAL", "HIGH"]]
        })
        
    return jsonify({
        "status": "success",
        "incidents": technical_view
    })

@handler_bp.route("/incidents/<report_id>/playbook", methods=["GET"])
def get_playbook(report_id):
    """Retrieve the exact technical commands to run for this incident."""
    reports = DataService.get_all_reports()
    for r in reports:
        if r.get("report_id") == report_id:
            return jsonify({
                "incident_id": report_id,
                "entity_id": r.get("entity_id"),
                "playbook": r.get("playbook", {})
            })
    return jsonify({"error": "Incident not found"}), 404

@handler_bp.route("/isolation/status/<entity_id>", methods=["GET"])
def get_isolation_status(entity_id):
    """Check what isolation actions AEGIS has already applied."""
    actions = DataService.get_isolation_actions()
    entity_actions = [a for a in actions if a.get("entity_id") == entity_id]
    
    return jsonify({
        "entity_id": entity_id,
        "total_actions": len(entity_actions),
        "actions_log": entity_actions
    })
