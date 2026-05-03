"""
AEGIS API — SOC Analyst Blueprint
=================================
Role: SOC L1/L2 Analyst
Focus: Real-time alerts, IP risk scoring, Entity History, Log traces.
"""

from flask import Blueprint, jsonify
from src.api.services import DataService

soc_bp = Blueprint("soc", __name__, url_prefix="/api/soc")

@soc_bp.route("/feed", methods=["GET"])
def get_alert_feed():
    """Stream of recent alerts directly from the blockchain (Phase 2 output)."""
    ledger = DataService.get_blockchain_ledger()
    
    alerts = []
    # Read blockchain backwards to get newest first
    for block in reversed(ledger):
        for tx in block.get("transactions", []):
            if tx.get("document_type") == "EnrichedAlert":
                alerts.append({
                    "time": tx.get("timestamp"),
                    "tx_id": tx.get("tx_id"),
                    "entity_id": tx.get("document_id"),
                    "attack_type": tx.get("metadata", {}).get("attack_type"),
                    "severity": tx.get("metadata", {}).get("severity"),
                    "block_index": block.get("index")
                })
                
    return jsonify({
        "status": "success",
        "live_alerts": alerts
    })

@soc_bp.route("/entity/<entity_id>", methods=["GET"])
def get_entity_profile(entity_id):
    """Deep dive into a specific IP/Entity (History, Risk Score, Actions)."""
    history = DataService.get_entity_history(entity_id)
    
    # Calculate current risk score based on history
    max_risk = 0.0
    for r in history.get("incident_reports", []):
        risk = float(r.get("risk_score", 0))
        if risk > max_risk:
            max_risk = risk
            
    return jsonify({
        "entity_id": entity_id,
        "current_risk_score": max_risk,
        "is_isolated": len(history.get("isolation_actions", [])) > 0,
        "history": history
    })

@soc_bp.route("/metrics", methods=["GET"])
def get_soc_metrics():
    """High-level metrics for SOC Dashboard."""
    ledger = DataService.get_blockchain_ledger()
    total_blocks = len(ledger)
    total_alerts = sum(1 for b in ledger for t in b.get("transactions", []) if t.get("document_type") == "EnrichedAlert")
    
    reports = DataService.get_all_reports()
    
    return jsonify({
        "total_blocks": total_blocks,
        "total_alerts": total_alerts,
        "total_incidents": len(reports),
        "system_status": "Healthy (Immutable Mode)"
    })
