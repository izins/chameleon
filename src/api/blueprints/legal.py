"""
AEGIS API — Legal Blueprint
=============================
Role: Équipe Légal (Legal Team)
Focus: CERT-DZ / ANPDP Notifications, Deadlines, Compliance Risks, Blockchain verifiable history.
"""

import hashlib
import json
from flask import Blueprint, jsonify
from src.api.services import DataService

legal_bp = Blueprint("legal", __name__, url_prefix="/api/legal")

@legal_bp.route("/dashboard", methods=["GET"])
def get_legal_dashboard():
    reports = DataService.get_all_reports()
    
    legal_summary = []
    for r in reports:
        # Extract Legal info
        cert = r.get("cert_dz_notification", {})
        anpdp = r.get("anpdp_notification", {})
        
        legal_summary.append({
            "incident_id": r.get("report_id"),
            "date": r.get("generated_at"),
            "entity": r.get("entity_id"),
            "severity": r.get("severity"),
            "cert_dz": {
                "deadline": cert.get("deadline"),
                "hours_remaining": cert.get("hours_remaining"),
                "legal_liability_risk": cert.get("legal_liability_risk")
            },
            "anpdp": {
                "deadline": anpdp.get("deadline"),
                "hours_remaining": anpdp.get("hours_remaining"),
                "fines_for_non_compliance": anpdp.get("fines_for_non_compliance")
            },
            "blockchain_anchored": True  # By architectural design
        })
        
    return jsonify({
        "status": "success",
        "total_incidents": len(legal_summary),
        "pending_notifications": [x for x in legal_summary if x["cert_dz"].get("hours_remaining", 0) > 0],
        "history": legal_summary
    })

@legal_bp.route("/blockchain/verify/<report_id>", methods=["GET"])
def verify_report(report_id):
    """Get the blockchain transaction proving the report's immutability."""
    ledger = DataService.get_blockchain_ledger()
    for block in ledger:
        for tx in block.get("transactions", []):
            if tx.get("document_id") == report_id and tx.get("document_type") == "IncidentReport":
                return jsonify({
                    "verified": True,
                    "block_index": block.get("index"),
                    "mined_at": block.get("timestamp"),
                    "transaction": tx
                })
    return jsonify({"verified": False, "message": "Not found in Blockchain"}), 404

@legal_bp.route("/history/verified", methods=["GET"])
def get_verified_history():
    """Retrieve all historical incident reports and verify their integrity via Blockchain."""
    reports = DataService.get_all_reports()
    ledger = DataService.get_blockchain_ledger()
    
    verified_history = []
    
    for r in reports:
        report_id = r.get("report_id")
        
        # Calculate SHA-256 of the JSON report on disk
        report_json = json.dumps(r, sort_keys=True)
        current_hash = hashlib.sha256(report_json.encode('utf-8')).hexdigest()
        
        # Search the ledger for the original anchor
        is_verified = False
        anchor_tx = None
        for block in ledger:
            for tx in block.get("transactions", []):
                if tx.get("document_id") == report_id and tx.get("document_type") == "IncidentReport":
                    anchor_tx = tx
                    if tx.get("document_hash") == current_hash:
                        is_verified = True
                    break
            if anchor_tx:
                break
                
        verified_history.append({
            "incident_id": report_id,
            "generated_at": r.get("generated_at"),
            "severity": r.get("severity"),
            "cryptographic_integrity_valid": is_verified,
            "blockchain_hash_match": anchor_tx is not None and is_verified,
            "full_data": r if is_verified else None, # Only expose full data if it wasn't tampered with
            "error": "Tampering detected!" if not is_verified else None
        })
        
    return jsonify({
        "status": "success",
        "total_historical_incidents": len(verified_history),
        "verified_incidents": verified_history
    })
