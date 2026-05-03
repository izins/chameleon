"""
AEGIS API — Notifications & Alarms Blueprint
============================================
Role: Automated Response & Escalation
Focus: Sending critical alerts via Email, SMS, and Automated Phone Calls 
for P1 (Critical) incidents.
"""

import logging
from flask import Blueprint, jsonify, request
import time

logger = logging.getLogger(__name__)

notifications_bp = Blueprint("notifications", __name__, url_prefix="/api/notifications")

def send_email_alert(incident_id: str, severity: str, entity: str):
    """
    Mock implementation of an Email sender (e.g., using SMTP or SendGrid).
    In production, this connects to the corporate exchange server.
    """
    logger.info(f"📧 [EMAIL SENT] To: soc-l2@aegis.com | Subject: URGENT {severity} - Incident {incident_id} on {entity}")
    # time.sleep(0.5) # Simulate network latency
    return True

def send_phone_call_alert(incident_id: str, phone_number: str):
    """
    Mock implementation of a Phone Call (e.g., using Twilio Voice API).
    Plays an automated message: "This is AEGIS. A critical P1 incident has been detected..."
    """
    logger.info(f"📞 [CALL INITIATED] To: {phone_number} | Message: 'Critical AEGIS Alert: Incident {incident_id}'")
    # time.sleep(1)
    return True

@notifications_bp.route("/trigger", methods=["POST"])
def trigger_alarms():
    """
    Endpoint to manually or automatically trigger escalation alarms.
    Expects JSON payload: {"incident_id": "...", "severity": "P1", "entity_id": "...", "escalation_level": "Level_3"}
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid payload"}), 400
        
    incident_id = data.get("incident_id", "UNKNOWN")
    severity = data.get("severity", "UNKNOWN")
    entity_id = data.get("entity_id", "UNKNOWN")
    escalation_level = data.get("escalation_level", "Level_1")
    
    results = {"email": False, "phone": False}
    
    # Send Email to SOC Team
    results["email"] = send_email_alert(incident_id, severity, entity_id)
    
    # If Critical (P1) or Level 3, wake up the on-call engineer via Phone Call
    if severity == "P1" or escalation_level == "Level_3":
        on_call_number = "+213000000000" # Example DZ number
        results["phone"] = send_phone_call_alert(incident_id, on_call_number)
        
    return jsonify({
        "status": "success",
        "message": f"Alarms triggered successfully for incident {incident_id}.",
        "delivery_status": results
    })
