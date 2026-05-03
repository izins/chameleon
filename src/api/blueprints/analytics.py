"""
AEGIS API — Analytics & Threat Intelligence
===========================================
Focus: Aggregated metrics for Data Visualization (Dashboards).

All data is now sourced from the Hot SQLite Database (data/aegis_hot.db),
populated in real-time by the EntityTracker and ThreatIntelAggregator.

Endpoints:
  GET /api/analytics/global    → Full dashboard summary (all metrics)
  GET /api/analytics/geo       → Geo-IP attack origins (for threat map)
  GET /api/analytics/timeline  → Recent attacks (for live feed)
  GET /api/analytics/entity/<ip> → Detailed entity profile
"""

import logging

from flask import Blueprint, jsonify, request

from src.database.db_manager import db

logger = logging.getLogger(__name__)

analytics_bp = Blueprint("analytics", __name__, url_prefix="/api/analytics")


@analytics_bp.route("/global", methods=["GET"])
def get_global_analytics():
    """Full dashboard summary — one call, all metrics.

    Returns:
        JSON with top attackers, attack distribution, hourly heatmap,
        geo origins, and recent attack timeline.
    """
    try:
        summary = db.get_dashboard_summary()
        return jsonify({"status": "success", **summary})
    except Exception as e:
        logger.error("Analytics /global failed: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500


@analytics_bp.route("/geo", methods=["GET"])
def get_geo_distribution():
    """Attack geographic origins — for the SOC threat map.

    Returns:
        JSON list of attack origins with GPS coordinates, country,
        ISP, Tor/VPN flags, and cumulative score.
    """
    try:
        geo = db.get_geo_distribution()
        return jsonify({"status": "success", "origins": geo})
    except Exception as e:
        logger.error("Analytics /geo failed: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500


@analytics_bp.route("/timeline", methods=["GET"])
def get_attack_timeline():
    """Recent attacks in reverse chronological order — for the live feed.

    Query params:
        limit (int): Number of results (default 50, max 200).

    Returns:
        JSON list of recent alerts.
    """
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        timeline = db.get_attack_timeline(limit)
        return jsonify({"status": "success", "timeline": timeline})
    except Exception as e:
        logger.error("Analytics /timeline failed: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500


@analytics_bp.route("/entity/<ip>", methods=["GET"])
def get_entity_detail(ip: str):
    """Full detail for a specific entity/IP — entity + geo + alert history.

    Args:
        ip: The IP address to look up.

    Returns:
        JSON with entity score, geo data, and list of alerts.
    """
    try:
        detail = db.get_entity_detail(ip)
        if not detail:
            return jsonify({"status": "error", "message": f"Entity {ip} not found"}), 404
        return jsonify({"status": "success", **detail})
    except Exception as e:
        logger.error("Analytics /entity/%s failed: %s", ip, e)
        return jsonify({"status": "error", "message": str(e)}), 500
