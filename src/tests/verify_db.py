"""Verify the Hot Database content after an integration run."""
import json
import os
os.environ.setdefault("AEGIS_DEMO_MODE", "true")

from src.database.db_manager import db

print("=" * 70)
print("  AEGIS HOT DATABASE — LIVE CONTENT VERIFICATION")
print("=" * 70)

summary = db.get_dashboard_summary()

print()
print("Total entities tracked :", summary["total_entities_tracked"])
print("Total alerts logged    :", summary["total_alerts_logged"])
print("Total geo cached       :", summary["total_geolocations_cached"])

print("\n--- TOP ATTACKERS ---")
for a in summary["top_attackers"]:
    print(f"  {a['ip']:20s} score={a['cumulative_score']:>8.1f}  alerts={a['alert_count']}  types={a['attack_types']}")

print("\n--- ATTACK DISTRIBUTION (Pie Chart) ---")
for k, v in summary["attack_distribution"].items():
    print(f"  {k:30s} -> {v} attacks")

print("\n--- ATTACKS BY HOUR (Heatmap) ---")
for h, c in summary["attacks_by_hour"].items():
    print(f"  {h} -> {c} attacks")

print("\n--- GEO ORIGINS (Threat Map) ---")
for g in summary["geo_origins"]:
    print(f"  {g['country']:15s} {g['city']:15s}  lat={g['latitude']:>8.4f}  lng={g['longitude']:>8.4f}  tor={g['is_tor']}  score={g['score']}")

print("\n--- RECENT ATTACKS (Live Feed) ---")
for t in summary["recent_attacks"]:
    print(f"  {t['timestamp'][:19]}  {t['ip']:20s}  {t['attack_type']}")

print("\n--- ENTITY DETAIL (185.220.101.42) ---")
detail = db.get_entity_detail("185.220.101.42")
if detail:
    print(f"  Entity: {json.dumps(detail['entity'], indent=4)}")
    if detail["geo"]:
        print(f"  Geo: {json.dumps(detail['geo'], indent=4)}")
    print(f"  Alerts: {len(detail['recent_alerts'])} records")

print("\nALL QUERIES VERIFIED")
