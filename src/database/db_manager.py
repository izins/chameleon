"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/database/db_manager.py

Hot storage database manager using SQLite.
Stores entity history, alerts, and geolocation data for fast
dashboard queries and real-time ML feature extraction.

Tables:
- entities: Tracks IP risk scores and attack counts over time.
- alerts: Logs individual attacks for fast querying.
- geo_cache: Caches geolocation data to avoid repeated external API calls.
"""

import sqlite3
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

DB_DIR = Path("data")
DB_PATH = DB_DIR / "aegis_hot.db"


class DBManager:
    """Manages the SQLite hot database for AEGIS."""

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a configured database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        # Enable Write-Ahead Logging for better concurrent read/write
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            
            # Entities Table (The "Hot" Entity History)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entities (
                    ip TEXT PRIMARY KEY,
                    cumulative_score REAL DEFAULT 0.0,
                    alert_count INTEGER DEFAULT 0,
                    attack_types TEXT DEFAULT '[]',
                    first_seen TEXT,
                    last_seen TEXT
                )
            """)
            
            # Alerts Table (Fast log of attacks for dashboards)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    ip TEXT,
                    attack_type TEXT,
                    severity TEXT,
                    confidence REAL,
                    timestamp TEXT,
                    FOREIGN KEY(ip) REFERENCES entities(ip)
                )
            """)
            
            # Geo Cache Table (Speeds up Threat Intel and Dashboards)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS geo_cache (
                    ip TEXT PRIMARY KEY,
                    country TEXT,
                    country_code TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    asn INTEGER,
                    isp TEXT,
                    is_tor BOOLEAN,
                    is_vpn BOOLEAN,
                    timestamp TEXT
                )
            """)
            
            conn.commit()

            # Performance indexes for dashboard queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_entities_score ON entities(cumulative_score)")
            conn.commit()

            logger.info("Hot Database initialized at %s", self.db_path)

    # ── Entity Operations ──────────────────────────────────────────────

    def get_entity(self, ip: str) -> Optional[Dict[str, Any]]:
        """Retrieve an entity's hot state."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM entities WHERE ip = ?", (ip,)).fetchone()
            if row:
                data = dict(row)
                data['attack_types'] = json.loads(data['attack_types'])
                return data
            return None

    def upsert_entity(self, ip: str, score_delta: float, attack_type: str) -> Dict[str, Any]:
        """Update or create an entity's score and attack history."""
        now = datetime.now(timezone.utc).isoformat()
        
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("SELECT * FROM entities WHERE ip = ?", (ip,)).fetchone()
            
            if row:
                # Update existing
                new_score = row['cumulative_score'] + score_delta
                new_count = row['alert_count'] + 1
                attack_types = json.loads(row['attack_types'])
                if attack_type not in attack_types:
                    attack_types.append(attack_type)
                
                cursor.execute("""
                    UPDATE entities 
                    SET cumulative_score = ?, alert_count = ?, attack_types = ?, last_seen = ?
                    WHERE ip = ?
                """, (new_score, new_count, json.dumps(attack_types), now, ip))
                
                return {
                    "ip": ip, "cumulative_score": new_score, 
                    "alert_count": new_count, "attack_types": attack_types,
                    "first_seen": row['first_seen'], "last_seen": now
                }
            else:
                # Insert new
                attack_types = [attack_type]
                cursor.execute("""
                    INSERT INTO entities (ip, cumulative_score, alert_count, attack_types, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (ip, score_delta, 1, json.dumps(attack_types), now, now))
                
                return {
                    "ip": ip, "cumulative_score": score_delta, 
                    "alert_count": 1, "attack_types": attack_types,
                    "first_seen": now, "last_seen": now
                }

    # ── Alert Operations ───────────────────────────────────────────────

    def log_alert(self, alert_id: str, ip: str, attack_type: str, severity: str, confidence: float) -> None:
        """Log an alert into the hot database."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO alerts (alert_id, ip, attack_type, severity, confidence, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (alert_id, ip, attack_type, severity, confidence, now))

    # ── Geo Cache Operations ───────────────────────────────────────────

    def get_geo(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get cached geolocation data."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
            return dict(row) if row else None

    def save_geo(self, ip: str, geo_data: Dict[str, Any]) -> None:
        """Save geolocation data to cache."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO geo_cache 
                (ip, country, country_code, city, latitude, longitude, asn, isp, is_tor, is_vpn, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ip, geo_data.get('country', ''), geo_data.get('country_code', ''),
                geo_data.get('city', ''), geo_data.get('latitude', 0.0),
                geo_data.get('longitude', 0.0), geo_data.get('asn', 0),
                geo_data.get('isp', ''), geo_data.get('is_tor', False),
                geo_data.get('is_vpn', False), now
            ))

    # ── Analytics Operations (For Dashboards) ──────────────────────────

    def get_top_attackers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top attacking IPs by cumulative score.

        Args:
            limit: Max number of results.

        Returns:
            List of entity dicts sorted by score descending.
        """
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM entities ORDER BY cumulative_score DESC LIMIT ?",
                (limit,),
            ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["attack_types"] = json.loads(d["attack_types"])
                results.append(d)
            return results

    def get_attack_distribution(self) -> Dict[str, int]:
        """Get counts of attacks by type (for pie chart).

        Returns:
            Dict mapping attack_type -> count.
        """
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT attack_type, COUNT(*) as count FROM alerts GROUP BY attack_type"
            ).fetchall()
            return {r["attack_type"]: r["count"] for r in rows}

    def get_attacks_by_hour(self) -> Dict[str, int]:
        """Get attack distribution by hour of day (for heatmap).

        Returns:
            Dict mapping "HH:00" -> count.
        """
        with self._get_conn() as conn:
            # Use SQL substr to extract the hour from ISO timestamps
            # ISO format: 2026-05-02T11:40:28.143856+00:00
            #             position 12-13 is the hour
            rows = conn.execute("""
                SELECT SUBSTR(timestamp, 12, 2) || ':00' as hour_key,
                       COUNT(*) as count
                FROM alerts
                WHERE timestamp IS NOT NULL
                GROUP BY hour_key
                ORDER BY hour_key
            """).fetchall()
            return {r["hour_key"]: r["count"] for r in rows}

    def get_geo_distribution(self) -> List[Dict[str, Any]]:
        """Get attack origins with GPS for the threat map.

        Returns:
            List of dicts with country, city, lat, lng, count.
        """
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT g.ip, g.country, g.country_code, g.city, g.latitude, g.longitude,
                       g.isp, g.is_tor, g.is_vpn,
                       COALESCE(e.cumulative_score, 0) as score,
                       COALESCE(e.alert_count, 0) as alert_count
                FROM geo_cache g
                LEFT JOIN entities e ON g.ip = e.ip
                ORDER BY score DESC
            """).fetchall()
            return [dict(r) for r in rows]

    def get_attack_timeline(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent attacks in chronological order (for live feed).

        Args:
            limit: Max number of results.

        Returns:
            List of alert dicts sorted by timestamp descending.
        """
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_entity_detail(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get full detail of an entity (entity + geo + alerts).

        Uses a single connection for all 3 queries to avoid
        connection overhead (was 3 separate connections before).

        Args:
            ip: The IP address to look up.

        Returns:
            Dict with entity data, geo data, and recent alerts.
        """
        with self._get_conn() as conn:
            # 1. Entity
            entity_row = conn.execute(
                "SELECT * FROM entities WHERE ip = ?", (ip,)
            ).fetchone()
            if not entity_row:
                return None
            entity = dict(entity_row)
            entity["attack_types"] = json.loads(entity["attack_types"])

            # 2. Geo
            geo_row = conn.execute(
                "SELECT * FROM geo_cache WHERE ip = ?", (ip,)
            ).fetchone()
            geo = dict(geo_row) if geo_row else None

            # 3. Recent alerts
            alert_rows = conn.execute(
                "SELECT * FROM alerts WHERE ip = ? ORDER BY timestamp DESC LIMIT 20",
                (ip,),
            ).fetchall()
            alerts = [dict(r) for r in alert_rows]

        return {
            "entity": entity,
            "geo": geo,
            "recent_alerts": alerts,
        }

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get a full dashboard summary payload in one call.

        Returns:
            Dict with all dashboard metrics.
        """
        with self._get_conn() as conn:
            total_entities = conn.execute("SELECT COUNT(*) as c FROM entities").fetchone()["c"]
            total_alerts = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()["c"]
            total_geo = conn.execute("SELECT COUNT(*) as c FROM geo_cache").fetchone()["c"]

        return {
            "total_entities_tracked": total_entities,
            "total_alerts_logged": total_alerts,
            "total_geolocations_cached": total_geo,
            "top_attackers": self.get_top_attackers(5),
            "attack_distribution": self.get_attack_distribution(),
            "attacks_by_hour": self.get_attacks_by_hour(),
            "geo_origins": self.get_geo_distribution(),
            "recent_attacks": self.get_attack_timeline(10),
        }


# Singleton instance
db = DBManager()

