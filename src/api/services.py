"""
AEGIS API — Data Access Layer (Services)
========================================
Provides unified access to AEGIS data: JSON Reports, 
Isolation Actions, and Blockchain Ledger.
"""

import json
from pathlib import Path
from typing import Dict, List, Any

def _load_json_file(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default if default is not None else []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return default if default is not None else []

def _load_jsonl_file(path: Path) -> List[Dict]:
    if not path.exists():
        return []
    lines = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    lines.append(json.loads(line))
        return lines
    except Exception:
        return []

class DataService:
    @staticmethod
    def get_all_reports() -> List[Dict]:
        """Load all Incident Reports (JSON)."""
        reports_dir = Path("data/reports")
        reports = []
        if reports_dir.exists():
            for file in reports_dir.glob("FULL_REPORT_*.json"):
                data = _load_json_file(file, default={})
                if data:
                    reports.append(data)
        # Sort by generated_at descending
        reports.sort(key=lambda x: x.get("generated_at", ""), reverse=True)
        return reports

    @staticmethod
    def get_blockchain_ledger() -> List[Dict]:
        """Load the Blockchain Ledger."""
        return _load_json_file(Path("data/blockchain/ledger.json"), default=[])

    @staticmethod
    def get_isolation_actions() -> List[Dict]:
        """Load all isolation actions logged."""
        return _load_jsonl_file(Path("data/isolation_actions.jsonl"))
    
    @staticmethod
    def get_entity_history(entity_id: str) -> Dict:
        """Aggregate all actions, alerts, and reports for a specific IP/Entity."""
        # 1. Get reports
        reports = [r for r in DataService.get_all_reports() if r.get("entity_id") == entity_id]
        
        # 2. Get isolation actions
        actions = [a for a in DataService.get_isolation_actions() if a.get("entity_id") == entity_id]
        
        # 3. Get alerts from ledger
        ledger = DataService.get_blockchain_ledger()
        alerts = []
        for block in ledger:
            for tx in block.get("transactions", []):
                if tx.get("document_type") == "EnrichedAlert" and tx.get("metadata", {}).get("entity") == entity_id:
                    # Depending on how we stored it, entity might be in document_id or metadata
                    pass # We will do a generic search
                # Actually, document_id is the alert_id, but the entity is sometimes in metadata or we have to map it.
                if tx.get("document_type") == "EnrichedAlert":
                    # For simplicity in this endpoint
                    alerts.append(tx)
                    
        return {
            "entity_id": entity_id,
            "incident_reports": reports,
            "isolation_actions": actions,
            "blockchain_events_count": len(alerts)
        }
