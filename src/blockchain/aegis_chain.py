"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/blockchain/aegis_chain.py

The high-level integration layer between AEGIS and the Immutable Ledger.
Provides functions to seamlessly anchor IncidentReports and EvidencePackages
into the blockchain for legal non-repudiation.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any, List, Optional

from pydantic import BaseModel

from src.blockchain.ledger import Ledger
from src.blockchain.models import Transaction
from src.enrichment.enrichment_engine import EnrichedAlert
from src.response.isolation_log import IsolationAction

if TYPE_CHECKING:
    from src.reporting.report_generator import IncidentReport

logger = logging.getLogger(__name__)


class AegisChain:
    """Interface for anchoring AEGIS artifacts into the blockchain.
    
    This class handles the conversion of complex AEGIS objects (like 
    IncidentReport) into cryptographic hashes, submits them to the ledger
    as transactions, and triggers the mining process.
    """

    def __init__(self, ledger: Optional[Ledger] = None) -> None:
        """Initialize the AegisChain interface.
        
        Args:
            ledger: Optional existing Ledger instance. If None, a new one
                    will be initialized (which loads from disk).
        """
        self.ledger = ledger or Ledger()
        logger.info("AegisChain interface initialized.")

    def _hash_document(self, document: BaseModel) -> str:
        """Calculate a deterministic SHA-256 hash of any Pydantic model.
        
        We serialize the Pydantic model to JSON with sorted keys to ensure
        the hash is completely deterministic regardless of field order.
        """
        doc_dict = document.model_dump(mode='json')
        doc_json = json.dumps(doc_dict, sort_keys=True)
        return hashlib.sha256(doc_json.encode('utf-8')).hexdigest()

    def anchor_alert(self, alert: EnrichedAlert) -> str:
        """Anchor a raw EnrichedAlert as soon as it's generated (Phase 2)."""
        logger.info("Anchoring Alert %s to blockchain...", alert.enriched_id)
        
        tx = Transaction(
            document_type="EnrichedAlert",
            document_id=alert.enriched_id,
            document_hash=self._hash_document(alert),
            metadata={
                "attack_type": alert.original_alert.attack_type,
                "severity": alert.original_alert.severity,
            }
        )
        self.ledger.add_transaction(tx)
        block = self.ledger.mine_pending_transactions()
        if block:
            logger.info("✓ Alert %s secured in Block %d", alert.enriched_id[:8], block.index)
        return tx.tx_id

    def anchor_isolation_actions(self, incident_id: str, actions: List[IsolationAction]) -> str:
        """Anchor the execution of containment actions (Phase 3)."""
        logger.info("Anchoring %d Actions for Incident %s...", len(actions), incident_id)
        
        # Serialize list of actions deterministically
        action_dicts = [a.model_dump(mode='json') for a in actions]
        action_json = json.dumps(action_dicts, sort_keys=True)
        actions_hash = hashlib.sha256(action_json.encode('utf-8')).hexdigest()
        
        tx = Transaction(
            document_type="IsolationActions",
            document_id=incident_id,
            document_hash=actions_hash,
            metadata={"actions_count": len(actions)}
        )
        self.ledger.add_transaction(tx)
        block = self.ledger.mine_pending_transactions()
        if block:
            logger.info("✓ Actions secured in Block %d", block.index)
        return tx.tx_id

    def anchor_incident_report(self, report: IncidentReport) -> str:
        """Anchor a complete IncidentReport into the blockchain.
        
        This process guarantees that the report, its evidence, the playbook,
        and the legal documents cannot be altered retroactively.
        
        Args:
            report: The IncidentReport to anchor.
            
        Returns:
            The transaction ID representing this record in the blockchain.
        """
        logger.info("Anchoring IncidentReport %s to blockchain...", report.report_id)
        
        # 1. Calculate the cryptographic hash of the entire report
        report_hash = self._hash_document(report)
        
        # 2. Create a blockchain transaction
        tx = Transaction(
            document_type="IncidentReport",
            document_id=report.report_id,
            document_hash=report_hash,
            metadata={
                "entity_id": report.entity_id,
                "severity": report.severity,
                "risk_score": report.risk_score,
                "attack_classification": report.analysis.attack_classification,
            }
        )
        
        # 3. Submit transaction to ledger
        self.ledger.add_transaction(tx)
        
        # 4. Mine the block immediately (since security incidents are critical)
        block = self.ledger.mine_pending_transactions()
        
        if block:
            logger.info(
                "✓ IncidentReport %s successfully secured in Block %d (Tx: %s)", 
                report.report_id[:8], block.index, tx.tx_id[:8]
            )
        
        return tx.tx_id

    def verify_report_integrity(self, report: IncidentReport) -> bool:
        """Verify that a given IncidentReport exactly matches the blockchain.
        
        This function is used during audits or legal proceedings to prove
        that the report being presented is exactly the same one that was
        generated at the time of the incident.
        
        Args:
            report: The IncidentReport to verify.
            
        Returns:
            True if the report matches the blockchain, False if it was altered 
            or not found.
        """
        # 1. Verify the blockchain itself hasn't been tampered with
        if not self.ledger.is_chain_valid():
            logger.error("Integrity Check Failed: The blockchain itself is compromised!")
            return False
            
        # 2. Calculate the hash of the presented report
        current_hash = self._hash_document(report)
        
        # 3. Search the blockchain for this report's original hash
        for block in reversed(self.ledger.chain):
            for tx in block.transactions:
                if tx.document_id == report.report_id:
                    # Found the record! Let's compare hashes.
                    if tx.document_hash == current_hash:
                        logger.info(
                            "✓ Integrity Verified: Report %s matches blockchain record exactly.", 
                            report.report_id[:8]
                        )
                        return True
                    else:
                        logger.warning(
                            "❌ Integrity Check Failed! Report %s has been altered since it was anchored.", 
                            report.report_id[:8]
                        )
                        logger.debug("Original hash: %s", tx.document_hash)
                        logger.debug("Current hash : %s", current_hash)
                        return False
                        
        logger.warning(
            "❌ Integrity Check Failed: Report %s not found in the blockchain.", 
            report.report_id[:8]
        )
        return False
