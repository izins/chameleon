"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/blockchain/models.py

Defines the core data structures for the AEGIS Immutable Ledger.
Transactions represent forensic artifacts (like Incident Reports).
Blocks group transactions and chain to the previous block via cryptohash.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from pydantic import BaseModel, Field


class Transaction(BaseModel):
    """Represents a single immutable record in the blockchain.
    
    In AEGIS, a transaction is typically a hash of an IncidentReport
    or an EvidencePackage, proving its existence at a specific time.
    """
    tx_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    document_type: str  # e.g., "IncidentReport", "EvidencePackage"
    document_id: str    # The UUID of the report
    document_hash: str  # SHA-256 of the JSON representation of the document
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    def calculate_hash(self) -> str:
        """Calculate the SHA-256 hash of this transaction."""
        tx_string = json.dumps(self.model_dump(), sort_keys=True)
        return hashlib.sha256(tx_string.encode('utf-8')).hexdigest()


class Block(BaseModel):
    """Represents a block in the AEGIS blockchain.
    
    Chains cryptographically to the previous block.
    """
    index: int
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    transactions: List[Transaction] = Field(default_factory=list)
    previous_hash: str
    nonce: int = 0
    hash: str = ""
    
    def calculate_hash(self) -> str:
        """Calculate the SHA-256 hash of the block.
        
        Note: We do not include the 'hash' field itself in the calculation.
        """
        block_dict = self.model_dump(exclude={"hash"})
        block_string = json.dumps(block_dict, sort_keys=True)
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()
    
    def mine_block(self, difficulty: int) -> None:
        """Simple Proof-of-Work to make tampering computationally expensive."""
        target = "0" * difficulty
        self.hash = self.calculate_hash()
        
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
