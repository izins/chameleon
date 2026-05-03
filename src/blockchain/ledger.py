"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/blockchain/ledger.py

Implements the Blockchain ledger that manages the sequence of blocks,
validates chain integrity, and persists the ledger to disk.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import List, Optional

from pydantic import ValidationError

from src.blockchain.models import Block, Transaction
from src.config.settings import settings

logger = logging.getLogger(__name__)


class Ledger:
    """The AEGIS Immutable Ledger.
    
    Manages the chain of blocks, handles mining (Proof-of-Work),
    and validates the cryptographical integrity of the entire chain.
    """

    def __init__(self, difficulty: int = 2) -> None:
        """Initialize the ledger.
        
        Args:
            difficulty: Number of leading zeros required for a valid block hash.
                        Default is 2 for fast demo purposes. In production, 
                        this would be higher to increase tamper resistance.
        """
        self.difficulty = difficulty
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        
        # In a real distributed system, we would load the longest valid chain 
        # from peers. Here we load from local disk.
        self._ledger_file = Path(settings.demo_output_file).parent / "blockchain" / "ledger.json"
        self._ledger_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.load_chain()
        
        if not self.chain:
            self._create_genesis_block()

    def _create_genesis_block(self) -> None:
        """Create the very first block in the blockchain."""
        genesis_block = Block(
            index=0,
            previous_hash="0" * 64,  # No previous block
        )
        # Add a special genesis transaction
        tx = Transaction(
            document_type="SystemEvent",
            document_id="genesis",
            document_hash="0" * 64,
            metadata={"message": "AEGIS Ledger Initialized"}
        )
        genesis_block.transactions.append(tx)
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)
        self.save_chain()
        logger.info("Genesis block created. Hash: %s", genesis_block.hash[:8])

    def get_latest_block(self) -> Block:
        """Return the most recent block in the chain."""
        return self.chain[-1]

    def add_transaction(self, transaction: Transaction) -> int:
        """Add a transaction to the pending pool.
        
        Args:
            transaction: The transaction to add.
            
        Returns:
            The index of the block that will hold this transaction.
        """
        self.pending_transactions.append(transaction)
        logger.debug("Transaction added to pending pool: %s", transaction.tx_id)
        return self.get_latest_block().index + 1

    def mine_pending_transactions(self) -> Optional[Block]:
        """Mine all pending transactions into a new block.
        
        Returns:
            The newly mined block, or None if no pending transactions.
        """
        if not self.pending_transactions:
            logger.debug("No pending transactions to mine.")
            return None

        previous_block = self.get_latest_block()
        new_block = Block(
            index=previous_block.index + 1,
            previous_hash=previous_block.hash,
            transactions=self.pending_transactions.copy()
        )
        
        logger.info("Mining new block %d...", new_block.index)
        new_block.mine_block(self.difficulty)
        
        self.chain.append(new_block)
        
        # Clear pending transactions
        self.pending_transactions = []
        
        # Persist to disk
        self.save_chain()
        
        logger.info(
            "Block %d successfully mined and anchored to ledger. Hash: %s", 
            new_block.index, new_block.hash[:8]
        )
        return new_block

    def is_chain_valid(self) -> bool:
        """Validate the cryptographical integrity of the entire blockchain.
        
        Returns:
            True if the chain is valid, False if it has been tampered with.
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # 1. Check if current block's hash is correct
            if current_block.hash != current_block.calculate_hash():
                logger.error("Tampering detected! Block %d hash is invalid.", current_block.index)
                return False

            # 2. Check if current block correctly points to previous block
            if current_block.previous_hash != previous_block.hash:
                logger.error(
                    "Tampering detected! Block %d previous_hash does not match Block %d hash.",
                    current_block.index, previous_block.index
                )
                return False
                
            # 3. Verify Proof-of-Work
            target = "0" * self.difficulty
            if not current_block.hash.startswith(target):
                logger.error("Tampering detected! Block %d does not meet difficulty target.", current_block.index)
                return False

        logger.info("Blockchain integrity verified. Chain is valid.")
        return True

    def save_chain(self) -> None:
        """Serialize and persist the blockchain to disk."""
        try:
            chain_dict = [block.model_dump() for block in self.chain]
            with open(self._ledger_file, "w", encoding="utf-8") as f:
                json.dump(chain_dict, f, indent=2)
        except Exception as exc:
            logger.error("Failed to save ledger to disk: %s", exc)

    def load_chain(self) -> None:
        """Load the blockchain from disk."""
        if not self._ledger_file.exists():
            return
            
        try:
            with open(self._ledger_file, "r", encoding="utf-8") as f:
                chain_dict = json.load(f)
                
            self.chain = []
            for block_data in chain_dict:
                try:
                    self.chain.append(Block(**block_data))
                except ValidationError as ve:
                    logger.error("Ledger file corrupted. Invalid block data: %s", ve)
                    return
            logger.info("Ledger loaded from disk. %d blocks found.", len(self.chain))
            
            # Re-verify integrity upon load
            if not self.is_chain_valid():
                logger.critical("Loaded ledger is INVALID! Cryptographic integrity compromised.")
        except Exception as exc:
            logger.error("Failed to load ledger from disk: %s", exc)
