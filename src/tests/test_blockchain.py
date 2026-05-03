"""Tests for Phase 5 - Blockchain Integration."""

import os
from pathlib import Path

import pytest

from src.blockchain.aegis_chain import AegisChain
from src.blockchain.ledger import Ledger
from src.blockchain.models import Block, Transaction
from src.config.settings import settings
from src.reporting.report_generator import IncidentReport


@pytest.fixture(autouse=True)
def setup_teardown():
    """Setup and teardown for tests to avoid writing to real ledger."""
    # Override ledger path for tests
    os.environ["AEGIS_DEMO_MODE"] = "true"
    test_ledger_path = Path(settings.demo_output_file).parent / "blockchain" / "ledger.json"
    
    # Clean up before
    if test_ledger_path.exists():
        test_ledger_path.unlink()
        
    yield
    
    # Clean up after
    if test_ledger_path.exists():
        test_ledger_path.unlink()


def test_genesis_block():
    """Test that initializing a ledger creates a valid genesis block."""
    ledger = Ledger(difficulty=1)
    assert len(ledger.chain) == 1
    
    genesis = ledger.chain[0]
    assert genesis.index == 0
    assert genesis.previous_hash == "0" * 64
    assert len(genesis.transactions) == 1
    assert genesis.transactions[0].document_id == "genesis"
    
    # Check proof of work
    assert genesis.hash.startswith("0")
    assert genesis.hash == genesis.calculate_hash()


def test_mining_and_chain_validity():
    """Test mining new blocks and validating the chain."""
    ledger = Ledger(difficulty=1)
    
    # Add a transaction
    tx = Transaction(
        document_type="TestDoc",
        document_id="test-123",
        document_hash="hash_123"
    )
    ledger.add_transaction(tx)
    
    # Mine
    block = ledger.mine_pending_transactions()
    assert block is not None
    assert block.index == 1
    assert len(ledger.chain) == 2
    
    # Validate chain
    assert ledger.is_chain_valid() is True


def test_tampering_detection():
    """Test that altering a block invalidates the chain."""
    ledger = Ledger(difficulty=1)
    
    # Add block 1
    ledger.add_transaction(Transaction(document_type="T", document_id="1", document_hash="A"))
    ledger.mine_pending_transactions()
    
    # Add block 2
    ledger.add_transaction(Transaction(document_type="T", document_id="2", document_hash="B"))
    ledger.mine_pending_transactions()
    
    assert ledger.is_chain_valid() is True
    
    # TAMPER: Change data in Block 1
    ledger.chain[1].transactions[0].document_hash = "TAMPERED_HASH"
    
    # The chain should now be invalid because the hash of block 1 no longer matches its contents
    assert ledger.is_chain_valid() is False


def test_aegis_chain_anchoring():
    """Test anchoring an IncidentReport into the blockchain."""
    # Create a dummy report
    report = IncidentReport(
        entity_id="10.0.0.99",
        severity="P2",
        risk_score=6.5
    )
    
    aegis_chain = AegisChain(ledger=Ledger(difficulty=1))
    
    # Anchor it
    tx_id = aegis_chain.anchor_incident_report(report)
    assert tx_id is not None
    
    # Verify it
    assert aegis_chain.verify_report_integrity(report) is True
    
    # Tamper with the report in memory
    report.severity = "P4" # "Hacker" tries to downgrade the severity
    
    # Verification should now fail
    assert aegis_chain.verify_report_integrity(report) is False
