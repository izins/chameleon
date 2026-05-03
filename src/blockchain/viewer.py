"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/blockchain/viewer.py

A simple CLI tool to explore the AEGIS Blockchain Ledger.
It reads the local ledger file, verifies its cryptographic integrity,
and displays a chronological history of all anchored security events
(Alerts, Isolation Actions, and Incident Reports).
"""

import json
from datetime import datetime
from pathlib import Path
from colorama import Fore, Style, init

from src.blockchain.ledger import Ledger

init(autoreset=True)


def format_timestamp(ts_str: str) -> str:
    """Format an ISO timestamp to a readable string."""
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return ts_str


def explore_ledger():
    """Load and display the blockchain ledger."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}======================================================")
    print(f"{Fore.CYAN}{Style.BRIGHT}  ⛓️  AEGIS BLOCKCHAIN EXPLORER")
    print(f"{Fore.CYAN}{Style.BRIGHT}======================================================\n")

    # Load ledger
    ledger = Ledger(difficulty=1)  # Difficulty doesn't matter for reading
    
    if len(ledger.chain) <= 1:
        print(f"{Fore.YELLOW}The ledger is empty. Only the genesis block exists.")
        return

    # 1. Verify Integrity First
    print(f"{Fore.BLUE}Running cryptographic integrity check...")
    is_valid = ledger.is_chain_valid()
    
    if is_valid:
        print(f"{Fore.GREEN}✓ INTEGRITY VERIFIED: 0 tampered blocks detected.\n")
    else:
        print(f"{Fore.RED}{Style.BRIGHT}❌ CRITICAL ALERT: Blockchain integrity is COMPROMISED! Data has been tampered with.\n")

    print(f"{Fore.WHITE}{Style.BRIGHT}Total Blocks: {len(ledger.chain)}")
    print(f"{Fore.WHITE}------------------------------------------------------\n")

    # 2. Print chronological history
    for block in ledger.chain:
        # Skip genesis block to keep output clean, unless it's the only one
        if block.index == 0:
            continue
            
        print(f"{Fore.MAGENTA}{Style.BRIGHT}📦 BLOCK #{block.index} "
              f"{Fore.LIGHTBLACK_EX}(Mined: {format_timestamp(block.timestamp)})")
        print(f"{Fore.LIGHTBLACK_EX}   Hash: {block.hash[:16]}... | Prev: {block.previous_hash[:16]}...")
        print(f"{Fore.LIGHTBLACK_EX}   Proof-of-Work Nonce: {block.nonce}")
        
        for tx in block.transactions:
            print(f"   ├─ {Fore.YELLOW}Transaction ID: {tx.tx_id[:8]}")
            
            # Formatting based on document type
            if tx.document_type == "EnrichedAlert":
                severity = tx.metadata.get("severity", "UNKNOWN")
                attack = tx.metadata.get("attack_type", "Unknown Attack")
                color = Fore.RED if severity == "P1" else Fore.LIGHTYELLOW_EX
                
                print(f"   │  {color}🚨 ALERT DETECTED  : {attack} ({severity})")
                print(f"   │  {Fore.WHITE}   Target Entity  : {tx.document_id}")
                
            elif tx.document_type == "IsolationActions":
                count = tx.metadata.get("actions_count", 0)
                print(f"   │  {Fore.CYAN}🛡️  ACTIONS TAKEN   : {count} isolation actions executed")
                print(f"   │  {Fore.WHITE}   For Incident   : {tx.document_id[:8]}")
                
            elif tx.document_type == "IncidentReport":
                entity = tx.metadata.get("entity_id", "Unknown")
                risk = tx.metadata.get("risk_score", 0.0)
                print(f"   │  {Fore.GREEN}📄 FINAL REPORT    : {tx.document_id[:8]}")
                print(f"   │  {Fore.WHITE}   Entity         : {entity}")
                print(f"   │  {Fore.WHITE}   Final Risk     : {risk}/10")
            else:
                print(f"   │  {Fore.WHITE}📄 {tx.document_type}: {tx.document_id[:8]}")
                
            print(f"   │  {Fore.LIGHTBLACK_EX}   Document Hash  : {tx.document_hash}")
        
        print("")

    print(f"{Fore.CYAN}======================================================")
    print(f"{Fore.CYAN}  End of Ledger. Data is immutable and legally sound.")
    print(f"{Fore.CYAN}======================================================\n")

if __name__ == "__main__":
    # Ensure colorama is installed or fallback
    try:
        import colorama
    except ImportError:
        import os
        os.system("pip install colorama")
        
    explore_ledger()
