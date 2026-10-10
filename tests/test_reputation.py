import sys
import os
import time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from reputation import ReputationManager

def test_reputation_allowlist():
    rm = ReputationManager(dry_run=True, allowlist=["10.0.0.0/8"])
    
    # Allowed IP should never increase score
    score, blocked = rm.add_alert("10.1.2.3", "High", "Test", time.time())
    assert score == 0.0
    assert not blocked
    
    # Non-allowed IP
    score, blocked = rm.add_alert("192.168.1.1", "High", "Test", time.time())
    assert score == 100.0
    assert not blocked

def test_reputation_blocking_and_decay():
    rm = ReputationManager(block_ttl_seconds=10, dry_run=True)
    t0 = time.time()
    
    # First alert
    score, blocked = rm.add_alert("1.1.1.1", "High", "Test", t0)
    assert score == 100.0
    assert not blocked
    
    # Decay after 60 seconds (score should halve)
    t1 = t0 + 60
    score, blocked = rm.add_alert("1.1.1.1", "High", "Test", t1)
    # Old score 100 -> decays to 50 -> + 100 = 150
    assert score == 150.0
    assert not blocked
    
    # Alert immediately after (no decay)
    t2 = t1
    score, blocked = rm.add_alert("1.1.1.1", "High", "Test", t2)
    # Score becomes 150 + 100 = 250 -> block threshold reached
    assert score == 250.0
    assert blocked
    
    rm.stop()
