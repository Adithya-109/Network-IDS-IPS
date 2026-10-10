import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from baselines import AdaptiveThresholds, BaselineTracker

def test_baseline_poisoning_resistance():
    """Test that a baseline cannot be poisoned indefinitely due to floor/ceiling limits."""
    tracker = BaselineTracker()
    
    # Simulate normal traffic
    for i in range(100):
        tracker.update(10)
    
    # Threshold should be around 10
    thresh = tracker.get_threshold(k_sigma=3.0, floor=5, ceiling=20)
    assert 5 <= thresh <= 20
    
    # Attempt to poison by slowly raising the value (if we were allowing malicious updates)
    for i in range(1000):
        tracker.update(100)
    
    # Threshold should hit the ceiling and not go beyond
    thresh = tracker.get_threshold(k_sigma=3.0, floor=5, ceiling=20)
    assert thresh == 20

def test_adaptive_threshold_warmup():
    tracker = BaselineTracker()
    
    # Too few samples => warmup phase => fallback to ceiling
    for i in range(10):
        tracker.update(5)
        
    thresh = tracker.get_threshold(k_sigma=3.0, floor=5, ceiling=30, is_warm=False)
    assert thresh == 30

    # Enough samples => warm
    for i in range(40):
        tracker.update(5)
    
    thresh = tracker.get_threshold(k_sigma=3.0, floor=5, ceiling=30, is_warm=True)
    # Should be close to 5, bounded by floor
    assert thresh == 5
