import sys
import os
import time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from detector import DetectionEngine
import config

def test_slow_ramp_attack_adaptive():
    engine = DetectionEngine()
    
    # Wait for dynamic config to load
    time.sleep(1)
    
    # Ensure dynamic is enabled
    assert engine._is_dynamic_enabled()
    
    src_ip = "192.168.1.100"
    
    # Simulate normal traffic to build baseline (warmup)
    # E.g. SYN rate is around 5 packets per window
    # Wait, the check_syn_flood takes timestamps.
    now = time.time()
    
    for i in range(100):
        # 5 packets every 5 seconds -> ~1 packet/sec
        # Update baseline
        engine.update_baseline_if_normal(src_ip, "SYN_FLOOD", 5, False)
        
    # Baseline mean should be ~5
    tracker = engine.baselines.get_tracker(src_ip, "SYN_FLOOD")
    assert tracker.samples >= 100
    
    # Now simulate a slow ramp attack:
    # Say 15 packets in 5 seconds.
    # Static threshold is 40 (config.SYN_FLOOD_THRESHOLD) -> Static would miss it.
    # Adaptive threshold should be around floor (10).
    
    # Push 15 timestamps into syn_map
    for i in range(15):
        engine.syn_map[src_ip].append(now - 4.0 + i * 0.2)
        
    alert = engine.check_syn_flood(src_ip, now)
    
    # Should catch the slow ramp attack!
    assert alert is not None
    assert alert["method"] == "adaptive"
    assert "thresh=" in alert["baseline"]
    
    # Static wouldn't catch this because 15 < 40
    assert 15 < config.SYN_FLOOD_THRESHOLD
    
    engine.stop()
