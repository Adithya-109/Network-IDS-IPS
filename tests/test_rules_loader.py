import sys
import os
import json
import time
import tempfile
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from rules_loader import RulesLoader

def test_rules_loader_hot_reload():
    # Create a temporary rules file
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, 'w') as f:
        json.dump({
            "suspicious_ports": {"9999": "TestService"},
            "dpi_signatures": [{"id": "SIG-TEST", "patterns": ["test_pattern"], "enabled": True}]
        }, f)
        
    loader = RulesLoader(rules_path=path)
    rules = loader.get_rules()
    
    assert "9999" in rules["suspicious_ports"]
    assert len(rules["dpi_signatures"]) == 1
    assert rules["dpi_signatures"][0]["id"] == "SIG-TEST"
    assert "compiled_patterns" in rules["dpi_signatures"][0]
    
    # Modify the file
    with open(path, 'w') as f:
        json.dump({
            "suspicious_ports": {"8888": "NewService"},
            "dpi_signatures": [{"id": "SIG-TEST", "patterns": ["test_pattern"], "enabled": False}]
        }, f)
        
    # Reload
    loader.load_rules()
    rules = loader.get_rules()
    
    assert "8888" in rules["suspicious_ports"]
    assert "9999" not in rules["suspicious_ports"]
    
    # Signature is disabled, so compiled list should be empty
    assert len(rules["dpi_signatures"]) == 0
    
    os.remove(path)

def test_invalid_regex():
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, 'w') as f:
        json.dump({
            "dpi_signatures": [{"id": "SIG-INVALID", "patterns": ["["], "enabled": True}]
        }, f)
        
    loader = RulesLoader(rules_path=path)
    rules = loader.get_rules()
    
    # Should skip invalid regex
    assert len(rules["dpi_signatures"]) == 0
    
    os.remove(path)
