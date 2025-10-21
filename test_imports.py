#!/usr/bin/env python3
"""Test the enhanced_github_monitor import to find the exact error"""

import sys
import traceback

try:
    # Try importing the main modules to see where the error comes from
    print("Testing imports...")
    
    print("1. Importing pathlib...")
    from pathlib import Path
    print("   ✓ OK")
    
    print("2. Importing basic modules...")
    import os, re, json, sys
    print("   ✓ OK")
    
    print("3. Importing src.advanced_config_manager...")
    from src.advanced_config_manager import AdvancedConfigManager
    print("   ✓ OK")
    
    print("4. Creating AdvancedConfigManager instance...")
    config = AdvancedConfigManager()
    print("   ✓ OK")
    
    print("5. Testing regex compilation...")
    for rule_id, rule in config.regex_rules.items():
        try:
            re.compile(rule.pattern)
        except re.error as e:
            print(f"   ✗ Error in rule {rule_id}: {e}")
            print(f"     Pattern: {rule.pattern}")
            raise
    print("   ✓ All regex patterns OK")
    
    print("All tests passed!")
    
except Exception as e:
    print(f"Error: {e}")
    traceback.print_exc()