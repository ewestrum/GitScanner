#!/usr/bin/env python3
"""Debug config loading"""

import os
import sys
from pathlib import Path

# Add src directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, 'src')
sys.path.insert(0, src_dir)

from config_manager import ConfigManager

def debug_config():
    print("🔍 Debugging configuration loading...")
    
    config_manager = ConfigManager('.env')
    config = config_manager.config_data
    
    print("\n📋 Raw config values:")
    email_related_keys = [k for k in config.keys() if 'EMAIL' in k.upper() or 'SMTP' in k.upper() or 'SENDER' in k.upper() or 'RECIPIENT' in k.upper()]
    
    for key in sorted(email_related_keys):
        value = config[key]
        print(f"   {key}: {repr(value)} (type: {type(value).__name__})")
    
    # Test boolean conversion
    email_enabled = config.get('EMAIL_ENABLED')
    print(f"\n🧪 EMAIL_ENABLED tests:")
    print(f"   Raw value: {repr(email_enabled)}")
    print(f"   == 'true': {email_enabled == 'true'}")
    print(f"   == True: {email_enabled == True}")
    print(f"   bool(): {bool(email_enabled)}")
    print(f"   lower() == 'true': {email_enabled.lower() == 'true' if isinstance(email_enabled, str) else 'N/A'}")

if __name__ == "__main__":
    debug_config()