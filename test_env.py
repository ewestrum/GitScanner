#!/usr/bin/env python3
"""Test .env file loading"""

import os
import sys
from pathlib import Path

# Add src directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, 'src')
sys.path.insert(0, src_dir)

from config_manager import ConfigManager

def test_env_loading():
    print("Testing .env file loading...")
    
    # Check if .env file exists
    env_file = Path('.env')
    if not env_file.exists():
        print("❌ .env file not found!")
        return
    
    print(f"✓ .env file found: {env_file.absolute()}")
    
    # Load configuration
    try:
        config_manager = ConfigManager('.env')
        config = config_manager.config_data
        
        print("\n📋 Loaded configuration:")
        print(f"GitHub Token: {'*' * 20 if config.get('GITHUB_TOKEN') and config.get('GITHUB_TOKEN') != 'your_github_token_here' else 'NOT SET (still placeholder)'}")
        print(f"GitHub Username: {config.get('GITHUB_USERNAME', 'NOT SET')}")
        print(f"Email From: {config.get('EMAIL_FROM', 'NOT SET')}")
        
        # Check if token is still placeholder
        token = config.get('GITHUB_TOKEN', '')
        if token == 'your_github_token_here' or not token:
            print("\n⚠️  WARNING: GitHub token is still set to placeholder value!")
            print("   Please update GITHUB_TOKEN in .env file with your actual GitHub Personal Access Token")
            print("   Create one at: https://github.com/settings/tokens")
        else:
            print(f"\n✓ GitHub token appears to be set (length: {len(token)})")
            
    except Exception as e:
        print(f"❌ Error loading configuration: {e}")

if __name__ == "__main__":
    test_env_loading()