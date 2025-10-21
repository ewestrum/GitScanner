#!/usr/bin/env python3
"""Debug GitHub authentication"""

import os
import sys
import requests
from pathlib import Path

# Add src directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, 'src')
sys.path.insert(0, src_dir)

from config_manager import ConfigManager

def debug_github_auth():
    print("🔍 Debugging GitHub authentication...")
    
    try:
        # Load config
        config_manager = ConfigManager('.env')
        config = config_manager.config_data
        
        token = config.get('GITHUB_TOKEN', '').strip()
        username = config.get('GITHUB_USERNAME', '').strip()
        
        print(f"📋 Configuration status:")
        print(f"   - Token length: {len(token)}")
        print(f"   - Token starts with: {token[:4]}..." if len(token) > 4 else f"   - Token: {token}")
        print(f"   - Username: {username}")
        
        if not token or token == 'your_github_token_here':
            print("\n❌ GitHub token is not set or still has placeholder value!")
            print("   Please update GITHUB_TOKEN in .env file")
            return
        
        if not token.startswith('ghp_') and not token.startswith('github_pat_'):
            print(f"\n⚠️  Warning: Token doesn't start with expected prefix (ghp_ or github_pat_)")
            print(f"   Your token starts with: {token[:10]}...")
        
        # Test the token manually
        print(f"\n🧪 Testing GitHub API authentication...")
        
        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'GitHubMonitor/1.0'
        }
        
        response = requests.get('https://api.github.com/user', headers=headers)
        print(f"   - Status code: {response.status_code}")
        print(f"   - Response headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            user_data = response.json()
            print(f"   ✅ Authentication successful!")
            print(f"   - Authenticated as: {user_data.get('login')}")
            print(f"   - Account type: {user_data.get('type')}")
            print(f"   - Public repos: {user_data.get('public_repos')}")
        else:
            print(f"   ❌ Authentication failed!")
            if response.status_code == 401:
                print("   - This usually means the token is invalid, expired, or has wrong format")
            elif response.status_code == 403:
                print("   - This usually means rate limiting or insufficient permissions")
            
            try:
                error_data = response.json()
                print(f"   - Error message: {error_data}")
            except:
                print(f"   - Response text: {response.text}")
        
    except Exception as e:
        print(f"❌ Error during debug: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_github_auth()