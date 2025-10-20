#!/usr/bin/env python3
"""
GitHub Repository Test - Check what repositories are available
"""

import os
import sys
import requests
from pathlib import Path

# Add src directory to path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

from config_manager import ConfigManager

def test_github_access():
    """Test GitHub API access and repository visibility"""
    
    config = ConfigManager()
    token = config.get('GITHUB_TOKEN')
    
    if not token:
        print("❌ No GitHub token found in .env file")
        return
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "GitHubMonitor/1.0"
    }
    
    print("🔍 Testing GitHub API access...")
    print()
    
    # Test 1: Get user info
    try:
        response = requests.get("https://api.github.com/user", headers=headers)
        response.raise_for_status()
        user_info = response.json()
        
        print(f"✅ Authenticated as: {user_info.get('login', 'Unknown')}")
        print(f"📊 Account type: {user_info.get('type', 'Unknown')}")
        print(f"📁 Public repos: {user_info.get('public_repos', 0)}")
        print(f"🔒 Total private repos: {user_info.get('total_private_repos', 0)}")
        print(f"👥 Following: {user_info.get('following', 0)}")
        print(f"👥 Followers: {user_info.get('followers', 0)}")
        print()
        
    except Exception as e:
        print(f"❌ Failed to get user info: {e}")
        return
    
    # Test 2: Try different repository endpoints
    endpoints_to_test = [
        ("/user/repos", "All repositories (user endpoint)"),
        ("/user/repos?type=all", "All repositories (explicit)"),
        ("/user/repos?type=owner", "Owned repositories"),
        ("/user/repos?type=member", "Member repositories"),
        (f"/users/{user_info.get('login', '')}/repos", "Public repositories (public endpoint)"),
    ]
    
    for endpoint, description in endpoints_to_test:
        try:
            print(f"🔗 Testing: {description}")
            response = requests.get(f"https://api.github.com{endpoint}", headers=headers)
            response.raise_for_status()
            repos = response.json()
            
            print(f"   Found {len(repos)} repositories")
            
            if repos:
                print("   Repositories:")
                for repo in repos[:5]:  # Show first 5
                    private_status = "🔒 Private" if repo.get('private') else "🌐 Public"
                    print(f"   - {repo.get('name', 'Unknown')} ({private_status})")
                
                if len(repos) > 5:
                    print(f"   ... and {len(repos) - 5} more")
            
            print()
            
        except Exception as e:
            print(f"   ❌ Failed: {e}")
            print()
    
    # Test 3: Check token scopes
    try:
        response = requests.get("https://api.github.com/user", headers=headers)
        scopes = response.headers.get('X-OAuth-Scopes', '').split(', ') if response.headers.get('X-OAuth-Scopes') else []
        
        print(f"🔐 Token scopes: {', '.join(scopes) if scopes else 'None detected'}")
        
        required_scopes = ['repo', 'public_repo']
        has_required = any(scope in scopes for scope in required_scopes)
        
        if has_required:
            print("✅ Token has required repository access")
        else:
            print("⚠️  Token may not have sufficient repository access")
            print("   Required scopes: 'repo' (for private repos) or 'public_repo' (for public repos)")
        
        print()
        
    except Exception as e:
        print(f"⚠️  Could not check token scopes: {e}")
        print()
    
    # Test 4: Rate limiting info
    try:
        response = requests.get("https://api.github.com/rate_limit", headers=headers)
        response.raise_for_status()
        rate_info = response.json()
        
        core = rate_info.get('resources', {}).get('core', {})
        print(f"⏱️  Rate limit: {core.get('remaining', 0)}/{core.get('limit', 0)} remaining")
        print()
        
    except Exception as e:
        print(f"⚠️  Could not check rate limit: {e}")
        print()

if __name__ == "__main__":
    test_github_access()