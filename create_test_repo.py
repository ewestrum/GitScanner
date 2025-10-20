#!/usr/bin/env python3
"""
Create Test Repository - Creates a test repository for GitHub Monitor demonstration
"""

import os
import sys
import requests
import json
from pathlib import Path

# Add src directory to path  
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

from config_manager import ConfigManager

def create_test_repo():
    """Create a test repository with some sample files"""
    
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
    
    print("🚀 Creating test repository for GitHub Monitor demonstration...")
    print()
    
    # Repository data
    repo_data = {
        "name": "github-monitor-test",
        "description": "Test repository for GitHub Monitor Tool - contains sample files for security scanning",
        "private": False,  # Make it public so it's easier to test
        "auto_init": True,
        "gitignore_template": "Python"
    }
    
    try:
        # Create repository
        print("📁 Creating repository...")
        response = requests.post(
            "https://api.github.com/user/repos",
            headers=headers,
            json=repo_data
        )
        
        if response.status_code == 201:
            repo_info = response.json()
            print(f"✅ Repository created: {repo_info['html_url']}")
            repo_name = repo_info['full_name']
        elif response.status_code == 422:
            print("ℹ️  Repository already exists, using existing one...")
            user_response = requests.get("https://api.github.com/user", headers=headers)
            user_info = user_response.json()
            repo_name = f"{user_info['login']}/github-monitor-test"
        else:
            print(f"❌ Failed to create repository: {response.status_code} - {response.text}")
            return
        
        print()
        
        # Add sample files with security issues for testing
        sample_files = {
            ".env.example": '''# Sample environment file with potential issues
API_KEY=sk-1234567890abcdef1234567890abcdef12345678
DATABASE_URL=postgresql://user:password123@localhost:5432/mydb
SECRET_KEY=super-secret-key-that-should-not-be-here
GMAIL_PASSWORD=mypassword123
''',
            "config.py": '''# Configuration file with embedded secrets
import os

class Config:
    # This is bad - hardcoded credentials
    DATABASE_PASSWORD = "hardcoded_password_123"
    API_KEY = "aea123456789abcdef123456789abcdef"
    
    # Personal data that shouldn't be in code
    ADMIN_EMAIL = "admin@mycompany.com"
    SUPPORT_PHONE = "+31612345678"
    
    # This is better - using environment variables
    GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
''',
            "README.md": '''# GitHub Monitor Test Repository

This repository contains sample files designed to test the GitHub Monitor Tool.

## Test Files

- `.env.example` - Contains sample API keys and passwords
- `config.py` - Python config with hardcoded credentials
- `secrets.json` - JSON file with sensitive information

## Contact Information

For questions, contact:
- Email: developer@example.com
- Phone: 06-12345678
- BSN: 123456782 (sample BSN for testing)

⚠️ **Warning**: This repository contains sample sensitive data for testing purposes only!
''',
            "secrets.json": '''{
    "api_keys": {
        "openai": "sk-abcd1234567890abcdef1234567890abcdef123456",
        "stripe": "sk_test_1234567890abcdef1234567890abcdef",
        "github": "ghp_1234567890abcdef1234567890abcdef123456"
    },
    "database": {
        "host": "localhost",
        "user": "admin", 
        "password": "super_secret_password_123"
    },
    "personal_info": {
        "credit_card": "4532123456789012",
        "phone": "+31612345678",
        "email": "sensitive@personal-domain.com"
    }
}'''
        }
        
        print("📄 Adding sample files with security issues...")
        
        for filename, content in sample_files.items():
            try:
                # Check if file already exists
                file_response = requests.get(
                    f"https://api.github.com/repos/{repo_name}/contents/{filename}",
                    headers=headers
                )
                
                file_data = {
                    "message": f"Add {filename} for GitHub Monitor testing",
                    "content": content.encode().hex()  # GitHub API expects hex-encoded content
                }
                
                if file_response.status_code == 200:
                    # File exists, update it
                    existing_file = file_response.json()
                    file_data["sha"] = existing_file["sha"]
                    
                response = requests.put(
                    f"https://api.github.com/repos/{repo_name}/contents/{filename}",
                    headers=headers,
                    json=file_data
                )
                
                if response.status_code in [200, 201]:
                    print(f"   ✅ {filename}")
                else:
                    print(f"   ❌ {filename}: {response.status_code}")
                    
            except Exception as e:
                print(f"   ⚠️  {filename}: {e}")
        
        print()
        print("🎉 Test repository setup complete!")
        print()
        print(f"Repository URL: https://github.com/{repo_name}")
        print()
        print("You can now run the GitHub Monitor to scan this test repository:")
        print("  python github_monitor.py")
        print("  python run_monitor.py scan")
        print()
        print("Expected findings:")
        print("  - API keys in .env.example and config.py")
        print("  - Hardcoded passwords") 
        print("  - Email addresses and phone numbers")
        print("  - Credit card number in secrets.json")
        print("  - Sample BSN in README.md")
        
    except Exception as e:
        print(f"❌ Error creating test repository: {e}")

if __name__ == "__main__":
    create_test_repo()