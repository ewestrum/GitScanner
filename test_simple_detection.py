#!/usr/bin/env python3
"""
Quick test to see what simple monitor finds
"""
import os
import sys

# Add src to path for local imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from github_client import GitHubClient
from config_manager import ConfigManager

def test_simple_detection():
    """Test simple filename-based detection"""
    # Initialize configuration
    config_manager = ConfigManager('.env')
    config = config_manager.config_data
    
    # GitHub client
    github_token = config.get('GITHUB_TOKEN')
    github_client = GitHubClient(github_token)
    
    # Get first repository
    repositories = github_client.get_user_repositories()
    if not repositories:
        print("No repositories found")
        return
        
    repo = repositories[0]
    repo_name = repo['full_name']
    print(f"Testing repository: {repo_name}")
    
    # Get repository contents
    files = github_client.get_repository_contents(repo_name)
    
    suspicious_patterns = [
        '.env', '.secret', '.private', '.pem', '.p12', '.pfx',
        'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
        'credentials', 'config.json', 'secrets.json',
        'password', 'passwd', 'shadow'
    ]
    
    print(f"Found {len(files)} files")
    
    suspicious_files = []
    for file_info in files:
        filename = file_info['name']
        filename_lower = filename.lower()
        
        if any(pattern in filename_lower for pattern in suspicious_patterns):
            suspicious_files.append({
                'name': filename,
                'path': file_info['path'],
                'size': file_info.get('size', 0)
            })
            print(f"SUSPICIOUS: {filename} at {file_info['path']}")
    
    print(f"\nFound {len(suspicious_files)} suspicious files")
    
    return suspicious_files

if __name__ == "__main__":
    test_simple_detection()