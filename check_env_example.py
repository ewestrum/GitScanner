#!/usr/bin/env python3
"""
Check .env.example content to see if it should be flagged
"""
import os
import sys

# Add src to path for local imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from github_client import GitHubClient
from config_manager import ConfigManager
from enhanced_content_analyzer import EnhancedContentAnalyzer
import base64

def check_env_example():
    """Check .env.example content"""
    # Initialize configuration
    config_manager = ConfigManager('.env')
    config = config_manager.config_data
    
    # GitHub client
    github_token = config.get('GITHUB_TOKEN')
    github_client = GitHubClient(github_token)
    
    # Get .env.example content
    try:
        # First get repository contents to find the .env.example file
        files = github_client.get_repository_contents('ewestrum/GitScanner')
        env_file = None
        
        for file_info in files:
            if file_info['name'] == '.env.example':
                env_file = file_info
                break
        
        if not env_file:
            print(".env.example not found")
            return
            
        content = github_client.get_file_content(env_file['download_url'])
        if content:
            print("Content of .env.example:")
            print("=" * 50)
            
            # Decode if base64 encoded
            try:
                decoded = base64.b64decode(content).decode('utf-8')
                print(decoded)
            except:
                print(content)
            
            print("=" * 50)
            
            # Test with enhanced analyzer
            analyzer = EnhancedContentAnalyzer([])
            
            # Use decoded content for analysis
            try:
                test_content = base64.b64decode(content).decode('utf-8')
            except:
                test_content = content
                
            findings = analyzer.analyze_content(test_content, '.env.example')
            print(f"\nEnhanced analyzer findings: {len(findings)}")
            
            for finding in findings:
                print(f"- {finding['type']}: {finding['pattern']} (risk: {finding['risk_score']})")
            
        else:
            print("Could not retrieve .env.example content")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_env_example()