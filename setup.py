#!/usr/bin/env python3
"""
GitHub Monitor Tool Setup Script
Run this script to set up the GitHub Monitor tool
"""

import os
import sys
import subprocess
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    
    print(f"✅ Python version OK: {sys.version.split()[0]}")
    return True

def install_requirements():
    """Install required Python packages"""
    print("📦 Installing required packages...")
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("✅ Packages installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing packages: {e}")
        return False

def create_env_file():
    """Create .env file from example if it doesn't exist"""
    env_file = Path('.env')
    env_example = Path('.env.example')
    
    if env_file.exists():
        print("ℹ️  .env file already exists")
        return True
    
    if not env_example.exists():
        print("❌ Error: .env.example file not found")
        return False
    
    try:
        # Copy example to .env
        with open(env_example, 'r', encoding='utf-8') as src:
            content = src.read()
        
        with open(env_file, 'w', encoding='utf-8') as dst:
            dst.write(content)
        
        print("✅ Created .env file from template")
        print("⚠️  IMPORTANT: Please edit .env file with your actual credentials!")
        return True
        
    except Exception as e:
        print(f"❌ Error creating .env file: {e}")
        return False

def test_configuration():
    """Test basic configuration"""
    print("🧪 Testing configuration...")
    
    try:
        from src.config_manager import ConfigManager
        
        config = ConfigManager()
        
        # Check if GitHub token is configured
        if not config.get('GITHUB_TOKEN'):
            print("⚠️  Warning: GITHUB_TOKEN not configured")
            return False
        
        # Validate token format
        if not config.validate_github_token():
            print("⚠️  Warning: GitHub token format may be invalid")
        
        print("✅ Basic configuration test passed")
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def show_next_steps():
    """Show next steps to the user"""
    print("\n" + "="*60)
    print("🎉 GitHub Monitor Setup Complete!")
    print("="*60)
    print()
    print("Next steps:")
    print("1. Edit .env file with your GitHub token and email credentials")
    print("2. Create GitHub Personal Access Token at:")
    print("   https://github.com/settings/tokens")
    print("3. For Gmail, create App Password at:")
    print("   https://myaccount.google.com/apppasswords")
    print("4. Run the monitor: python github_monitor.py")
    print()
    print("For help and documentation, see README.md")
    print()

def main():
    """Main setup function"""
    print("🚀 GitHub Monitor Tool Setup")
    print("="*40)
    print()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        print("\n❌ Setup failed during package installation")
        sys.exit(1)
    
    # Create .env file
    if not create_env_file():
        print("\n❌ Setup failed during .env creation")
        sys.exit(1)
    
    # Test configuration
    test_configuration()  # Don't fail on config test, just warn
    
    # Show next steps
    show_next_steps()

if __name__ == "__main__":
    main()