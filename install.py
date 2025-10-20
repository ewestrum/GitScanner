"""
Installation script for Enhanced GitHub Monitor dependencies
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"\\n{description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✓ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {description} failed:")
        print(f"  Command: {command}")
        print(f"  Error: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"✗ Python 3.8+ required. Current version: {version.major}.{version.minor}")
        return False
    print(f"✓ Python version {version.major}.{version.minor}.{version.micro} is compatible")
    return True

def install_requirements():
    """Install required Python packages"""
    requirements = [
        "requests>=2.28.0",
        "python-dotenv>=0.19.0", 
        "chardet>=5.0.0",
        "python-magic>=0.4.27",
        "PyYAML>=6.0"
    ]
    
    print("\\nInstalling required Python packages...")
    
    for package in requirements:
        success = run_command(f"pip install {package}", f"Installing {package}")
        if not success:
            print(f"Warning: Failed to install {package}")
    
    return True

def install_system_dependencies():
    """Install system dependencies based on platform"""
    system = os.name
    
    if system == 'nt':  # Windows
        print("\\nWindows detected - installing python-magic-bin...")
        run_command("pip install python-magic-bin", "Installing python-magic-bin for Windows")
    
    elif system == 'posix':  # Linux/macOS
        print("\\nLinux/macOS detected")
        
        # Try to detect the package manager
        if os.path.exists('/usr/bin/apt-get'):  # Ubuntu/Debian
            print("Debian/Ubuntu detected - installing libmagic1...")
            run_command("sudo apt-get update && sudo apt-get install -y libmagic1", 
                       "Installing libmagic1")
        
        elif os.path.exists('/usr/bin/yum'):  # RHEL/CentOS
            print("RHEL/CentOS detected - installing file-libs...")
            run_command("sudo yum install -y file-libs", "Installing file-libs")
        
        elif os.path.exists('/opt/homebrew/bin/brew') or os.path.exists('/usr/local/bin/brew'):  # macOS
            print("macOS detected - installing libmagic...")
            run_command("brew install libmagic", "Installing libmagic via Homebrew")
        
        else:
            print("Unknown Linux distribution - you may need to install libmagic manually")
    
    return True

def create_directories():
    """Create necessary directories"""
    directories = [
        "logs",
        "reports", 
        "temp",
        "config"
    ]
    
    print("\\nCreating directories...")
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✓ Created directory: {directory}")
    
    return True

def create_sample_config():
    """Create sample configuration file if it doesn't exist"""
    config_path = Path(".env.example")
    
    if not config_path.exists():
        print("\\nCreating sample configuration file...")
        
        sample_config = '''# GitHub Monitor Enhanced Configuration

# GitHub API Configuration
GITHUB_TOKEN=your_github_token_here
GITHUB_API_URL=https://api.github.com

# Email Configuration (optional)
EMAIL_SMTP_SERVER=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=your_email@gmail.com
EMAIL_PASSWORD=your_app_password
EMAIL_FROM=your_email@gmail.com
EMAIL_TO=admin@company.com

# Advanced Configuration
ADVANCED_CONFIG_PATH=github_monitor_rules.yaml

# Performance Settings
MAX_WORKERS=4
MAX_FILE_SIZE=10485760  # 10MB
MAX_TEXT_FILE_SIZE=2097152  # 2MB

# Risk Scoring Thresholds
RISK_THRESHOLD_CRITICAL=100
RISK_THRESHOLD_HIGH=50
RISK_THRESHOLD_MEDIUM=20
RISK_THRESHOLD_LOW=5

# Output Settings
REDACT_SECRETS=true
OUTPUT_FORMAT=json
ENABLE_SARIF_OUTPUT=true

# Git History Analysis
ANALYZE_GIT_HISTORY=true
MAX_COMMITS_TO_ANALYZE=500
GIT_HISTORY_DAYS=30

# Logging
LOG_LEVEL=INFO
LOG_FILE=github_monitor_enhanced.log
'''
        
        with open(config_path, 'w') as f:
            f.write(sample_config)
        
        print(f"✓ Created sample configuration: {config_path}")
        print("  Please copy this to .env and update with your settings")
    
    return True

def verify_installation():
    """Verify that all components are working"""
    print("\\nVerifying installation...")
    
    # Test imports
    try:
        import requests
        print("✓ requests module working")
    except ImportError:
        print("✗ requests module not working")
        return False
    
    try:
        import dotenv
        print("✓ python-dotenv module working")
    except ImportError:
        print("✗ python-dotenv module not working")
        return False
    
    try:
        import chardet
        print("✓ chardet module working")
    except ImportError:
        print("✗ chardet module not working")
        return False
    
    try:
        import magic
        print("✓ python-magic module working")
    except ImportError:
        print("✗ python-magic module not working")
        return False
    
    try:
        import yaml
        print("✓ PyYAML module working")
    except ImportError:
        print("✗ PyYAML module not working")
        return False
    
    # Test enhanced components
    try:
        sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
        from src.enhanced_file_scanner import EnhancedFileScanner
        from src.enhanced_content_analyzer import EnhancedContentAnalyzer
        from src.risk_scoring_engine import RiskScoringEngine
        print("✓ Enhanced GitHub Monitor components working")
    except ImportError as e:
        print(f"✗ Enhanced GitHub Monitor components not working: {e}")
        return False
    
    print("\\n✓ All components verified successfully!")
    return True

def main():
    """Main installation function"""
    print("Enhanced GitHub Monitor - Installation Script")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install Python packages
    install_requirements()
    
    # Install system dependencies
    install_system_dependencies()
    
    # Create directories
    create_directories()
    
    # Create sample config
    create_sample_config()
    
    # Verify installation
    if verify_installation():
        print("\\n" + "=" * 50)
        print("✓ Installation completed successfully!")
        print("\\nNext steps:")
        print("1. Copy .env.example to .env")
        print("2. Update .env with your GitHub token and email settings")
        print("3. Run: python enhanced_github_monitor.py")
        print("\\nFor more information, see the documentation.")
    else:
        print("\\n" + "=" * 50)
        print("✗ Installation completed with errors!")
        print("Please check the error messages above and resolve any issues.")
        sys.exit(1)

if __name__ == "__main__":
    main()