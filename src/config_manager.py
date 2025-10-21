"""
Configuration Manager - Handle application configuration and environment variables
"""

import os
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

logger = logging.getLogger(__name__)


class ConfigManager:
    """Configuration manager for GitHub Monitor"""
    
    def __init__(self, config_path: str = '.env'):
        """Initialize configuration manager
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config_data = {}
        
        # Load configuration
        self._load_config()
        
        logger.info("Configuration manager initialized")
    
    def _load_config(self):
        """Load configuration from environment file and variables"""
        
        # Load from .env file if available
        if DOTENV_AVAILABLE and Path(self.config_path).exists():
            load_dotenv(self.config_path)
            logger.info(f"Loaded configuration from {self.config_path}")
        elif Path(self.config_path).exists():
            logger.warning("python-dotenv not available, loading .env manually")
            self._load_env_manual()
        else:
            logger.info("No .env file found, using environment variables only")
        
        # Load from environment variables
        self.config_data = {
            # GitHub Configuration
            'GITHUB_TOKEN': os.getenv('GITHUB_TOKEN'),
            'GITHUB_USERNAME': os.getenv('GITHUB_USERNAME'),
            
            # Email Configuration
            'EMAIL_ENABLED': os.getenv('EMAIL_ENABLED', 'true').lower() == 'true',
            'SMTP_SERVER': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
            'SMTP_PORT': int(os.getenv('SMTP_PORT', '587')),
            'SENDER_EMAIL': os.getenv('SENDER_EMAIL'),
            'SENDER_PASSWORD': os.getenv('SENDER_PASSWORD'),
            'RECIPIENT_EMAILS': self._parse_email_list(os.getenv('RECIPIENT_EMAILS', '')),
            
            # Scanning Configuration
            'SCAN_PRIVATE_REPOS': os.getenv('SCAN_PRIVATE_REPOS', 'true').lower() == 'true',
            'SCAN_DEPTH': int(os.getenv('SCAN_DEPTH', '2')),
                    'MAX_FILE_SIZE': 100 * 1024 * 1024,  # 100MB - increased for security scanning
            'RATE_LIMIT_DELAY': float(os.getenv('RATE_LIMIT_DELAY', '1.0')),
            
            # Alert Configuration
            'ALERT_CRITICAL': os.getenv('ALERT_CRITICAL', 'true').lower() == 'true',
            'ALERT_HIGH': os.getenv('ALERT_HIGH', 'true').lower() == 'true',
            'ALERT_MEDIUM': os.getenv('ALERT_MEDIUM', 'false').lower() == 'true',
            
            # Logging Configuration
            'LOG_LEVEL': os.getenv('LOG_LEVEL', 'INFO'),
            'LOG_FILE': os.getenv('LOG_FILE', 'github_monitor.log'),
        }
        
        # Validate required configuration
        self._validate_config()
    
    def _load_env_manual(self):
        """Manually load .env file without python-dotenv"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip().strip('\'"')
        except Exception as e:
            logger.error(f"Error loading .env file manually: {e}")
    
    def _parse_email_list(self, email_string: str) -> List[str]:
        """Parse comma-separated email list"""
        if not email_string:
            return []
        
        emails = [email.strip() for email in email_string.split(',')]
        return [email for email in emails if email and '@' in email]
    
    def _validate_config(self):
        """Validate required configuration parameters"""
        errors = []
        
        # Check GitHub token
        if not self.config_data['GITHUB_TOKEN']:
            errors.append("GITHUB_TOKEN is required")
        
        # Check email configuration if email is enabled
        if self.config_data['EMAIL_ENABLED']:
            if not self.config_data['SENDER_EMAIL']:
                errors.append("SENDER_EMAIL is required when email is enabled")
            if not self.config_data['SENDER_PASSWORD']:
                errors.append("SENDER_PASSWORD is required when email is enabled")
            if not self.config_data['RECIPIENT_EMAILS']:
                errors.append("RECIPIENT_EMAILS is required when email is enabled")
        
        if errors:
            error_msg = "Configuration validation failed:\\n" + "\\n".join(f"- {error}" for error in errors)
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        logger.info("Configuration validation passed")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        return self.config_data.get(key, default)
    
    def get_scan_rules(self) -> Dict[str, Any]:
        """Get scanning rules configuration
        
        Returns:
            Dictionary containing scanning rules
        """
        return {
            'suspicious_patterns': [
                # Custom suspicious file patterns
                r'.*\\.key$',
                r'.*\\.pem$',
                r'.*\\.p12$',
                r'.*\\.pfx$',
                r'.*\\.jks$',
                r'.*\\.keystore$',
                r'.*password.*',
                r'.*secret.*',
                r'.*credential.*',
                r'.*\\.env$',
                r'.*\\.env\\..*',
                r'.*config\\.json$',
                r'.*settings\\.json$',
                r'.*\\.sqlite$',
                r'.*\\.db$',
                r'.*\\.sql$',
                r'.*\\.dump$',
                r'.*\\.backup$',
                r'.*\\.bak$',
            ],
            'allowed_directories': [
                # Directories that are generally safe
                'docs/',
                'documentation/',
                'examples/',
                'samples/',
                'tests/',
                'test/',
                '__tests__/',
                'spec/',
                'specs/',
                '.github/',
                'node_modules/',
                'vendor/',
                'public/',
                'assets/',
                'static/',
            ],
            'max_file_size': self.get('MAX_FILE_SIZE', 1048576),
            'scan_depth': self.get('SCAN_DEPTH', 2),
            'scan_private_repos': self.get('SCAN_PRIVATE_REPOS', True),
        }
    
    def get_content_rules(self) -> Dict[str, Any]:
        """Get content analysis rules configuration
        
        Returns:
            Dictionary containing content analysis rules
        """
        return {
            'custom_patterns': [
                {
                    'pattern': r'(?i)password\s*[=:]\s*["\']([^"\'\\s]{6,})["\']',
                    'description': 'Password Assignment',
                    'severity': 'HIGH'
                },
                {
                    'pattern': r'(?i)api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
                    'description': 'API Key Assignment',
                    'severity': 'CRITICAL'
                },
                {
                    'pattern': r'(?i)secret\s*[=:]\s*["\']([^"\'\\s]{10,})["\']',
                    'description': 'Secret Assignment',
                    'severity': 'HIGH'
                },
                {
                    'pattern': r'(?i)token\s*[=:]\s*["\']([a-zA-Z0-9_.-]{20,})["\']',
                    'description': 'Token Assignment',
                    'severity': 'HIGH'
                },
                {
                    'pattern': r'(?i)private[_-]?key\s*[=:]\s*["\']([^"\'\\s]{20,})["\']',
                    'description': 'Private Key Assignment',
                    'severity': 'CRITICAL'
                },
                # Dutch specific patterns
                {
                    'pattern': r'\\b[1-9][0-9]{8}\\b',
                    'description': 'Possible Dutch BSN',
                    'severity': 'HIGH'
                },
                {
                    'pattern': r'\\b(?:\\+31|0031|0)[1-9][0-9]{8}\\b',
                    'description': 'Dutch Phone Number',
                    'severity': 'MEDIUM'
                },
            ],
            'exclude_patterns': [
                # Patterns to exclude from analysis
                r'.*test.*',
                r'.*example.*',
                r'.*sample.*',
                r'.*demo.*',
                r'.*mock.*',
                r'.*placeholder.*',
            ],
            'file_size_limit': self.get('MAX_FILE_SIZE', 1048576),
        }
    
    def get_email_config(self) -> Dict[str, Any]:
        """Get email configuration
        
        Returns:
            Dictionary containing email configuration
        """
        return {
            'enabled': self.get('EMAIL_ENABLED', True),
            'smtp_server': self.get('SMTP_SERVER', 'smtp.gmail.com'),
            'smtp_port': self.get('SMTP_PORT', 587),
            'sender_email': self.get('SENDER_EMAIL'),
            'sender_password': self.get('SENDER_PASSWORD'),
            'recipient_emails': self.get('RECIPIENT_EMAILS', []),
            'alert_critical': self.get('ALERT_CRITICAL', True),
            'alert_high': self.get('ALERT_HIGH', True),
            'alert_medium': self.get('ALERT_MEDIUM', False),
        }
    
    def get_github_config(self) -> Dict[str, Any]:
        """Get GitHub configuration
        
        Returns:
            Dictionary containing GitHub configuration
        """
        return {
            'token': self.get('GITHUB_TOKEN'),
            'username': self.get('GITHUB_USERNAME'),
            'scan_private_repos': self.get('SCAN_PRIVATE_REPOS', True),
            'rate_limit_delay': self.get('RATE_LIMIT_DELAY', 1.0),
        }
    
    def create_sample_config(self, output_path: str = '.env.example') -> None:
        """Create a sample configuration file
        
        Args:
            output_path: Path for the sample configuration file
        """
        sample_config = '''# GitHub Monitor Configuration

# GitHub Settings
GITHUB_TOKEN=your_github_personal_access_token_here
GITHUB_USERNAME=your_github_username

# Email Notification Settings
EMAIL_ENABLED=true
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your-email@gmail.com
SENDER_PASSWORD=your_email_password_or_app_password
RECIPIENT_EMAILS=security@yourcompany.com,admin@yourcompany.com

# Scanning Configuration
SCAN_PRIVATE_REPOS=true
SCAN_DEPTH=2
MAX_FILE_SIZE=1048576
RATE_LIMIT_DELAY=1.0

# Alert Configuration
ALERT_CRITICAL=true
ALERT_HIGH=true
ALERT_MEDIUM=false

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=github_monitor.log

# Security Notes:
# - Never commit your actual .env file to version control
# - Use GitHub Personal Access Token with minimal required permissions
# - For Gmail, use App Passwords instead of your regular password
# - Consider using environment variables in production instead of .env files
'''
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(sample_config)
            
            logger.info(f"Sample configuration created at: {output_path}")
            print(f"Sample configuration file created: {output_path}")
            print("Please copy this to .env and update with your actual values.")
            
        except Exception as e:
            logger.error(f"Failed to create sample configuration: {e}")
            raise
    
    def validate_github_token(self) -> bool:
        """Validate GitHub token format
        
        Returns:
            True if token format is valid
        """
        token = self.get('GITHUB_TOKEN')
        if not token:
            return False
        
        # GitHub token patterns
        valid_patterns = [
            r'^ghp_[a-zA-Z0-9]{36}$',    # Personal access token
            r'^ghs_[a-zA-Z0-9]{36}$',    # GitHub App token
            r'^github_pat_[a-zA-Z0-9_]{82}$',  # Fine-grained PAT
        ]
        
        import re
        for pattern in valid_patterns:
            if re.match(pattern, token):
                return True
        
        # Also allow classic tokens (40 hex characters)
        if re.match(r'^[a-f0-9]{40}$', token):
            return True
        
        logger.warning("GitHub token format may be invalid")
        return False