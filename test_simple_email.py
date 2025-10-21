#!/usr/bin/env python3
"""
Test simple monitor email functionaliteit
"""
import os
import sys
import time

# Add src to path for local imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from config_manager import ConfigManager
from email_notifier import EmailNotifier

def test_simple_monitor_email():
    """Test email zoals simple monitor het doet"""
    
    # Initialize configuration
    config_manager = ConfigManager('.env')
    config = config_manager.config_data
    
    # Email notifier
    email_enabled = config.get('EMAIL_ENABLED', False)
    if email_enabled:
        email_config = {
            'smtp_server': config.get('SMTP_SERVER', 'smtp.gmail.com'),
            'smtp_port': config.get('SMTP_PORT', 587),
            'sender_email': config.get('SENDER_EMAIL', ''),
            'sender_password': config.get('SENDER_PASSWORD', ''),
            'recipient_emails': config.get('RECIPIENT_EMAILS', []),
            'enable_html': True
        }
        email_notifier = EmailNotifier(email_config)
    else:
        print("Email not enabled")
        return
    
    # Create test alert data like simple monitor does
    alert_data = {
        'repository': {
            'name': 'GitScanner',
            'full_name': 'ewestrum/GitScanner',
            'private': False,
            'description': 'Test repository'
        },
        'suspicious_files': [{
            'path': '.env.example',
            'name': '.env.example',
            'size': 1234,
            'reason': 'Environment file potentially containing secrets'
        }],
        'issues': [{
            'type': 'suspicious_file',
            'severity': 'MEDIUM',
            'file_path': '.env.example',
            'description': 'Suspicious file detected: .env.example',
            'risk_score': 50
        }],
        'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'scan_summary': {
            'files_scanned': 25,
            'issues_found': 1,
            'high_risk_issues': 0
        }
    }
    
    print("Sending test email...")
    success = email_notifier.send_security_alert(alert_data)
    
    if success:
        print("✅ Email sent successfully!")
    else:
        print("❌ Email sending failed!")

if __name__ == "__main__":
    test_simple_monitor_email()