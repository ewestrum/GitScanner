#!/usr/bin/env python3
"""
Email Template Preview - Generate HTML previews of email templates for testing
"""

import os
import sys
from pathlib import Path
from datetime import datetime

# Add src directory to path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

from email_notifier import EmailNotifier
from config_manager import ConfigManager

def create_sample_data():
    """Create sample scan results for testing email templates"""
    
    sample_results = [
        {
            'repository': 'my-web-app',
            'full_name': 'ewestrum/my-web-app',
            'scan_time': datetime.now().isoformat(),
            'suspicious_files': [
                {
                    'path': '.env',
                    'type': 'file',
                    'reason': 'Environment file met potentiële credentials'
                },
                {
                    'path': 'config/database.yml', 
                    'type': 'file',
                    'reason': 'Database configuratie bestand'
                }
            ],
            'sensitive_content': [
                {
                    'type': 'api_key',
                    'pattern': 'API Key',
                    'match': 'sk-1234****abcd',
                    'file_path': '.env',
                    'line_number': 5,
                    'severity': 'CRITICAL'
                },
                {
                    'type': 'password',
                    'pattern': 'Password Assignment',
                    'match': 'password="****"',
                    'file_path': 'config/database.yml',
                    'line_number': 12,
                    'severity': 'HIGH'
                },
                {
                    'type': 'email',
                    'pattern': 'Email Address',
                    'match': 'admin@mycompany.com',
                    'file_path': 'README.md',
                    'line_number': 45,
                    'severity': 'MEDIUM'
                }
            ],
            'risk_level': 'CRITICAL',
            'recommendations': [
                'Verwijder .env bestand uit git repository',
                'Gebruik environment variabelen voor gevoelige configuratie',
                'Roteer alle geëxposeerde API keys onmiddellijk',
                'Implementeer secrets management systeem'
            ]
        },
        {
            'repository': 'mobile-app',
            'full_name': 'ewestrum/mobile-app',
            'scan_time': datetime.now().isoformat(),
            'suspicious_files': [
                {
                    'path': 'src/config/secrets.json',
                    'type': 'file', 
                    'reason': 'JSON bestand met "secrets" in naam'
                }
            ],
            'sensitive_content': [
                {
                    'type': 'phone',
                    'pattern': 'Phone Number',
                    'match': '+31612345678',
                    'file_path': 'README.md',
                    'line_number': 23,
                    'severity': 'MEDIUM'
                }
            ],
            'risk_level': 'HIGH',
            'recommendations': [
                'Verwijder telefoonnummers uit documentatie',
                'Gebruik placeholder data in voorbeelden'
            ]
        },
        {
            'repository': 'documentation',
            'full_name': 'ewestrum/documentation',
            'scan_time': datetime.now().isoformat(),
            'suspicious_files': [],
            'sensitive_content': [],
            'risk_level': 'LOW',
            'recommendations': []
        },
        {
            'repository': 'test-project',
            'full_name': 'ewestrum/test-project',
            'scan_time': datetime.now().isoformat(),
            'suspicious_files': [
                {
                    'path': 'backup.sql',
                    'type': 'file',
                    'reason': 'Database backup bestand'
                }
            ],
            'sensitive_content': [
                {
                    'type': 'bsn',
                    'pattern': 'Dutch BSN Number',
                    'match': '123456***',
                    'file_path': 'test_data.sql',
                    'line_number': 156,
                    'severity': 'HIGH'
                }
            ],
            'risk_level': 'MEDIUM',
            'recommendations': [
                'Gebruik anonieme test data',
                'Verwijder database dumps uit repository'
            ]
        }
    ]
    
    return sample_results

def generate_email_previews():
    """Generate HTML preview files for email templates"""
    
    print("🎨 Generating email template previews...")
    
    # Create config (dummy data for preview)
    config = ConfigManager()
    email_config = {
        'enabled': True,
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'sender_email': 'test@example.com',
        'sender_password': 'dummy',
        'recipient_emails': ['security@example.com'],
    }
    
    notifier = EmailNotifier(email_config)
    sample_data = create_sample_data()
    
    # Create output directory
    output_dir = Path('email_previews')
    output_dir.mkdir(exist_ok=True)
    
    # Generate summary report preview
    print("📊 Generating summary report preview...")
    summary_html = notifier._generate_summary_html(sample_data)
    
    summary_file = output_dir / 'summary_report.html'
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write(summary_html)
    
    print(f"   ✅ Summary report saved: {summary_file}")
    
    # Generate individual alert previews
    for i, result in enumerate(sample_data):
        if result['risk_level'] in ['HIGH', 'CRITICAL']:
            print(f"🚨 Generating alert preview for {result['repository']}...")
            
            alert_html = notifier._generate_alert_html(result)
            
            alert_file = output_dir / f'alert_{result["repository"].replace("-", "_")}.html'
            with open(alert_file, 'w', encoding='utf-8') as f:
                f.write(alert_html)
            
            print(f"   ✅ Alert preview saved: {alert_file}")
    
    print()
    print("🎉 Email previews generated successfully!")
    print()
    print("📁 Preview files:")
    for html_file in output_dir.glob('*.html'):
        print(f"   • {html_file.name}")
    
    print()
    print("🌐 Open these HTML files in your browser to preview the email templates")
    print("💡 These templates show how your security emails will look when sent")

def create_css_file():
    """Create a standalone CSS file for easier customization"""
    
    css_content = """
    /* GitHub Monitor Email Templates - CSS Styles */
    
    /* You can customize these styles to match your company branding */
    
    :root {
        --primary-color: #667eea;
        --secondary-color: #764ba2;
        --success-color: #28a745;
        --warning-color: #ffc107;
        --danger-color: #dc3545;
        --info-color: #17a2b8;
        --light-color: #f8f9fa;
        --dark-color: #343a40;
        
        --border-radius: 12px;
        --box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        --transition: all 0.3s ease;
    }
    
    /* Add your company logo */
    .header::before {
        content: "";
        /* background-image: url('your-logo-url-here'); */
        background-size: contain;
        background-repeat: no-repeat;
        height: 50px;
        width: 200px;
        margin: 0 auto 20px;
        display: block;
    }
    
    /* Customize colors for different risk levels */
    .risk-critical {
        --risk-color: var(--danger-color);
    }
    
    .risk-high {
        --risk-color: #fd7e14;
    }
    
    .risk-medium {
        --risk-color: var(--warning-color);
    }
    
    .risk-low {
        --risk-color: var(--success-color);
    }
    
    /* Company branding customization */
    .footer {
        /* Add your company colors/branding here */
    }
    """
    
    css_file = Path('email_previews') / 'email_styles.css'
    with open(css_file, 'w', encoding='utf-8') as f:
        f.write(css_content)
    
    print(f"🎨 CSS customization file created: {css_file}")

if __name__ == "__main__":
    try:
        generate_email_previews()
        create_css_file()
        
        print()
        print("📧 Next steps:")
        print("1. Open the HTML files in your browser to see the email templates")
        print("2. Run a real scan to test the actual email sending")
        print("3. Customize the CSS file to match your company branding")
        
    except Exception as e:
        print(f"❌ Error generating previews: {e}")
        sys.exit(1)