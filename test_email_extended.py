#!/usr/bin/env python3
"""
Test script voor uitgebreide email functionaliteit
"""

import sys
import os
from datetime import datetime

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def create_test_email_with_logs():
    """Create test email with extended test logs"""
    
    # Mock scan result with test log information
    scan_result = {
        'repository': {
            'full_name': 'ewestrum/TestRepo',
            'name': 'TestRepo',
            'html_url': 'https://github.com/ewestrum/TestRepo'
        },
        'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'risk_level': 'HIGH',
        'files_scanned': 156,
        'suspicious_files': [
            {
                'path': '.env',
                'reason': 'Configuration file met mogelijke secrets'
            },
            {
                'path': 'private.key',
                'reason': 'Private key bestand'
            }
        ],
        'sensitive_content': [
            {
                'pattern': 'API Key Pattern',
                'file_path': 'config.py',
                'line_number': 23,
                'severity': 'HIGH',
                'match': '[REDACTED]'
            },
            {
                'pattern': 'IBAN Pattern',
                'file_path': 'test_data.txt',
                'line_number': 45,
                'severity': 'CRITICAL', 
                'match': '[REDACTED]'
            }
        ],
        'recommendations': [
            'Verwijder .env bestand uit git repository',
            'Gebruik environment variabelen voor API keys',
            'Implementeer .gitignore voor gevoelige bestanden'
        ]
    }
    
    # Generate extended HTML email content
    html_content = generate_extended_alert_html(scan_result)
    
    # Write to file for inspection
    with open('extended_email_test.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print("✅ Uitgebreide email HTML gegenereerd: extended_email_test.html")
    print(f"📊 Test data bevat {len(scan_result['suspicious_files'])} verdachte bestanden")
    print(f"⚠️  Test data bevat {len(scan_result['sensitive_content'])} gevoelige content items")


def generate_extended_alert_html(scan_result):
    """Generate extended HTML email with detailed test logs"""
    
    repo_name = scan_result['repository']['full_name']
    risk_level = scan_result.get('risk_level', 'UNKNOWN')
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>GitHub Security Alert - {repo_name}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 800px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #dc3545 0%, #fd7e14 100%); color: white; padding: 30px; border-radius: 8px; text-align: center; margin-bottom: 20px; }}
            .section {{ background: white; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .section-header {{ background: #f8f9fa; padding: 15px; border-bottom: 1px solid #dee2e6; border-radius: 8px 8px 0 0; }}
            .section-content {{ padding: 20px; }}
            .test-category {{ margin-bottom: 20px; background: #f8f9fa; padding: 15px; border-radius: 6px; }}
            .test-item {{ display: flex; align-items: center; padding: 8px; margin: 5px 0; border-radius: 4px; }}
            .test-passed {{ background: #d4edda; border-left: 4px solid #28a745; }}
            .test-failed {{ background: #f8d7da; border-left: 4px solid #dc3545; }}
            .test-warning {{ background: #fff3cd; border-left: 4px solid #ffc107; }}
            .scan-summary {{ background: #e9ecef; padding: 15px; border-radius: 6px; margin-top: 20px; }}
            .stat-item {{ display: flex; justify-content: space-between; padding: 5px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🚨 GitHub Security Alert</h1>
                <h2>📁 {repo_name}</h2>
                <p>Risk Level: <strong>{risk_level}</strong></p>
            </div>
    """
    
    # Add findings section
    suspicious_files = scan_result.get('suspicious_files', [])
    if suspicious_files:
        html += """
            <div class="section">
                <div class="section-header">
                    <h3>📁 Verdachte Bestanden</h3>
                </div>
                <div class="section-content">
                    <ul>
        """
        for file_info in suspicious_files:
            html += f'<li><strong>{file_info["path"]}</strong>: {file_info["reason"]}</li>'
        html += """
                    </ul>
                </div>
            </div>
        """
    
    sensitive_content = scan_result.get('sensitive_content', [])
    if sensitive_content:
        html += """
            <div class="section">
                <div class="section-header">
                    <h3>⚠️ Gevoelige Content</h3>
                </div>
                <div class="section-content">
                    <ul>
        """
        for content_info in sensitive_content:
            html += f"""
                <li><strong>{content_info["pattern"]}</strong> in {content_info["file_path"]}:{content_info["line_number"]} (Severity: {content_info["severity"]})</li>
            """
        html += """
                    </ul>
                </div>
            </div>
        """
    
    # Add detailed test logs section  
    html += f"""
            <div class="section">
                <div class="section-header">
                    <h3>📋 Uitgevoerde Tests voor {repo_name}</h3>
                </div>
                <div class="section-content">
    """
    
    # Test categories with results
    test_categories = [
        {
            'name': '🔍 Bestandsnaam Analyse',
            'description': 'Scanning van verdachte bestandsnamen en extensies', 
            'tests': [
                ('Configuratie bestanden (.env, .config)', 'FAILED' if any('.env' in f['path'] for f in suspicious_files) else 'PASSED'),
                ('Sleutel bestanden (private keys, certificates)', 'FAILED' if any('key' in f['path'].lower() for f in suspicious_files) else 'PASSED'),
                ('Backup en database bestanden', 'PASSED'),
                ('Log bestanden met gevoelige data', 'PASSED')
            ]
        },
        {
            'name': '🔐 Content Security Analyse',
            'description': 'Diepgaande analyse van bestandsinhoud',
            'tests': [
                ('API Keys en Tokens', 'FAILED' if any('API' in c['pattern'] for c in sensitive_content) else 'PASSED'),
                ('Wachtwoorden en Credentials', 'PASSED'),
                ('Database Connection Strings', 'PASSED'),
                ('Private SSH Keys', 'PASSED')
            ]
        },
        {
            'name': '👤 Persoonlijke Data Detectie',
            'description': 'Scanning naar persoonlijke en gevoelige klantgegevens',
            'tests': [
                ('IBAN en Bankrekeningnummers', 'FAILED' if any('IBAN' in c['pattern'] for c in sensitive_content) else 'PASSED'),
                ('BSN (Burgerservicenummers)', 'PASSED'),
                ('Nederlandse Postcodes', 'PASSED'),
                ('Persoonsnamen en Adressen', 'PASSED'),
                ('Telefoonnummers', 'PASSED'),
                ('Email Adressen', 'PASSED')
            ]
        },
        {
            'name': '🏥 Medische en Financiële Data',
            'description': 'Specifieke controles voor gevoelige sectoren',
            'tests': [
                ('Medische Terminologie', 'PASSED'),
                ('Financiële Termen', 'PASSED'),
                ('Kentekens en Rijbewijzen', 'PASSED')
            ]
        },
        {
            'name': '⚡ Code Kwaliteit Checks',
            'description': 'Algemene code veiligheid en best practices',
            'tests': [
                ('Hardcoded Secrets', 'WARNING' if sensitive_content else 'PASSED'),
                ('Debug Code in Productie', 'PASSED'),
                ('Test Files met Echte Data', 'INFO')
            ]
        }
    ]
    
    for category in test_categories:
        html += f"""
                    <div class="test-category">
                        <h4>{category['name']}</h4>
                        <p style="color: #6c757d; font-size: 0.9em;">{category['description']}</p>
        """
        
        for test_name, status in category['tests']:
            status_icon = {'PASSED': '✅', 'FAILED': '❌', 'WARNING': '⚠️', 'INFO': 'ℹ️'}[status]
            css_class = {'PASSED': 'test-passed', 'FAILED': 'test-failed', 'WARNING': 'test-warning', 'INFO': 'test-warning'}[status]
            
            html += f"""
                        <div class="test-item {css_class}">
                            <span style="margin-right: 10px;">{status_icon}</span>
                            <span style="flex-grow: 1;">{test_name}</span>
                            <span style="font-weight: 600; font-size: 0.85em;">{status}</span>
                        </div>
            """
        
        html += "</div>"
    
    # Add scan summary
    html += f"""
                    <div class="scan-summary">
                        <h4>📊 Scan Samenvatting</h4>
                        <div class="stat-item">
                            <span>Totaal bestanden gescand:</span>
                            <span><strong>{scan_result.get('files_scanned', 0)}</strong></span>
                        </div>
                        <div class="stat-item">
                            <span>Scan uitgevoerd op:</span>
                            <span><strong>{scan_result.get('scan_time')}</strong></span>
                        </div>
                        <div class="stat-item">
                            <span>Verdachte bestanden gevonden:</span>
                            <span><strong>{len(suspicious_files)}</strong></span>
                        </div>
                        <div class="stat-item">
                            <span>Gevoelige content gedetecteerd:</span>
                            <span><strong>{len(sensitive_content)}</strong></span>
                        </div>
                    </div>
                </div>
            </div>
    """
    
    # Add recommendations
    recommendations = scan_result.get('recommendations', [])
    if recommendations:
        html += """
            <div class="section">
                <div class="section-header">
                    <h3>💡 Aanbevelingen</h3>
                </div>
                <div class="section-content">
                    <ul>
        """
        for rec in recommendations:
            html += f'<li>{rec}</li>'
        html += """
                    </ul>
                </div>
            </div>
        """
    
    # Footer
    html += """
            <div style="text-align: center; padding: 20px; color: #666; font-size: 0.9em;">
                <p><strong>GitHub Monitor Tool</strong> • Automatische security scanning</p>
                <p>Voor vragen of ondersteuning, neem contact op met je security team</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return html


if __name__ == "__main__":
    create_test_email_with_logs()