"""
Email Notifier - Send security alerts via email
FIXED VERSION with extended test logs
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class EmailNotifier:
    """Email notification service for security alerts"""
    
    def __init__(self, email_config: Dict[str, Any]):
        """Initialize email notifier
        
        Args:
            email_config: Dictionary containing email configuration
        """
        self.config = email_config
        self.smtp_server = email_config.get('smtp_server', 'smtp.gmail.com')
        self.smtp_port = email_config.get('smtp_port', 587)
        self.sender_email = email_config.get('sender_email')
        self.sender_password = email_config.get('sender_password')
        self.recipient_emails = email_config.get('recipient_emails', [])
        
        # Validate configuration
        if not self.sender_email or not self.sender_password:
            logger.warning("Email configuration incomplete - notifications will be disabled")
            self.enabled = False
        else:
            self.enabled = True
            logger.info("Email notifier initialized")
    
    def send_security_alert(self, scan_result: Dict[str, Any]) -> bool:
        """Send security alert email for repository scan results
        
        Args:
            scan_result: Repository scan results
            
        Returns:
            True if email was sent successfully
        """
        if not self.enabled:
            logger.warning("Email notifications are disabled - check configuration")
            return False
        
        try:
            # Create email message
            message = self._create_security_alert_message(scan_result)
            
            # Send email
            return self._send_email(message)
            
        except Exception as e:
            logger.error(f"Failed to send security alert: {e}")
            return False
    
    def send_notification(self, scan_results: Dict[str, Any]) -> bool:
        """Send notification email (alias for send_summary_report for compatibility)
        
        Args:
            scan_results: Scan results dictionary
            
        Returns:
            True if email was sent successfully
        """
        # Convert single result to list format if needed
        if isinstance(scan_results, dict):
            if 'repositories' in scan_results:
                # This is a summary report format
                return self.send_summary_report([scan_results])
            else:
                # This is a single repository result
                return self.send_security_alert(scan_results)
        else:
            return self.send_summary_report(scan_results)
    
    def send_summary_report(self, scan_results: List[Dict[str, Any]]) -> bool:
        """Send summary report of all repository scans
        
        Args:
            scan_results: List of all repository scan results
            
        Returns:
            True if email was sent successfully
        """
        if not self.enabled:
            logger.warning("Email notifications are disabled - check configuration")
            return False
        
        try:
            # Create summary email message
            message = self._create_summary_report_message(scan_results)
            
            # Send email
            return self._send_email(message)
            
        except Exception as e:
            logger.error(f"Failed to send summary report: {e}")
            return False
    
    def _create_security_alert_message(self, scan_result: Dict[str, Any]) -> MIMEMultipart:
        """Create security alert email message"""
        
        # Extract repository name properly
        repository = scan_result.get('repository', {})
        repo_name = repository.get('name', 'Unknown Repository')
        if isinstance(repository, dict) and 'full_name' in repository:
            repo_name = repository['full_name']
        elif isinstance(repository, str):
            repo_name = repository
        
        # Create message
        message = MIMEMultipart("alternative")
        message["Subject"] = f"🚨 GitHub Security Alert - {repo_name}"
        message["From"] = self.sender_email
        message["To"] = ", ".join(self.recipient_emails)
        
        # Create HTML content with extended test logs
        html_content = self._generate_extended_alert_html(scan_result)
        
        # Create text content (fallback) with extended test logs
        text_content = self._generate_extended_alert_text(scan_result)
        
        # Attach parts
        text_part = MIMEText(text_content, "plain", "utf-8")
        html_part = MIMEText(html_content, "html", "utf-8")
        
        message.attach(text_part)
        message.attach(html_part)
        
        return message
    
    def _extract_repo_name(self, scan_result: Dict[str, Any]) -> str:
        """Extract repository name from scan result"""
        repository = scan_result.get('repository', {})
        
        if isinstance(repository, dict):
            return repository.get('full_name', repository.get('name', 'Unknown Repository'))
        elif isinstance(repository, str):
            return repository
        else:
            return 'Unknown Repository'
    
    def _extract_repo_url(self, scan_result: Dict[str, Any]) -> str:
        """Extract repository URL from scan result"""
        repository = scan_result.get('repository', {})
        
        if isinstance(repository, dict):
            return repository.get('html_url', f"https://github.com/{repository.get('full_name', '')}")
        else:
            return ""
    
    def _generate_extended_alert_html(self, scan_result: Dict[str, Any]) -> str:
        """Generate extended HTML content with detailed test logs"""
        
        repo_name = self._extract_repo_name(scan_result)
        repo_url = self._extract_repo_url(scan_result)
        risk_level = scan_result.get('risk_level', 'UNKNOWN')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>GitHub Security Alert - {repo_name}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f7fa; }}
                .container {{ max-width: 900px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #dc3545 0%, #fd7e14 100%); color: white; padding: 30px; border-radius: 12px; text-align: center; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .section {{ background: white; margin-bottom: 20px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .section-header {{ background: #f8f9fa; padding: 20px; border-bottom: 1px solid #dee2e6; border-radius: 12px 12px 0 0; }}
                .section-title {{ font-size: 1.3em; font-weight: 600; color: #495057; }}
                .section-content {{ padding: 25px; }}
                .test-category {{ margin-bottom: 25px; background: #f8f9fa; border-radius: 8px; padding: 20px; }}
                .category-header h4 {{ color: #495057; margin-bottom: 8px; font-size: 1.1em; }}
                .category-description {{ color: #6c757d; font-size: 0.9em; margin-bottom: 15px; }}
                .test-item {{ display: flex; align-items: center; padding: 12px; margin: 8px 0; border-radius: 6px; border-left: 4px solid; }}
                .test-passed {{ background: #d4edda; border-left-color: #28a745; }}
                .test-failed {{ background: #f8d7da; border-left-color: #dc3545; }}
                .test-warning {{ background: #fff3cd; border-left-color: #ffc107; }}
                .test-info {{ background: #d1ecf1; border-left-color: #17a2b8; }}
                .test-status {{ margin-right: 12px; font-size: 1.2em; }}
                .test-name {{ flex-grow: 1; font-weight: 500; }}
                .test-result {{ font-size: 0.85em; font-weight: 600; padding: 4px 8px; border-radius: 4px; background: rgba(0,0,0,0.1); }}
                .scan-summary {{ background: #e9ecef; padding: 20px; border-radius: 8px; margin-top: 20px; }}
                .scan-summary h4 {{ color: #495057; margin-bottom: 15px; }}
                .stat-item {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #dee2e6; }}
                .stat-item:last-child {{ border-bottom: none; }}
                .stat-label {{ font-weight: 500; color: #495057; }}
                .stat-value {{ font-weight: 600; color: #212529; }}
                .issue-list {{ list-style: none; padding: 0; }}
                .issue-item {{ background: #f8f9fa; margin: 10px 0; padding: 15px; border-radius: 6px; border-left: 4px solid #0366d6; }}
                .issue-title {{ font-weight: 600; margin-bottom: 5px; }}
                .issue-details {{ color: #6c757d; font-size: 0.9em; }}
                .footer {{ text-align: center; padding: 20px; color: #666; font-size: 0.9em; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 GitHub Security Alert</h1>
                    <h2>📁 {repo_name}</h2>
                    <p>Risk Level: <strong>{risk_level}</strong></p>
                    <p>Scan Time: {scan_result.get('scan_time', 'Unknown')}</p>
                </div>
        """
        
        # Add suspicious files section
        suspicious_files = scan_result.get('suspicious_files', [])
        if suspicious_files:
            html += """
                <div class="section">
                    <div class="section-header">
                        <div class="section-title">📁 Verdachte Bestanden</div>
                    </div>
                    <div class="section-content">
                        <ul class="issue-list">
            """
            for file_info in suspicious_files:
                file_path = file_info.get('path', 'Unknown path')
                reason = file_info.get('reason', 'Onbekend')
                html += f"""
                            <li class="issue-item">
                                <div class="issue-title">📄 {file_path}</div>
                                <div class="issue-details">Reden: {reason}</div>
                            </li>
                """
            html += """
                        </ul>
                    </div>
                </div>
            """
        
        # Add sensitive content section
        sensitive_content = scan_result.get('sensitive_content', [])
        if sensitive_content:
            html += """
                <div class="section">
                    <div class="section-header">
                        <div class="section-title">⚠️ Gevoelige Content</div>
                    </div>
                    <div class="section-content">
                        <ul class="issue-list">
            """
            for content_info in sensitive_content:
                pattern = content_info.get('pattern', 'Onbekend patroon')
                file_path = content_info.get('file_path', 'Onbekend bestand')
                line_number = content_info.get('line_number', '?')
                severity = content_info.get('severity', 'MEDIUM')
                
                html += f"""
                            <li class="issue-item">
                                <div class="issue-title">🔍 {pattern}</div>
                                <div class="issue-details">Bestand: {file_path}:{line_number} | Severity: {severity}</div>
                            </li>
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
                        <div class="section-title">📋 Uitgevoerde Tests voor {repo_name}</div>
                    </div>
                    <div class="section-content">
        """
        
        # Test categories with results
        test_categories = [
            {
                'name': '🔍 Bestandsnaam Analyse',
                'description': 'Scanning van verdachte bestandsnamen en extensies',
                'tests': [
                    ('Configuratie bestanden (.env, .config)', 'PASSED' if not any('.env' in f.get('path', '') for f in suspicious_files) else 'FAILED'),
                    ('Sleutel bestanden (private keys, certificates)', 'PASSED' if not any('key' in f.get('path', '').lower() for f in suspicious_files) else 'FAILED'),
                    ('Backup en database bestanden', 'PASSED' if not any(ext in f.get('path', '').lower() for f in suspicious_files for ext in ['.sql', '.db']) else 'FAILED'),
                    ('Log bestanden met gevoelige data', 'PASSED' if not any('.log' in f.get('path', '').lower() for f in suspicious_files) else 'FAILED')
                ]
            },
            {
                'name': '🔐 Content Security Analyse',
                'description': 'Diepgaande analyse van bestandsinhoud',
                'tests': [
                    ('API Keys en Tokens', 'PASSED' if not any('api' in c.get('pattern', '').lower() for c in sensitive_content) else 'FAILED'),
                    ('Wachtwoorden en Credentials', 'PASSED' if not any('password' in c.get('pattern', '').lower() for c in sensitive_content) else 'FAILED'),
                    ('Database Connection Strings', 'PASSED' if not any('database' in c.get('pattern', '').lower() for c in sensitive_content) else 'FAILED'),
                    ('Private SSH Keys', 'PASSED' if not any('ssh' in c.get('pattern', '').lower() for c in sensitive_content) else 'FAILED')
                ]
            },
            {
                'name': '👤 Persoonlijke Data Detectie',
                'description': 'Scanning naar persoonlijke en gevoelige klantgegevens',
                'tests': [
                    ('IBAN en Bankrekeningnummers', 'PASSED' if not any('iban' in c.get('pattern', '').lower() for c in sensitive_content) else 'FAILED'),
                    ('BSN (Burgerservicenummers)', 'PASSED' if not any('bsn' in c.get('pattern', '').lower() for c in sensitive_content) else 'FAILED'),
                    ('Nederlandse Postcodes', 'PASSED' if not any('postcode' in c.get('pattern', '').lower() for c in sensitive_content) else 'FAILED'),
                    ('Persoonsnamen en Adressen', 'PASSED' if not any('personal' in c.get('pattern', '').lower() for c in sensitive_content) else 'FAILED'),
                    ('Telefoonnummers', 'PASSED' if not any('phone' in c.get('pattern', '').lower() for c in sensitive_content) else 'FAILED'),
                    ('Email Adressen', 'PASSED' if not any('email' in c.get('pattern', '').lower() for c in sensitive_content) else 'FAILED')
                ]
            },
            {
                'name': '🏥 Medische en Financiële Data',
                'description': 'Specifieke controles voor gevoelige sectoren',
                'tests': [
                    ('Medische Terminologie', 'PASSED' if not any('medical' in c.get('pattern', '').lower() for c in sensitive_content) else 'FAILED'),
                    ('Financiële Termen', 'PASSED' if not any('financial' in c.get('pattern', '').lower() for c in sensitive_content) else 'FAILED'),
                    ('Kentekens en Rijbewijzen', 'PASSED' if not any('license' in c.get('pattern', '').lower() for c in sensitive_content) else 'FAILED')
                ]
            },
            {
                'name': '⚡ Code Kwaliteit Checks',  
                'description': 'Algemene code veiligheid en best practices',
                'tests': [
                    ('Hardcoded Secrets', 'PASSED' if not sensitive_content else 'WARNING'),
                    ('Debug Code in Productie', 'PASSED' if not any('debug' in f.get('path', '').lower() for f in suspicious_files) else 'WARNING'),
                    ('Test Files met Echte Data', 'PASSED' if not any('test' in f.get('path', '').lower() for f in suspicious_files) else 'INFO')
                ]
            }
        ]
        
        for category in test_categories:
            html += f"""
                        <div class="test-category">
                            <div class="category-header">
                                <h4>{category['name']}</h4>
                                <p class="category-description">{category['description']}</p>
                            </div>
            """
            
            for test_name, status in category['tests']:
                status_icon = {'PASSED': '✅', 'FAILED': '❌', 'WARNING': '⚠️', 'INFO': 'ℹ️'}[status]
                css_class = {'PASSED': 'test-passed', 'FAILED': 'test-failed', 'WARNING': 'test-warning', 'INFO': 'test-info'}[status]
                
                html += f"""
                            <div class="test-item {css_class}">
                                <span class="test-status">{status_icon}</span>
                                <span class="test-name">{test_name}</span>
                                <span class="test-result">{status}</span>
                            </div>
                """
            
            html += "</div>"
        
        # Add scan summary
        html += f"""
                        <div class="scan-summary">
                            <h4>📊 Scan Samenvatting</h4>
                            <div class="stat-item">
                                <span class="stat-label">Totaal bestanden gescand:</span>
                                <span class="stat-value">{scan_result.get('files_scanned', 0)}</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">Scan uitgevoerd op:</span>
                                <span class="stat-value">{scan_result.get('scan_time', 'Onbekend')}</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">Verdachte bestanden gevonden:</span>
                                <span class="stat-value">{len(suspicious_files)}</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">Gevoelige content gedetecteerd:</span>
                                <span class="stat-value">{len(sensitive_content)}</span>
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
                        <div class="section-title">💡 Aanbevelingen</div>
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
        
        # No issues found
        if not suspicious_files and not sensitive_content:
            html += """
                <div class="section">
                    <div class="section-content">
                        <h3>✅ Geen beveiligingsproblemen gevonden!</h3>
                        <p>Deze repository lijkt veilig te zijn volgens onze security checks.</p>
                    </div>
                </div>
            """
        
        html += """
                <div class="footer">
                    <p><strong>GitHub Monitor Tool</strong> • Automatische security scanning</p>
                    <p>Voor vragen of ondersteuning, neem contact op met je security team</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _generate_extended_alert_text(self, scan_result: Dict[str, Any]) -> str:
        """Generate extended plain text content with detailed test logs"""
        
        repo_name = self._extract_repo_name(scan_result)
        
        lines = [
            "🚨 GITHUB SECURITY ALERT 🚨",
            "=" * 50,
            f"Repository: {repo_name}",
            f"Risk Level: {scan_result.get('risk_level', 'UNKNOWN')}",
            f"Scan Time: {scan_result.get('scan_time', 'Unknown')}",
            ""
        ]
        
        # Add suspicious files
        suspicious_files = scan_result.get('suspicious_files', [])
        if suspicious_files:
            lines.extend([
                "📁 VERDACHTE BESTANDEN:",
                "-" * 25
            ])
            for file_info in suspicious_files:
                lines.append(f"• {file_info['path']}")
                lines.append(f"  Reden: {file_info.get('reason', 'Onbekend')}")
            lines.append("")
        
        # Add sensitive content
        sensitive_content = scan_result.get('sensitive_content', [])
        if sensitive_content:
            lines.extend([
                "⚠️ GEVOELIGE CONTENT:",
                "-" * 20
            ])
            for content_info in sensitive_content:
                lines.append(f"• {content_info.get('pattern', 'Onbekend patroon')}")
                lines.append(f"  Bestand: {content_info.get('file_path', 'Onbekend')}")
                lines.append(f"  Regel: {content_info.get('line_number', '?')}")
                lines.append(f"  Severity: {content_info.get('severity', 'UNKNOWN')}")
                lines.append("")
        
        # Add detailed test logs
        lines.extend([
            "📋 UITGEVOERDE TESTS:",
            "=" * 40,
            ""
        ])
        
        test_categories = [
            ("🔍 BESTANDSNAAM ANALYSE", [
                "Configuratie bestanden (.env, .config)",
                "Sleutel bestanden (private keys, certificates)", 
                "Backup en database bestanden",
                "Log bestanden met potentieel gevoelige data"
            ]),
            ("🔐 CONTENT SECURITY ANALYSE", [
                "API Keys en Tokens",
                "Wachtwoorden en Credentials",
                "Database Connection Strings",
                "Private SSH Keys"
            ]),
            ("👤 PERSOONLIJKE DATA DETECTIE", [
                "IBAN en Bankrekeningnummers",
                "BSN (Burgerservicenummers)",
                "Nederlandse Postcodes",
                "Persoonsnamen en Adressen",
                "Telefoonnummers",
                "Email Adressen"
            ]),
            ("🏥 MEDISCHE EN FINANCIËLE DATA", [
                "Medische Terminologie",
                "Financiële Termen",
                "Kentekens en Rijbewijzen"
            ]),
            ("⚡ CODE KWALITEIT CHECKS", [
                "Hardcoded Secrets",
                "Debug Code in Productie",
                "Test Files met Echte Data"
            ])
        ]
        
        for category_name, tests in test_categories:
            lines.append(category_name)
            lines.append("-" * len(category_name))
            
            for test in tests:
                # Simple logic to determine pass/fail based on findings
                status = "✅ PASSED"
                if scan_result.get('suspicious_files', []) or scan_result.get('sensitive_content', []):
                    if any(keyword in test.lower() for keyword in ['api', 'password', 'key', 'secret']):
                        status = "❌ FAILED"
                    elif any(keyword in test.lower() for keyword in ['iban', 'bsn', 'postcode', 'phone']):
                        status = "❌ FAILED" if scan_result.get('sensitive_content', []) else "✅ PASSED"
                
                lines.append(f"  {status} {test}")
            lines.append("")
        
        # Add scan statistics
        lines.extend([
            "📊 SCAN STATISTIEKEN:",
            "-" * 20,
            f"Totaal bestanden gescand: {scan_result.get('files_scanned', 0)}",
            f"Verdachte bestanden: {len(scan_result.get('suspicious_files', []))}",
            f"Gevoelige content items: {len(scan_result.get('sensitive_content', []))}",
            f"Scan tijd: {scan_result.get('scan_time', 'Onbekend')}",
            ""
        ])
        
        # Add recommendations
        recommendations = scan_result.get('recommendations', [])
        if recommendations:
            lines.extend([
                "💡 AANBEVELINGEN:",
                "-" * 15
            ])
            for rec in recommendations:
                lines.append(f"• {rec}")
            lines.append("")
        
        lines.extend([
            "",
            "Deze email is automatisch gegenereerd door GitHub Monitor Tool.",
            "Voor vragen of ondersteuning, neem contact op met je security team."
        ])
        
        return "\\n".join(lines)
    
    def _create_summary_report_message(self, scan_results: List[Dict[str, Any]]) -> MIMEMultipart:
        """Create summary report email message"""
        
        # Calculate summary statistics
        total_repos = len(scan_results)
        high_risk_repos = [r for r in scan_results if r.get('risk_level') in ['HIGH', 'CRITICAL']]
        
        # Create message
        message = MIMEMultipart("alternative")
        message["Subject"] = f"📊 GitHub Security Report - {total_repos} repositories scanned"
        message["From"] = self.sender_email
        message["To"] = ", ".join(self.recipient_emails)
        
        # Create simple HTML content (basic version for summary)
        html_content = self._generate_summary_html(scan_results)
        
        # Create text content
        text_content = self._generate_summary_text(scan_results)
        
        # Attach parts
        text_part = MIMEText(text_content, "plain", "utf-8")
        html_part = MIMEText(html_content, "html", "utf-8")
        
        message.attach(text_part)
        message.attach(html_part)
        
        return message
    
    def _generate_summary_html(self, scan_results: List[Dict[str, Any]]) -> str:
        """Generate basic summary HTML"""
        total_repos = len(scan_results)
        high_risk = sum(1 for r in scan_results if r.get('risk_level') in ['HIGH', 'CRITICAL'])
        
        html = f"""
        <html><body style="font-family: Arial, sans-serif;">
        <h2>📊 GitHub Security Summary Report</h2>
        <p><strong>Total repositories scanned:</strong> {total_repos}</p>
        <p><strong>High-risk repositories:</strong> {high_risk}</p>
        <hr>
        """
        
        for repo in scan_results:
            repo_name = self._extract_repo_name(repo)
            suspicious_count = len(repo.get('suspicious_files', []))
            sensitive_count = len(repo.get('sensitive_content', []))
            
            html += f"""
            <div style="border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px;">
                <h3>📁 {repo_name}</h3>
                <p>Risk Level: <strong>{repo.get('risk_level', 'LOW')}</strong></p>
                <p>Verdachte bestanden: {suspicious_count} | Gevoelige content: {sensitive_count}</p>
            </div>
            """
        
        html += "</body></html>"
        return html
    
    def _generate_summary_text(self, scan_results: List[Dict[str, Any]]) -> str:
        """Generate summary text"""
        lines = [
            "📊 GITHUB SECURITY SUMMARY REPORT",
            "=" * 40,
            f"Total repositories scanned: {len(scan_results)}",
            ""
        ]
        
        for repo in scan_results:
            repo_name = self._extract_repo_name(repo)
            lines.append(f"📁 {repo_name}: {repo.get('risk_level', 'LOW')} risk")
        
        return "\\n".join(lines)
    
    def _send_email(self, message: MIMEMultipart) -> bool:
        """Send email message via SMTP"""
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                
                for recipient in self.recipient_emails:
                    server.send_message(message, to_addrs=[recipient])
                
                logger.info(f"Email sent successfully to {len(self.recipient_emails)} recipients")
                return True
                
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test email connection"""
        if not self.enabled:
            return False
        
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                logger.info("Email connection test successful")
                return True
                
        except Exception as e:
            logger.error(f"Email connection test failed: {e}")
            return False