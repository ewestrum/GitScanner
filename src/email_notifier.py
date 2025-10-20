"""
Email Notifier - Send security alerts via email
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
        
        # Create message
        message = MIMEMultipart("alternative")
        message["Subject"] = f"🚨 GitHub Security Alert - {scan_result['repository']}"
        message["From"] = self.sender_email
        message["To"] = ", ".join(self.recipient_emails)
        
        # Create HTML content
        html_content = self._generate_alert_html(scan_result)
        
        # Create text content (fallback)
        text_content = self._generate_alert_text(scan_result)
        
        # Attach parts
        text_part = MIMEText(text_content, "plain", "utf-8")
        html_part = MIMEText(html_content, "html", "utf-8")
        
        message.attach(text_part)
        message.attach(html_part)
        
        return message
    
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
        
        # Create HTML content
        html_content = self._generate_summary_html(scan_results)
        
        # Create text content (fallback)
        text_content = self._generate_summary_text(scan_results)
        
        # Attach parts
        text_part = MIMEText(text_content, "plain", "utf-8")
        html_part = MIMEText(html_content, "html", "utf-8")
        
        message.attach(text_part)
        message.attach(html_part)
        
        return message
    
    def _generate_alert_html(self, scan_result: Dict[str, Any]) -> str:
        """Generate HTML content for security alert with modern dashboard design"""
        
        risk_level = scan_result.get('risk_level', 'UNKNOWN')
        risk_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14', 
            'MEDIUM': '#ffc107',
            'LOW': '#28a745'
        }
        risk_color = risk_colors.get(risk_level, '#6c757d')
        
        # Get counts
        suspicious_count = len(scan_result.get('suspicious_files', []))
        sensitive_count = len(scan_result.get('sensitive_content', []))
        
        # Risk level emoji and status
        risk_emoji = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '⚠️', 
            'LOW': '✅'
        }.get(risk_level, '❓')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>GitHub Security Alert - {scan_result.get('repository', 'Unknown Repository')}</title>
            <style>
                * {{
                    box-sizing: border-box;
                    margin: 0;
                    padding: 0;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    background-color: #f5f7fa;
                }}
                
                .container {{
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                
                .alert-header {{
                    background: linear-gradient(135deg, {risk_color} 0%, {risk_color}dd 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 12px;
                    text-align: center;
                    margin-bottom: 30px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }}
                
                .alert-header h1 {{
                    font-size: 2.2em;
                    margin-bottom: 15px;
                    font-weight: 300;
                }}
                
                .repo-name {{
                    font-size: 1.3em;
                    margin-bottom: 10px;
                    background: rgba(255,255,255,0.2);
                    padding: 10px 20px;
                    border-radius: 25px;
                    display: inline-block;
                }}
                
                .risk-badge {{
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    background: rgba(255,255,255,0.9);
                    color: {risk_color};
                    padding: 8px 16px;
                    border-radius: 25px;
                    font-weight: bold;
                    font-size: 1.1em;
                    margin: 10px;
                }}
                
                .stats-overview {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                
                .stat-card {{
                    background: white;
                    padding: 25px;
                    border-radius: 12px;
                    text-align: center;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    border-left: 5px solid {risk_color};
                }}
                
                .stat-number {{
                    font-size: 2.5em;
                    font-weight: bold;
                    color: {risk_color};
                    margin-bottom: 10px;
                }}
                
                .stat-label {{
                    color: #666;
                    font-size: 1em;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }}
                
                .section {{
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    margin-bottom: 25px;
                    overflow: hidden;
                }}
                
                .section-header {{
                    background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
                    padding: 20px 25px;
                    border-bottom: 1px solid #dee2e6;
                }}
                
                .section-title {{
                    font-size: 1.3em;
                    font-weight: 600;
                    color: #495057;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }}
                
                .section-content {{
                    padding: 25px;
                }}
                
                .issue-list {{
                    list-style: none;
                }}
                
                .issue-item {{
                    background: #f8f9fa;
                    border-left: 4px solid {risk_color};
                    padding: 15px 20px;
                    margin: 12px 0;
                    border-radius: 6px;
                    transition: transform 0.2s ease;
                }}
                
                .issue-item:hover {{
                    transform: translateX(5px);
                }}
                
                .issue-title {{
                    font-weight: 600;
                    color: #495057;
                    margin-bottom: 8px;
                    font-size: 1.05em;
                }}
                
                .issue-details {{
                    color: #666;
                    font-size: 0.95em;
                    margin-bottom: 5px;
                }}
                
                .issue-path {{
                    font-family: 'Courier New', monospace;
                    background: #e9ecef;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 0.85em;
                    color: #495057;
                }}
                
                .severity-badge {{
                    display: inline-block;
                    padding: 3px 8px;
                    border-radius: 12px;
                    font-size: 0.75em;
                    font-weight: bold;
                    text-transform: uppercase;
                    margin-top: 8px;
                }}
                
                .severity-critical {{
                    background: #dc3545;
                    color: white;
                }}
                
                .severity-high {{
                    background: #fd7e14;
                    color: white;
                }}
                
                .severity-medium {{
                    background: #ffc107;
                    color: #333;
                }}
                
                .severity-low {{
                    background: #28a745;
                    color: white;
                }}
                
                .recommendations {{
                    background: linear-gradient(135deg, #e7f3ff 0%, #cce7ff 100%);
                    border-left: 4px solid #0366d6;
                    padding: 20px;
                    border-radius: 8px;
                }}
                
                .recommendations h4 {{
                    color: #0366d6;
                    margin-bottom: 15px;
                    font-size: 1.1em;
                }}
                
                .recommendation-list {{
                    list-style: none;
                }}
                
                .recommendation-item {{
                    background: rgba(255,255,255,0.7);
                    padding: 12px 15px;
                    margin: 8px 0;
                    border-radius: 6px;
                    border-left: 3px solid #0366d6;
                    position: relative;
                }}
                
                .recommendation-item:before {{
                    content: "💡";
                    margin-right: 10px;
                }}
                
                .scan-info {{
                    background: #f8f9fa;
                    padding: 15px 20px;
                    border-radius: 8px;
                    margin: 20px 0;
                    color: #666;
                    font-size: 0.9em;
                    text-align: center;
                }}
                
                .footer {{
                    text-align: center;
                    padding: 30px 20px;
                    color: #666;
                    font-size: 0.9em;
                    border-top: 1px solid #dee2e6;
                    margin-top: 40px;
                }}
                
                .footer strong {{
                    color: #495057;
                }}
                
                .no-issues {{
                    text-align: center;
                    padding: 40px;
                    color: #28a745;
                }}
                
                .no-issues h3 {{
                    font-size: 1.5em;
                    margin-bottom: 10px;
                }}
                
                @media (max-width: 600px) {{
                    .container {{
                        padding: 10px;
                    }}
                    
                    .alert-header {{
                        padding: 20px;
                    }}
                    
                    .alert-header h1 {{
                        font-size: 1.8em;
                    }}
                    
                    .stats-overview {{
                        grid-template-columns: 1fr;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="alert-header">
                    <h1>{risk_emoji} Security Alert</h1>
                    <div class="repo-name">📁 {scan_result.get('repository', 'Unknown Repository')}</div>
                    <div class="risk-badge">
                        {risk_emoji} {risk_level} RISK
                    </div>
                </div>
                
                <div class="stats-overview">
                    <div class="stat-card">
                        <div class="stat-number">{suspicious_count}</div>
                        <div class="stat-label">Verdachte Bestanden</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{sensitive_count}</div>
                        <div class="stat-label">Gevoelige Content</div>
                    </div>
                </div>
                
                <div class="scan-info">
                    📅 Scan uitgevoerd op {scan_result.get('scan_time', 'Unknown')} door GitHub Monitor Tool
                </div>
        """
        
        # Add suspicious files section
        suspicious_files = scan_result.get('suspicious_files', [])
        if suspicious_files:
            html += """
                <div class="section">
                    <div class="section-header">
                        <div class="section-title">
                            � Verdachte Bestanden
                        </div>
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
                                <div class="issue-path">{file_path}</div>
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
                        <div class="section-title">
                            ⚠️ Gevoelige Content Gedetecteerd
                        </div>
                    </div>
                    <div class="section-content">
                        <ul class="issue-list">
            """
            for content_info in sensitive_content:
                pattern = content_info.get('pattern', 'Onbekend patroon')
                file_path = content_info.get('file_path', 'Onbekend bestand')
                line_number = content_info.get('line_number', '?')
                severity = content_info.get('severity', 'MEDIUM').lower()
                match_text = content_info.get('match', 'Verborgen')
                
                html += f"""
                            <li class="issue-item">
                                <div class="issue-title">🔍 {pattern}</div>
                                <div class="issue-details">Gevonden op regel {line_number}</div>
                                <div class="issue-path">{file_path}:{line_number}</div>
                                <div class="severity-badge severity-{severity}">{severity.upper()}</div>
                            </li>
                """
            html += """
                        </ul>
                    </div>
                </div>
            """
        
        # Add recommendations section
        recommendations = scan_result.get('recommendations', [])
        if recommendations:
            html += """
                <div class="section">
                    <div class="section-content">
                        <div class="recommendations">
                            <h4>💡 Aanbevelingen voor {scan_result.get('repository', 'deze repository')}</h4>
                            <ul class="recommendation-list">
            """
            for rec in recommendations:
                html += f'<li class="recommendation-item">{rec}</li>'
            html += """
                            </ul>
                        </div>
                    </div>
                </div>
            """
        
        # No issues found
        if not suspicious_files and not sensitive_content:
            html += """
                <div class="section">
                    <div class="no-issues">
                        <h3>✅ Geen beveiligingsproblemen gevonden!</h3>
                        <p>Deze repository lijkt veilig te zijn volgens onze security checks.</p>
                    </div>
                </div>
            """
        
        html += """
                <div class="footer">
                    <p><strong>GitHub Monitor Tool</strong> • Automatische security scanning</p>
                    <p>Voor vragen of ondersteuning, neem contact op met je security team</p>
                    <p style="margin-top: 10px; font-size: 0.8em; color: #999;">
                        Deze alert is automatisch gegenereerd. Controleer altijd handmatig voor false positives.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _generate_alert_text(self, scan_result: Dict[str, Any]) -> str:
        """Generate plain text content for security alert"""
        
        lines = [
            "🚨 GITHUB SECURITY ALERT 🚨",
            "=" * 40,
            f"Repository: {scan_result['repository']}",
            f"Risk Level: {scan_result.get('risk_level', 'UNKNOWN')}",
            f"Scan Time: {scan_result['scan_time']}",
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
    
    def _generate_summary_html(self, scan_results: List[Dict[str, Any]]) -> str:
        """Generate HTML content for summary report with interactive dashboard"""
        
        # Calculate statistics
        total_repos = len(scan_results)
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        total_suspicious_files = 0
        total_sensitive_content = 0
        
        for result in scan_results:
            risk_level = result.get('risk_level', 'LOW')
            risk_counts[risk_level] += 1
            total_suspicious_files += len(result.get('suspicious_files', []))
            total_sensitive_content += len(result.get('sensitive_content', []))
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>GitHub Security Dashboard</title>
            <style>
                * {{
                    box-sizing: border-box;
                    margin: 0;
                    padding: 0;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    background-color: #f5f7fa;
                }}
                
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 12px;
                    text-align: center;
                    margin-bottom: 30px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }}
                
                .header h1 {{
                    font-size: 2.5em;
                    margin-bottom: 10px;
                    font-weight: 300;
                }}
                
                .header .subtitle {{
                    font-size: 1.1em;
                    opacity: 0.9;
                }}
                
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                
                .stat-card {{
                    background: white;
                    padding: 25px;
                    border-radius: 12px;
                    text-align: center;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    border-left: 5px solid #ddd;
                    transition: transform 0.2s ease;
                }}
                
                .stat-card:hover {{
                    transform: translateY(-2px);
                }}
                
                .stat-card.critical {{
                    border-left-color: #dc3545;
                    background: linear-gradient(135deg, #fff 0%, #ffebee 100%);
                }}
                
                .stat-card.high {{
                    border-left-color: #fd7e14;
                    background: linear-gradient(135deg, #fff 0%, #fff3e0 100%);
                }}
                
                .stat-card.medium {{
                    border-left-color: #ffc107;
                    background: linear-gradient(135deg, #fff 0%, #fffde7 100%);
                }}
                
                .stat-card.low {{
                    border-left-color: #28a745;
                    background: linear-gradient(135deg, #fff 0%, #e8f5e8 100%);
                }}
                
                .stat-number {{
                    font-size: 3em;
                    font-weight: bold;
                    margin-bottom: 10px;
                }}
                
                .stat-label {{
                    font-size: 1.1em;
                    color: #666;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }}
                
                .dashboard-section {{
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    margin-bottom: 30px;
                }}
                
                .section-header {{
                    background: #f8f9fa;
                    padding: 20px 30px;
                    border-bottom: 1px solid #dee2e6;
                    border-radius: 12px 12px 0 0;
                }}
                
                .section-title {{
                    font-size: 1.5em;
                    font-weight: 600;
                    color: #495057;
                }}
                
                .repos-table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                
                .repos-table th {{
                    background: #f8f9fa;
                    padding: 15px;
                    text-align: left;
                    font-weight: 600;
                    color: #495057;
                    border-bottom: 2px solid #dee2e6;
                }}
                
                .repos-table td {{
                    padding: 15px;
                    border-bottom: 1px solid #dee2e6;
                    vertical-align: middle;
                }}
                
                .repos-table tbody tr:hover {{
                    background: #f8f9fa;
                }}
                
                .status-badge {{
                    display: inline-flex;
                    align-items: center;
                    padding: 6px 12px;
                    border-radius: 20px;
                    font-size: 0.85em;
                    font-weight: 600;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }}
                
                .status-passed {{
                    background: #d4edda;
                    color: #155724;
                }}
                
                .status-warning {{
                    background: #fff3cd;
                    color: #856404;
                }}
                
                .status-failed {{
                    background: #f8d7da;
                    color: #721c24;
                }}
                
                .status-critical {{
                    background: #dc3545;
                    color: white;
                }}
                
                .check-icon {{
                    margin-right: 5px;
                }}
                
                .repo-name {{
                    font-weight: 600;
                    color: #0366d6;
                }}
                
                .tabs {{
                    margin-top: 30px;
                }}
                
                .tab-buttons {{
                    display: flex;
                    border-bottom: 2px solid #dee2e6;
                    margin-bottom: 20px;
                }}
                
                .tab-button {{
                    background: none;
                    border: none;
                    padding: 15px 30px;
                    cursor: pointer;
                    font-size: 1em;
                    color: #666;
                    border-bottom: 3px solid transparent;
                    transition: all 0.3s ease;
                }}
                
                .tab-button.active {{
                    color: #0366d6;
                    border-bottom-color: #0366d6;
                    background: #f6f8fa;
                }}
                
                .tab-button:hover {{
                    background: #f6f8fa;
                }}
                
                .tab-content {{
                    display: none;
                    padding: 20px 0;
                }}
                
                .tab-content.active {{
                    display: block;
                }}
                
                .repo-details {{
                    background: #f8f9fa;
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 20px;
                }}
                
                .repo-details h4 {{
                    color: #495057;
                    margin-bottom: 15px;
                    padding-bottom: 10px;
                    border-bottom: 2px solid #dee2e6;
                }}
                
                .issue-list {{
                    list-style: none;
                }}
                
                .issue-item {{
                    background: white;
                    padding: 12px 15px;
                    margin: 8px 0;
                    border-radius: 6px;
                    border-left: 4px solid #dc3545;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                }}
                
                .issue-item.medium {{
                    border-left-color: #ffc107;
                }}
                
                .issue-item.high {{
                    border-left-color: #fd7e14;
                }}
                
                .issue-item.critical {{
                    border-left-color: #dc3545;
                }}
                
                .issue-title {{
                    font-weight: 600;
                    color: #495057;
                }}
                
                .issue-path {{
                    color: #666;
                    font-size: 0.9em;
                    font-family: 'Courier New', monospace;
                }}
                
                .recommendations {{
                    background: #e7f3ff;
                    border-left: 4px solid #0366d6;
                    padding: 15px;
                    margin: 15px 0;
                    border-radius: 6px;
                }}
                
                .recommendations h5 {{
                    color: #0366d6;
                    margin-bottom: 10px;
                }}
                
                .recommendations ul {{
                    margin: 0;
                    padding-left: 20px;
                }}
                
                .footer {{
                    text-align: center;
                    padding: 30px;
                    color: #666;
                    font-size: 0.9em;
                    border-top: 1px solid #dee2e6;
                }}
                
                .summary-stats {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 15px;
                    margin: 20px 0;
                }}
                
                .summary-stat {{
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 8px;
                    text-align: center;
                }}
                
                .summary-stat .number {{
                    font-size: 2em;
                    font-weight: bold;
                    color: #495057;
                }}
                
                .summary-stat .label {{
                    color: #666;
                    font-size: 0.9em;
                }}
            </style>
            <script>
                function showTab(tabName) {{
                    // Hide all tab contents
                    var contents = document.querySelectorAll('.tab-content');
                    contents.forEach(function(content) {{
                        content.classList.remove('active');
                    }});
                    
                    // Remove active class from all buttons
                    var buttons = document.querySelectorAll('.tab-button');
                    buttons.forEach(function(button) {{
                        button.classList.remove('active');
                    }});
                    
                    // Show selected tab content
                    document.getElementById(tabName).classList.add('active');
                    
                    // Add active class to clicked button
                    event.target.classList.add('active');
                }}
                
                document.addEventListener('DOMContentLoaded', function() {{
                    // Show first tab by default
                    document.querySelector('.tab-button').classList.add('active');
                    document.querySelector('.tab-content').classList.add('active');
                }});
            </script>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ GitHub Security Dashboard</h1>
                    <div class="subtitle">
                        Scan uitgevoerd op {datetime.now().strftime('%d %B %Y om %H:%M')} • {total_repos} repositories gescand
                    </div>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card critical">
                        <div class="stat-number" style="color: #dc3545;">{risk_counts['CRITICAL']}</div>
                        <div class="stat-label">Critical Risk</div>
                    </div>
                    <div class="stat-card high">
                        <div class="stat-number" style="color: #fd7e14;">{risk_counts['HIGH']}</div>
                        <div class="stat-label">High Risk</div>
                    </div>
                    <div class="stat-card medium">
                        <div class="stat-number" style="color: #ffc107;">{risk_counts['MEDIUM']}</div>
                        <div class="stat-label">Medium Risk</div>
                    </div>
                    <div class="stat-card low">
                        <div class="stat-number" style="color: #28a745;">{risk_counts['LOW']}</div>
                        <div class="stat-label">Low Risk</div>
                    </div>
                </div>
                
                <div class="summary-stats">
                    <div class="summary-stat">
                        <div class="number">{total_suspicious_files}</div>
                        <div class="label">Verdachte Bestanden</div>
                    </div>
                    <div class="summary-stat">
                        <div class="number">{total_sensitive_content}</div>
                        <div class="label">Gevoelige Content</div>
                    </div>
                    <div class="summary-stat">
                        <div class="number">{len([r for r in scan_results if r.get('risk_level') in ['HIGH', 'CRITICAL']])}</div>
                        <div class="label">Actie Vereist</div>
                    </div>
                </div>
                
                <div class="dashboard-section">
                    <div class="section-header">
                        <div class="section-title">📊 Repository Overzicht</div>
                    </div>
                    <table class="repos-table">
                        <thead>
                            <tr>
                                <th>Repository</th>
                                <th>Status</th>
                                <th>Risk Level</th>
                                <th>Verdachte Bestanden</th>
                                <th>Gevoelige Content</th>
                                <th>Laatste Scan</th>
                            </tr>
                        </thead>
                        <tbody>"""
        
        # Add repository rows
        for result in scan_results:
            repo_name = result.get('repository', 'Unknown')
            risk_level = result.get('risk_level', 'LOW')
            suspicious_count = len(result.get('suspicious_files', []))
            sensitive_count = len(result.get('sensitive_content', []))
            scan_time = result.get('scan_time', 'Unknown')
            
            # Determine status
            if risk_level == 'CRITICAL':
                status_class = 'status-critical'
                status_icon = '🚨'
                status_text = 'Critical'
            elif risk_level == 'HIGH':
                status_class = 'status-failed'
                status_icon = '⚠️'
                status_text = 'Failed'
            elif risk_level == 'MEDIUM':
                status_class = 'status-warning'
                status_icon = '⚠️'
                status_text = 'Warning'
            else:
                status_class = 'status-passed'
                status_icon = '✅'
                status_text = 'Passed'
            
            # Format scan time
            try:
                from datetime import datetime as dt
                parsed_time = dt.fromisoformat(scan_time.replace('Z', '+00:00'))
                formatted_time = parsed_time.strftime('%H:%M')
            except:
                formatted_time = 'Unknown'
            
            html += f"""
                            <tr>
                                <td><span class="repo-name">{repo_name}</span></td>
                                <td><span class="status-badge {status_class}"><span class="check-icon">{status_icon}</span>{status_text}</span></td>
                                <td><strong style="color: {'#dc3545' if risk_level == 'CRITICAL' else '#fd7e14' if risk_level == 'HIGH' else '#ffc107' if risk_level == 'MEDIUM' else '#28a745'}">{risk_level}</strong></td>
                                <td>{suspicious_count}</td>
                                <td>{sensitive_count}</td>
                                <td>{formatted_time}</td>
                            </tr>"""
        
        html += """
                        </tbody>
                    </table>
                </div>
        """
        
        # Add tabs with detailed repository information
        if scan_results:
            html += """
                <div class="dashboard-section">
                    <div class="section-header">
                        <div class="section-title">🔍 Gedetailleerde Repository Analyse</div>
                    </div>
                    <div class="tabs">
                        <div class="tab-buttons">
            """
            
            # Create tab buttons
            for i, result in enumerate(scan_results):
                repo_name = result.get('repository', f'Repo {i+1}')
                risk_level = result.get('risk_level', 'LOW')
                risk_emoji = '🚨' if risk_level == 'CRITICAL' else '⚠️' if risk_level in ['HIGH', 'MEDIUM'] else '✅'
                
                html += f"""
                            <button class="tab-button" onclick="showTab('repo-{i}')">{risk_emoji} {repo_name}</button>
                """
            
            html += """
                        </div>
            """
            
            # Create tab contents
            for i, result in enumerate(scan_results):
                repo_name = result.get('repository', f'Repository {i+1}')
                risk_level = result.get('risk_level', 'LOW')
                suspicious_files = result.get('suspicious_files', [])
                sensitive_content = result.get('sensitive_content', [])
                recommendations = result.get('recommendations', [])
                
                html += f"""
                        <div id="repo-{i}" class="tab-content">
                            <div class="repo-details">
                                <h4>📁 {repo_name} - Risk Level: {risk_level}</h4>
                """
                
                if suspicious_files:
                    html += """
                                <div style="margin: 20px 0;">
                                    <h5 style="color: #dc3545; margin-bottom: 10px;">🚨 Verdachte Bestanden</h5>
                                    <ul class="issue-list">
                    """
                    for file_info in suspicious_files:
                        file_path = file_info.get('path', 'Unknown path')
                        reason = file_info.get('reason', 'Unknown reason')
                        html += f"""
                                        <li class="issue-item critical">
                                            <div class="issue-title">{file_path}</div>
                                            <div class="issue-path">Reden: {reason}</div>
                                        </li>
                        """
                    html += """
                                    </ul>
                                </div>
                    """
                
                if sensitive_content:
                    html += """
                                <div style="margin: 20px 0;">
                                    <h5 style="color: #fd7e14; margin-bottom: 10px;">⚠️ Gevoelige Content</h5>
                                    <ul class="issue-list">
                    """
                    for content_info in sensitive_content:
                        pattern = content_info.get('pattern', 'Unknown pattern')
                        file_path = content_info.get('file_path', 'Unknown file')
                        line_number = content_info.get('line_number', '?')
                        severity = content_info.get('severity', 'MEDIUM').lower()
                        
                        html += f"""
                                        <li class="issue-item {severity}">
                                            <div class="issue-title">{pattern}</div>
                                            <div class="issue-path">{file_path}:{line_number}</div>
                                        </li>
                        """
                    html += """
                                    </ul>
                                </div>
                    """
                
                if recommendations:
                    html += """
                                <div class="recommendations">
                                    <h5>💡 Aanbevelingen</h5>
                                    <ul>
                    """
                    for rec in recommendations:
                        html += f"<li>{rec}</li>"
                    html += """
                                    </ul>
                                </div>
                    """
                
                if not suspicious_files and not sensitive_content:
                    html += """
                                <div style="text-align: center; padding: 40px; color: #28a745;">
                                    <h3>✅ Geen problemen gevonden!</h3>
                                    <p>Deze repository lijkt veilig te zijn.</p>
                                </div>
                    """
                
                html += """
                            </div>
                        </div>
                """
            
            html += """
                    </div>
                </div>
            """
        
        html += """
                <div class="footer">
                    <p><strong>GitHub Monitor Tool</strong> • Automatische security scanning voor je repositories</p>
                    <p>Voor vragen of ondersteuning, neem contact op met je security team</p>
                    <p style="margin-top: 15px; font-size: 0.8em; color: #999;">
                        Deze scan is uitgevoerd op {datetime.now().strftime('%d %B %Y om %H:%M:%S')}
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _generate_summary_text(self, scan_results: List[Dict[str, Any]]) -> str:
        """Generate plain text content for summary report"""
        
        # Calculate statistics
        total_repos = len(scan_results)
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        total_suspicious_files = 0
        total_sensitive_content = 0
        
        for result in scan_results:
            risk_level = result.get('risk_level', 'LOW')
            risk_counts[risk_level] += 1
            total_suspicious_files += len(result.get('suspicious_files', []))
            total_sensitive_content += len(result.get('sensitive_content', []))
        
        lines = [
            "📊 GITHUB SECURITY SUMMARY REPORT",
            "=" * 40,
            f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total repositories scanned: {total_repos}",
            "",
            "RISK LEVEL DISTRIBUTION:",
            f"  Critical: {risk_counts['CRITICAL']}",
            f"  High: {risk_counts['HIGH']}",
            f"  Medium: {risk_counts['MEDIUM']}",
            f"  Low: {risk_counts['LOW']}",
            "",
            f"Total verdachte bestanden: {total_suspicious_files}",
            f"Total gevoelige content instanties: {total_sensitive_content}",
            ""
        ]
        
        # Add high-risk repositories
        high_risk_repos = [
            result for result in scan_results 
            if result.get('risk_level') in ['HIGH', 'CRITICAL']
        ]
        
        if high_risk_repos:
            lines.extend([
                "⚠️ HIGH-RISK REPOSITORIES:",
                "-" * 30
            ])
            
            for repo in high_risk_repos:
                lines.extend([
                    f"Repository: {repo['repository']}",
                    f"Risk Level: {repo.get('risk_level', 'UNKNOWN')}",
                    f"Verdachte bestanden: {len(repo.get('suspicious_files', []))}",
                    f"Gevoelige content: {len(repo.get('sensitive_content', []))}",
                    ""
                ])
                
                recommendations = repo.get('recommendations', [])
                if recommendations:
                    lines.append("Aanbevelingen:")
                    for rec in recommendations[:3]:  # Limit to first 3
                        lines.append(f"  • {rec}")
                    lines.append("")
        
        lines.extend([
            "",
            "Deze email is automatisch gegenereerd door GitHub Monitor Tool.",
            "Voor gedetailleerde informatie, bekijk de volledige security rapporten."
        ])
        
        return "\\n".join(lines)
    
    def _send_email(self, message: MIMEMultipart) -> bool:
        """Send email message via SMTP
        
        Args:
            message: Email message to send
            
        Returns:
            True if email was sent successfully
        """
        try:
            # Create SMTP session
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()  # Enable TLS encryption
                server.login(self.sender_email, self.sender_password)
                
                # Send email to all recipients
                for recipient in self.recipient_emails:
                    server.send_message(message, to_addrs=[recipient])
                
                logger.info(f"Email sent successfully to {len(self.recipient_emails)} recipients")
                return True
                
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test email connection and authentication
        
        Returns:
            True if connection is successful
        """
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