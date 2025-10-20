#!/usr/bin/env python3
"""
Simple Enhanced GitHub Monitor
A simplified version that works without optional dependencies
"""
import os
import sys
import time
import json
import logging
from typing import Dict, Any, Optional, List

# Add src to path for local imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from config_manager import ConfigManager
from github_client import GitHubClient
from email_notifier_extended import EmailNotifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SimpleEnhancedMonitor:
    """Simple enhanced GitHub monitor without complex dependencies"""
    
    def __init__(self, config_path: str = '.env'):
        """Initialize the monitor
        
        Args:
            config_path: Path to configuration file
        """
        # Initialize configuration
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.config_data
        
        # GitHub client
        github_token = self.config.get('GITHUB_TOKEN')
        self.github_client = GitHubClient(github_token)
        
        # Email notifier
        email_enabled = self.config.get('EMAIL_ENABLED', False)
        if email_enabled:
            email_config = {
                'smtp_server': self.config.get('SMTP_SERVER', 'smtp.gmail.com'),
                'smtp_port': self.config.get('SMTP_PORT', 587),
                'sender_email': self.config.get('SENDER_EMAIL', ''),
                'sender_password': self.config.get('SENDER_PASSWORD', ''),
                'recipient_emails': self.config.get('RECIPIENT_EMAILS', []),
                'enable_html': True
            }
            self.email_notifier = EmailNotifier(email_config)
        else:
            self.email_notifier = None
            
        # Scan statistics
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'repositories_scanned': 0,
            'files_scanned': 0,
            'issues_found': 0,
            'high_risk_issues': 0
        }
        
    def scan_all_repositories(self, max_repositories: Optional[int] = None) -> Dict[str, Any]:
        """Scan all accessible repositories
        
        Args:
            max_repositories: Maximum number of repositories to scan
            
        Returns:
            Complete scan results
        """
        self.scan_stats['start_time'] = time.time()
        logger.info("Starting simple enhanced repository scan")
        
        try:
            # Get repositories
            repositories = self.github_client.get_user_repositories()
            
            if max_repositories:
                repositories = repositories[:max_repositories]
                
            logger.info(f"Found {len(repositories)} repositories to scan")
            
            all_results = {}
            
            for repo in repositories:
                repo_name = repo['full_name']
                logger.info(f"Scanning repository: {repo_name}")
                
                try:
                    # Get repository contents (top-level only for speed)
                    files = self._get_repository_files_fast(repo_name)
                    
                    repo_results = {
                        'repository': repo,
                        'scan_time': time.time(),
                        'files_scanned': 0,
                        'suspicious_files': [],
                        'issues': []
                    }
                    
                    for file_info in files:
                        # Simple file analysis
                        if self._should_scan_file(file_info['name']):
                            repo_results['files_scanned'] += 1
                            
                            # Check for suspicious files
                            if self._is_suspicious_file(file_info['name']):
                                repo_results['suspicious_files'].append({
                                    'path': file_info['path'],
                                    'name': file_info['name'],
                                    'size': file_info.get('size', 0),
                                    'reason': self._get_suspicion_reason(file_info['name'])
                                })
                                
                                # Add as issue
                                repo_results['issues'].append({
                                    'type': 'suspicious_file',
                                    'severity': 'MEDIUM',
                                    'file_path': file_info['path'],
                                    'description': f"Suspicious file detected: {file_info['name']}",
                                    'risk_score': 50
                                })
                    
                    all_results[repo_name] = repo_results
                    self.scan_stats['repositories_scanned'] += 1
                    self.scan_stats['files_scanned'] += repo_results['files_scanned']
                    self.scan_stats['issues_found'] += len(repo_results['issues'])
                    
                    # Count high risk issues
                    high_risk = sum(1 for issue in repo_results['issues'] 
                                  if issue.get('risk_score', 0) >= 75)
                    self.scan_stats['high_risk_issues'] += high_risk
                    
                    logger.info(f"Repository {repo_name} scan completed: {len(repo_results['issues'])} issues found")
                    
                    # Add delay between repositories to respect rate limits
                    time.sleep(1.0)
                    
                except Exception as e:
                    logger.error(f"Error scanning repository {repo_name}: {e}")
                    all_results[repo_name] = {
                        'repository': repo,
                        'error': str(e),
                        'scan_time': time.time()
                    }
            
            self.scan_stats['end_time'] = time.time()
            
            # Generate summary
            summary = self._generate_summary(all_results)
            
            return {
                'scan_stats': self.scan_stats,
                'summary': summary,
                'results': all_results,
                'scan_duration': self.scan_stats['end_time'] - self.scan_stats['start_time']
            }
            
        except Exception as e:
            logger.error(f"Error during repository scan: {e}")
            raise
    
    def _should_scan_file(self, filename: str) -> bool:
        """Check if file should be scanned"""
        # Skip binary files and large files
        skip_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.tar', '.gz'}
        
        file_ext = os.path.splitext(filename)[1].lower()
        return file_ext not in skip_extensions
    
    def _is_suspicious_file(self, filename: str) -> bool:
        """Check if file is suspicious"""
        suspicious_patterns = [
            '.env', '.secret', '.private', '.pem', '.p12', '.pfx',
            'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
            'credentials', 'config.json', 'secrets.json',
            'password', 'passwd', 'shadow'
        ]
        
        filename_lower = filename.lower()
        return any(pattern in filename_lower for pattern in suspicious_patterns)
    
    def _get_suspicion_reason(self, filename: str) -> str:
        """Get reason why file is suspicious"""
        filename_lower = filename.lower()
        
        if '.env' in filename_lower:
            return "Environment file potentially containing secrets"
        elif any(key in filename_lower for key in ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519']):
            return "SSH private key file"
        elif any(word in filename_lower for word in ['secret', 'private', 'password', 'passwd']):
            return "File name suggests sensitive content"
        elif filename_lower.endswith(('.pem', '.p12', '.pfx')):
            return "Certificate or key file"
        elif any(word in filename_lower for word in ['credential', 'config']):
            return "Configuration file potentially containing credentials"
        else:
            return "Potentially sensitive file"
    
    def _get_repository_files_fast(self, repo_name: str) -> List[Dict[str, Any]]:
        """Get repository files efficiently with rate limiting"""
        import time
        
        try:
            # Only get top-level directory to avoid deep recursion
            api_url = f"https://api.github.com/repos/{repo_name}/contents"
            
            # Use the GitHub client's request method with built-in rate limiting
            response = self.github_client._make_request(api_url)
            
            if not response:
                return []
            
            files = []
            for item in response:
                if item['type'] == 'file':
                    files.append({
                        'name': item['name'],
                        'path': item['path'],
                        'size': item.get('size', 0),
                        'type': 'file'
                    })
                elif item['type'] == 'dir':
                    # Only scan common important directories
                    if item['name'].lower() in ['.github', 'config', 'configs', 'secrets', 'env']:
                        logger.info(f"Scanning important directory: {item['name']}")
                        
                        # Add small delay to respect rate limits
                        time.sleep(0.5)
                        
                        try:
                            subdir_url = f"https://api.github.com/repos/{repo_name}/contents/{item['path']}"
                            subdir_response = self.github_client._make_request(subdir_url)
                            
                            if subdir_response:
                                for subitem in subdir_response:
                                    if subitem['type'] == 'file':
                                        files.append({
                                            'name': subitem['name'],
                                            'path': subitem['path'],
                                            'size': subitem.get('size', 0),
                                            'type': 'file'
                                        })
                        except Exception as e:
                            logger.warning(f"Error scanning subdirectory {item['name']}: {e}")
                            continue
            
            logger.info(f"Found {len(files)} files in {repo_name}")
            return files
            
        except Exception as e:
            logger.error(f"Error getting repository files for {repo_name}: {e}")
            return []
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate scan summary"""
        total_repos = len(results)
        total_issues = sum(len(repo.get('issues', [])) for repo in results.values())
        repos_with_issues = sum(1 for repo in results.values() if repo.get('issues', []))
        
        # Categorize issues by severity
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for repo in results.values():
            for issue in repo.get('issues', []):
                severity = issue.get('severity', 'MEDIUM')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_repositories': total_repos,
            'repositories_with_issues': repos_with_issues,
            'total_issues': total_issues,
            'severity_breakdown': severity_counts,
            'scan_duration': self.scan_stats.get('end_time', 0) - self.scan_stats.get('start_time', 0)
        }
    
    def generate_report(self, scan_results: Dict[str, Any], output_format: str = 'html') -> str:
        """Generate scan report"""
        summary = scan_results['summary']
        
        if output_format == 'html':
            return self._generate_html_report(scan_results)
        else:
            return self._generate_text_report(scan_results)
    
    def _generate_html_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate HTML report"""
        summary = scan_results['summary']
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>GitHub Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .summary {{ margin: 20px 0; }}
                .repo-section {{ margin: 20px 0; border-left: 3px solid #007cba; padding-left: 15px; }}
                .issue {{ margin: 10px 0; padding: 10px; background-color: #fff3cd; border-radius: 3px; }}
                .high {{ background-color: #f8d7da; }}
                .medium {{ background-color: #fff3cd; }}
                .low {{ background-color: #d1ecf1; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>GitHub Security Monitoring Report</h1>
                <p>Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Repositories scanned:</strong> {summary['total_repositories']}</p>
                <p><strong>Issues found:</strong> {summary['total_issues']}</p>
                <p><strong>Scan duration:</strong> {summary['scan_duration']:.2f} seconds</p>
                
                <h3>Issues by Severity</h3>
                <ul>
                    <li>High: {summary['severity_breakdown'].get('HIGH', 0)}</li>
                    <li>Medium: {summary['severity_breakdown'].get('MEDIUM', 0)}</li>
                    <li>Low: {summary['severity_breakdown'].get('LOW', 0)}</li>
                </ul>
            </div>
        """
        
        # Add repository details
        for repo_name, repo_data in scan_results['results'].items():
            if 'error' in repo_data:
                html += f"""
                <div class="repo-section">
                    <h3>{repo_name}</h3>
                    <p style="color: red;"><strong>Error:</strong> {repo_data['error']}</p>
                </div>
                """
                continue
                
            issues = repo_data.get('issues', [])
            if issues:
                html += f"""
                <div class="repo-section">
                    <h3>{repo_name}</h3>
                    <p><strong>Files scanned:</strong> {repo_data.get('files_scanned', 0)}</p>
                    <p><strong>Issues found:</strong> {len(issues)}</p>
                    
                    <h4>Issues:</h4>
                """
                
                for issue in issues:
                    severity_class = issue.get('severity', 'MEDIUM').lower()
                    html += f"""
                    <div class="issue {severity_class}">
                        <strong>{issue.get('type', 'Unknown')}</strong> - {issue.get('severity', 'MEDIUM')}
                        <br>File: {issue.get('file_path', 'Unknown')}
                        <br>Description: {issue.get('description', 'No description')}
                        <br>Risk Score: {issue.get('risk_score', 0)}
                    </div>
                    """
                
                html += "</div>"
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    def _generate_text_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate text report"""
        summary = scan_results['summary']
        
        report = f"""
GitHub Security Monitoring Report
Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY
=======
Repositories scanned: {summary['total_repositories']}
Issues found: {summary['total_issues']}
Scan duration: {summary['scan_duration']:.2f} seconds

SEVERITY BREAKDOWN
==================
High: {summary['severity_breakdown'].get('HIGH', 0)}
Medium: {summary['severity_breakdown'].get('MEDIUM', 0)}
Low: {summary['severity_breakdown'].get('LOW', 0)}

REPOSITORY DETAILS
==================
"""
        
        for repo_name, repo_data in scan_results['results'].items():
            if 'error' in repo_data:
                report += f"\n{repo_name}\n{'='*len(repo_name)}\nError: {repo_data['error']}\n"
                continue
                
            issues = repo_data.get('issues', [])
            if issues:
                report += f"\n{repo_name}\n{'='*len(repo_name)}\n"
                report += f"Files scanned: {repo_data.get('files_scanned', 0)}\n"
                report += f"Issues found: {len(issues)}\n\n"
                
                for issue in issues:
                    report += f"  [{issue.get('severity', 'MEDIUM')}] {issue.get('type', 'Unknown')}\n"
                    report += f"  File: {issue.get('file_path', 'Unknown')}\n"
                    report += f"  Description: {issue.get('description', 'No description')}\n"
                    report += f"  Risk Score: {issue.get('risk_score', 0)}\n\n"
        
        return report
    
    def send_notifications(self, scan_results: Dict[str, Any]) -> bool:
        """Send email notifications if configured"""
        if not self.email_notifier:
            logger.info("Email notifications not configured")
            return False
        
        # Check if there are any issues to report
        summary = scan_results.get('summary', {})
        total_issues = summary.get('total_issues', 0)
        
        if total_issues == 0:
            logger.info("No security issues found, skipping email notification")
            return True
        
        try:
            # Send notifications for each repository with issues
            success_count = 0
            total_notifications = 0
            
            for repo_name, repo_data in scan_results.get('results', {}).items():
                if 'error' in repo_data:
                    continue
                    
                issues = repo_data.get('issues', [])
                if len(issues) > 0:
                    total_notifications += 1
                    
                    # Create repository alert data structure
                    alert_data = {
                        'repository': repo_data['repository'],
                        'suspicious_files': repo_data.get('suspicious_files', []),
                        'issues': issues,
                        'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'scan_summary': {
                            'files_scanned': repo_data.get('files_scanned', 0),
                            'issues_found': len(issues),
                            'high_risk_issues': sum(1 for issue in issues if issue.get('risk_score', 0) >= 75)
                        }
                    }
                    
                    if self.email_notifier.send_security_alert(alert_data):
                        success_count += 1
                        logger.info(f"Email sent for repository: {repo_name}")
                    else:
                        logger.error(f"Failed to send email for repository: {repo_name}")
            
            logger.info(f"Email notifications: {success_count}/{total_notifications} sent successfully")
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Error sending notifications: {e}")
            return False


def main():
    """Main entry point"""
    try:
        # Initialize monitor
        monitor = SimpleEnhancedMonitor()
        
        # Run scan
        logger.info("Starting GitHub repository scan...")
        results = monitor.scan_all_repositories(max_repositories=5)  # Limit for testing
        
        # Generate report
        report = monitor.generate_report(results)
        
        # Save report
        with open('scan_report.html', 'w', encoding='utf-8') as f:
            f.write(report)
        
        logger.info("Report saved to scan_report.html")
        
        # Send notifications
        monitor.send_notifications(results)
        
        # Print summary
        summary = results['summary']
        print(f"\nScan completed successfully!")
        print(f"Repositories scanned: {summary['total_repositories']}")
        print(f"Issues found: {summary['total_issues']}")
        print(f"High risk issues: {monitor.scan_stats['high_risk_issues']}")
        print(f"Scan duration: {summary['scan_duration']:.2f} seconds")
        
    except Exception as e:
        logger.error(f"Error in main: {e}")
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())