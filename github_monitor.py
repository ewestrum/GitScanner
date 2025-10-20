#!/usr/bin/env python3
"""
GitHub Monitor Tool - Monitor repositories for sensitive information and data leaks

This tool scans GitHub repositories for:
- Suspicious file types (credentials, databases, etc.)
- Personal data patterns (emails, phone numbers, etc.)
- Sensitive content (API keys, passwords, etc.)
"""

import os
import sys
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import time

from src.github_client import GitHubClient
from src.file_scanner import FileScanner
from src.content_analyzer import ContentAnalyzer
from src.email_notifier import EmailNotifier
from src.config_manager import ConfigManager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('github_monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class GitHubMonitor:
    """Main GitHub monitoring class"""
    
    def __init__(self, config_path: str = '.env'):
        """Initialize the GitHub Monitor
        
        Args:
            config_path: Path to configuration file
        """
        self.config = ConfigManager(config_path)
        self.github_client = GitHubClient(self.config.get('GITHUB_TOKEN'))
        self.file_scanner = FileScanner(self.config.get_scan_rules())
        self.content_analyzer = ContentAnalyzer(self.config.get_content_rules())
        self.email_notifier = EmailNotifier(self.config.get_email_config())
        
        logger.info("GitHub Monitor initialized")
    
    def scan_all_repositories(self) -> List[Dict[str, Any]]:
        """Scan all user repositories for sensitive content
        
        Returns:
            List of scan results for each repository
        """
        logger.info("Starting scan of all repositories")
        
        try:
            repositories = self.github_client.get_user_repositories()
            logger.info(f"Found {len(repositories)} repositories to scan")
            
            all_results = []
            
            for repo in repositories:
                logger.info(f"Scanning repository: {repo['name']}")
                
                try:
                    result = self.scan_repository(repo)
                    all_results.append(result)
                    
                    # Rate limiting
                    time.sleep(1)
                    
                except Exception as e:
                    logger.error(f"Error scanning repository {repo['name']}: {e}")
                    continue
            
            logger.info(f"Completed scan of {len(all_results)} repositories")
            return all_results
            
        except Exception as e:
            logger.error(f"Error during repository scan: {e}")
            raise
    
    def scan_repository(self, repository: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a single repository for sensitive content
        
        Args:
            repository: Repository information from GitHub API
            
        Returns:
            Scan results for the repository
        """
        repo_name = repository['name']
        repo_full_name = repository['full_name']
        
        scan_result = {
            'repository': repo_name,
            'full_name': repo_full_name,
            'scan_time': datetime.now().isoformat(),
            'suspicious_files': [],
            'sensitive_content': [],
            'risk_level': 'LOW',
            'recommendations': []
        }
        
        try:
            # Get repository contents
            contents = self.github_client.get_repository_contents(repo_full_name)
            
            for content_item in contents:
                # Scan file paths for suspicious patterns
                if self.file_scanner.is_suspicious_file(content_item['path']):
                    suspicious_file = {
                        'path': content_item['path'],
                        'type': content_item['type'],
                        'reason': self.file_scanner.get_suspicion_reason(content_item['path']),
                        'download_url': content_item.get('download_url')
                    }
                    scan_result['suspicious_files'].append(suspicious_file)
                
                # Analyze file content for sensitive information
                if content_item['type'] == 'file' and content_item.get('download_url'):
                    try:
                        file_content = self.github_client.get_file_content(content_item['download_url'])
                        
                        if file_content:
                            sensitive_matches = self.content_analyzer.analyze_content(
                                file_content, 
                                content_item['path']
                            )
                            
                            if sensitive_matches:
                                scan_result['sensitive_content'].extend(sensitive_matches)
                    
                    except Exception as e:
                        logger.warning(f"Could not analyze content of {content_item['path']}: {e}")
            
            # Calculate risk level
            scan_result['risk_level'] = self._calculate_risk_level(scan_result)
            
            # Generate recommendations
            scan_result['recommendations'] = self._generate_recommendations(scan_result)
            
            # Send email notification if high risk
            if scan_result['risk_level'] in ['HIGH', 'CRITICAL']:
                self._send_security_alert(scan_result)
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning repository {repo_name}: {e}")
            scan_result['error'] = str(e)
            return scan_result
    
    def _calculate_risk_level(self, scan_result: Dict[str, Any]) -> str:
        """Calculate risk level based on scan results"""
        suspicious_count = len(scan_result['suspicious_files'])
        sensitive_count = len(scan_result['sensitive_content'])
        
        # Check for critical patterns
        critical_patterns = ['password', 'api_key', 'secret', 'token', 'private_key']
        has_critical = any(
            any(pattern in item.get('pattern', '').lower() for pattern in critical_patterns)
            for item in scan_result['sensitive_content']
        )
        
        if has_critical or sensitive_count >= 5:
            return 'CRITICAL'
        elif sensitive_count >= 3 or suspicious_count >= 3:
            return 'HIGH'
        elif sensitive_count >= 1 or suspicious_count >= 1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_recommendations(self, scan_result: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if scan_result['suspicious_files']:
            recommendations.append("Verwijder verdachte bestanden of voeg ze toe aan .gitignore")
            recommendations.append("Controleer of gevoelige bestanden per ongeluk zijn gecommit")
        
        if scan_result['sensitive_content']:
            recommendations.append("Gebruik environment variabelen voor gevoelige configuratie")
            recommendations.append("Implementeer secrets management (bijv. GitHub Secrets)")
            recommendations.append("Voer een security audit uit van gecommitte code")
        
        if scan_result['risk_level'] in ['HIGH', 'CRITICAL']:
            recommendations.append("URGENT: Roteer alle geëxposeerde credentials onmiddellijk")
            recommendations.append("Overweeg de git history te herschrijven om gevoelige data te verwijderen")
        
        return recommendations
    
    def _send_security_alert(self, scan_result: Dict[str, Any]) -> None:
        """Send security alert email for high-risk repositories"""
        try:
            self.email_notifier.send_security_alert(scan_result)
            logger.info(f"Security alert sent for repository: {scan_result['repository']}")
        except Exception as e:
            logger.error(f"Failed to send security alert: {e}")
    
    def generate_report(self, scan_results: List[Dict[str, Any]]) -> str:
        """Generate a comprehensive security report
        
        Args:
            scan_results: Results from repository scans
            
        Returns:
            Formatted report string
        """
        report_lines = [
            "=" * 60,
            "GITHUB SECURITY MONITORING REPORT",
            "=" * 60,
            f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total repositories scanned: {len(scan_results)}",
            ""
        ]
        
        # Summary statistics
        risk_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        total_suspicious_files = 0
        total_sensitive_content = 0
        
        for result in scan_results:
            risk_level = result.get('risk_level', 'LOW')
            risk_counts[risk_level] += 1
            total_suspicious_files += len(result.get('suspicious_files', []))
            total_sensitive_content += len(result.get('sensitive_content', []))
        
        report_lines.extend([
            "RISK LEVEL DISTRIBUTION:",
            f"  Critical: {risk_counts['CRITICAL']}",
            f"  High: {risk_counts['HIGH']}",
            f"  Medium: {risk_counts['MEDIUM']}",
            f"  Low: {risk_counts['LOW']}",
            "",
            f"Total suspicious files found: {total_suspicious_files}",
            f"Total sensitive content instances: {total_sensitive_content}",
            ""
        ])
        
        # Detailed results for high-risk repositories
        high_risk_repos = [
            result for result in scan_results 
            if result.get('risk_level') in ['HIGH', 'CRITICAL']
        ]
        
        if high_risk_repos:
            report_lines.append("HIGH-RISK REPOSITORIES:")
            report_lines.append("-" * 40)
            
            for result in high_risk_repos:
                report_lines.extend([
                    f"Repository: {result['repository']}",
                    f"Risk Level: {result['risk_level']}",
                    f"Suspicious files: {len(result.get('suspicious_files', []))}",
                    f"Sensitive content: {len(result.get('sensitive_content', []))}",
                    "Recommendations:"
                ])
                
                for rec in result.get('recommendations', []):
                    report_lines.append(f"  - {rec}")
                
                report_lines.append("")
        
        return "\n".join(report_lines)


def main():
    """Main application entry point"""
    try:
        monitor = GitHubMonitor()
        
        logger.info("Starting GitHub security monitoring...")
        
        # Scan all repositories
        results = monitor.scan_all_repositories()
        
        # Generate and display report
        report = monitor.generate_report(results)
        print(report)
        
        # Save report to file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"github_security_report_{timestamp}.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        logger.info(f"Security report saved to: {report_file}")
        
        # Check if any critical issues were found
        critical_repos = [r for r in results if r.get('risk_level') == 'CRITICAL']
        if critical_repos:
            logger.warning(f"CRITICAL SECURITY ISSUES FOUND in {len(critical_repos)} repositories!")
            return 1
        
        return 0
        
    except Exception as e:
        logger.error(f"Application error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
