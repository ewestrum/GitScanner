"""
Enhanced GitHub Monitor with enterprise-level features
"""

import os
import sys
import logging
import time
import shutil
import tempfile
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

# Add src directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, 'src')
sys.path.insert(0, src_dir)

from config_manager import ConfigManager
from github_client import GitHubClient
from enhanced_file_scanner import EnhancedFileScanner
from enhanced_content_analyzer import EnhancedContentAnalyzer
from git_history_analyzer import GitHistoryAnalyzer
from risk_scoring_engine import RiskScoringEngine, create_default_scoring_config
from output_formatters import ReportGenerator
from performance_optimizer import PerformanceOptimizer, create_default_performance_config
from advanced_config_manager import AdvancedConfigManager
from email_notifier_extended import EmailNotifier

logger = logging.getLogger(__name__)


class EnhancedGitHubMonitor:
    """Enhanced GitHub Monitor with enterprise-level security scanning capabilities"""
    
    def __init__(self, config_path: str = '.env'):
        """Initialize enhanced GitHub monitor
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        
        # Load configuration
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.config_data  # Use config_data property
        
        # Initialize advanced configuration
        # Don't use YAML config file if PyYAML is not available
        advanced_config_path = self.config.get('ADVANCED_CONFIG_PATH', 'github_monitor_rules.yaml')
        
        # Check if it's a YAML file and PyYAML is available
        is_yaml = advanced_config_path.endswith('.yaml') or advanced_config_path.endswith('.yml')
        
        if os.path.exists(advanced_config_path) and (not is_yaml or 'yaml' in sys.modules):
            self.advanced_config = AdvancedConfigManager(advanced_config_path)
        else:
            # Use default config if file doesn't exist or is YAML but PyYAML not available
            self.advanced_config = AdvancedConfigManager()
            if is_yaml and 'yaml' not in sys.modules:
                logger.info(f"PyYAML not available, using default config instead of {advanced_config_path}")
            else:
                logger.info(f"Advanced config file not found at {advanced_config_path}, using defaults")
        
        # Initialize components
        self._init_components()
        
        # Scan statistics
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'total_repositories': 0,
            'total_files_scanned': 0,
            'total_findings': 0,
            'repositories_with_issues': 0,
            'critical_findings': 0,
            'high_risk_findings': 0
        }
        
        logger.info("Enhanced GitHub Monitor initialized")
    
    def _init_components(self):
        """Initialize all monitoring components"""
        
        # GitHub client - use existing config format
        github_token = self.config.get('GITHUB_TOKEN')
        
        self.github_client = GitHubClient(github_token)
        
        # Performance optimizer - map from existing config
        performance_config = create_default_performance_config()
        performance_config.update({
            'max_file_size': self.config.get('MAX_FILE_SIZE', 104857600),  # 100MB for security scanning
            'max_workers': 4  # Use default for now
        })
        self.performance_optimizer = PerformanceOptimizer(performance_config)
        
        # Enhanced file scanner
        file_scanner_config = self.config.get('file_scanner', {})
        self.file_scanner = EnhancedFileScanner(file_scanner_config)
        
        # Enhanced content analyzer
        content_rules = {
            'entropy_threshold': 4.5,  # Default entropy threshold
            'max_file_size': self.config.get('MAX_FILE_SIZE', 10485760)
        }
        self.content_analyzer = EnhancedContentAnalyzer(content_rules)
        
        # Git history analyzer
        max_commits = 500  # Default value
        self.git_history_analyzer = GitHistoryAnalyzer(
            self.content_analyzer,
            max_commits=max_commits
        )
        
        # Risk scoring engine
        scoring_config = create_default_scoring_config()
        # Use default thresholds for now
        self.risk_scoring_engine = RiskScoringEngine(scoring_config)
        
        # Report generator
        redact_secrets = True  # Default to redacting secrets
        self.report_generator = ReportGenerator(redact_secrets)
        
        # Email notifier - use existing email config format
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
    
    def cleanup_temp_directories(self):
        """Clean up any existing temporary directories before scanning"""
        temp_dir = tempfile.gettempdir()
        logger.info(f"Cleaning up temporary directories in: {temp_dir}")
            
        # Clean up common repository temp directories
        common_repo_names = ['GitScanner', 'AnimatronicMask', 'WaterClockLabTube', 
                           'WLED_PCB_KiCAD', 'ESP32_Wifi_Controller']
        
        cleanup_count = 0
        for repo_name in common_repo_names:
            repo_temp_path = os.path.join(temp_dir, repo_name)
            if os.path.exists(repo_temp_path):
                try:
                    # First try normal removal
                    shutil.rmtree(repo_temp_path, ignore_errors=False)
                    logger.info(f"Removed temp directory: {repo_temp_path}")
                    cleanup_count += 1
                except PermissionError:
                    # If permission error, try to change permissions and retry
                    try:
                        for root, dirs, files in os.walk(repo_temp_path):
                            for dir in dirs:
                                os.chmod(os.path.join(root, dir), 0o777)
                            for file in files:
                                os.chmod(os.path.join(root, file), 0o777)
                        shutil.rmtree(repo_temp_path, ignore_errors=False)
                        logger.info(f"Removed temp directory after permission fix: {repo_temp_path}")
                        cleanup_count += 1
                    except Exception as e:
                        logger.warning(f"Could not remove temp directory {repo_temp_path}: {e}")
                except Exception as e:
                    logger.warning(f"Could not remove temp directory {repo_temp_path}: {e}")
        
        if cleanup_count > 0:
            logger.info(f"Cleaned up {cleanup_count} temporary directories")
        else:
            logger.info("No temporary directories found to clean up")
    
    def scan_all_repositories(self, 
                            include_git_history: bool = True,
                            max_repositories: Optional[int] = None,
                            repository_filter: Optional[str] = None) -> Dict[str, Any]:
        """Scan all accessible repositories
        
        Args:
            include_git_history: Whether to analyze git history
            max_repositories: Maximum number of repositories to scan
            repository_filter: Filter repositories by name pattern
            
        Returns:
            Complete scan results
        """
        # Clean up temporary directories before starting scan
        self.cleanup_temp_directories()
        
        self.scan_stats['start_time'] = time.time()
        logger.info("Starting enhanced repository scan")
        
        try:
            # Get repositories
            repositories = self.github_client.get_user_repositories()
            
            if repository_filter:
                repositories = [
                    repo for repo in repositories 
                    if repository_filter.lower() in repo['name'].lower()
                ]
            
            if max_repositories:
                repositories = repositories[:max_repositories]
            
            self.scan_stats['total_repositories'] = len(repositories)
            logger.info(f"Scanning {len(repositories)} repositories")
            
            # Scan each repository
            scanned_repositories = []
            
            for i, repo in enumerate(repositories, 1):
                logger.info(f"Scanning repository {i}/{len(repositories)}: {repo['name']}")
                
                try:
                    repo_results = self._scan_repository(repo, include_git_history)
                    scanned_repositories.append(repo_results)
                    
                    # Update statistics
                    if repo_results.get('findings'):
                        self.scan_stats['repositories_with_issues'] += 1
                        self.scan_stats['total_findings'] += len(repo_results['findings'])
                        
                        # Count severity levels
                        for finding in repo_results['findings']:
                            severity = finding.get('severity', '').upper()
                            if severity == 'CRITICAL':
                                self.scan_stats['critical_findings'] += 1
                            elif severity == 'HIGH':
                                self.scan_stats['high_risk_findings'] += 1
                    
                    self.scan_stats['total_files_scanned'] += repo_results.get('files_scanned', 0)
                    
                except Exception as e:
                    logger.error(f"Error scanning repository {repo['name']}: {e}")
                    continue
            
            self.scan_stats['end_time'] = time.time()
            
            # Compile final results
            scan_results = {
                'scan_info': {
                    'timestamp': datetime.now().isoformat(),
                    'duration': self.scan_stats['end_time'] - self.scan_stats['start_time'],
                    'github_monitor_version': '2.0.0',
                    'features_enabled': self._get_enabled_features()
                },
                'summary': self.scan_stats.copy(),
                'repositories': scanned_repositories,
                # Email template compatibility
                'files_scanned': self.scan_stats['total_files_scanned']
            }
            
            # Calculate overall risk assessment
            scan_results['risk_assessment'] = self._calculate_overall_risk(scanned_repositories)
            
            # Convert findings to email template format
            all_suspicious_files = []
            all_sensitive_content = []
            
            for repo in scanned_repositories:
                for finding in repo.get('findings', []):
                    if finding.get('type') == 'file':
                        # File-based findings go to suspicious_files
                        all_suspicious_files.append({
                            'name': finding.get('file_path', finding.get('path', 'Unknown')),
                            'risk': finding.get('severity', 'MEDIUM'),
                            'reason': finding.get('description', finding.get('message', 'Suspicious file detected')),
                            'repository': repo['name']
                        })
                    else:
                        # Content-based findings go to sensitive_content
                        all_sensitive_content.append({
                            'type': finding.get('rule', finding.get('type', 'Unknown')),
                            'description': finding.get('description', finding.get('message', 'Sensitive content found')),
                            'file': finding.get('file_path', finding.get('path', 'Unknown')),
                            'line': finding.get('line_number', 0),
                            'severity': finding.get('severity', 'MEDIUM'),
                            'repository': repo['name']
                        })
            
            # Add email template compatibility fields
            scan_results['suspicious_files'] = all_suspicious_files
            scan_results['sensitive_content'] = all_sensitive_content
            
            logger.info(f"Scan completed: {self.scan_stats['total_findings']} findings in {len(scanned_repositories)} repositories")
            
            return scan_results
            
        except Exception as e:
            logger.error(f"Error during repository scan: {e}")
            raise
    
    def _scan_repository(self, repo: Dict[str, Any], include_git_history: bool = True) -> Dict[str, Any]:
        """Scan a single repository with enhanced capabilities
        
        Args:
            repo: Repository information
            include_git_history: Whether to analyze git history
            
        Returns:
            Repository scan results
        """
        repo_start_time = time.time()
        
        try:
            # Clone/download repository
            local_path = self.github_client.clone_repository(repo['clone_url'], repo['name'])
            
            if not local_path or not os.path.exists(local_path):
                logger.error(f"Failed to download repository: {repo['name']}")
                return {
                    'name': repo['name'],
                    'error': 'Failed to download repository',
                    'findings': [],
                    'files_scanned': 0
                }
            
            # Scan files with enhanced scanner
            file_scan_results = self._scan_repository_files(local_path, repo['name'])
            
            # Analyze git history if requested
            git_history_results = {}
            if include_git_history:
                git_history_results = self._analyze_repository_history(local_path, repo['name'])
            
            # Combine all findings
            all_findings = file_scan_results['findings'] + git_history_results.get('matches', [])
            
            # Apply risk scoring
            risk_assessment = self.risk_scoring_engine.calculate_repository_risk_score(all_findings)
            
            # Extract findings with fallback
            findings = risk_assessment.get('scored_findings', all_findings)
            
            # Clean up temporary files
            self.github_client.cleanup_temp_files()
            
            scan_duration = time.time() - repo_start_time
            
            return {
                'name': repo['name'],
                'url': repo['html_url'],
                'private': repo['private'],
                'description': repo.get('description', ''),
                'default_branch': repo.get('default_branch', 'main'),
                'scan_duration': scan_duration,
                'files_scanned': file_scan_results['files_scanned'],
                'findings': findings,
                'risk_assessment': {
                    'overall_score': risk_assessment.get('overall_score', 0.0),
                    'risk_level': risk_assessment.get('risk_level', 'INFO'),
                    'risk_distribution': risk_assessment.get('risk_distribution', {}),
                    'max_individual_score': risk_assessment.get('max_individual_score', 0.0),
                    'average_score': risk_assessment.get('average_score', 0.0)
                },
                'file_analysis': file_scan_results.get('file_analysis', {}),
                'git_history': git_history_results,
                'scan_metadata': {
                    'advanced_rules_used': len(self.advanced_config.regex_rules),
                    'performance_optimizations': self.performance_optimizer.get_cache_stats(),
                    'scan_timestamp': datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Error scanning repository {repo['name']}: {e}")
            return {
                'name': repo['name'],
                'error': str(e),
                'findings': [],
                'files_scanned': 0
            }
    
    def _scan_repository_files(self, repo_path: str, repo_name: str) -> Dict[str, Any]:
        """Scan repository files with enhanced detection
        
        Args:
            repo_path: Local path to repository
            repo_name: Repository name
            
        Returns:
            File scanning results
        """
        logger.info(f"Scanning files in {repo_name}")
        
        try:
            # Get all files in repository
            all_files = []
            for root, dirs, files in os.walk(repo_path):
                # Apply directory filtering
                self.performance_optimizer.get_directory_filter()(dirs)
                
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, repo_path)
                    
                    # Check if file should be scanned
                    if (self.performance_optimizer.should_scan_file(relative_path) and
                        self.advanced_config.should_scan_path(relative_path)):
                        all_files.append(file_path)
            
            # Optimize scanning order
            optimized_files = self.performance_optimizer.optimize_scan_order(all_files)
            
            logger.info(f"Scanning {len(optimized_files)} files in {repo_name}")
            
            # Scan files
            all_findings = []
            file_analysis = {
                'total_files': len(all_files),
                'scanned_files': len(optimized_files),
                'file_types': {},
                'large_files_skipped': len(all_files) - len(optimized_files)
            }
            
            for file_path in optimized_files:
                try:
                    relative_path = os.path.relpath(file_path, repo_path)
                    
                    # Read file efficiently
                    content = self.performance_optimizer.read_file_efficiently(file_path)
                    if content is None:
                        continue
                    
                    # Enhanced file analysis
                    file_info = self.file_scanner.analyze_file(file_path, content)
                    
                    # Track file types
                    file_ext = Path(file_path).suffix.lower()
                    file_analysis['file_types'][file_ext] = file_analysis['file_types'].get(file_ext, 0) + 1
                    
                    # Skip if file is classified as non-sensitive
                    if file_info.get('classification') == 'safe':
                        continue
                    
                    # Apply advanced content analysis
                    content_findings = self.content_analyzer.analyze_content(content, relative_path)
                    
                    # Apply advanced regex rules
                    regex_findings = self.advanced_config.apply_regex_rules(content, relative_path)
                    
                    # Combine findings
                    file_findings = content_findings + regex_findings
                    
                    # Add file metadata to findings
                    for finding in file_findings:
                        finding.update({
                            'file_size': file_info.get('size', 0),
                            'mime_type': file_info.get('mime_type'),
                            'encoding': file_info.get('encoding'),
                            'file_classification': file_info.get('classification')
                        })
                    
                    all_findings.extend(file_findings)
                    
                except Exception as e:
                    logger.debug(f"Error scanning file {file_path}: {e}")
                    continue
            
            return {
                'findings': all_findings,
                'files_scanned': len(optimized_files),
                'file_analysis': file_analysis
            }
            
        except Exception as e:
            logger.error(f"Error scanning repository files: {e}")
            return {
                'findings': [],
                'files_scanned': 0,
                'file_analysis': {},
                'error': str(e)
            }
    
    def _analyze_repository_history(self, repo_path: str, repo_name: str) -> Dict[str, Any]:
        """Analyze repository git history
        
        Args:
            repo_path: Local path to repository
            repo_name: Repository name
            
        Returns:
            Git history analysis results
        """
        logger.info(f"Analyzing git history for {repo_name}")
        
        try:
            # Analyze recent commits (last 30 days)
            recent_results = self.git_history_analyzer.analyze_recent_commits(repo_path, days=30)
            
            # If no recent findings, analyze full history with limit
            if not recent_results.get('matches'):
                full_results = self.git_history_analyzer.analyze_repository_history(repo_path)
                return full_results
            
            return recent_results
            
        except Exception as e:
            logger.error(f"Error analyzing git history for {repo_name}: {e}")
            return {
                'error': str(e),
                'matches': [],
                'commits_analyzed': 0
            }
    
    def _calculate_overall_risk(self, repositories: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall risk assessment across all repositories
        
        Args:
            repositories: List of repository scan results
            
        Returns:
            Overall risk assessment
        """
        if not repositories:
            return {
                'overall_risk_level': 'INFO',
                'total_critical_repos': 0,
                'total_high_risk_repos': 0,
                'average_repo_score': 0.0,
                'highest_risk_repo': None
            }
        
        critical_repos = 0
        high_risk_repos = 0
        repo_scores = []
        highest_risk_repo = None
        highest_score = 0
        
        for repo in repositories:
            risk_assessment = repo.get('risk_assessment', {})
            risk_level = risk_assessment.get('risk_level', 'INFO')
            repo_score = risk_assessment.get('overall_score', 0)
            
            repo_scores.append(repo_score)
            
            if risk_level == 'CRITICAL':
                critical_repos += 1
            elif risk_level == 'HIGH':
                high_risk_repos += 1
            
            if repo_score > highest_score:
                highest_score = repo_score
                highest_risk_repo = {
                    'name': repo['name'],
                    'score': repo_score,
                    'risk_level': risk_level
                }
        
        avg_score = sum(repo_scores) / len(repo_scores) if repo_scores else 0
        
        # Determine overall risk level
        if critical_repos > 0:
            overall_risk = 'CRITICAL'
        elif high_risk_repos > 0:
            overall_risk = 'HIGH'
        elif avg_score > 20:
            overall_risk = 'MEDIUM'
        else:
            overall_risk = 'LOW'
        
        return {
            'overall_risk_level': overall_risk,
            'total_critical_repos': critical_repos,
            'total_high_risk_repos': high_risk_repos,
            'average_repo_score': round(avg_score, 1),
            'highest_risk_repo': highest_risk_repo,
            'risk_score_distribution': {
                'min': min(repo_scores) if repo_scores else 0,
                'max': max(repo_scores) if repo_scores else 0,
                'median': sorted(repo_scores)[len(repo_scores)//2] if repo_scores else 0
            }
        }
    
    def _get_enabled_features(self) -> List[str]:
        """Get list of enabled enterprise features"""
        features = []
        
        if self.file_scanner:
            features.append('enhanced_file_scanning')
        if self.content_analyzer:
            features.append('deterministic_content_analysis')
        if self.git_history_analyzer:
            features.append('git_history_analysis')
        if self.risk_scoring_engine:
            features.append('risk_scoring')
        if self.performance_optimizer:
            features.append('performance_optimization')
        if self.advanced_config:
            features.append('advanced_regex_rules')
        
        return features
    
    def generate_report(self, scan_results: Dict[str, Any], format_type: str = 'json') -> str:
        """Generate scan report in specified format
        
        Args:
            scan_results: Complete scan results
            format_type: Output format ('json' or 'sarif')
            
        Returns:
            Formatted report string
        """
        return self.report_generator.generate_report(scan_results, format_type)
    
    def save_report(self, scan_results: Dict[str, Any], output_path: str, format_type: str = 'json'):
        """Save scan report to file
        
        Args:
            scan_results: Complete scan results
            output_path: Path to save report
            format_type: Output format ('json' or 'sarif')
        """
        self.report_generator.save_report(scan_results, output_path, format_type)
    
    def send_email_notification(self, scan_results: Dict[str, Any]) -> bool:
        """Send email notification with scan results
        
        Args:
            scan_results: Complete scan results
            
        Returns:
            True if email sent successfully
        """
        if not self.email_notifier:
            logger.warning("Email notifier not configured")
            return False
        
        try:
            return self.email_notifier.send_notification(scan_results)
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
            return False
    
    def cleanup(self):
        """Clean up resources and temporary files"""
        try:
            if hasattr(self, 'github_client'):
                self.github_client.cleanup_temp_files()
            
            if hasattr(self, 'performance_optimizer'):
                self.performance_optimizer.clear_caches()
            
            if hasattr(self, 'git_history_analyzer'):
                self.git_history_analyzer.clear_cache()
            
            logger.info("Cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


def main():
    """Main entry point for enhanced GitHub monitor"""
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('github_monitor_enhanced.log'),
            logging.StreamHandler()
        ]
    )
    
    try:
        # Initialize enhanced monitor
        monitor = EnhancedGitHubMonitor()
        
        # Run scan
        results = monitor.scan_all_repositories(
            include_git_history=True,
            max_repositories=None  # Scan all repositories
        )
        
        # Generate reports
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON report
        json_path = f"github_monitor_report_{timestamp}.json"
        monitor.save_report(results, json_path, 'json')
        print(f"JSON report saved to: {json_path}")
        
        # Save SARIF report
        sarif_path = f"github_monitor_report_{timestamp}.sarif"
        monitor.save_report(results, sarif_path, 'sarif')
        print(f"SARIF report saved to: {sarif_path}")
        
        # Send email notification
        if monitor.send_email_notification(results):
            print("Email notification sent successfully")
        
        # Print summary
        summary = results['summary']
        print(f"\\nScan Summary:")
        print(f"- Repositories scanned: {summary['total_repositories']}")
        print(f"- Files scanned: {summary['total_files_scanned']}")
        print(f"- Total findings: {summary['total_findings']}")
        print(f"- Critical findings: {summary['critical_findings']}")
        print(f"- High risk findings: {summary['high_risk_findings']}")
        print(f"- Repositories with issues: {summary['repositories_with_issues']}")
        
        risk_assessment = results.get('risk_assessment', {})
        print(f"- Overall risk level: {risk_assessment.get('overall_risk_level', 'UNKNOWN')}")
        
        # Cleanup
        monitor.cleanup()
        
    except Exception as e:
        logger.error(f"Error in main: {e}")
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()