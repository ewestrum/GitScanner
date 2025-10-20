"""
Output formatters for structured reporting in JSON and SARIF formats
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from pathlib import Path
import hashlib
import urllib.parse

logger = logging.getLogger(__name__)


class OutputFormatter:
    """Base class for output formatters"""
    
    def __init__(self, redact_secrets: bool = True):
        """Initialize output formatter
        
        Args:
            redact_secrets: Whether to redact secret values in output
        """
        self.redact_secrets = redact_secrets
        self.timestamp = datetime.now(timezone.utc).isoformat()
    
    def format_output(self, scan_results: Dict[str, Any]) -> str:
        """Format scan results - to be implemented by subclasses"""
        raise NotImplementedError


class JSONFormatter(OutputFormatter):
    """JSON output formatter for structured reporting"""
    
    def format_output(self, scan_results: Dict[str, Any]) -> str:
        """Format scan results as JSON
        
        Args:
            scan_results: Complete scan results dictionary
            
        Returns:
            JSON formatted string
        """
        try:
            formatted_results = self._prepare_json_structure(scan_results)
            
            return json.dumps(formatted_results, indent=2, ensure_ascii=False, default=str)
            
        except Exception as e:
            logger.error(f"Error formatting JSON output: {e}")
            return json.dumps({'error': str(e), 'timestamp': self.timestamp})
    
    def _prepare_json_structure(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare structured JSON output"""
        
        # Extract main components
        repositories = scan_results.get('repositories', [])
        summary = scan_results.get('summary', {})
        
        formatted_repos = []
        
        for repo in repositories:
            repo_data = {
                'repository': {
                    'name': repo.get('name'),
                    'url': repo.get('url'),
                    'private': repo.get('private', False),
                    'description': repo.get('description'),
                    'default_branch': repo.get('default_branch')
                },
                'scan_info': {
                    'scan_timestamp': self.timestamp,
                    'scan_duration': repo.get('scan_duration'),
                    'files_scanned': repo.get('files_scanned', 0),
                    'total_findings': len(repo.get('findings', []))
                },
                'risk_assessment': repo.get('risk_assessment', {}),
                'findings': self._format_findings(repo.get('findings', [])),
                'git_history': repo.get('git_history', {}),
                'file_analysis': repo.get('file_analysis', {})
            }
            
            formatted_repos.append(repo_data)
        
        return {
            'format': 'github-monitor-json',
            'version': '1.0',
            'timestamp': self.timestamp,
            'summary': {
                'total_repositories': summary.get('total_repositories', 0),
                'repositories_with_issues': summary.get('repositories_with_issues', 0),
                'total_findings': summary.get('total_findings', 0),
                'critical_findings': summary.get('critical_findings', 0),
                'high_risk_findings': summary.get('high_risk_findings', 0),
                'scan_duration': summary.get('total_scan_duration')
            },
            'repositories': formatted_repos,
            'configuration': {
                'redact_secrets': self.redact_secrets,
                'output_format': 'json'
            }
        }
    
    def _format_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format findings for JSON output"""
        formatted_findings = []
        
        for finding in findings:
            formatted_finding = {
                'id': self._generate_finding_id(finding),
                'type': finding.get('type'),
                'severity': finding.get('severity', 'MEDIUM'),
                'confidence': finding.get('confidence', 'MEDIUM'),
                'title': finding.get('pattern', finding.get('type', 'Unknown')),
                'description': self._generate_finding_description(finding),
                'location': {
                    'file_path': finding.get('file_path'),
                    'line_number': finding.get('line_number'),
                    'start_position': finding.get('start_pos'),
                    'end_position': finding.get('end_pos')
                },
                'content': {
                    'matched_text': finding.get('match') if not self.redact_secrets else self._redact_content(finding.get('match', '')),
                    'context': finding.get('context', '')
                },
                'risk_score': finding.get('score'),
                'risk_level': finding.get('risk_level'),
                'scoring_breakdown': finding.get('breakdown', {}),
                'metadata': {
                    'entropy': finding.get('entropy'),
                    'file_type': self._get_file_type(finding.get('file_path', '')),
                    'mime_type': finding.get('mime_type')
                }
            }
            
            # Add git history information if available
            if 'commit_hash' in finding:
                formatted_finding['git_history'] = {
                    'commit_hash': finding.get('commit_hash'),
                    'commit_author': finding.get('commit_author'),
                    'commit_email': finding.get('commit_email'),
                    'commit_date': finding.get('commit_date'),
                    'commit_message': finding.get('commit_message')
                }
            
            formatted_findings.append(formatted_finding)
        
        return formatted_findings
    
    def _generate_finding_id(self, finding: Dict[str, Any]) -> str:
        """Generate unique ID for finding"""
        components = [
            finding.get('file_path', ''),
            str(finding.get('line_number', '')),
            finding.get('type', ''),
            finding.get('match', '')[:50]  # First 50 chars of match
        ]
        
        id_string = '|'.join(components)
        return hashlib.md5(id_string.encode('utf-8')).hexdigest()[:16]
    
    def _generate_finding_description(self, finding: Dict[str, Any]) -> str:
        """Generate human-readable description for finding"""
        finding_type = finding.get('type', 'unknown')
        file_path = finding.get('file_path', 'unknown file')
        
        descriptions = {
            'private_key': f"Private key detected in {file_path}",
            'aws_credential': f"AWS credential detected in {file_path}",
            'github_token': f"GitHub token detected in {file_path}",
            'api_key': f"API key detected in {file_path}",
            'jwt_token': f"JWT token detected in {file_path}",
            'database_connection': f"Database connection string detected in {file_path}",
            'credit_card': f"Credit card number detected in {file_path}",
            'email': f"Email address detected in {file_path}",
            'high_entropy_secret': f"High entropy secret detected in {file_path}",
            'base64_secret': f"Base64 encoded secret detected in {file_path}"
        }
        
        return descriptions.get(finding_type, f"Sensitive information ({finding_type}) detected in {file_path}")
    
    def _redact_content(self, content: str) -> str:
        """Redact sensitive content"""
        if not content or len(content) < 8:
            return '*' * len(content)
        
        return content[:2] + '*' * (len(content) - 4) + content[-2:]
    
    def _get_file_type(self, file_path: str) -> str:
        """Get file type from path"""
        return Path(file_path).suffix.lower() if file_path else ''


class SARIFFormatter(OutputFormatter):
    """SARIF (Static Analysis Results Interchange Format) formatter"""
    
    def __init__(self, redact_secrets: bool = True, tool_name: str = "GitHub Monitor"):
        """Initialize SARIF formatter
        
        Args:
            redact_secrets: Whether to redact secret values
            tool_name: Name of the scanning tool
        """
        super().__init__(redact_secrets)
        self.tool_name = tool_name
    
    def format_output(self, scan_results: Dict[str, Any]) -> str:
        """Format scan results as SARIF
        
        Args:
            scan_results: Complete scan results dictionary
            
        Returns:
            SARIF formatted JSON string
        """
        try:
            sarif_document = self._create_sarif_document(scan_results)
            
            return json.dumps(sarif_document, indent=2, ensure_ascii=False)
            
        except Exception as e:
            logger.error(f"Error formatting SARIF output: {e}")
            return json.dumps({'error': str(e), 'timestamp': self.timestamp})
    
    def _create_sarif_document(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create SARIF document structure"""
        
        # Create rules for each finding type
        rules = self._create_rules(scan_results)
        
        # Create results from findings
        results = []
        repositories = scan_results.get('repositories', [])
        
        for repo in repositories:
            repo_results = self._create_results_for_repository(repo, rules)
            results.extend(repo_results)
        
        # Create tool information
        tool = {
            'driver': {
                'name': self.tool_name,
                'version': '1.0.0',
                'informationUri': 'https://github.com/your-org/github-monitor',
                'rules': list(rules.values())
            }
        }
        
        # Create SARIF document
        sarif_doc = {
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'version': '2.1.0',
            'runs': [
                {
                    'tool': tool,
                    'results': results,
                    'invocations': [
                        {
                            'startTimeUtc': self.timestamp,
                            'executionSuccessful': True
                        }
                    ],
                    'artifacts': self._create_artifacts(repositories),
                    'properties': {
                        'scan_summary': scan_results.get('summary', {}),
                        'github_monitor_version': '1.0'
                    }
                }
            ]
        }
        
        return sarif_doc
    
    def _create_rules(self, scan_results: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Create SARIF rules for each finding type"""
        
        # Collect all unique finding types
        finding_types = set()
        repositories = scan_results.get('repositories', [])
        
        for repo in repositories:
            for finding in repo.get('findings', []):
                finding_types.add(finding.get('type', 'unknown'))
        
        rules = {}
        
        rule_definitions = {
            'private_key': {
                'name': 'Private Key Detection',
                'shortDescription': {'text': 'Private cryptographic key detected'},
                'fullDescription': {'text': 'A private cryptographic key was detected in the code. This could lead to unauthorized access if exposed.'},
                'defaultConfiguration': {'level': 'error'},
                'help': {'text': 'Remove private keys from source code and use secure key management systems.'}
            },
            'aws_credential': {
                'name': 'AWS Credential Detection',
                'shortDescription': {'text': 'AWS access credential detected'},
                'fullDescription': {'text': 'An AWS access key or secret was detected. This could provide unauthorized access to AWS resources.'},
                'defaultConfiguration': {'level': 'error'},
                'help': {'text': 'Use AWS IAM roles or environment variables for credential management.'}
            },
            'github_token': {
                'name': 'GitHub Token Detection',
                'shortDescription': {'text': 'GitHub access token detected'},
                'fullDescription': {'text': 'A GitHub personal access token or OAuth token was detected.'},
                'defaultConfiguration': {'level': 'error'},
                'help': {'text': 'Revoke the exposed token and use GitHub App tokens or environment variables.'}
            },
            'api_key': {
                'name': 'API Key Detection',
                'shortDescription': {'text': 'API key detected'},
                'fullDescription': {'text': 'An API key for a third-party service was detected.'},
                'defaultConfiguration': {'level': 'error'},
                'help': {'text': 'Remove API keys from source code and use environment variables or secure vaults.'}
            },
            'jwt_token': {
                'name': 'JWT Token Detection',
                'shortDescription': {'text': 'JWT token detected'},
                'fullDescription': {'text': 'A JSON Web Token (JWT) was detected in the code.'},
                'defaultConfiguration': {'level': 'warning'},
                'help': {'text': 'Avoid hardcoding JWT tokens. Use secure token storage mechanisms.'}
            },
            'database_connection': {
                'name': 'Database Connection String',
                'shortDescription': {'text': 'Database connection string detected'},
                'fullDescription': {'text': 'A database connection string with embedded credentials was detected.'},
                'defaultConfiguration': {'level': 'error'},
                'help': {'text': 'Use environment variables or secure configuration for database credentials.'}
            },
            'high_entropy_secret': {
                'name': 'High Entropy Secret',
                'shortDescription': {'text': 'High entropy string detected'},
                'fullDescription': {'text': 'A string with high entropy was detected, which may be a secret or API key.'},
                'defaultConfiguration': {'level': 'warning'},
                'help': {'text': 'Review the detected string to ensure it is not a secret that should be protected.'}
            }
        }
        
        for finding_type in finding_types:
            rule_id = f"github-monitor-{finding_type}"
            
            if finding_type in rule_definitions:
                rule_config = rule_definitions[finding_type]
            else:
                rule_config = {
                    'name': f'{finding_type.replace("_", " ").title()} Detection',
                    'shortDescription': {'text': f'{finding_type.replace("_", " ").title()} detected'},
                    'fullDescription': {'text': f'A {finding_type.replace("_", " ")} was detected in the code.'},
                    'defaultConfiguration': {'level': 'warning'},
                    'help': {'text': 'Review the detected content for potential security issues.'}
                }
            
            rules[finding_type] = {
                'id': rule_id,
                **rule_config
            }
        
        return rules
    
    def _create_results_for_repository(self, repo: Dict[str, Any], rules: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create SARIF results for a repository"""
        results = []
        
        for finding in repo.get('findings', []):
            result = self._create_sarif_result(finding, rules, repo)
            results.append(result)
        
        return results
    
    def _create_sarif_result(self, finding: Dict[str, Any], rules: Dict[str, Dict[str, Any]], repo: Dict[str, Any]) -> Dict[str, Any]:
        """Create a SARIF result from a finding"""
        
        finding_type = finding.get('type', 'unknown')
        rule_id = f"github-monitor-{finding_type}"
        
        # Map severity to SARIF level
        severity_map = {
            'CRITICAL': 'error',
            'HIGH': 'error', 
            'MEDIUM': 'warning',
            'LOW': 'note',
            'INFO': 'note'
        }
        
        severity = finding.get('severity', 'MEDIUM')
        sarif_level = severity_map.get(severity, 'warning')
        
        # Create location
        file_path = finding.get('file_path', '')
        
        # Normalize file path for SARIF (use forward slashes)
        normalized_path = file_path.replace('\\\\', '/')
        
        location = {
            'physicalLocation': {
                'artifactLocation': {
                    'uri': normalized_path
                },
                'region': {
                    'startLine': finding.get('line_number', 1),
                    'startColumn': 1
                }
            }
        }
        
        # Add position information if available
        if 'start_pos' in finding and 'end_pos' in finding:
            location['physicalLocation']['region'].update({
                'charOffset': finding.get('start_pos'),
                'charLength': finding.get('end_pos', 0) - finding.get('start_pos', 0)
            })
        
        # Create message
        message_text = finding.get('pattern', finding_type)
        if self.redact_secrets:
            match_text = self._redact_content(finding.get('match', ''))
        else:
            match_text = finding.get('match', '')
        
        if match_text:
            message_text += f": {match_text}"
        
        result = {
            'ruleId': rule_id,
            'level': sarif_level,
            'message': {
                'text': message_text
            },
            'locations': [location],
            'properties': {
                'confidence': finding.get('confidence', 'MEDIUM'),
                'risk_score': finding.get('score'),
                'risk_level': finding.get('risk_level'),
                'repository': repo.get('name'),
                'finding_type': finding_type
            }
        }
        
        # Add entropy information if available
        if 'entropy' in finding:
            result['properties']['entropy'] = finding['entropy']
        
        # Add git history information if available
        if 'commit_hash' in finding:
            result['properties']['git_commit'] = {
                'hash': finding.get('commit_hash'),
                'author': finding.get('commit_author'),
                'date': finding.get('commit_date'),
                'message': finding.get('commit_message')
            }
        
        return result
    
    def _create_artifacts(self, repositories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create SARIF artifacts list"""
        artifacts = []
        seen_files = set()
        
        for repo in repositories:
            for finding in repo.get('findings', []):
                file_path = finding.get('file_path', '')
                if file_path and file_path not in seen_files:
                    artifacts.append({
                        'location': {
                            'uri': file_path.replace('\\\\', '/')
                        },
                        'mimeType': finding.get('mime_type', 'text/plain'),
                        'properties': {
                            'repository': repo.get('name')
                        }
                    })
                    seen_files.add(file_path)
        
        return artifacts
    
    def _redact_content(self, content: str) -> str:
        """Redact sensitive content for SARIF output"""
        if not content or len(content) < 8:
            return '[REDACTED]'
        
        return content[:2] + '[REDACTED]' + content[-2:]


class ReportGenerator:
    """Generate various output formats for scan results"""
    
    def __init__(self, redact_secrets: bool = True):
        """Initialize report generator
        
        Args:
            redact_secrets: Whether to redact secret values in output
        """
        self.redact_secrets = redact_secrets
        self.formatters = {
            'json': JSONFormatter(redact_secrets),
            'sarif': SARIFFormatter(redact_secrets)
        }
    
    def generate_report(self, scan_results: Dict[str, Any], format_type: str = 'json') -> str:
        """Generate report in specified format
        
        Args:
            scan_results: Complete scan results
            format_type: Output format ('json' or 'sarif')
            
        Returns:
            Formatted report string
        """
        if format_type not in self.formatters:
            raise ValueError(f"Unsupported format: {format_type}")
        
        formatter = self.formatters[format_type]
        return formatter.format_output(scan_results)
    
    def save_report(self, scan_results: Dict[str, Any], output_path: str, format_type: str = 'json'):
        """Save report to file
        
        Args:
            scan_results: Complete scan results
            output_path: Path to save the report
            format_type: Output format ('json' or 'sarif')
        """
        try:
            report_content = self.generate_report(scan_results, format_type)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            logger.info(f"Report saved to {output_path} in {format_type.upper()} format")
            
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            raise