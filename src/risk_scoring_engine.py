"""
Risk Scoring Engine for security findings with configurable scoring rules
"""

import logging
from typing import Dict, List, Any, Optional
from enum import Enum
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk level enumeration"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH" 
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskScoringEngine:
    """Calculate risk scores for security findings with configurable rules"""
    
    def __init__(self, scoring_config: Dict[str, Any]):
        """Initialize risk scoring engine
        
        Args:
            scoring_config: Configuration dictionary with scoring rules
        """
        self.scoring_config = scoring_config
        self._init_default_rules()
        self._load_custom_rules()
        
        # Risk thresholds
        self.risk_thresholds = scoring_config.get('risk_thresholds', {
            'CRITICAL': 100,
            'HIGH': 50,
            'MEDIUM': 20,
            'LOW': 5,
            'INFO': 0
        })
        
        logger.info("Risk scoring engine initialized")
    
    def _init_default_rules(self):
        """Initialize default scoring rules"""
        self.base_scores = {
            # Credential types (highest risk)
            'private_key': 100,
            'aws_credential': 90,
            'github_token': 85,
            'api_key': 80,
            'jwt_token': 75,
            'database_connection': 70,
            
            # Financial data
            'credit_card': 85,
            'iban': 80,
            'bsn': 75,  # Dutch social security number
            
            # Personal data
            'email': 25,
            'ip_address': 15,
            
            # High entropy secrets
            'high_entropy_secret': 60,
            'base64_secret': 40,
            
            # Default for unknown types
            'unknown': 30
        }
        
        # File type multipliers
        self.file_type_multipliers = {
            # Production files (higher risk)
            '.env': 1.5,
            '.config': 1.3,
            '.ini': 1.3,
            '.conf': 1.3,
            '.yaml': 1.2,
            '.yml': 1.2,
            '.json': 1.2,
            '.xml': 1.1,
            
            # Source code (medium risk)
            '.py': 1.1,
            '.js': 1.1,
            '.ts': 1.1,
            '.java': 1.1,
            '.cs': 1.1,
            '.cpp': 1.1,
            '.c': 1.1,
            '.php': 1.1,
            '.rb': 1.1,
            '.go': 1.1,
            '.rs': 1.1,
            
            # Documentation (lower risk)
            '.md': 0.8,
            '.txt': 0.8,
            '.rst': 0.8,
            
            # Test files (lower risk)
            '_test.py': 0.7,
            '.test.js': 0.7,
            '_spec.rb': 0.7,
            'test_': 0.7,
            'spec_': 0.7,
        }
        
        # Path-based risk modifiers
        self.path_risk_modifiers = {
            # Production indicators (higher risk)
            'prod': 1.4,
            'production': 1.4,
            'live': 1.3,
            'staging': 1.2,
            'config': 1.2,
            'secrets': 1.5,
            'keys': 1.4,
            'credentials': 1.4,
            
            # Development indicators (medium risk)
            'dev': 1.1,
            'development': 1.1,
            
            # Test indicators (lower risk)
            'test': 0.7,
            'tests': 0.7,
            'spec': 0.7,
            'mock': 0.6,
            'example': 0.6,
            'sample': 0.6,
            'demo': 0.6,
            'fixture': 0.6,
        }
        
        # Context-based modifiers
        self.context_modifiers = {
            'in_comment': 0.8,      # Found in comment
            'in_string': 1.0,       # Found in string literal
            'in_assignment': 1.2,   # Found in variable assignment
            'in_env_file': 1.3,     # Found in environment file
            'in_config': 1.2,       # Found in configuration
            'placeholder': 0.1,     # Obvious placeholder
            'example': 0.2,         # Example value
            'test_data': 0.5,       # Test data
        }
        
        # Severity multipliers based on confidence
        self.confidence_multipliers = {
            'HIGH': 1.0,
            'MEDIUM': 0.8,
            'LOW': 0.6
        }
    
    def _load_custom_rules(self):
        """Load custom scoring rules from configuration"""
        custom_scores = self.scoring_config.get('custom_base_scores', {})
        self.base_scores.update(custom_scores)
        
        custom_multipliers = self.scoring_config.get('custom_file_multipliers', {})
        self.file_type_multipliers.update(custom_multipliers)
        
        custom_path_modifiers = self.scoring_config.get('custom_path_modifiers', {})
        self.path_risk_modifiers.update(custom_path_modifiers)
    
    def calculate_score(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk score for a security finding
        
        Args:
            finding: Dictionary containing finding details
            
        Returns:
            Dictionary with score, risk level, and scoring breakdown
        """
        try:
            # Get base score
            finding_type = finding.get('type', 'unknown')
            base_score = self.base_scores.get(finding_type, self.base_scores['unknown'])
            
            # Initialize scoring breakdown
            breakdown = {
                'base_score': base_score,
                'multipliers': {},
                'modifiers': {},
                'final_score': base_score
            }
            
            current_score = float(base_score)
            
            # Apply file type multiplier
            file_path = finding.get('file_path', '')
            file_multiplier = self._get_file_type_multiplier(file_path)
            if file_multiplier != 1.0:
                current_score *= file_multiplier
                breakdown['multipliers']['file_type'] = file_multiplier
            
            # Apply path-based modifiers
            path_modifier = self._get_path_risk_modifier(file_path)
            if path_modifier != 1.0:
                current_score *= path_modifier
                breakdown['modifiers']['path_context'] = path_modifier
            
            # Apply context modifiers
            context_modifier = self._get_context_modifier(finding)
            if context_modifier != 1.0:
                current_score *= context_modifier
                breakdown['modifiers']['context'] = context_modifier
            
            # Apply confidence multiplier
            confidence = finding.get('confidence', 'MEDIUM')
            confidence_multiplier = self.confidence_multipliers.get(confidence, 0.8)
            if confidence_multiplier != 1.0:
                current_score *= confidence_multiplier
                breakdown['multipliers']['confidence'] = confidence_multiplier
            
            # Apply entropy bonus for high-entropy findings
            if 'entropy' in finding:
                entropy_bonus = self._calculate_entropy_bonus(finding['entropy'])
                if entropy_bonus != 1.0:
                    current_score *= entropy_bonus
                    breakdown['multipliers']['entropy'] = entropy_bonus
            
            # Apply git history penalty/bonus
            if 'commit_hash' in finding:
                history_modifier = self._get_history_modifier(finding)
                if history_modifier != 1.0:
                    current_score *= history_modifier
                    breakdown['modifiers']['history'] = history_modifier
            
            # Round to reasonable precision
            final_score = round(current_score, 1)
            breakdown['final_score'] = final_score
            
            # Determine risk level
            risk_level = self._determine_risk_level(final_score)
            
            return {
                'score': final_score,
                'risk_level': risk_level.value,
                'breakdown': breakdown,
                'scoring_version': '1.0'
            }
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            return {
                'score': 50.0,
                'risk_level': RiskLevel.MEDIUM.value,
                'breakdown': {'error': str(e)},
                'scoring_version': '1.0'
            }
    
    def _get_file_type_multiplier(self, file_path: str) -> float:
        """Get file type multiplier based on file extension"""
        if not file_path:
            return 1.0
        
        path_obj = Path(file_path)
        
        # Check for compound extensions first (e.g., .test.js)
        for suffix_pattern, multiplier in self.file_type_multipliers.items():
            if file_path.endswith(suffix_pattern):
                return multiplier
        
        # Check simple extension
        extension = path_obj.suffix.lower()
        return self.file_type_multipliers.get(extension, 1.0)
    
    def _get_path_risk_modifier(self, file_path: str) -> float:
        """Get path-based risk modifier"""
        if not file_path:
            return 1.0
        
        path_lower = file_path.lower()
        modifier = 1.0
        
        # Apply strongest modifier found
        for indicator, risk_modifier in self.path_risk_modifiers.items():
            if indicator in path_lower:
                # Use highest risk modifier if multiple found
                if risk_modifier > modifier:
                    modifier = risk_modifier
                # Use lowest risk modifier if it's a reduction
                elif risk_modifier < 1.0 and modifier == 1.0:
                    modifier = risk_modifier
        
        return modifier
    
    def _get_context_modifier(self, finding: Dict[str, Any]) -> float:
        """Get context-based modifier"""
        modifier = 1.0
        
        # Check for placeholder indicators
        match_text = finding.get('match', '').lower()
        if any(placeholder in match_text for placeholder in ['placeholder', 'example', 'your_', 'change_me', 'xxx', '***']):
            modifier *= self.context_modifiers['placeholder']
        
        # Check if it's in a test context
        file_path = finding.get('file_path', '').lower()
        if any(test_indicator in file_path for test_indicator in ['test', 'spec', 'mock', 'fixture']):
            modifier *= self.context_modifiers['test_data']
        
        # Check for environment file context
        if file_path.endswith('.env') or 'environment' in file_path:
            modifier *= self.context_modifiers['in_env_file']
        
        # Check for configuration file context
        if any(config_ext in file_path for config_ext in ['.config', '.conf', '.ini', '.yaml', '.yml']):
            modifier *= self.context_modifiers['in_config']
        
        return modifier
    
    def _calculate_entropy_bonus(self, entropy: float) -> float:
        """Calculate entropy-based score bonus"""
        if entropy < 3.0:
            return 0.8  # Lower entropy = less likely to be real secret
        elif entropy > 5.0:
            return 1.3  # Very high entropy = likely real secret
        elif entropy > 4.5:
            return 1.2  # High entropy = probably real secret
        else:
            return 1.0  # Normal entropy
    
    def _get_history_modifier(self, finding: Dict[str, Any]) -> float:
        """Get git history-based modifier"""
        modifier = 1.0
        
        # Check commit message for indicators
        commit_message = finding.get('commit_message', '').lower()
        
        # Indicators that suggest this might be a real secret
        secret_indicators = ['fix', 'remove', 'delete', 'clean', 'secret', 'key', 'password', 'token']
        if any(indicator in commit_message for indicator in secret_indicators):
            modifier *= 1.2  # Increase score if commit message suggests secret handling
        
        # Indicators that suggest this might be test data
        test_indicators = ['test', 'example', 'demo', 'sample', 'mock']
        if any(indicator in commit_message for indicator in test_indicators):
            modifier *= 0.8  # Decrease score if commit message suggests test data
        
        # Check author email domain
        author_email = finding.get('commit_email', '').lower()
        if author_email.endswith(('.test.com', '.example.com', '.demo.com')):
            modifier *= 0.7  # Test domain = likely test data
        
        return modifier
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level based on score"""
        if score >= self.risk_thresholds['CRITICAL']:
            return RiskLevel.CRITICAL
        elif score >= self.risk_thresholds['HIGH']:
            return RiskLevel.HIGH
        elif score >= self.risk_thresholds['MEDIUM']:
            return RiskLevel.MEDIUM
        elif score >= self.risk_thresholds['LOW']:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def calculate_repository_risk_score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall repository risk score
        
        Args:
            findings: List of individual findings
            
        Returns:
            Dictionary with repository risk assessment
        """
        if not findings:
            return {
                'overall_score': 0.0,
                'risk_level': RiskLevel.INFO.value,
                'total_findings': 0,
                'risk_distribution': {},
                'top_risks': []
            }
        
        # Calculate scores for all findings
        scored_findings = []
        for finding in findings:
            score_info = self.calculate_score(finding)
            finding_with_score = finding.copy()
            finding_with_score.update(score_info)
            scored_findings.append(finding_with_score)
        
        # Calculate overall metrics
        total_score = sum(f['score'] for f in scored_findings)
        max_score = max(f['score'] for f in scored_findings)
        avg_score = total_score / len(scored_findings)
        
        # Count risk levels
        risk_counts = {}
        for finding in scored_findings:
            risk_level = finding['risk_level']
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        # Calculate overall repository score (weighted toward highest risks)
        critical_count = risk_counts.get('CRITICAL', 0)
        high_count = risk_counts.get('HIGH', 0)
        
        # Repository score factors in maximum risk and volume
        repo_score = max_score  # Start with highest individual risk
        
        # Add volume penalty for multiple high-risk findings
        if critical_count > 1:
            repo_score += (critical_count - 1) * 20
        if high_count > 1:
            repo_score += (high_count - 1) * 10
        
        # Cap at reasonable maximum
        repo_score = min(repo_score, 200.0)
        
        # Determine overall risk level
        overall_risk = self._determine_risk_level(repo_score)
        
        # Get top 10 highest risk findings
        top_risks = sorted(scored_findings, key=lambda x: x['score'], reverse=True)[:10]
        
        return {
            'overall_score': round(repo_score, 1),
            'risk_level': overall_risk.value,
            'total_findings': len(findings),
            'max_individual_score': round(max_score, 1),
            'average_score': round(avg_score, 1),
            'risk_distribution': risk_counts,
            'top_risks': top_risks,
            'scored_findings': scored_findings
        }
    
    def export_scoring_config(self) -> Dict[str, Any]:
        """Export current scoring configuration"""
        return {
            'base_scores': self.base_scores,
            'file_type_multipliers': self.file_type_multipliers,
            'path_risk_modifiers': self.path_risk_modifiers,
            'context_modifiers': self.context_modifiers,
            'confidence_multipliers': self.confidence_multipliers,
            'risk_thresholds': self.risk_thresholds
        }
    
    def update_scoring_rules(self, new_rules: Dict[str, Any]):
        """Update scoring rules dynamically"""
        if 'base_scores' in new_rules:
            self.base_scores.update(new_rules['base_scores'])
        
        if 'file_type_multipliers' in new_rules:
            self.file_type_multipliers.update(new_rules['file_type_multipliers'])
        
        if 'path_risk_modifiers' in new_rules:
            self.path_risk_modifiers.update(new_rules['path_risk_modifiers'])
        
        if 'risk_thresholds' in new_rules:
            self.risk_thresholds.update(new_rules['risk_thresholds'])
        
        logger.info("Scoring rules updated")


def create_default_scoring_config() -> Dict[str, Any]:
    """Create default scoring configuration"""
    return {
        'risk_thresholds': {
            'CRITICAL': 100,
            'HIGH': 50,
            'MEDIUM': 20,
            'LOW': 5,
            'INFO': 0
        },
        'custom_base_scores': {},
        'custom_file_multipliers': {},
        'custom_path_modifiers': {}
    }