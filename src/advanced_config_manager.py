"""
Advanced Configuration Manager with regex-based rules engine
"""

import logging
import json
import re
# Try to import yaml with fallback
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logging.warning("PyYAML not available, YAML configuration features disabled")
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import os
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class RegexRule:
    """Regex-based detection rule"""
    id: str
    name: str
    description: str
    pattern: str
    severity: str = "MEDIUM"
    confidence: str = "MEDIUM"
    file_patterns: List[str] = None
    exclude_patterns: List[str] = None
    context_patterns: List[str] = None
    enabled: bool = True
    tags: List[str] = None
    
    def __post_init__(self):
        if self.file_patterns is None:
            self.file_patterns = []
        if self.exclude_patterns is None:
            self.exclude_patterns = []
        if self.context_patterns is None:
            self.context_patterns = []
        if self.tags is None:
            self.tags = []


@dataclass
class PathFilter:
    """Path-based filtering rule"""
    name: str
    patterns: List[str]
    action: str  # "include" or "exclude"
    priority: int = 0


@dataclass
class ContentFilter:
    """Content-based filtering rule"""
    name: str
    patterns: List[str]
    action: str  # "include" or "exclude"
    context: str = "any"  # "any", "line", "file"


class AdvancedConfigManager:
    """Advanced configuration manager with regex-based rules engine"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize advanced configuration manager
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config = {}
        self.regex_rules = {}
        self.path_filters = {}
        self.content_filters = {}
        self.compiled_patterns = {}
        
        # Load configuration
        if config_path and os.path.exists(config_path):
            self.load_config(config_path)
        else:
            self._init_default_config()
        
        # Compile regex patterns
        self._compile_patterns()
        
        logger.info(f"Advanced configuration manager initialized with {len(self.regex_rules)} rules")
    
    def _init_default_config(self):
        """Initialize default configuration with comprehensive rules"""
        
        # Default regex rules for various secret types
        default_rules = [
            # AWS Credentials
            RegexRule(
                id="aws-access-key",
                name="AWS Access Key ID",
                description="Amazon Web Services Access Key ID",
                pattern=r'\bAKIA[0-9A-Z]{16}\b',
                severity="CRITICAL",
                confidence="HIGH",
                tags=["aws", "credentials", "api-key"]
            ),
            RegexRule(
                id="aws-secret-key",
                name="AWS Secret Access Key",
                description="Amazon Web Services Secret Access Key",
                pattern=r'(?i)aws[_-]?secret[_-]?access[_-]?key["\s]*[:=]["\s]*[A-Za-z0-9/+=]{40}',
                severity="CRITICAL",
                confidence="HIGH",
                tags=["aws", "credentials", "secret"]
            ),
            
            # GitHub Tokens
            RegexRule(
                id="github-pat",
                name="GitHub Personal Access Token",
                description="GitHub Personal Access Token",
                pattern=r'\bghp_[a-zA-Z0-9]{36}\b',
                severity="CRITICAL",
                confidence="HIGH",
                tags=["github", "token", "api-key"]
            ),
            RegexRule(
                id="github-oauth",
                name="GitHub OAuth Token",
                description="GitHub OAuth App Token",
                pattern=r'\bgho_[a-zA-Z0-9]{36}\b',
                severity="CRITICAL",
                confidence="HIGH",
                tags=["github", "oauth", "token"]
            ),
            
            # Private Keys
            RegexRule(
                id="rsa-private-key",
                name="RSA Private Key",
                description="RSA Private Key",
                pattern=r'-----BEGIN (RSA )?PRIVATE KEY-----',
                severity="CRITICAL",
                confidence="HIGH",
                tags=["private-key", "rsa", "crypto"]
            ),
            RegexRule(
                id="ec-private-key",
                name="EC Private Key",
                description="Elliptic Curve Private Key",
                pattern=r'-----BEGIN EC PRIVATE KEY-----',
                severity="CRITICAL",
                confidence="HIGH",
                tags=["private-key", "ec", "crypto"]
            ),
            
            # API Keys (Generic)
            RegexRule(
                id="generic-api-key",
                name="Generic API Key",
                description="Generic API Key Pattern",
                pattern=r'(?i)api[_-]?key["\s]*[:=]["\s]*[A-Za-z0-9_-]{20,}',
                severity="HIGH",
                confidence="MEDIUM",
                tags=["api-key", "generic"]
            ),
            
            # Database Connection Strings
            RegexRule(
                id="postgres-connection",
                name="PostgreSQL Connection String",
                description="PostgreSQL database connection string",
                pattern=r'postgresql://[^\s"]+',
                severity="HIGH",
                confidence="HIGH",
                tags=["database", "postgresql", "connection"]
            ),
            RegexRule(
                id="mysql-connection",
                name="MySQL Connection String",
                description="MySQL database connection string",
                pattern=r'mysql://[^\s"]+',
                severity="HIGH",
                confidence="HIGH",
                tags=["database", "mysql", "connection"]
            ),
            
            # JWT Tokens
            RegexRule(
                id="jwt-token",
                name="JWT Token",
                description="JSON Web Token",
                pattern=r'\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b',
                severity="MEDIUM",
                confidence="HIGH",
                tags=["jwt", "token", "auth"]
            ),
            
            # Slack Tokens
            RegexRule(
                id="slack-token",
                name="Slack Token",
                description="Slack API Token",
                pattern=r'\bxox[baprs]-[0-9a-zA-Z-]{10,48}\b',
                severity="HIGH",
                confidence="HIGH",
                tags=["slack", "token", "api-key"]
            ),
            
            # Discord Tokens
            RegexRule(
                id="discord-token",
                name="Discord Token",
                description="Discord Bot Token",
                pattern=r'\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b',
                severity="HIGH",
                confidence="HIGH",
                tags=["discord", "token", "bot"]
            ),
            
            # Stripe Keys
            RegexRule(
                id="stripe-key",
                name="Stripe API Key",
                description="Stripe API Key",
                pattern=r'\b(sk|pk)_(test|live)_[a-zA-Z0-9]{24,}\b',
                severity="CRITICAL",
                confidence="HIGH",
                tags=["stripe", "payment", "api-key"]
            ),
            
            # Google API Keys
            RegexRule(
                id="google-api-key",
                name="Google API Key",
                description="Google API Key",
                pattern=r'\bAIza[0-9A-Za-z_-]{35}\b',
                severity="HIGH",
                confidence="HIGH",
                tags=["google", "api-key"]
            ),
            
            # OpenAI API Keys
            RegexRule(
                id="openai-api-key",
                name="OpenAI API Key",
                description="OpenAI API Key",
                pattern=r'\bsk-[a-zA-Z0-9]{48}\b',
                severity="CRITICAL",
                confidence="HIGH",
                tags=["openai", "api-key", "ai"]
            ),
            
            # Email Addresses
            RegexRule(
                id="email-address",
                name="Email Address",
                description="Email address",
                pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                severity="LOW",
                confidence="MEDIUM",
                exclude_patterns=[
                    r'.*@(example\.com|test\.com|localhost|your-domain\.com)',
                    r'.*@(noreply|no-reply|support|info|admin)'
                ],
                tags=["email", "pii"]
            ),
            
            # IP Addresses
            RegexRule(
                id="ipv4-address",
                name="IPv4 Address",
                description="IPv4 IP Address",
                pattern=r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
                severity="LOW",
                confidence="MEDIUM",
                exclude_patterns=[
                    r'127\.0\.0\.1',  # localhost
                    r'192\.168\.',     # private network
                    r'10\.',            # private network
                    r'172\.(1[6-9]|2[0-9]|3[01])\.',  # private network
                    r'0\.0\.0\.0',    # any address
                    r'255\.255\.255\.255'  # broadcast
                ],
                tags=["ip", "network"]
            ),
            
            # Credit Card Numbers
            RegexRule(
                id="credit-card",
                name="Credit Card Number",
                description="Credit card number",
                pattern=r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
                severity="HIGH",
                confidence="MEDIUM",
                tags=["credit-card", "pii", "financial"]
            ),
            
            # High Entropy Strings
            RegexRule(
                id="high-entropy-string",
                name="High Entropy String",
                description="High entropy string (potential secret)",
                pattern=r'(?i)(?:secret|key|token|password|auth)["\s]*[:=]["\s]*[A-Za-z0-9+/=]{20,}',
                severity="MEDIUM",
                confidence="LOW",
                exclude_patterns=[
                    r'.*["\']+(example|test|demo|sample|placeholder|your_|change_me)["\s]*',
                    r'.*["\']+(x{3,}|\*{3,}|\.{3,})["\s]*'
                ],
                tags=["entropy", "secret", "generic"]
            )
        ]
        
        # Convert to dictionary
        self.regex_rules = {rule.id: rule for rule in default_rules}
        
        # Default path filters
        self.path_filters = {
            "skip-test-files": PathFilter(
                name="Skip Test Files",
                patterns=[
                    r'.*test.*',
                    r'.*spec.*',
                    r'.*mock.*',
                    r'.*fixture.*'
                ],
                action="exclude",
                priority=10
            ),
            "skip-vendor": PathFilter(
                name="Skip Vendor Directories",
                patterns=[
                    r'.*/vendor/.*',
                    r'.*/node_modules/.*',
                    r'.*/__pycache__/.*',
                    r'.*/\\.git/.*'
                ],
                action="exclude",
                priority=20
            ),
            "include-config": PathFilter(
                name="Include Config Files",
                patterns=[
                    r'.*\\.env.*',
                    r'.*config.*',
                    r'.*\\.ya?ml$',
                    r'.*\\.json$'
                ],
                action="include",
                priority=5
            )
        }
        
        # Default content filters
        self.content_filters = {
            "exclude-comments": ContentFilter(
                name="Exclude Comment Sections",
                patterns=[
                    r'//.*',  # Single line comments
                    r'/\\*.*?\\*/',  # Multi-line comments
                    r'#.*',   # Hash comments
                    r'<!--.*?-->'  # HTML comments
                ],
                action="exclude",
                context="line"
            ),
            "exclude-placeholders": ContentFilter(
                name="Exclude Placeholder Values",
                patterns=[
                    r'(?i)(placeholder|example|sample|test|demo|your_|change_me)',
                    r'(x{3,}|\*{3,}|\.{3,})',
                    r'(?i)(todo|fixme|replace)'
                ],
                action="exclude",
                context="any"
            )
        }
        
        # Main configuration
        self.config = {
            "version": "1.0",
            "regex_rules": {rule_id: asdict(rule) for rule_id, rule in self.regex_rules.items()},
            "path_filters": {filter_id: asdict(pf) for filter_id, pf in self.path_filters.items()},
            "content_filters": {filter_id: asdict(cf) for filter_id, cf in self.content_filters.items()},
            "settings": {
                "enable_regex_rules": True,
                "enable_path_filtering": True,
                "enable_content_filtering": True,
                "case_sensitive": False,
                "multiline": True,
                "max_match_length": 1000
            }
        }
    
    def load_config(self, config_path: str):
        """Load configuration from file
        
        Args:
            config_path: Path to configuration file
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                    if YAML_AVAILABLE:
                        self.config = yaml.safe_load(f)
                    else:
                        raise ImportError("PyYAML is required for YAML configuration files")
                else:
                    self.config = json.load(f)
            
            # Parse rules from config
            self._parse_rules_from_config()
            
            logger.info(f"Configuration loaded from {config_path}")
            
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            self._init_default_config()
    
    def save_config(self, config_path: Optional[str] = None):
        """Save configuration to file
        
        Args:
            config_path: Path to save configuration (uses instance path if None)
        """
        if config_path is None:
            config_path = self.config_path
        
        if not config_path:
            raise ValueError("No configuration path specified")
        
        try:
            # Update config with current rules
            self.config["regex_rules"] = {rule_id: asdict(rule) for rule_id, rule in self.regex_rules.items()}
            self.config["path_filters"] = {filter_id: asdict(pf) for filter_id, pf in self.path_filters.items()}
            self.config["content_filters"] = {filter_id: asdict(cf) for filter_id, cf in self.content_filters.items()}
            
            with open(config_path, 'w', encoding='utf-8') as f:
                if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                    if YAML_AVAILABLE:
                        yaml.dump(self.config, f, default_flow_style=False, indent=2)
                    else:
                        raise ImportError("PyYAML is required for YAML configuration files")
                else:
                    json.dump(self.config, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Configuration saved to {config_path}")
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            raise
    
    def _parse_rules_from_config(self):
        """Parse rules from loaded configuration"""
        
        # Parse regex rules
        regex_rules_config = self.config.get("regex_rules", {})
        self.regex_rules = {}
        for rule_id, rule_data in regex_rules_config.items():
            try:
                self.regex_rules[rule_id] = RegexRule(**rule_data)
            except Exception as e:
                logger.error(f"Error parsing regex rule {rule_id}: {e}")
        
        # Parse path filters
        path_filters_config = self.config.get("path_filters", {})
        self.path_filters = {}
        for filter_id, filter_data in path_filters_config.items():
            try:
                self.path_filters[filter_id] = PathFilter(**filter_data)
            except Exception as e:
                logger.error(f"Error parsing path filter {filter_id}: {e}")
        
        # Parse content filters
        content_filters_config = self.config.get("content_filters", {})
        self.content_filters = {}
        for filter_id, filter_data in content_filters_config.items():
            try:
                self.content_filters[filter_id] = ContentFilter(**filter_data)
            except Exception as e:
                logger.error(f"Error parsing content filter {filter_id}: {e}")
    
    def _compile_patterns(self):
        """Compile regex patterns for performance"""
        self.compiled_patterns = {}
        
        # Compile regex rules
        for rule_id, rule in self.regex_rules.items():
            if rule.enabled:
                try:
                    flags = re.IGNORECASE if not self.config.get("settings", {}).get("case_sensitive", False) else 0
                    if self.config.get("settings", {}).get("multiline", True):
                        flags |= re.MULTILINE | re.DOTALL
                    
                    self.compiled_patterns[rule_id] = {
                        'pattern': re.compile(rule.pattern, flags),
                        'exclude_patterns': [re.compile(p, flags) for p in rule.exclude_patterns],
                        'context_patterns': [re.compile(p, flags) for p in rule.context_patterns],
                        'file_patterns': [re.compile(p, flags) for p in rule.file_patterns] if rule.file_patterns else []
                    }
                except Exception as e:
                    logger.error(f"Error compiling pattern for rule {rule_id}: {e}")
        
        # Compile path filters
        for filter_id, path_filter in self.path_filters.items():
            try:
                self.compiled_patterns[f"path_{filter_id}"] = [
                    re.compile(pattern) for pattern in path_filter.patterns
                ]
            except Exception as e:
                logger.error(f"Error compiling path filter {filter_id}: {e}")
        
        # Compile content filters
        for filter_id, content_filter in self.content_filters.items():
            try:
                self.compiled_patterns[f"content_{filter_id}"] = [
                    re.compile(pattern) for pattern in content_filter.patterns
                ]
            except Exception as e:
                logger.error(f"Error compiling content filter {filter_id}: {e}")
    
    def should_scan_path(self, file_path: str) -> bool:
        """Check if file path should be scanned based on path filters
        
        Args:
            file_path: File path to check
            
        Returns:
            True if file should be scanned
        """
        if not self.config.get("settings", {}).get("enable_path_filtering", True):
            return True
        
        # Sort filters by priority (higher priority first)
        sorted_filters = sorted(
            self.path_filters.items(),
            key=lambda x: x[1].priority,
            reverse=True
        )
        
        for filter_id, path_filter in sorted_filters:
            patterns = self.compiled_patterns.get(f"path_{filter_id}", [])
            
            for pattern in patterns:
                if pattern.search(file_path):
                    return path_filter.action == "include"
        
        # Default to include if no patterns match
        return True
    
    def apply_regex_rules(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Apply regex rules to content
        
        Args:
            content: File content to analyze
            file_path: Path of the file being analyzed
            
        Returns:
            List of matches found
        """
        if not self.config.get("settings", {}).get("enable_regex_rules", True):
            return []
        
        matches = []
        
        for rule_id, rule in self.regex_rules.items():
            if not rule.enabled:
                continue
            
            compiled_rule = self.compiled_patterns.get(rule_id)
            if not compiled_rule:
                continue
            
            # Check if rule applies to this file type
            if compiled_rule['file_patterns']:
                if not any(pattern.search(file_path) for pattern in compiled_rule['file_patterns']):
                    continue
            
            # Find matches
            for match in compiled_rule['pattern'].finditer(content):
                match_text = match.group(0)
                
                # Check exclude patterns
                if any(pattern.search(match_text) for pattern in compiled_rule['exclude_patterns']):
                    continue
                
                # Check context patterns if specified
                if compiled_rule['context_patterns']:
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end]
                    
                    if not any(pattern.search(context) for pattern in compiled_rule['context_patterns']):
                        continue
                
                # Apply content filters
                if self._should_exclude_content(match_text, context):
                    continue
                
                line_num = content[:match.start()].count('\\n') + 1
                
                matches.append({
                    'rule_id': rule_id,
                    'type': rule_id.replace('-', '_'),
                    'pattern': rule.name,
                    'match': match_text,
                    'file_path': file_path,
                    'line_number': line_num,
                    'severity': rule.severity,
                    'confidence': rule.confidence,
                    'start_pos': match.start(),
                    'end_pos': match.end(),
                    'description': rule.description,
                    'tags': rule.tags
                })
        
        return matches
    
    def _should_exclude_content(self, match_text: str, context: str = None) -> bool:
        """Check if content should be excluded based on content filters
        
        Args:
            match_text: The matched text
            context: Context around the match
            
        Returns:
            True if content should be excluded
        """
        if not self.config.get("settings", {}).get("enable_content_filtering", True):
            return False
        
        for filter_id, content_filter in self.content_filters.items():
            if content_filter.action != "exclude":
                continue
            
            patterns = self.compiled_patterns.get(f"content_{filter_id}", [])
            
            # Choose what to check based on context setting
            check_text = match_text
            if content_filter.context == "line" and context:
                # Check the entire line
                lines = context.split('\\n')
                for line in lines:
                    if match_text in line:
                        check_text = line
                        break
            elif content_filter.context == "file" and context:
                check_text = context
            
            # Check patterns
            for pattern in patterns:
                if pattern.search(check_text):
                    return True
        
        return False
    
    def add_regex_rule(self, rule: RegexRule):
        """Add a new regex rule
        
        Args:
            rule: RegexRule instance to add
        """
        self.regex_rules[rule.id] = rule
        self._compile_patterns()
        logger.info(f"Added regex rule: {rule.id}")
    
    def remove_regex_rule(self, rule_id: str):
        """Remove a regex rule
        
        Args:
            rule_id: ID of rule to remove
        """
        if rule_id in self.regex_rules:
            del self.regex_rules[rule_id]
            if rule_id in self.compiled_patterns:
                del self.compiled_patterns[rule_id]
            logger.info(f"Removed regex rule: {rule_id}")
    
    def enable_rule(self, rule_id: str):
        """Enable a regex rule"""
        if rule_id in self.regex_rules:
            self.regex_rules[rule_id].enabled = True
            self._compile_patterns()
    
    def disable_rule(self, rule_id: str):
        """Disable a regex rule"""
        if rule_id in self.regex_rules:
            self.regex_rules[rule_id].enabled = False
            if rule_id in self.compiled_patterns:
                del self.compiled_patterns[rule_id]
    
    def get_rules_by_tag(self, tag: str) -> List[RegexRule]:
        """Get rules that have a specific tag
        
        Args:
            tag: Tag to search for
            
        Returns:
            List of rules with the specified tag
        """
        return [rule for rule in self.regex_rules.values() if tag in rule.tags]
    
    def validate_config(self) -> Dict[str, List[str]]:
        """Validate the current configuration
        
        Returns:
            Dictionary with validation errors
        """
        errors = {
            "regex_rules": [],
            "path_filters": [],
            "content_filters": []
        }
        
        # Validate regex rules
        for rule_id, rule in self.regex_rules.items():
            try:
                re.compile(rule.pattern)
            except re.error as e:
                errors["regex_rules"].append(f"Rule {rule_id}: Invalid pattern - {e}")
            
            # Validate exclude patterns
            for pattern in rule.exclude_patterns:
                try:
                    re.compile(pattern)
                except re.error as e:
                    errors["regex_rules"].append(f"Rule {rule_id}: Invalid exclude pattern - {e}")
        
        # Validate path filters
        for filter_id, path_filter in self.path_filters.items():
            for pattern in path_filter.patterns:
                try:
                    re.compile(pattern)
                except re.error as e:
                    errors["path_filters"].append(f"Filter {filter_id}: Invalid pattern - {e}")
        
        # Validate content filters
        for filter_id, content_filter in self.content_filters.items():
            for pattern in content_filter.patterns:
                try:
                    re.compile(pattern)
                except re.error as e:
                    errors["content_filters"].append(f"Filter {filter_id}: Invalid pattern - {e}")
        
        return errors
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get summary of current configuration"""
        return {
            "total_regex_rules": len(self.regex_rules),
            "enabled_regex_rules": len([r for r in self.regex_rules.values() if r.enabled]),
            "path_filters": len(self.path_filters),
            "content_filters": len(self.content_filters),
            "compiled_patterns": len(self.compiled_patterns),
            "settings": self.config.get("settings", {})
        }