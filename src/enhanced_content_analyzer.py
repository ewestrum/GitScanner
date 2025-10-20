"""
Enhanced Content Analyzer with deterministic patterns, entropy analysis, and Luhn validation
"""

import re
import math
import logging
from typing import List, Dict, Any, Optional, Tuple
import hashlib

logger = logging.getLogger(__name__)


class EnhancedContentAnalyzer:
    """Advanced content analyzer with deterministic patterns and entropy analysis"""
    
    def __init__(self, content_rules: Dict[str, Any]):
        """Initialize enhanced content analyzer
        
        Args:
            content_rules: Dictionary containing content analysis rules
        """
        self.content_rules = content_rules
        self.entropy_threshold = content_rules.get('entropy_threshold', 4.5)
        
        # Initialize deterministic patterns
        self._init_deterministic_patterns()
        
        logger.info("Enhanced content analyzer initialized")
    
    def _init_deterministic_patterns(self):
        """Initialize deterministic regex patterns for reliable detection"""
        
        # Private Keys (deterministic patterns)
        self.private_key_patterns = [
            re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'),
            re.compile(r'-----BEGIN PRIVATE KEY-----'),
            re.compile(r'-----BEGIN ENCRYPTED PRIVATE KEY-----'),
            re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
        ]
        
        # AWS Access Keys (deterministic format)
        self.aws_patterns = [
            re.compile(r'\\bAKIA[0-9A-Z]{16}\\b'),  # AWS Access Key ID
            re.compile(r'\\b[A-Za-z0-9/+=]{40}\\b(?=.*aws|AWS)'),  # AWS Secret (with context)
        ]
        
        # JWT Tokens (deterministic structure)
        self.jwt_pattern = re.compile(
            r'\\beyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}\\b'
        )
        
        # GitHub Tokens (deterministic patterns)
        self.github_patterns = [
            re.compile(r'\\bghp_[a-zA-Z0-9]{36}\\b'),    # Personal access token
            re.compile(r'\\bghs_[a-zA-Z0-9]{36}\\b'),    # GitHub App token
            re.compile(r'\\bgho_[a-zA-Z0-9]{36}\\b'),    # OAuth token
            re.compile(r'\\bghu_[a-zA-Z0-9]{36}\\b'),    # GitHub user token
            re.compile(r'\\bgithub_pat_[a-zA-Z0-9_]{82}\\b'),  # Fine-grained PAT
        ]
        
        # API Keys (various services)
        self.api_key_patterns = [
            # OpenAI
            re.compile(r'\\bsk-[a-zA-Z0-9]{48}\\b'),
            
            # Stripe
            re.compile(r'\\b(sk|pk)_(test|live)_[a-zA-Z0-9]{24,}\\b'),
            
            # Google API
            re.compile(r'\\bAIza[0-9A-Za-z_-]{35}\\b'),
            
            # Slack
            re.compile(r'\\bxox[baprs]-[0-9a-zA-Z-]{10,48}\\b'),
            
            # Discord
            re.compile(r'\\b[MN][A-Za-z\\d]{23}\\.[\\w-]{6}\\.[\\w-]{27}\\b'),
            
            # Twilio
            re.compile(r'\\bAC[a-z0-9]{32}\\b'),
            
            # SendGrid
            re.compile(r'\\bSG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}\\b'),
        ]
        
        # Email patterns (improved)
        self.email_patterns = [
            re.compile(r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b'),
        ]
        
        # IPv4 addresses
        self.ipv4_pattern = re.compile(
            r'\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b'
        )
        
        # IBAN patterns (European bank accounts)
        self.iban_pattern = re.compile(
            r'\\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\\b'
        )
        
        # Dutch BSN pattern (with context filtering)
        self.bsn_pattern = re.compile(r'\\b[1-9][0-9]{8}\\b')
        self.bsn_context_indicators = [
            'bsn', 'burgerservicenummer', 'sofi', 'sofinummer', 
            'social', 'security', 'citizen'
        ]
        
        # Credit card patterns (major card types)
        self.credit_card_patterns = [
            re.compile(r'\\b4[0-9]{12}(?:[0-9]{3})?\\b'),      # Visa
            re.compile(r'\\b5[1-5][0-9]{14}\\b'),              # MasterCard
            re.compile(r'\\b3[47][0-9]{13}\\b'),               # American Express
            re.compile(r'\\b6(?:011|5[0-9]{2})[0-9]{12}\\b'),  # Discover
        ]
        
        # Database connection strings
        self.db_connection_patterns = [
            re.compile(r'(?i)postgresql://[^\\s"\']+'),
            re.compile(r'(?i)mysql://[^\\s"\']+'),
            re.compile(r'(?i)mongodb://[^\\s"\']+'),
            re.compile(r'(?i)redis://[^\\s"\']+'),
            re.compile(r'(?i)sqlite:///[^\\s"\']+'),
        ]
        
        # High-entropy key-value patterns (.env style)
        self.env_key_pattern = re.compile(
            r'(?i)^\\s*([A-Z_][A-Z0-9_]*?)\\s*=\\s*["\']?([^"\'\\n\\r]+)["\']?\\s*$',
            re.MULTILINE
        )
        
        # Base64 patterns (potential encoded secrets)
        self.base64_pattern = re.compile(
            r'\\b[A-Za-z0-9+/]{20,}={0,2}\\b'
        )
        
        # Hash patterns (might indicate password hashes)
        self.hash_patterns = [
            re.compile(r'\\b[a-f0-9]{32}\\b'),  # MD5
            re.compile(r'\\b[a-f0-9]{40}\\b'),  # SHA1
            re.compile(r'\\b[a-f0-9]{64}\\b'),  # SHA256
        ]
        
        # Placeholder detection patterns
        self.placeholder_patterns = [
            re.compile(r'(?i)\\b(your|placeholder|example|sample|test|demo|fake|dummy)\\b'),
            re.compile(r'\\b(xxx+|\\*{3,}|\\.{3,})\\b'),
            re.compile(r'(?i)\\b(change_me|replace_me|todo|fixme)\\b'),
        ]
    
    def analyze_content(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze content for sensitive information with enhanced detection
        
        Args:
            content: File content to analyze
            file_path: Path of the file being analyzed
            
        Returns:
            List of sensitive content matches
        """
        if not content:
            return []
        
        matches = []
        
        # Skip very large content
        if len(content) > 10 * 1024 * 1024:  # 10MB
            logger.warning(f"Skipping large content analysis for {file_path}")
            return matches
        
        try:
            # Deterministic pattern matching
            matches.extend(self._find_private_keys(content, file_path))
            matches.extend(self._find_aws_credentials(content, file_path))
            matches.extend(self._find_jwt_tokens(content, file_path))
            matches.extend(self._find_github_tokens(content, file_path))
            matches.extend(self._find_api_keys(content, file_path))
            matches.extend(self._find_emails(content, file_path))
            matches.extend(self._find_ip_addresses(content, file_path))
            matches.extend(self._find_iban_numbers(content, file_path))
            matches.extend(self._find_bsn_numbers(content, file_path))
            matches.extend(self._find_credit_cards(content, file_path))
            matches.extend(self._find_database_connections(content, file_path))
            matches.extend(self._find_high_entropy_secrets(content, file_path))
            matches.extend(self._find_base64_secrets(content, file_path))
            
            # Remove duplicates and false positives
            matches = self._deduplicate_and_filter(matches)
            
            return matches
            
        except Exception as e:
            logger.error(f"Error analyzing content in {file_path}: {e}")
            return matches
    
    def _find_private_keys(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find private keys using deterministic patterns"""
        matches = []
        
        for pattern in self.private_key_patterns:
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count('\\n') + 1
                
                matches.append({
                    'type': 'private_key',
                    'pattern': 'Private Key',
                    'match': '[PRIVATE KEY DETECTED]',
                    'file_path': file_path,
                    'line_number': line_num,
                    'severity': 'CRITICAL',
                    'confidence': 'HIGH',
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
        
        return matches
    
    def _find_aws_credentials(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find AWS credentials using deterministic patterns"""
        matches = []
        
        for pattern in self.aws_patterns:
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count('\\n') + 1
                key_value = match.group(0)
                
                # Skip if it looks like a placeholder
                if self._is_placeholder_value(key_value):
                    continue
                
                matches.append({
                    'type': 'aws_credential',
                    'pattern': 'AWS Access Key',
                    'match': self._mask_secret(key_value),
                    'file_path': file_path,
                    'line_number': line_num,
                    'severity': 'CRITICAL',
                    'confidence': 'HIGH',
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
        
        return matches
    
    def _find_jwt_tokens(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find JWT tokens using deterministic pattern"""
        matches = []
        
        for match in self.jwt_pattern.finditer(content):
            line_num = content[:match.start()].count('\\n') + 1
            token = match.group(0)
            
            # Validate JWT structure
            if self._validate_jwt_structure(token):
                matches.append({
                    'type': 'jwt_token',
                    'pattern': 'JWT Token',
                    'match': self._mask_secret(token),
                    'file_path': file_path,
                    'line_number': line_num,
                    'severity': 'HIGH',
                    'confidence': 'HIGH',
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
        
        return matches
    
    def _find_github_tokens(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find GitHub tokens using deterministic patterns"""
        matches = []
        
        for pattern in self.github_patterns:
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count('\\n') + 1
                token = match.group(0)
                
                matches.append({
                    'type': 'github_token',
                    'pattern': 'GitHub Token',
                    'match': self._mask_secret(token),
                    'file_path': file_path,
                    'line_number': line_num,
                    'severity': 'CRITICAL',
                    'confidence': 'HIGH',
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
        
        return matches
    
    def _find_api_keys(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find API keys using deterministic patterns"""
        matches = []
        
        for pattern in self.api_key_patterns:
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count('\\n') + 1
                api_key = match.group(0)
                
                # Skip if it looks like a placeholder
                if self._is_placeholder_value(api_key):
                    continue
                
                matches.append({
                    'type': 'api_key',
                    'pattern': 'API Key',
                    'match': self._mask_secret(api_key),
                    'file_path': file_path,
                    'line_number': line_num,
                    'severity': 'CRITICAL',
                    'confidence': 'HIGH',
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
        
        return matches
    
    def _find_emails(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find email addresses with context filtering"""
        matches = []
        
        for pattern in self.email_patterns:
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count('\\n') + 1
                email = match.group(0)
                
                # Skip common non-personal emails
                if self._is_common_email(email):
                    continue
                
                matches.append({
                    'type': 'email',
                    'pattern': 'Email Address',
                    'match': email,
                    'file_path': file_path,
                    'line_number': line_num,
                    'severity': 'MEDIUM',
                    'confidence': 'MEDIUM',
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
        
        return matches
    
    def _find_ip_addresses(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find IPv4 addresses (excluding common internal ranges)"""
        matches = []
        
        for match in self.ipv4_pattern.finditer(content):
            line_num = content[:match.start()].count('\\n') + 1
            ip = match.group(0)
            
            # Skip common internal/example IPs
            if self._is_internal_ip(ip):
                continue
            
            matches.append({
                'type': 'ip_address',
                'pattern': 'IP Address',
                'match': ip,
                'file_path': file_path,
                'line_number': line_num,
                'severity': 'LOW',
                'confidence': 'MEDIUM',
                'start_pos': match.start(),
                'end_pos': match.end()
            })
        
        return matches
    
    def _find_iban_numbers(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find IBAN numbers with validation"""
        matches = []
        
        for match in self.iban_pattern.finditer(content):
            line_num = content[:match.start()].count('\\n') + 1
            iban = match.group(0)
            
            # Validate IBAN checksum
            if self._validate_iban(iban):
                matches.append({
                    'type': 'iban',
                    'pattern': 'IBAN Number',
                    'match': self._mask_secret(iban),
                    'file_path': file_path,
                    'line_number': line_num,
                    'severity': 'HIGH',
                    'confidence': 'HIGH',
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
        
        return matches
    
    def _find_bsn_numbers(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find Dutch BSN numbers with context filtering and validation"""
        matches = []
        
        for match in self.bsn_pattern.finditer(content):
            line_num = content[:match.start()].count('\\n') + 1
            bsn = match.group(0)
            
            # Get context around the match
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 50)
            context = content[start:end].lower()
            
            # Check if context suggests this is actually a BSN
            has_context = any(indicator in context for indicator in self.bsn_context_indicators)
            
            # Validate BSN checksum
            if self._validate_bsn(bsn) and has_context:
                matches.append({
                    'type': 'bsn',
                    'pattern': 'Dutch BSN',
                    'match': self._mask_secret(bsn),
                    'file_path': file_path,
                    'line_number': line_num,
                    'severity': 'HIGH',
                    'confidence': 'HIGH',
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
        
        return matches
    
    def _find_credit_cards(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find credit card numbers with Luhn validation"""
        matches = []
        
        for pattern in self.credit_card_patterns:
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count('\\n') + 1
                cc_number = match.group(0)
                
                # Validate using Luhn algorithm
                if self._validate_luhn(cc_number):
                    matches.append({
                        'type': 'credit_card',
                        'pattern': 'Credit Card Number',
                        'match': self._mask_credit_card(cc_number),
                        'file_path': file_path,
                        'line_number': line_num,
                        'severity': 'HIGH',
                        'confidence': 'HIGH',
                        'start_pos': match.start(),
                        'end_pos': match.end()
                    })
        
        return matches
    
    def _find_database_connections(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find database connection strings"""
        matches = []
        
        for pattern in self.db_connection_patterns:
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count('\\n') + 1
                conn_string = match.group(0)
                
                # Skip localhost connections in test files
                if 'localhost' in conn_string and ('test' in file_path.lower() or 'spec' in file_path.lower()):
                    continue
                
                matches.append({
                    'type': 'database_connection',
                    'pattern': 'Database Connection String',
                    'match': self._mask_connection_string(conn_string),
                    'file_path': file_path,
                    'line_number': line_num,
                    'severity': 'HIGH',
                    'confidence': 'HIGH',
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
        
        return matches
    
    def _find_high_entropy_secrets(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find high-entropy secrets in environment variable style assignments"""
        matches = []
        
        for match in self.env_key_pattern.finditer(content):
            line_num = content[:match.start()].count('\\n') + 1
            key = match.group(1)
            value = match.group(2)
            
            # Skip if value is too short or looks like a placeholder
            if len(value) < 8 or self._is_placeholder_value(value):
                continue
            
            # Calculate entropy
            entropy = self._calculate_entropy(value)
            
            # Check if this looks like a secret key name
            secret_indicators = ['key', 'secret', 'token', 'password', 'auth', 'api', 'private']
            is_secret_key = any(indicator in key.lower() for indicator in secret_indicators)
            
            if entropy >= self.entropy_threshold and is_secret_key:
                matches.append({
                    'type': 'high_entropy_secret',
                    'pattern': f'High Entropy Secret ({key})',
                    'match': f'{key}={self._mask_secret(value)}',
                    'file_path': file_path,
                    'line_number': line_num,
                    'severity': 'HIGH',
                    'confidence': 'MEDIUM',
                    'entropy': entropy,
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
        
        return matches
    
    def _find_base64_secrets(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find potential Base64 encoded secrets"""
        matches = []
        
        for match in self.base64_pattern.finditer(content):
            line_num = content[:match.start()].count('\\n') + 1
            b64_string = match.group(0)
            
            # Skip short strings or obvious non-secrets
            if len(b64_string) < 20:
                continue
            
            # Check entropy
            entropy = self._calculate_entropy(b64_string)
            
            # Get context to see if this might be a secret
            start = max(0, match.start() - 30)
            end = min(len(content), match.end() + 30)
            context = content[start:end].lower()
            
            secret_indicators = ['key', 'secret', 'token', 'auth', 'private', 'cert']
            has_secret_context = any(indicator in context for indicator in secret_indicators)
            
            if entropy >= 4.0 and has_secret_context:
                matches.append({
                    'type': 'base64_secret',
                    'pattern': 'Base64 Encoded Secret',
                    'match': self._mask_secret(b64_string),
                    'file_path': file_path,
                    'line_number': line_num,
                    'severity': 'MEDIUM',
                    'confidence': 'LOW',
                    'entropy': entropy,
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
        
        return matches
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0
        
        # Count character frequencies
        frequencies = {}
        for char in data:
            frequencies[char] = frequencies.get(char, 0) + 1
        
        # Calculate entropy
        length = len(data)
        entropy = 0.0
        
        for count in frequencies.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _validate_jwt_structure(self, token: str) -> bool:
        """Validate JWT token structure"""
        parts = token.split('.')
        return len(parts) == 3 and all(len(part) > 0 for part in parts)
    
    def _validate_luhn(self, number: str) -> bool:
        """Validate credit card number using Luhn algorithm"""
        try:
            digits = [int(d) for d in number if d.isdigit()]
            checksum = 0
            
            # Process digits from right to left
            for i in range(len(digits) - 2, -1, -1):
                digit = digits[i]
                
                # Double every second digit from right
                if (len(digits) - i) % 2 == 0:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                
                checksum += digit
            
            return (checksum + digits[-1]) % 10 == 0
            
        except (ValueError, IndexError):
            return False
    
    def _validate_bsn(self, bsn: str) -> bool:
        """Validate Dutch BSN using checksum algorithm"""
        if len(bsn) != 9:
            return False
        
        try:
            digits = [int(d) for d in bsn]
            checksum = sum(digits[i] * (9 - i) for i in range(8))
            checksum -= digits[8]
            return checksum % 11 == 0
        except ValueError:
            return False
    
    def _validate_iban(self, iban: str) -> bool:
        """Validate IBAN using MOD-97 algorithm"""
        try:
            # Move first 4 characters to end
            rearranged = iban[4:] + iban[:4]
            
            # Replace letters with numbers (A=10, B=11, etc.)
            numeric = ""
            for char in rearranged:
                if char.isalpha():
                    numeric += str(ord(char) - ord('A') + 10)
                else:
                    numeric += char
            
            # Check MOD 97
            return int(numeric) % 97 == 1
            
        except (ValueError, TypeError):
            return False
    
    def _is_placeholder_value(self, value: str) -> bool:
        """Check if value is likely a placeholder"""
        return any(pattern.search(value) for pattern in self.placeholder_patterns)
    
    def _is_common_email(self, email: str) -> bool:
        """Check if email is a common non-personal address"""
        common_domains = [
            'example.com', 'test.com', 'localhost', 'demo.com',
            'sample.com', 'placeholder.com', 'your-domain.com',
            'company.com', 'yourdomain.com'
        ]
        return any(domain in email.lower() for domain in common_domains)
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal/private range"""
        parts = [int(x) for x in ip.split('.')]
        
        # Common internal ranges and examples
        internal_ranges = [
            (10, 0, 0, 0, 8),      # 10.0.0.0/8
            (172, 16, 0, 0, 12),   # 172.16.0.0/12
            (192, 168, 0, 0, 16),  # 192.168.0.0/16
            (127, 0, 0, 0, 8),     # 127.0.0.0/8 (localhost)
        ]
        
        # Example IPs
        if ip in ['192.0.2.1', '198.51.100.1', '203.0.113.1']:
            return True
        
        for start_a, start_b, start_c, start_d, prefix in internal_ranges:
            if prefix == 8 and parts[0] == start_a:
                return True
            elif prefix == 12 and parts[0] == start_a and 16 <= parts[1] <= 31:
                return True
            elif prefix == 16 and parts[0] == start_a and parts[1] == start_b:
                return True
        
        return False
    
    def _mask_secret(self, secret: str) -> str:
        """Mask secret value for safe logging"""
        if len(secret) <= 8:
            return '*' * len(secret)
        return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]
    
    def _mask_credit_card(self, cc_number: str) -> str:
        """Mask credit card number"""
        clean = ''.join(c for c in cc_number if c.isdigit())
        if len(clean) < 8:
            return '*' * len(clean)
        return clean[:4] + '*' * (len(clean) - 8) + clean[-4:]
    
    def _mask_connection_string(self, conn_str: str) -> str:
        """Mask passwords in connection strings"""
        # Mask password in connection strings
        patterns = [
            (r'(password|pwd)=([^;\\s&]+)', r'\\1=***'),
            (r'://([^:]+):([^@]+)@', r'://\\1:***@'),
        ]
        
        masked = conn_str
        for pattern, replacement in patterns:
            masked = re.sub(pattern, replacement, masked, flags=re.IGNORECASE)
        
        return masked
    
    def _deduplicate_and_filter(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate matches and apply additional filtering"""
        
        # Create unique identifier for each match
        seen = set()
        filtered_matches = []
        
        for match in matches:
            # Create identifier based on position and type
            identifier = (
                match['file_path'],
                match['line_number'], 
                match['type'],
                match.get('start_pos', 0)
            )
            
            if identifier not in seen:
                seen.add(identifier)
                filtered_matches.append(match)
        
        return filtered_matches