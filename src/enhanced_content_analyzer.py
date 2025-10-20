"""
Enhanced Content Analyzer with deterministic pattern detection
"""

import re
import hashlib
import math
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter

class EnhancedContentAnalyzer:
    """Enhanced content analyzer with deterministic patterns and entropy analysis"""
    
    def __init__(self, content_rules: List[Dict[str, Any]]):
        """Initialize enhanced content analyzer
        
        Args:
            content_rules: List of content analysis rules
        """
        self.content_rules = content_rules
        self.min_entropy_threshold = 4.5  # Threshold for high entropy strings
        self.min_string_length = 20       # Minimum length for entropy analysis
        
        # Initialize deterministic patterns
        self._init_deterministic_patterns()
    
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
            re.compile(r'\bAKIA[0-9A-Z]{16}\b'),  # AWS Access Key ID
            re.compile(r'\b[A-Za-z0-9/+=]{40}\b(?=.*aws|AWS)'),  # AWS Secret (with context)
        ]
        
        # JWT Tokens (deterministic structure)
        self.jwt_pattern = re.compile(
            r'\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b'
        )
        
        # GitHub Tokens (deterministic patterns)
        self.github_patterns = [
            re.compile(r'\bghp_[a-zA-Z0-9]{36}\b'),    # Personal access token
            re.compile(r'\bghs_[a-zA-Z0-9]{36}\b'),    # GitHub App token
            re.compile(r'\bgho_[a-zA-Z0-9]{36}\b'),    # OAuth token
            re.compile(r'\bghu_[a-zA-Z0-9]{36}\b'),    # GitHub user token
            re.compile(r'\bgithub_pat_[a-zA-Z0-9_]{82}\b'),  # Fine-grained PAT
        ]
        
        # API Keys (various services)
        self.api_key_patterns = [
            # OpenAI
            re.compile(r'\bsk-[a-zA-Z0-9]{48}\b'),
            
            # Stripe
            re.compile(r'\b(sk|pk)_(test|live)_[a-zA-Z0-9]{24,}\b'),
            
            # Google API
            re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b'),
            
            # Slack
            re.compile(r'\bxox[baprs]-[0-9a-zA-Z-]{10,48}\b'),
            
            # Discord
            re.compile(r'\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b'),
            
            # Twilio
            re.compile(r'\bAC[a-z0-9]{32}\b'),
            
            # SendGrid
            re.compile(r'\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b'),
        ]
        
        # Email patterns
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        
        # IP Address patterns
        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        # IBAN pattern
        self.iban_pattern = re.compile(
            r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b'
        )
        
        # Dutch BSN pattern
        self.bsn_pattern = re.compile(r'\b[1-9][0-9]{8}\b')
        
        # Customer and Personal Data Patterns
        # Dutch postal codes
        self.postal_code_patterns = [
            re.compile(r'\b[1-9][0-9]{3}\s?[A-Za-z]{2}\b'),  # Dutch postal code
            re.compile(r'\b[0-9]{5}(?:-[0-9]{4})?\b'),        # US ZIP code
        ]
        
        # Personal names patterns
        self.personal_name_patterns = [
            re.compile(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b'),  # First Last name
            re.compile(r'\b[A-Z][a-z]+\s+(?:de|van|der)\s+[A-Z][a-z]+\b'),  # Dutch names
        ]
        
        # Address patterns
        self.address_patterns = [
            re.compile(r'\b[A-Z][a-z]+(?:straat|laan|weg|plein|kade)\s+[0-9]+[a-z]?\b'),  # Dutch street
            re.compile(r'\b[0-9]+\s+[A-Z][a-z]+\s+(?:Street|Avenue|Road|Drive|Lane)\b'),    # English street
        ]
        
        # Date of birth patterns
        self.dob_patterns = [
            re.compile(r'\b[0-3]?[0-9][-/][0-1]?[0-9][-/][12][90][0-9]{2}\b'),  # DD-MM-YYYY
            re.compile(r'\b[12][90][0-9]{2}[-/][0-1]?[0-9][-/][0-3]?[0-9]\b'),  # YYYY-MM-DD
        ]
        
        # Phone number patterns
        self.phone_patterns = [
            re.compile(r'(?:\+31|0031|0)[1-9][0-9]{8}'),  # Dutch format
            re.compile(r'\+[1-9][0-9]{1,14}'),            # International
        ]
        
        # License plate patterns
        self.license_plate_patterns = [
            re.compile(r'\b[0-9]{2}-[A-Z]{2}-[0-9]{2}\b'),      # Dutch old format
            re.compile(r'\b[0-9]{1,3}-[A-Z]{3}-[0-9]{1,2}\b'),  # Dutch new format
        ]
        
        # Financial patterns
        self.financial_patterns = [
            re.compile(r'\b(?:salary|salaris|income|inkomen)\s*[=:]\s*[€$][0-9,]+\b', re.IGNORECASE),
            re.compile(r'\b(?:account|rekening)\s*(?:number|nummer)?\s*[=:]\s*[0-9]{8,12}\b', re.IGNORECASE),
        ]
        
        # Medical/sensitive keywords
        self.medical_keywords = [
            re.compile(r'\b(?:diagnose|diagnosis|medical|patient|treatment)\b', re.IGNORECASE),
            re.compile(r'\b(?:ziekenhuis|dokter|arts|medicijn|behandeling)\b', re.IGNORECASE),
        ]
        
        # Business data patterns
        self.business_data_patterns = [
            re.compile(r'\b(?:customer|klant|client)\s*(?:id|nummer)?\s*[=:]\s*[A-Z0-9]{6,}\b', re.IGNORECASE),
            re.compile(r'\b(?:order|bestelling)\s*(?:id|nummer)?\s*[=:]\s*[A-Z0-9]{6,}\b', re.IGNORECASE),
        ]
        
        # Hash patterns (deterministic length and format)
        self.hash_patterns = [
            re.compile(r'\b[a-f0-9]{32}\b'),  # MD5
            re.compile(r'\b[a-f0-9]{40}\b'),  # SHA1
            re.compile(r'\b[a-f0-9]{64}\b'),  # SHA256
        ]
        
        # Credit card patterns
        self.credit_card_patterns = [
            re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'),      # Visa
            re.compile(r'\b5[1-5][0-9]{14}\b'),              # MasterCard
            re.compile(r'\b3[47][0-9]{13}\b'),               # American Express
            re.compile(r'\b6(?:011|5[0-9]{2})[0-9]{12}\b'),  # Discover
        ]
        
        # Database connection strings
        self.db_connection_patterns = [
            re.compile(r'postgresql://[^\s"]+'),
            re.compile(r'mysql://[^\s"]+'),
            re.compile(r'mongodb://[^\s"]+'),
            re.compile(r'redis://[^\s"]+'),
        ]
        
        # Configuration patterns
        self.config_patterns = [
            re.compile(r'(?i)password\s*[:=]\s*[\'"][^\'"\s]{8,}[\'"]'),
            re.compile(r'(?i)secret\s*[:=]\s*[\'"][^\'"\s]{8,}[\'"]'),
            re.compile(r'(?i)token\s*[:=]\s*[\'"][^\'"\s]{16,}[\'"]'),
            re.compile(r'(?i)key\s*[:=]\s*[\'"][^\'"\s]{16,}[\'"]'),
        ]
        
        # High entropy string patterns
        self.high_entropy_patterns = [
            re.compile(r'\b[A-Za-z0-9+/]{40,}={0,2}\b'),  # Base64-like
            re.compile(r'\b[A-Fa-f0-9]{32,}\b'),          # Hex strings
        ]
        
        # Placeholder detection patterns
        self.placeholder_patterns = [
            re.compile(r'(?i)\b(your|placeholder|example|sample|test|demo|fake|dummy)\b'),
            re.compile(r'\b(x{3,}|\*{3,}|\.{3,})\b'),
            re.compile(r'(?i)\b(change_me|replace_me|todo|fixme)\b'),
        ]
    
    def analyze_content(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze content for sensitive information
        
        Args:
            content: File content to analyze
            file_path: Path to the file being analyzed
            
        Returns:
            List of findings
        """
        findings = []
        
        # Analyze using deterministic patterns
        findings.extend(self._analyze_deterministic_patterns(content, file_path))
        
        # Analyze entropy
        findings.extend(self._analyze_entropy(content, file_path))
        
        # Analyze configuration patterns
        findings.extend(self._analyze_config_patterns(content, file_path))
        
        # Analyze personal and customer data (skip for code files)
        if not self._is_code_file(file_path):
            findings.extend(self._analyze_personal_data(content, file_path))
        
        # Filter out placeholders
        findings = self._filter_placeholders(findings, content)
        
        return findings
    
    def _analyze_deterministic_patterns(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze content using deterministic patterns"""
        findings = []
        
        # Private keys
        for pattern in self.private_key_patterns:
            for match in pattern.finditer(content):
                findings.append({
                    'type': 'private_key',
                    'pattern': 'Private Key',
                    'match': match.group(0),
                    'line': content[:match.start()].count('\n') + 1,
                    'column': match.start() - content.rfind('\n', 0, match.start()),
                    'confidence': 'HIGH',
                    'severity': 'CRITICAL',
                    'file_path': file_path
                })
        
        # AWS patterns
        for pattern in self.aws_patterns:
            for match in pattern.finditer(content):
                findings.append({
                    'type': 'aws_credential',
                    'pattern': 'AWS Credential',
                    'match': match.group(0),
                    'line': content[:match.start()].count('\n') + 1,
                    'column': match.start() - content.rfind('\n', 0, match.start()),
                    'confidence': 'HIGH',
                    'severity': 'CRITICAL',
                    'file_path': file_path
                })
        
        # JWT tokens
        for match in self.jwt_pattern.finditer(content):
            findings.append({
                'type': 'jwt_token',
                'pattern': 'JWT Token',
                'match': match.group(0),
                'line': content[:match.start()].count('\n') + 1,
                'column': match.start() - content.rfind('\n', 0, match.start()),
                'confidence': 'HIGH',
                'severity': 'HIGH',
                'file_path': file_path
            })
        
        # GitHub tokens
        for pattern in self.github_patterns:
            for match in pattern.finditer(content):
                findings.append({
                    'type': 'github_token',
                    'pattern': 'GitHub Token',
                    'match': match.group(0),
                    'line': content[:match.start()].count('\n') + 1,
                    'column': match.start() - content.rfind('\n', 0, match.start()),
                    'confidence': 'HIGH',
                    'severity': 'CRITICAL',
                    'file_path': file_path
                })
        
        # API keys
        for pattern in self.api_key_patterns:
            for match in pattern.finditer(content):
                findings.append({
                    'type': 'api_key',
                    'pattern': 'API Key',
                    'match': match.group(0),
                    'line': content[:match.start()].count('\n') + 1,
                    'column': match.start() - content.rfind('\n', 0, match.start()),
                    'confidence': 'HIGH',
                    'severity': 'HIGH',
                    'file_path': file_path
                })
        
        # Email addresses
        for match in self.email_pattern.finditer(content):
            findings.append({
                'type': 'email',
                'pattern': 'Email Address',
                'match': match.group(0),
                'line': content[:match.start()].count('\n') + 1,
                'column': match.start() - content.rfind('\n', 0, match.start()),
                'confidence': 'MEDIUM',
                'severity': 'LOW',
                'file_path': file_path
            })
        
        # Credit cards
        for pattern in self.credit_card_patterns:
            for match in pattern.finditer(content):
                # Validate using Luhn algorithm
                if self._validate_credit_card(match.group(0)):
                    findings.append({
                        'type': 'credit_card',
                        'pattern': 'Credit Card Number',
                        'match': match.group(0),
                        'line': content[:match.start()].count('\n') + 1,
                        'column': match.start() - content.rfind('\n', 0, match.start()),
                        'confidence': 'HIGH',
                        'severity': 'HIGH',
                        'file_path': file_path
                    })
        
        # Database connections
        for pattern in self.db_connection_patterns:
            for match in pattern.finditer(content):
                findings.append({
                    'type': 'database_connection',
                    'pattern': 'Database Connection String',
                    'match': match.group(0),
                    'line': content[:match.start()].count('\n') + 1,
                    'column': match.start() - content.rfind('\n', 0, match.start()),
                    'confidence': 'HIGH',
                    'severity': 'HIGH',
                    'file_path': file_path
                })
        
        return findings
    
    def _analyze_entropy(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze content for high entropy strings that might be secrets"""
        findings = []
        
        # Split content into words and analyze each
        words = re.findall(r'\b[A-Za-z0-9+/=]{20,}\b', content)
        
        for word in words:
            if len(word) >= self.min_string_length:
                entropy = self._calculate_entropy(word)
                
                if entropy >= self.min_entropy_threshold:
                    # Find the position in content
                    match_pos = content.find(word)
                    if match_pos != -1:
                        findings.append({
                            'type': 'high_entropy',
                            'pattern': 'High Entropy String',
                            'match': word,
                            'line': content[:match_pos].count('\n') + 1,
                            'column': match_pos - content.rfind('\n', 0, match_pos),
                            'confidence': 'MEDIUM',
                            'severity': 'MEDIUM',
                            'entropy': entropy,
                            'file_path': file_path
                        })
        
        return findings
    
    def _analyze_config_patterns(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze configuration patterns"""
        findings = []
        
        for pattern in self.config_patterns:
            for match in pattern.finditer(content):
                findings.append({
                    'type': 'config_secret',
                    'pattern': 'Configuration Secret',
                    'match': match.group(0),
                    'line': content[:match.start()].count('\n') + 1,
                    'column': match.start() - content.rfind('\n', 0, match.start()),
                    'confidence': 'MEDIUM',
                    'severity': 'MEDIUM',
                    'file_path': file_path
                })
        
        return findings
    
    def _filter_placeholders(self, findings: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Filter out placeholder/dummy values"""
        filtered_findings = []
        
        for finding in findings:
            match_text = finding['match'].lower()
            is_placeholder = False
            
            # Check against placeholder patterns
            for pattern in self.placeholder_patterns:
                if pattern.search(match_text):
                    is_placeholder = True
                    break
            
            # Additional placeholder checks
            if not is_placeholder:
                placeholder_indicators = [
                    'example', 'test', 'demo', 'sample', 'placeholder',
                    'dummy', 'fake', 'your_', 'my_', 'change_me',
                    'replace_me', 'todo', 'fixme'
                ]
                
                for indicator in placeholder_indicators:
                    if indicator in match_text:
                        is_placeholder = True
                        break
            
            if not is_placeholder:
                filtered_findings.append(finding)
        
        return filtered_findings
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0
        
        # Count character frequencies
        counter = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _validate_credit_card(self, number: str) -> bool:
        """Validate credit card number using Luhn algorithm"""
        # Remove any spaces or dashes
        number = re.sub(r'[\s-]', '', number)
        
        # Must be all digits
        if not number.isdigit():
            return False
        
        # Apply Luhn algorithm
        total = 0
        reverse_digits = number[::-1]
        
        for i, digit in enumerate(reverse_digits):
            n = int(digit)
            if i % 2 == 1:  # Every second digit from right
                n *= 2
                if n > 9:
                    n = n // 10 + n % 10
            total += n
        
        return total % 10 == 0
    
    def get_pattern_stats(self) -> Dict[str, int]:
        """Get statistics about loaded patterns"""
        return {
            'private_key_patterns': len(self.private_key_patterns),
            'aws_patterns': len(self.aws_patterns),
            'github_patterns': len(self.github_patterns),
            'api_key_patterns': len(self.api_key_patterns),
            'credit_card_patterns': len(self.credit_card_patterns),
            'config_patterns': len(self.config_patterns),
            'total_deterministic_patterns': (
                len(self.private_key_patterns) +
                len(self.aws_patterns) +
                len(self.github_patterns) +
                len(self.api_key_patterns) +
                len(self.credit_card_patterns) +
                len(self.config_patterns)
            )
        }
    
    def _is_code_file(self, file_path: str) -> bool:
        """Check if file is likely a code file"""
        code_extensions = {'.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.cs', '.php', '.rb', '.go', '.rs'}
        extension = '.' + file_path.lower().split('.')[-1] if '.' in file_path else ''
        return extension in code_extensions
    
    def _analyze_personal_data(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze content for personal and customer data"""
        findings = []
        
        # BSN numbers (Dutch social security)
        bsn_matches = self.bsn_pattern.findall(content)
        if bsn_matches:
            findings.append({
                'type': 'bsn_number',
                'pattern': 'BSN Number',
                'match': f'{len(bsn_matches)} BSN numbers found',
                'confidence': 'HIGH',
                'severity': 'CRITICAL',
                'file_path': file_path,
                'risk_score': 95
            })
        
        # IBAN numbers
        iban_matches = self.iban_pattern.findall(content)
        if iban_matches:
            findings.append({
                'type': 'iban_number',
                'pattern': 'IBAN Number',
                'match': f'{len(iban_matches)} IBAN numbers found',
                'confidence': 'HIGH',
                'severity': 'HIGH',
                'file_path': file_path,
                'risk_score': 80
            })
        
        # Personal names (only if many found)
        name_count = 0
        for pattern in self.personal_name_patterns:
            name_count += len(pattern.findall(content))
        
        if name_count > 5:  # Only flag if many names
            findings.append({
                'type': 'personal_names',
                'pattern': 'Personal Names',
                'match': f'{name_count} personal names found',
                'confidence': 'MEDIUM',
                'severity': 'MEDIUM',
                'file_path': file_path,
                'risk_score': 60
            })
        
        # Addresses
        address_count = 0
        for pattern in self.address_patterns:
            address_count += len(pattern.findall(content))
        
        if address_count > 0:
            findings.append({
                'type': 'addresses',
                'pattern': 'Street Addresses',
                'match': f'{address_count} addresses found',
                'confidence': 'MEDIUM',
                'severity': 'MEDIUM',
                'file_path': file_path,
                'risk_score': 65
            })
        
        # Date of birth
        dob_count = 0
        for pattern in self.dob_patterns:
            dob_count += len(pattern.findall(content))
        
        if dob_count > 0:
            findings.append({
                'type': 'date_of_birth',
                'pattern': 'Date of Birth',
                'match': f'{dob_count} birth dates found',
                'confidence': 'HIGH',
                'severity': 'HIGH',
                'file_path': file_path,
                'risk_score': 75
            })
        
        # Phone numbers
        phone_count = 0
        for pattern in self.phone_patterns:
            phone_count += len(pattern.findall(content))
        
        if phone_count > 2:  # Multiple phone numbers
            findings.append({
                'type': 'phone_numbers',
                'pattern': 'Phone Numbers',
                'match': f'{phone_count} phone numbers found',
                'confidence': 'MEDIUM',
                'severity': 'MEDIUM',
                'file_path': file_path,
                'risk_score': 55
            })
        
        # License plates
        plate_count = 0
        for pattern in self.license_plate_patterns:
            plate_count += len(pattern.findall(content))
        
        if plate_count > 0:
            findings.append({
                'type': 'license_plates',
                'pattern': 'License Plates',
                'match': f'{plate_count} license plates found',
                'confidence': 'MEDIUM',
                'severity': 'MEDIUM',
                'file_path': file_path,
                'risk_score': 55
            })
        
        # Financial data
        financial_count = 0
        for pattern in self.financial_patterns:
            financial_count += len(pattern.findall(content))
        
        if financial_count > 0:
            findings.append({
                'type': 'financial_data',
                'pattern': 'Financial Information',
                'match': f'{financial_count} financial records found',
                'confidence': 'HIGH',
                'severity': 'HIGH',
                'file_path': file_path,
                'risk_score': 80
            })
        
        # Medical data
        medical_count = 0
        for pattern in self.medical_keywords:
            medical_count += len(pattern.findall(content))
        
        if medical_count > 3:  # Multiple medical terms
            findings.append({
                'type': 'medical_data',
                'pattern': 'Medical Information',
                'match': f'{medical_count} medical terms found',
                'confidence': 'MEDIUM',
                'severity': 'HIGH',
                'file_path': file_path,
                'risk_score': 85
            })
        
        # Business data
        business_count = 0
        for pattern in self.business_data_patterns:
            business_count += len(pattern.findall(content))
        
        if business_count > 0:
            findings.append({
                'type': 'business_data',
                'pattern': 'Business Data',
                'match': f'{business_count} business records found',
                'confidence': 'MEDIUM',
                'severity': 'MEDIUM',
                'file_path': file_path,
                'risk_score': 65
            })
        
        return findings