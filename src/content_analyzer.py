"""
Content Analyzer - Analyze file content for sensitive information patterns
"""

import re
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class ContentAnalyzer:
    """Analyzer for detecting sensitive content in files"""
    
    def __init__(self, content_rules: Dict[str, Any]):
        """Initialize content analyzer
        
        Args:
            content_rules: Dictionary containing content analysis rules
        """
        self.content_rules = content_rules
        
        # Initialize detection patterns
        self._init_patterns()
        
        logger.info("Content analyzer initialized")
    
    def _init_patterns(self):
        """Initialize regex patterns for sensitive content detection"""
        
        # API Keys and Tokens
        self.api_key_patterns = [
            # Generic API key patterns
            re.compile(r'(?i)api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?'),
            re.compile(r'(?i)access[_-]?token\s*[=:]\s*["\']?([a-zA-Z0-9_.-]{20,})["\']?'),
            re.compile(r'(?i)secret[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?'),
            re.compile(r'(?i)client[_-]?secret\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?'),
            
            # Specific service patterns
            re.compile(r'sk-[a-zA-Z0-9]{48}'),  # OpenAI API key
            re.compile(r'ghp_[a-zA-Z0-9]{36}'),  # GitHub personal access token
            re.compile(r'ghs_[a-zA-Z0-9]{36}'),  # GitHub app token  
            re.compile(r'AKIA[0-9A-Z]{16}'),    # AWS access key
            re.compile(r'ya29\\.[a-zA-Z0-9_-]{68,}'),  # Google OAuth token
            re.compile(r'xox[baprs]-([0-9a-zA-Z]{10,48})'),  # Slack tokens
        ]
        
        # Password patterns
        self.password_patterns = [
            re.compile(r'(?i)password\s*[=:]\s*["\']([^"\'\\s]{6,})["\']'),
            re.compile(r'(?i)passwd\s*[=:]\s*["\']([^"\'\\s]{6,})["\']'),
            re.compile(r'(?i)pwd\s*[=:]\s*["\']([^"\'\\s]{6,})["\']'),
        ]
        
        # Database connection strings
        self.db_connection_patterns = [
            re.compile(r'(?i)connection[_-]?string\s*[=:]\s*["\']([^"\']+)["\']'),
            re.compile(r'(?i)database[_-]?url\s*[=:]\s*["\']([^"\']+)["\']'),
            re.compile(r'(?i)mongodb://([^"\'\\s]+)'),
            re.compile(r'(?i)mysql://([^"\'\\s]+)'),
            re.compile(r'(?i)postgresql://([^"\'\\s]+)'),
            re.compile(r'(?i)sqlite://([^"\'\\s]+)'),
        ]
        
        # Email addresses
        self.email_pattern = re.compile(
            r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b'
        )
        
        # Phone numbers (Dutch and international)
        self.phone_patterns = [
            re.compile(r'(?:\\+31|0031|0)[1-9][0-9]{8}'),  # Dutch format
            re.compile(r'\\+[1-9][0-9]{1,14}'),            # International
            re.compile(r'\\b0[1-9][0-9]{7,8}\\b'),         # Dutch landline
        ]
        
        # Dutch BSN (Burgerservicenummer) pattern
        self.bsn_pattern = re.compile(r'\\b[1-9][0-9]{8}\\b')
        
        # Credit card numbers
        self.credit_card_patterns = [
            re.compile(r'\\b4[0-9]{12}(?:[0-9]{3})?\\b'),      # Visa
            re.compile(r'\\b5[1-5][0-9]{14}\\b'),              # MasterCard
            re.compile(r'\\b3[47][0-9]{13}\\b'),               # American Express
            re.compile(r'\\b6(?:011|5[0-9]{2})[0-9]{12}\\b'),  # Discover
        ]
        
        # Private keys
        self.private_key_patterns = [
            re.compile(r'-----BEGIN [A-Z ]+PRIVATE KEY-----'),
            re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
            re.compile(r'-----BEGIN DSA PRIVATE KEY-----'),
            re.compile(r'-----BEGIN EC PRIVATE KEY-----'),
            re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        ]
        
        # SSH public keys
        self.ssh_key_pattern = re.compile(
            r'ssh-(?:rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/=]+'
        )
        
        # Customer and Personal Data Patterns
        # Dutch postal codes
        self.postal_code_patterns = [
            re.compile(r'\b[1-9][0-9]{3}\s?[A-Za-z]{2}\b'),  # Dutch postal code
            re.compile(r'\b[0-9]{5}(?:-[0-9]{4})?\b'),        # US ZIP code
            re.compile(r'\b[A-Za-z][0-9][A-Za-z]\s?[0-9][A-Za-z][0-9]\b'),  # Canadian postal
        ]
        
        # IBAN patterns
        self.iban_patterns = [
            re.compile(r'\bNL[0-9]{2}[A-Z]{4}[0-9]{10}\b'),   # Dutch IBAN
            re.compile(r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b'),  # General IBAN
        ]
        
        # Personal names patterns (common Dutch/English names)
        self.personal_name_patterns = [
            re.compile(r'\b(Jan|Piet|Klaas|Marie|Anna|Emma|Noah|Liam|Olivia|Ava)\s+[A-Z][a-z]+\b'),
            re.compile(r'\b[A-Z][a-z]+\s+(de\s+)?[A-Z][a-z]+\b'),  # First Last or First de Last
        ]
        
        # Address patterns
        self.address_patterns = [
            re.compile(r'\b[A-Z][a-z]+(?:straat|laan|weg|plein|kade)\s+[0-9]+[a-z]?\b'),  # Dutch street
            re.compile(r'\b[0-9]+\s+[A-Z][a-z]+\s+(?:Street|Avenue|Road|Drive|Lane)\b'),    # English street
        ]
        
        # Date of birth patterns
        self.dob_patterns = [
            re.compile(r'\b[0-3]?[0-9][-/][0-1]?[0-9][-/][12][90][0-9]{2}\b'),  # DD-MM-YYYY or DD/MM/YYYY
            re.compile(r'\b[12][90][0-9]{2}[-/][0-1]?[0-9][-/][0-3]?[0-9]\b'),  # YYYY-MM-DD
        ]
        
        # License plate patterns
        self.license_plate_patterns = [
            re.compile(r'\b[0-9]{2}-[A-Z]{2}-[0-9]{2}\b'),      # Dutch old format
            re.compile(r'\b[0-9]{1,3}-[A-Z]{3}-[0-9]{1,2}\b'),  # Dutch new format
            re.compile(r'\b[A-Z]{2}-[0-9]{3}-[A-Z]{2}\b'),      # Dutch sidecode
        ]
        
        # Insurance/ID numbers
        self.id_number_patterns = [
            re.compile(r'\b[A-Z]{2}[0-9]{6,8}\b'),              # Generic ID pattern
            re.compile(r'\bNL[0-9]{9}B[0-9]{2}\b'),             # Dutch KvK number
        ]
        
        # Medical/sensitive keywords
        self.medical_keywords = [
            re.compile(r'\b(diagnose|diagnosis|medical|patient|treatment|medication|prescription)\b', re.IGNORECASE),
            re.compile(r'\b(ziekenhuis|dokter|arts|medicijn|behandeling|diagnose)\b', re.IGNORECASE),  # Dutch medical
        ]
        
        # Financial keywords and data
        self.financial_patterns = [
            re.compile(r'\b(salary|salaris|income|inkomen|bonus|commission)\s*[=:]?\s*[€$][0-9,]+\b', re.IGNORECASE),
            re.compile(r'\b(account|rekening)\s*(?:number|nummer)?[=:]?\s*[0-9]{8,12}\b', re.IGNORECASE),
        ]
        
        # Customer/Business data
        self.business_data_patterns = [
            re.compile(r'\b(customer|klant|client)\s*(?:id|number|nummer)?[=:]?\s*[A-Z0-9]{6,}\b', re.IGNORECASE),
            re.compile(r'\b(order|bestelling)\s*(?:id|number|nummer)?[=:]?\s*[A-Z0-9]{6,}\b', re.IGNORECASE),
            re.compile(r'\b(invoice|factuur)\s*(?:id|number|nummer)?[=:]?\s*[A-Z0-9]{6,}\b', re.IGNORECASE),
        ]
        
        # Cryptocurrency wallet addresses
        self.crypto_patterns = [
            re.compile(r'\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b'),  # Bitcoin
            re.compile(r'\\b0x[a-fA-F0-9]{40}\\b'),                # Ethereum
        ]
        
        # JWT tokens
        self.jwt_pattern = re.compile(
            r'eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*'
        )
    
    def _is_code_or_docs_file(self, file_path: str) -> bool:
        """Check if file is code or documentation"""
        code_extensions = {'.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.cs', '.php', '.rb', '.go', '.rs', '.swift'}
        docs_extensions = {'.md', '.txt', '.rst', '.pdf', '.doc', '.docx', '.html', '.xml'}
        
        extension = file_path.lower().split('.')[-1] if '.' in file_path else ''
        return f'.{extension}' in code_extensions or f'.{extension}' in docs_extensions
    
    def analyze_content(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze content for sensitive information including customer data
        
        Args:
            content: File content to analyze
            file_path: Path of the file being analyzed
            
        Returns:
            List of findings
        """
        findings = []
        
        if not content:
            return findings
            
        # Convert to string if bytes
        if isinstance(content, bytes):
            try:
                content = content.decode('utf-8', errors='ignore')
            except Exception:
                logger.warning(f"Could not decode content for {file_path}")
                return findings
        
        # Skip code files and documentation for personal data detection
        is_code_file = self._is_code_or_docs_file(file_path)
        
        # Check for API keys
        for pattern in self.api_key_patterns:
            matches = pattern.findall(content)
            for match in matches:
                match_str = match if isinstance(match, str) else match[0] if match else ''
                if not self._is_placeholder_value(match_str):
                    findings.append({
                        'type': 'api_key',
                        'severity': 'HIGH',
                        'pattern': pattern.pattern,
                        'match': match_str[:20] + '****' if len(match_str) > 20 else match_str,
                        'file_path': file_path,
                        'risk_score': 90
                    })
        
        # Check for passwords
        for pattern in self.password_patterns:
            matches = pattern.findall(content)
            for match in matches:
                if not self._is_placeholder_value(match):
                    findings.append({
                        'type': 'password',
                        'severity': 'HIGH',
                        'pattern': 'Password',
                        'match': '****',
                        'file_path': file_path,
                        'risk_score': 85
                    })
        
        # Personal and customer data detection (skip for code files)
        if not is_code_file:
            # Check for IBAN numbers
            for pattern in self.iban_patterns:
                matches = pattern.findall(content)
                for match in matches:
                    findings.append({
                        'type': 'iban_number',
                        'severity': 'HIGH',
                        'pattern': 'IBAN Number',
                        'match': match[:8] + '****',  # Mask sensitive part
                        'file_path': file_path,
                        'risk_score': 80
                    })
            
            # Check for postal codes
            postal_matches = 0
            for pattern in self.postal_code_patterns:
                matches = pattern.findall(content)
                postal_matches += len(matches)
            
            if postal_matches > 0:
                findings.append({
                    'type': 'postal_codes',
                    'severity': 'MEDIUM',
                    'pattern': 'Postal Codes',
                    'match': f'{postal_matches} postal codes found',
                    'file_path': file_path,
                    'risk_score': 50
                })
            
            # Check for personal names
            name_matches = 0
            for pattern in self.personal_name_patterns:
                matches = pattern.findall(content)
                name_matches += len(matches)
            
            if name_matches > 2:  # Only flag if multiple names found
                findings.append({
                    'type': 'personal_names',
                    'severity': 'MEDIUM',
                    'pattern': 'Personal Names',
                    'match': f'{name_matches} names found',
                    'file_path': file_path,
                    'risk_score': 60
                })
            
            # Check for addresses
            address_matches = 0
            for pattern in self.address_patterns:
                matches = pattern.findall(content)
                address_matches += len(matches)
            
            if address_matches > 0:
                findings.append({
                    'type': 'addresses',
                    'severity': 'MEDIUM',
                    'pattern': 'Addresses',
                    'match': f'{address_matches} addresses found',
                    'file_path': file_path,
                    'risk_score': 65
                })
            
            # Check for date of birth
            for pattern in self.dob_patterns:
                matches = pattern.findall(content)
                for match in matches:
                    findings.append({
                        'type': 'date_of_birth',
                        'severity': 'HIGH',
                        'pattern': 'Date of Birth',
                        'match': match,
                        'file_path': file_path,
                        'risk_score': 75
                    })
            
            # Check for license plates
            for pattern in self.license_plate_patterns:
                matches = pattern.findall(content)
                for match in matches:
                    findings.append({
                        'type': 'license_plate',
                        'severity': 'MEDIUM',
                        'pattern': 'License Plate',
                        'match': match,
                        'file_path': file_path,
                        'risk_score': 55
                    })
            
            # Check for ID numbers
            for pattern in self.id_number_patterns:
                matches = pattern.findall(content)
                for match in matches:
                    findings.append({
                        'type': 'id_number',
                        'severity': 'HIGH',
                        'pattern': 'ID Number',
                        'match': match[:4] + '****',  # Mask sensitive part
                        'file_path': file_path,
                        'risk_score': 70
                    })
            
            # Check for financial data
            for pattern in self.financial_patterns:
                matches = pattern.findall(content)
                for match in matches:
                    findings.append({
                        'type': 'financial_data',
                        'severity': 'HIGH',
                        'pattern': 'Financial Information',
                        'match': 'Financial data found',
                        'file_path': file_path,
                        'risk_score': 80
                    })
            
            # Check for business data
            business_matches = 0
            for pattern in self.business_data_patterns:
                matches = pattern.findall(content)
                business_matches += len(matches)
            
            if business_matches > 0:
                findings.append({
                    'type': 'business_data',
                    'severity': 'MEDIUM',
                    'pattern': 'Business Data',
                    'match': f'{business_matches} business records found',
                    'file_path': file_path,
                    'risk_score': 65
                })
            
            # Check for medical keywords
            medical_matches = 0
            for pattern in self.medical_keywords:
                matches = pattern.findall(content)
                medical_matches += len(matches)
            
            if medical_matches > 2:  # Only flag if multiple medical terms
                findings.append({
                    'type': 'medical_data',
                    'severity': 'HIGH',
                    'pattern': 'Medical Information',
                    'match': f'{medical_matches} medical terms found',
                    'file_path': file_path,
                    'risk_score': 85
                })
        
        # Check emails and phone numbers for all files
        email_matches = self.email_pattern.findall(content)
        filtered_emails = [email for email in email_matches if not self._is_common_email(email)]
        
        if len(filtered_emails) > 3:  # Multiple personal emails
            findings.append({
                'type': 'email_addresses',
                'severity': 'MEDIUM',
                'pattern': 'Email Addresses',
                'match': f'{len(filtered_emails)} email addresses found',
                'file_path': file_path,
                'risk_score': 50
            })
        
        # Check for phone numbers
        phone_matches = 0
        for pattern in self.phone_patterns:
            matches = pattern.findall(content)
            phone_matches += len(matches)
        
        if phone_matches > 0:
            findings.append({
                'type': 'phone_numbers',
                'severity': 'MEDIUM',
                'pattern': 'Phone Numbers',
                'match': f'{phone_matches} phone numbers found',
                'file_path': file_path,
                'risk_score': 55
            })
        
        # Check for BSN (Dutch social security numbers)
        bsn_matches = self.bsn_pattern.findall(content)
        if len(bsn_matches) > 0 and not is_code_file:
            findings.append({
                'type': 'bsn_number',
                'severity': 'CRITICAL',
                'pattern': 'BSN Number',
                'match': f'{len(bsn_matches)} BSN numbers found',
                'file_path': file_path,
                'risk_score': 95
            })
        
        # Check for credit card numbers
        cc_matches = 0
        for pattern in self.credit_card_patterns:
            matches = pattern.findall(content)
            cc_matches += len(matches)
        
        if cc_matches > 0 and not is_code_file:
            findings.append({
                'type': 'credit_card',
                'severity': 'CRITICAL',
                'pattern': 'Credit Card Number',
                'match': f'{cc_matches} credit card numbers found',
                'file_path': file_path,
                'risk_score': 90
            })
        
        return findings
    
    def _find_api_keys(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find API keys and tokens in content"""
        matches = []
        
        for pattern in self.api_key_patterns:
            for match in pattern.finditer(content):
                api_key = match.group(1) if match.groups() else match.group(0)
                
                # Skip obvious placeholder values
                if self._is_placeholder_value(api_key):
                    continue
                
                matches.append({
                    'type': 'api_key',
                    'pattern': 'API Key or Token',
                    'match': self._mask_sensitive_value(api_key),
                    'file_path': file_path,
                    'line_number': content[:match.start()].count('\\n') + 1,
                    'severity': 'CRITICAL'
                })
        
        return matches
    
    def _find_passwords(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find password assignments in content"""
        matches = []
        
        for pattern in self.password_patterns:
            for match in pattern.finditer(content):
                password = match.group(1)
                
                # Skip obvious placeholder values
                if self._is_placeholder_value(password):
                    continue
                
                matches.append({
                    'type': 'password',
                    'pattern': 'Password Assignment',
                    'match': self._mask_sensitive_value(password),
                    'file_path': file_path,
                    'line_number': content[:match.start()].count('\\n') + 1,
                    'severity': 'HIGH'
                })
        
        return matches
    
    def _find_database_connections(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find database connection strings"""
        matches = []
        
        for pattern in self.db_connection_patterns:
            for match in pattern.finditer(content):
                connection_string = match.group(1) if match.groups() else match.group(0)
                
                # Skip localhost connections in development files
                if 'localhost' in connection_string and ('test' in file_path.lower() or 'dev' in file_path.lower()):
                    continue
                
                matches.append({
                    'type': 'database_connection',
                    'pattern': 'Database Connection String',
                    'match': self._mask_connection_string(connection_string),
                    'file_path': file_path,
                    'line_number': content[:match.start()].count('\\n') + 1,
                    'severity': 'HIGH'
                })
        
        return matches
    
    def _find_personal_data(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find personal data like emails, phone numbers, etc."""
        matches = []
        
        # Find email addresses
        for match in self.email_pattern.finditer(content):
            email = match.group(0)
            
            # Skip common non-personal emails
            if self._is_common_email(email):
                continue
            
            matches.append({
                'type': 'email',
                'pattern': 'Email Address',
                'match': email,
                'file_path': file_path,
                'line_number': content[:match.start()].count('\\n') + 1,
                'severity': 'MEDIUM'
            })
        
        # Find phone numbers
        for pattern in self.phone_patterns:
            for match in pattern.finditer(content):
                phone = match.group(0)
                
                matches.append({
                    'type': 'phone',
                    'pattern': 'Phone Number',
                    'match': phone,
                    'file_path': file_path,
                    'line_number': content[:match.start()].count('\\n') + 1,
                    'severity': 'MEDIUM'
                })
        
        # Find potential BSN numbers (Dutch social security)
        for match in self.bsn_pattern.finditer(content):
            bsn = match.group(0)
            
            # Simple validation: BSN should pass checksum test
            if self._is_valid_bsn(bsn):
                matches.append({
                    'type': 'bsn',
                    'pattern': 'Dutch BSN Number',
                    'match': self._mask_sensitive_value(bsn),
                    'file_path': file_path,
                    'line_number': content[:match.start()].count('\\n') + 1,
                    'severity': 'HIGH'
                })
        
        # Find credit card numbers
        for pattern in self.credit_card_patterns:
            for match in pattern.finditer(content):
                cc_number = match.group(0)
                
                if self._is_valid_credit_card(cc_number):
                    matches.append({
                        'type': 'credit_card',
                        'pattern': 'Credit Card Number',
                        'match': self._mask_credit_card(cc_number),
                        'file_path': file_path,
                        'line_number': content[:match.start()].count('\\n') + 1,
                        'severity': 'HIGH'
                    })
        
        return matches
    
    def _find_private_keys(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find private keys and certificates"""
        matches = []
        
        for pattern in self.private_key_patterns:
            for match in pattern.finditer(content):
                matches.append({
                    'type': 'private_key',
                    'pattern': 'Private Key',
                    'match': '[Private Key Found]',
                    'file_path': file_path,
                    'line_number': content[:match.start()].count('\\n') + 1,
                    'severity': 'CRITICAL'
                })
        
        # Find SSH public keys (less critical but still noteworthy)
        for match in self.ssh_key_pattern.finditer(content):
            matches.append({
                'type': 'ssh_public_key',
                'pattern': 'SSH Public Key',
                'match': '[SSH Public Key Found]',
                'file_path': file_path,
                'line_number': content[:match.start()].count('\\n') + 1,
                'severity': 'MEDIUM'
            })
        
        return matches
    
    def _find_tokens(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Find various types of tokens"""
        matches = []
        
        # JWT tokens
        for match in self.jwt_pattern.finditer(content):
            jwt_token = match.group(0)
            
            matches.append({
                'type': 'jwt_token',
                'pattern': 'JWT Token',
                'match': self._mask_sensitive_value(jwt_token),
                'file_path': file_path,
                'line_number': content[:match.start()].count('\\n') + 1,
                'severity': 'HIGH'
            })
        
        # Cryptocurrency addresses
        for pattern in self.crypto_patterns:
            for match in pattern.finditer(content):
                crypto_addr = match.group(0)
                
                matches.append({
                    'type': 'cryptocurrency',
                    'pattern': 'Cryptocurrency Address',
                    'match': crypto_addr,
                    'file_path': file_path,
                    'line_number': content[:match.start()].count('\\n') + 1,
                    'severity': 'MEDIUM'
                })
        
        return matches
    
    def _apply_custom_patterns(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Apply user-defined custom patterns"""
        matches = []
        
        for rule in self.content_rules.get('custom_patterns', []):
            pattern = re.compile(rule['pattern'], re.IGNORECASE)
            severity = rule.get('severity', 'MEDIUM')
            description = rule.get('description', 'Custom Pattern Match')
            
            for match in pattern.finditer(content):
                matches.append({
                    'type': 'custom',
                    'pattern': description,
                    'match': match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0),
                    'file_path': file_path,
                    'line_number': content[:match.start()].count('\\n') + 1,
                    'severity': severity
                })
        
        return matches
    
    def _is_placeholder_value(self, value: str) -> bool:
        """Check if value is likely a placeholder"""
        placeholder_indicators = [
            'your', 'placeholder', 'example', 'sample', 'test',
            'demo', 'fake', 'dummy', 'xxx', '***', '...',
            'change_me', 'replace_me', 'todo', 'fixme'
        ]
        
        value_lower = value.lower()
        return any(indicator in value_lower for indicator in placeholder_indicators)
    
    def _is_common_email(self, email: str) -> bool:
        """Check if email is a common non-personal address"""
        common_emails = [
            'example.com', 'test.com', 'localhost', 'demo.com',
            'sample.com', 'placeholder.com', 'your-domain.com'
        ]
        
        return any(domain in email.lower() for domain in common_emails)
    
    def _is_valid_bsn(self, bsn: str) -> bool:
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
    
    def _is_valid_credit_card(self, cc_number: str) -> bool:
        """Basic Luhn algorithm validation for credit card"""
        try:
            digits = [int(d) for d in cc_number if d.isdigit()]
            checksum = 0
            
            for i in range(len(digits) - 2, -1, -1):
                if (len(digits) - i) % 2 == 0:
                    digits[i] *= 2
                    if digits[i] > 9:
                        digits[i] -= 9
                checksum += digits[i]
            
            return (checksum + digits[-1]) % 10 == 0
        except (ValueError, IndexError):
            return False
    
    def _mask_sensitive_value(self, value: str) -> str:
        """Mask sensitive value for logging"""
        if len(value) <= 8:
            return '*' * len(value)
        return value[:4] + '*' * (len(value) - 8) + value[-4:]
    
    def _mask_connection_string(self, conn_str: str) -> str:
        """Mask passwords in connection strings"""
        # Simple password masking in connection strings
        import re
        return re.sub(r'(password|pwd)=([^;\\s]+)', r'\\1=***', conn_str, flags=re.IGNORECASE)
    
    def _mask_credit_card(self, cc_number: str) -> str:
        """Mask credit card number"""
        return cc_number[:4] + '*' * (len(cc_number) - 8) + cc_number[-4:]
    
    def _is_placeholder_value(self, value: str) -> bool:
        """Check if a value is likely a placeholder"""
        placeholder_indicators = [
            'your_', 'example', 'placeholder', 'replace_me', 'change_me',
            'insert_', 'add_your', 'xxx', 'yyy', 'zzz', 'demo', 'test',
            'sample', 'dummy', 'fake', 'mock'
        ]
        
        if not value or len(value) < 6:
            return True
            
        value_lower = value.lower()
        return any(indicator in value_lower for indicator in placeholder_indicators)
    
    def _is_common_email(self, email: str) -> bool:
        """Check if email is a common non-personal address"""
        common_domains = [
            'example.com', 'test.com', 'demo.com', 'localhost',
            'noreply@', 'no-reply@', 'admin@', 'support@', 'info@'
        ]
        
        email_lower = email.lower()
        return any(domain in email_lower for domain in common_domains)