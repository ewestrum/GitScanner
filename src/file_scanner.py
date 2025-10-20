"""
File Scanner - Detect suspicious file names and patterns
"""

import re
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class FileScanner:
    """Scanner for detecting suspicious file names and patterns"""
    
    def __init__(self, scan_rules: Dict[str, Any]):
        """Initialize file scanner
        
        Args:
            scan_rules: Dictionary containing scanning rules and patterns
        """
        self.scan_rules = scan_rules
        
        # Default suspicious file patterns
        self.suspicious_extensions = {
            '.env', '.key', '.pem', '.p12', '.pfx', '.jks',
            '.keystore', '.cer', '.crt', '.der', '.ssh',
            '.ppk', '.rdp', '.ovpn', '.sqlite', '.db',
            '.sql', '.dump', '.backup', '.bak', '.log'
        }
        
        # Suspicious file names (case insensitive)
        self.suspicious_names = {
            'password', 'passwd', 'secret', 'private',
            'credential', 'config', 'settings', 'backup',
            'dump', 'export', 'id_rsa', 'id_dsa', 'shadow',
            'htpasswd', 'wp-config', 'database'
        }
        
        # Suspicious directory patterns
        self.suspicious_dirs = {
            '.ssh', '.aws', '.azure', 'credentials',
            'secrets', 'private', 'backup', 'dumps'
        }
        
        # Compiled regex patterns for performance
        self._compile_patterns()
        
        logger.info("File scanner initialized")
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance"""
        # Personal data patterns
        self.personal_data_patterns = [
            re.compile(r'password\s*[=:]\s*["\'][^"\']+["\']', re.IGNORECASE),
            re.compile(r'api[_-]?key\s*[=:]\s*["\'][^"\']+["\']', re.IGNORECASE),
            re.compile(r'secret\s*[=:]\s*["\'][^"\']+["\']', re.IGNORECASE),
            re.compile(r'token\s*[=:]\s*["\'][^"\']+["\']', re.IGNORECASE),
            re.compile(r'private[_-]?key\s*[=:]\s*["\'][^"\']+["\']', re.IGNORECASE),
        ]
        
        # Email patterns
        self.email_pattern = re.compile(r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b')
        
        # Phone number patterns (Dutch format)
        self.phone_patterns = [
            re.compile(r'\\b(?:\\+31|0031|0)[1-9][0-9]{8}\\b'),  # Dutch mobile
            re.compile(r'\\b0[1-9][0-9]{7,8}\\b'),  # Dutch landline
            re.compile(r'\\b\\+[1-9][0-9]{1,14}\\b'),  # International format
        ]
        
        # Credit card pattern (basic)
        self.credit_card_pattern = re.compile(r'\\b(?:[4][0-9]{12}(?:[0-9]{3})?|[5][1-5][0-9]{14})\\b')
        
        # SSH key patterns
        self.ssh_key_patterns = [
            re.compile(r'-----BEGIN [A-Z ]+-----'),
            re.compile(r'ssh-rsa AAAAB3NzaC1yc2E'),
            re.compile(r'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5'),
        ]
    
    def is_suspicious_file(self, file_path: str) -> bool:
        """Check if a file path is suspicious
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file is suspicious
        """
        if not file_path:
            return False
        
        path_obj = Path(file_path.lower())
        
        # Check file extension
        if path_obj.suffix in self.suspicious_extensions:
            return True
        
        # Check file name
        file_name = path_obj.name
        for suspicious_name in self.suspicious_names:
            if suspicious_name in file_name:
                return True
        
        # Check directory names
        for part in path_obj.parts:
            if part in self.suspicious_dirs:
                return True
        
        # Check custom rules
        if 'suspicious_patterns' in self.scan_rules:
            for pattern in self.scan_rules['suspicious_patterns']:
                if re.search(pattern, file_path, re.IGNORECASE):
                    return True
        
        # Check if file is in excluded directories
        if 'allowed_directories' in self.scan_rules:
            for allowed_dir in self.scan_rules['allowed_directories']:
                if file_path.startswith(allowed_dir):
                    return False
        
        return False
    
    def get_suspicion_reason(self, file_path: str) -> str:
        """Get reason why file is considered suspicious
        
        Args:
            file_path: Path to analyze
            
        Returns:
            Reason string
        """
        if not file_path:
            return "Unknown reason"
        
        path_obj = Path(file_path.lower())
        reasons = []
        
        # Check file extension
        if path_obj.suffix in self.suspicious_extensions:
            reasons.append(f"Suspicious file extension: {path_obj.suffix}")
        
        # Check file name
        file_name = path_obj.name
        for suspicious_name in self.suspicious_names:
            if suspicious_name in file_name:
                reasons.append(f"Suspicious file name contains: {suspicious_name}")
        
        # Check directory names
        for part in path_obj.parts:
            if part in self.suspicious_dirs:
                reasons.append(f"File in suspicious directory: {part}")
        
        return "; ".join(reasons) if reasons else "Matches custom pattern"
    
    def scan_file_content_for_personal_data(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Scan file content for personal data patterns
        
        Args:
            content: File content to scan
            file_path: Path of the file being scanned
            
        Returns:
            List of matches found
        """
        if not content:
            return []
        
        matches = []
        
        # Scan for email addresses
        email_matches = self.email_pattern.findall(content)
        for email in email_matches:
            matches.append({
                'type': 'email',
                'pattern': 'Email Address',
                'match': email,
                'file_path': file_path,
                'severity': 'MEDIUM'
            })
        
        # Scan for phone numbers
        for pattern in self.phone_patterns:
            phone_matches = pattern.findall(content)
            for phone in phone_matches:
                matches.append({
                    'type': 'phone',
                    'pattern': 'Phone Number',
                    'match': phone,
                    'file_path': file_path,
                    'severity': 'MEDIUM'
                })
        
        # Scan for credit card numbers
        cc_matches = self.credit_card_pattern.findall(content)
        for cc in cc_matches:
            matches.append({
                'type': 'credit_card',
                'pattern': 'Credit Card Number',
                'match': cc[:4] + '*' * (len(cc) - 8) + cc[-4:],  # Mask middle digits
                'file_path': file_path,
                'severity': 'HIGH'
            })
        
        # Scan for SSH keys
        for pattern in self.ssh_key_patterns:
            if pattern.search(content):
                matches.append({
                    'type': 'ssh_key',
                    'pattern': 'SSH Private Key',
                    'match': '[SSH Key Found]',
                    'file_path': file_path,
                    'severity': 'CRITICAL'
                })
        
        # Scan for credential patterns
        for pattern in self.personal_data_patterns:
            credential_matches = pattern.findall(content)
            for match in credential_matches:
                matches.append({
                    'type': 'credential',
                    'pattern': 'Potential Credential',
                    'match': match[:20] + '...' if len(match) > 20 else match,
                    'file_path': file_path,
                    'severity': 'HIGH'
                })
        
        return matches
    
    def is_allowed_file_type(self, file_path: str) -> bool:
        """Check if file type is explicitly allowed
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file type is allowed
        """
        if not file_path:
            return False
        
        # Allowed code file extensions
        allowed_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.html', '.css', '.scss',
            '.java', '.cpp', '.c', '.h', '.hpp', '.cs', '.php', '.rb',
            '.go', '.rs', '.swift', '.kt', '.scala', '.clj', '.elm',
            '.vue', '.svelte', '.md', '.txt', '.json', '.yaml', '.yml',
            '.xml', '.toml', '.ini', '.cfg', '.dockerfile', '.gitignore',
            '.gitattributes', '.editorconfig', '.eslintrc', '.prettierrc'
        }
        
        path_obj = Path(file_path.lower())
        return path_obj.suffix in allowed_extensions
    
    def get_file_risk_score(self, file_path: str, content_matches: List[Dict[str, Any]]) -> int:
        """Calculate risk score for a file
        
        Args:
            file_path: Path of the file
            content_matches: List of sensitive content matches
            
        Returns:
            Risk score (0-100)
        """
        score = 0
        
        # Base score for suspicious file
        if self.is_suspicious_file(file_path):
            score += 30
        
        # Add score based on content matches
        severity_scores = {
            'LOW': 5,
            'MEDIUM': 15,
            'HIGH': 25,
            'CRITICAL': 40
        }
        
        for match in content_matches:
            severity = match.get('severity', 'LOW')
            score += severity_scores.get(severity, 5)
        
        # Cap at 100
        return min(score, 100)