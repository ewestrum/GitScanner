"""
Enhanced File Scanner with MIME detection, entropy analysis, and advanced pattern matching
"""

import re
import os
import math
import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from pathlib import Path
import mimetypes

# Try to import optional libraries with fallbacks
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    logging.warning("python-magic not available, using fallback MIME detection")

try:
    import chardet
    CHARDET_AVAILABLE = True
except ImportError:
    CHARDET_AVAILABLE = False
    logging.warning("chardet not available, using fallback encoding detection")

logger = logging.getLogger(__name__)


class EnhancedFileScanner:
    """Advanced file scanner with MIME detection, entropy analysis, and content classification"""
    
    def __init__(self, scan_rules: Dict[str, Any]):
        """Initialize enhanced file scanner
        
        Args:
            scan_rules: Dictionary containing scanning rules and patterns
        """
        self.scan_rules = scan_rules
        self.max_text_size = scan_rules.get('max_text_size', 2 * 1024 * 1024)  # 2MB
        self.max_binary_size = scan_rules.get('max_binary_size', 10 * 1024 * 1024)  # 10MB
        
        # Initialize magic for MIME detection if available
        self.magic_mime = None
        self.magic_type = None
        
        if MAGIC_AVAILABLE:
            try:
                self.magic_mime = magic.Magic(mime=True)
                self.magic_type = magic.Magic()
                self.mime_available = True
                logger.info("python-magic initialized successfully")
            except Exception as e:
                logger.warning(f"python-magic not available, falling back to extension detection: {e}")
                self.mime_available = False
        else:
            self.mime_available = False
        
        # Enhanced suspicious file patterns
        self.suspicious_extensions = {
            # Credentials and keys
            '.env', '.key', '.pem', '.p12', '.pfx', '.jks', '.keystore', 
            '.cer', '.crt', '.der', '.ssh', '.ppk', '.ovpn',
            
            # Databases
            '.sqlite', '.sqlite3', '.db', '.sql', '.dump', '.backup', 
            '.bak', '.mdb', '.accdb',
            
            # Config files
            '.conf', '.config', '.ini', '.cfg', '.yaml', '.yml',
            
            # Data files
            '.csv', '.tsv', '.xlsx', '.xls', '.json', '.xml',
            
            # Archives (might contain sensitive data)
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
            
            # Logs
            '.log', '.out', '.err'
        }
        
        # Suspicious file name patterns
        self.suspicious_patterns = [
            # Credentials
            r'(?i).*password.*',
            r'(?i).*passwd.*',
            r'(?i).*secret.*',
            r'(?i).*private.*',
            r'(?i).*credential.*',
            r'(?i).*auth.*',
            r'(?i).*token.*',
            r'(?i).*key.*',
            
            # Backups and dumps
            r'(?i).*backup.*',
            r'(?i).*dump.*',
            r'(?i).*export.*',
            r'(?i).*migration.*',
            
            # Personal data
            r'(?i).*customer.*',
            r'(?i).*user.*data.*',
            r'(?i).*personal.*',
            r'(?i).*pii.*',
            
            # Common sensitive files
            r'(?i)wp-config.*',
            r'(?i)database.*',
            r'(?i)htpasswd.*',
            r'(?i)shadow.*',
            r'(?i)id_rsa.*',
            r'(?i)id_dsa.*',
        ]
        
        # Compile patterns for performance
        self.compiled_patterns = [re.compile(pattern) for pattern in self.suspicious_patterns]
        
        # Directories to ignore
        self.ignore_directories = {
            '.git', '.svn', '.hg', '.bzr',  # VCS
            'node_modules', 'dist', 'build', 'target',  # Build artifacts
            '.venv', 'venv', '__pycache__', '.pytest_cache',  # Python
            '.idea', '.vscode', '.vs',  # IDEs
            'vendor', 'packages',  # Dependencies
            'logs', 'tmp', 'temp', 'cache'  # Temporary files
        }
        
        logger.info("Enhanced file scanner initialized")
    
    def get_file_info(self, file_path: str, content: Optional[bytes] = None) -> Dict[str, Any]:
        """Get comprehensive file information including MIME type and classification
        
        Args:
            file_path: Path to the file
            content: Optional file content bytes
            
        Returns:
            Dictionary with file information
        """
        path_obj = Path(file_path)
        
        file_info = {
            'path': file_path,
            'name': path_obj.name,
            'extension': path_obj.suffix.lower(),
            'size': None,
            'mime_type': None,
            'file_type': None,
            'encoding': None,
            'is_text': False,
            'is_binary': False,
            'is_suspicious': False,
            'suspicion_reasons': [],
            'classification': 'unknown'
        }
        
        # Get file size
        if content is not None:
            file_info['size'] = len(content)
        
        # MIME type detection
        if self.mime_available and self.magic_mime and content is not None:
            try:
                file_info['mime_type'] = self.magic_mime.from_buffer(content)
                file_info['file_type'] = self.magic_type.from_buffer(content)
            except Exception as e:
                logger.debug(f"MIME detection failed for {file_path}: {e}")
                file_info['mime_type'] = self._guess_mime_from_extension(file_info['extension'])
                file_info['file_type'] = 'unknown'
        else:
            # Fallback to extension-based detection
            file_info['mime_type'] = self._guess_mime_from_extension(file_info['extension'])
            file_info['file_type'] = 'text' if self._is_text_file_extension(file_info['extension']) else 'binary'
        
        # Classify as text or binary
        mime_type = file_info['mime_type'] or ''
        if mime_type.startswith('text/') or mime_type in ['application/json', 'application/xml']:
            file_info['is_text'] = True
        elif mime_type.startswith(('image/', 'video/', 'audio/', 'application/octet-stream')):
            file_info['is_binary'] = True
        else:
            # Try to detect from content
            if content is not None:
                file_info['is_text'] = self._is_text_content(content)
                file_info['is_binary'] = not file_info['is_text']
        
        # Encoding detection for text files
        if file_info['is_text'] and content is not None:
            if CHARDET_AVAILABLE:
                try:
                    detected = chardet.detect(content)
                    file_info['encoding'] = detected.get('encoding', 'unknown')
                except Exception as e:
                    logger.debug(f"Encoding detection failed for {file_path}: {e}")
                    file_info['encoding'] = 'utf-8'  # Default fallback
            else:
                # Fallback encoding detection
                file_info['encoding'] = 'utf-8'  # Default to UTF-8
        
        # Check if file is suspicious
        file_info['is_suspicious'], file_info['suspicion_reasons'] = self._analyze_file_suspicion(file_info)
        
        # Classify file type
        file_info['classification'] = self._classify_file(file_info, content)
        
        return file_info
    
    def _is_text_file_extension(self, extension: str) -> bool:
        """Check if file extension indicates a text file"""
        text_extensions = {
            '.txt', '.md', '.rst', '.log', '.cfg', '.conf', '.ini',
            '.env', '.yaml', '.yml', '.json', '.xml', '.csv', '.tsv',
            '.py', '.js', '.ts', '.html', '.css', '.sql', '.sh', '.bat',
            '.c', '.cpp', '.h', '.java', '.cs', '.php', '.rb', '.go',
            '.rs', '.kt', '.swift', '.scala', '.pl', '.r', '.m'
        }
        return extension.lower() in text_extensions
    
    def _guess_mime_from_extension(self, extension: str) -> str:
        """Guess MIME type from file extension"""
        mime_map = {
            '.txt': 'text/plain',
            '.md': 'text/markdown',
            '.py': 'text/x-python',
            '.js': 'application/javascript',
            '.json': 'application/json',
            '.xml': 'application/xml',
            '.yaml': 'application/x-yaml',
            '.yml': 'application/x-yaml',
            '.csv': 'text/csv',
            '.sql': 'application/sql',
            '.env': 'text/plain',
            '.ini': 'text/plain',
            '.conf': 'text/plain',
            '.config': 'text/plain',
            '.log': 'text/plain',
            '.zip': 'application/zip',
            '.pdf': 'application/pdf',
            '.jpg': 'image/jpeg',
            '.png': 'image/png',
            '.exe': 'application/x-executable',
            '.dll': 'application/x-msdownload',
        }
        return mime_map.get(extension, 'application/octet-stream')
    
    def _is_text_content(self, content: bytes) -> bool:
        """Determine if content is text based on byte analysis"""
        if not content:
            return True
        
        # Check for null bytes (strong indicator of binary)
        if b'\\x00' in content[:1024]:
            return False
        
        # Check for high ratio of printable characters
        sample = content[:1024]
        printable_count = sum(1 for byte in sample if 32 <= byte <= 126 or byte in [9, 10, 13])
        printable_ratio = printable_count / len(sample) if sample else 1
        
        return printable_ratio > 0.7
    
    def _analyze_file_suspicion(self, file_info: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Analyze if file is suspicious and return reasons"""
        reasons = []
        
        # Check extension
        if file_info['extension'] in self.suspicious_extensions:
            reasons.append(f"Suspicious file extension: {file_info['extension']}")
        
        # Check file name patterns
        for pattern in self.compiled_patterns:
            if pattern.search(file_info['name']):
                reasons.append(f"Suspicious file name pattern: {pattern.pattern}")
                break
        
        # Check MIME type
        mime_type = file_info.get('mime_type', '')
        suspicious_mimes = [
            'application/x-pem-file',
            'application/pkcs12',
            'application/x-pkcs12',
            'application/x-sqlite3',
            'application/vnd.sqlite3',
        ]
        if any(mime in mime_type for mime in suspicious_mimes):
            reasons.append(f"Suspicious MIME type: {mime_type}")
        
        # Check size (very large text files might be data dumps)
        size = file_info.get('size', 0)
        if file_info['is_text'] and size > 10 * 1024 * 1024:  # 10MB
            reasons.append(f"Large text file ({size // 1024 // 1024}MB) - possible data dump")
        
        return len(reasons) > 0, reasons
    
    def _classify_file(self, file_info: Dict[str, Any], content: Optional[bytes] = None) -> str:
        """Classify file into categories"""
        
        # Code files
        code_extensions = {
            '.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.hpp', 
            '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt'
        }
        if file_info['extension'] in code_extensions:
            return 'code'
        
        # Configuration files
        config_extensions = {'.json', '.yaml', '.yml', '.ini', '.conf', '.config', '.env'}
        if file_info['extension'] in config_extensions:
            return 'config'
        
        # Documentation
        doc_extensions = {'.md', '.txt', '.rst', '.adoc'}
        if file_info['extension'] in doc_extensions:
            return 'documentation'
        
        # Data files
        data_extensions = {'.csv', '.tsv', '.sql', '.json', '.xml'}
        if file_info['extension'] in data_extensions:
            return 'data'
        
        # Database files
        db_extensions = {'.sqlite', '.sqlite3', '.db', '.mdb', '.accdb'}
        if file_info['extension'] in db_extensions:
            return 'database'
        
        # Credential files
        cred_extensions = {'.key', '.pem', '.p12', '.pfx', '.jks', '.keystore'}
        if file_info['extension'] in cred_extensions:
            return 'credentials'
        
        # Archives
        archive_extensions = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'}
        if file_info['extension'] in archive_extensions:
            return 'archive'
        
        # Media files
        media_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mp3', '.pdf'}
        if file_info['extension'] in media_extensions:
            return 'media'
        
        # Binary executables
        if file_info['is_binary']:
            return 'binary'
        
        # If it's text but we can't classify it, analyze content
        if file_info['is_text'] and content:
            return self._classify_text_content(content)
        
        return 'unknown'
    
    def _classify_text_content(self, content: bytes) -> str:
        """Classify text content based on patterns"""
        try:
            text = content.decode('utf-8', errors='ignore')[:2048]  # Sample first 2KB
            
            # Count code-like patterns
            code_patterns = [
                r'\\b(if|for|while|class|def|function|import|require)\\b',
                r'[{}();]',
                r'=\\s*["\']',
                r'\\b(true|false|null|undefined)\\b'
            ]
            
            code_score = sum(len(re.findall(pattern, text, re.IGNORECASE)) for pattern in code_patterns)
            
            # Count data-like patterns
            data_patterns = [
                r'\\d+[,\\t]\\d+',  # CSV-like
                r'[a-zA-Z0-9+/]{20,}={0,2}',  # Base64-like
                r'\\b\\d{4}-\\d{2}-\\d{2}\\b',  # Dates
                r'[,\\t]{3,}',  # Multiple delimiters
            ]
            
            data_score = sum(len(re.findall(pattern, text)) for pattern in data_patterns)
            
            # Heuristic classification
            if code_score > data_score * 2:
                return 'code'
            elif data_score > code_score:
                return 'data'
            else:
                return 'text'
                
        except Exception:
            return 'text'
    
    def should_ignore_path(self, file_path: str) -> bool:
        """Check if file path should be ignored"""
        path_parts = Path(file_path).parts
        
        # Check for ignored directories
        for part in path_parts:
            if part in self.ignore_directories:
                return True
        
        # Check for custom ignore patterns
        ignore_patterns = self.scan_rules.get('ignore_patterns', [])
        for pattern in ignore_patterns:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        
        return False
    
    def calculate_entropy(self, data: str) -> float:
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
    
    def find_high_entropy_lines(self, content: str, threshold: float = 4.5) -> List[Dict[str, Any]]:
        """Find lines with high entropy (potential secrets)"""
        high_entropy_lines = []
        
        for line_num, line in enumerate(content.split('\\n'), 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith(('#', '//', '/*', '*', '--')):
                continue
            
            # Calculate entropy for potential secret values
            # Look for assignment patterns like key=value
            assignment_patterns = [
                r'["\']([^"\']{20,})["\']',  # Quoted strings
                r'=\\s*([a-zA-Z0-9+/]{20,}={0,2})(?:\\s|$)',  # Base64-like assignments
                r':\\s*["\']([^"\']{20,})["\']',  # JSON-like values
            ]
            
            for pattern in assignment_patterns:
                matches = re.findall(pattern, line)
                for match in matches:
                    entropy = self.calculate_entropy(match)
                    
                    if entropy >= threshold:
                        high_entropy_lines.append({
                            'line_number': line_num,
                            'content': line[:100] + '...' if len(line) > 100 else line,
                            'entropy': entropy,
                            'suspicious_value': match[:20] + '...' if len(match) > 20 else match
                        })
        
        return high_entropy_lines
    
    def is_size_appropriate(self, file_info: Dict[str, Any]) -> bool:
        """Check if file size is appropriate for processing"""
        size = file_info.get('size', 0)
        
        if file_info['is_text']:
            return size <= self.max_text_size
        elif file_info['is_binary']:
            return size <= self.max_binary_size
        else:
            return size <= self.max_text_size  # Default to text limit
    
    def get_processing_recommendation(self, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """Get recommendation for how to process this file"""
        recommendation = {
            'should_scan_content': False,
            'scan_metadata_only': False,
            'skip_completely': False,
            'reason': ''
        }
        
        # Skip if path should be ignored
        if self.should_ignore_path(file_info['path']):
            recommendation.update({
                'skip_completely': True,
                'reason': 'Path in ignore list'
            })
            return recommendation
        
        # Skip if file is too large
        if not self.is_size_appropriate(file_info):
            recommendation.update({
                'scan_metadata_only': True,
                'reason': f'File too large ({file_info.get("size", 0)} bytes)'
            })
            return recommendation
        
        # Skip binary files (scan metadata only)
        if file_info['is_binary']:
            recommendation.update({
                'scan_metadata_only': True,
                'reason': 'Binary file - metadata scan only'
            })
            return recommendation
        
        # Scan content for text files
        if file_info['is_text']:
            recommendation.update({
                'should_scan_content': True,
                'reason': 'Text file - full content scan'
            })
            return recommendation
        
        # Default: scan content
        recommendation.update({
            'should_scan_content': True,
            'reason': 'Unknown type - attempt content scan'
        })
        
        return recommendation