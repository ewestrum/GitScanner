"""
Performance Optimizer for efficient scanning with encoding detection and smart filtering
"""

import logging
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
import mimetypes
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import functools

# Try to import chardet with fallback
try:
    import chardet
    CHARDET_AVAILABLE = True
except ImportError:
    CHARDET_AVAILABLE = False
    logging.warning("chardet not available, using default encoding")

logger = logging.getLogger(__name__)


class PerformanceOptimizer:
    """Optimize scanning performance with smart filtering and parallel processing"""
    
    def __init__(self, performance_config: Dict[str, Any]):
        """Initialize performance optimizer
        
        Args:
            performance_config: Configuration for performance optimization
        """
        self.config = performance_config
        
        # File size limits
        self.max_file_size = performance_config.get('max_file_size', 10 * 1024 * 1024)  # 10MB
        self.max_text_file_size = performance_config.get('max_text_file_size', 2 * 1024 * 1024)  # 2MB
        
        # Performance settings
        self.max_workers = performance_config.get('max_workers', 4)
        self.chunk_size = performance_config.get('chunk_size', 1024 * 1024)  # 1MB chunks
        self.encoding_detection_sample_size = performance_config.get('encoding_sample_size', 8192)  # 8KB
        
        # Caching
        self.encoding_cache = {}
        self.mime_cache = {}
        self.skip_cache = set()
        
        # Initialize filters
        self._init_filters()
        
        logger.info(f"Performance optimizer initialized (max_workers: {self.max_workers})")
    
    def _init_filters(self):
        """Initialize file and directory filters"""
        
        # Default binary extensions to skip
        self.binary_extensions = set(self.config.get('binary_extensions', [
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg', '.webp',
            '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm', '.mkv',
            '.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma',
            '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2', '.xz',
            '.exe', '.dll', '.so', '.dylib', '.app', '.deb', '.rpm',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.class', '.jar', '.war', '.ear',
            '.pyc', '.pyo', '.pyd',
            '.o', '.obj', '.lib', '.a',
            '.ico', '.woff', '.woff2', '.ttf', '.eot', '.otf'
        ]))
        
        # Directories to skip entirely
        self.skip_directories = set(self.config.get('skip_directories', [
            '.git', '.svn', '.hg', '.bzr',
            'node_modules', '__pycache__', '.venv', 'venv', 'env',
            'vendor', 'build', 'dist', 'target', 'out',
            '.idea', '.vscode', '.vs',
            'coverage', '.nyc_output', '.coverage',
            'logs', 'log', 'tmp', 'temp', 'cache',
            '.terraform', '.vagrant',
            'bower_components', 'jspm_packages'
        ]))
        
        # Files to skip based on patterns
        self.skip_file_patterns = [
            re.compile(pattern) for pattern in self.config.get('skip_file_patterns', [
                r'.*\.min\\.js$',  # Minified JavaScript
                r'.*\.min\\.css$',  # Minified CSS
                r'.*-min\\.',  # Other minified files
                r'.*\\.bundle\\.',  # Bundle files
                r'.*\\.chunk\\.',  # Chunk files
                r'.*\\.map$',  # Source maps
                r'package-lock\\.json$',  # NPM lock files
                r'yarn\\.lock$',  # Yarn lock files
                r'.*\\.lock$',  # General lock files
                r'.*\\.sql$',  # SQL dumps (can be large)
                r'.*\\.csv$',  # CSV files (usually data)
                r'.*\\.tsv$',  # TSV files (usually data)
                r'.*\\.dat$',  # Data files
                r'.*\\.db$',  # Database files
                r'.*\\.sqlite$',  # SQLite files
            ])
        ]
        
        # Priority file extensions (scan these first)
        self.priority_extensions = set(self.config.get('priority_extensions', [
            '.env', '.config', '.conf', '.ini', '.yaml', '.yml', '.json', '.xml',
            '.py', '.js', '.ts', '.java', '.cs', '.cpp', '.c', '.h',
            '.php', '.rb', '.go', '.rs', '.scala', '.kt', '.swift',
            '.sql', '.sh', '.bat', '.ps1', '.dockerfile'
        ]))
        
        # Allowlist patterns (always scan these)
        self.allowlist_patterns = [
            re.compile(pattern) for pattern in self.config.get('allowlist_patterns', [
                r'.*\\.env.*',  # Environment files
                r'.*config.*',  # Configuration files
                r'.*secret.*',  # Secret files
                r'.*key.*',  # Key files
                r'.*credential.*',  # Credential files
                r'.*password.*',  # Password files
            ])
        ]
    
    def should_scan_file(self, file_path: str, file_size: Optional[int] = None) -> bool:
        """Determine if a file should be scanned
        
        Args:
            file_path: Path to the file
            file_size: File size in bytes (optional)
            
        Returns:
            True if file should be scanned
        """
        # Check cache first
        cache_key = f"{file_path}:{file_size}"
        if cache_key in self.skip_cache:
            return False
        
        path_obj = Path(file_path)
        
        # Always scan if matches allowlist
        if any(pattern.match(file_path) for pattern in self.allowlist_patterns):
            return True
        
        # Skip if matches skip patterns
        if any(pattern.match(file_path) for pattern in self.skip_file_patterns):
            self.skip_cache.add(cache_key)
            return False
        
        # Check file extension
        extension = path_obj.suffix.lower()
        if extension in self.binary_extensions:
            self.skip_cache.add(cache_key)
            return False
        
        # Check file size
        if file_size is not None:
            if file_size > self.max_file_size:
                logger.debug(f"Skipping large file: {file_path} ({file_size} bytes)")
                self.skip_cache.add(cache_key)
                return False
        
        # Check if in skip directory
        for part in path_obj.parts:
            if part in self.skip_directories:
                self.skip_cache.add(cache_key)
                return False
        
        return True
    
    def should_scan_directory(self, dir_path: str) -> bool:
        """Determine if a directory should be scanned
        
        Args:
            dir_path: Path to the directory
            
        Returns:
            True if directory should be scanned
        """
        dir_name = Path(dir_path).name.lower()
        return dir_name not in self.skip_directories
    
    def detect_encoding(self, file_path: str, content_sample: bytes = None) -> str:
        """Detect file encoding efficiently
        
        Args:
            file_path: Path to the file
            content_sample: Optional content sample
            
        Returns:
            Detected encoding string
        """
        # Check cache first
        if file_path in self.encoding_cache:
            return self.encoding_cache[file_path]
        
        try:
            if content_sample is None:
                # Read sample from file
                with open(file_path, 'rb') as f:
                    content_sample = f.read(self.encoding_detection_sample_size)
            
            # Use chardet for detection if available
            if CHARDET_AVAILABLE:
                detection_result = chardet.detect(content_sample)
                encoding = detection_result.get('encoding', 'utf-8')
                confidence = detection_result.get('confidence', 0.0)
                
                # Fall back to utf-8 for low confidence
                if confidence < 0.7:
                    encoding = 'utf-8'
            else:
                # Fallback to utf-8 when chardet is not available
                encoding = 'utf-8'
                confidence = 0.0
            
            # Normalize encoding name
            if encoding:
                encoding = encoding.lower()
                # Map common variations
                encoding_map = {
                    'ascii': 'utf-8',
                    'windows-1252': 'cp1252',
                    'iso-8859-1': 'latin1'
                }
                encoding = encoding_map.get(encoding, encoding)
            else:
                encoding = 'utf-8'
            
            # Cache the result
            self.encoding_cache[file_path] = encoding
            
            return encoding
            
        except Exception as e:
            logger.debug(f"Error detecting encoding for {file_path}: {e}")
            return 'utf-8'
    
    def read_file_efficiently(self, file_path: str) -> Optional[str]:
        """Read file content efficiently with proper encoding detection
        
        Args:
            file_path: Path to the file
            
        Returns:
            File content as string, or None if error
        """
        try:
            # Check file size first
            file_size = Path(file_path).stat().st_size
            
            if not self.should_scan_file(file_path, file_size):
                return None
            
            # For very large files, read in chunks
            if file_size > self.chunk_size:
                return self._read_large_file(file_path, file_size)
            
            # Detect encoding
            encoding = self.detect_encoding(file_path)
            
            # Read file content
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                content = f.read()
            
            # Check if content is too large for text analysis
            if self._is_text_file(file_path) and len(content) > self.max_text_file_size:
                logger.debug(f"Text file too large for analysis: {file_path}")
                return None
            
            return content
            
        except Exception as e:
            logger.debug(f"Error reading file {file_path}: {e}")
            return None
    
    def _read_large_file(self, file_path: str, file_size: int) -> Optional[str]:
        """Read large file in chunks to avoid memory issues"""
        try:
            encoding = self.detect_encoding(file_path)
            chunks = []
            total_read = 0
            
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                while total_read < self.max_file_size:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    chunks.append(chunk)
                    total_read += len(chunk.encode('utf-8'))
                    
                    # Stop if we've read enough
                    if total_read >= self.max_file_size:
                        logger.debug(f"Truncated large file: {file_path} at {total_read} bytes")
                        break
            
            return ''.join(chunks)
            
        except Exception as e:
            logger.debug(f"Error reading large file {file_path}: {e}")
            return None
    
    def _is_text_file(self, file_path: str) -> bool:
        """Check if file is likely a text file"""
        # Check cache
        if file_path in self.mime_cache:
            mime_type = self.mime_cache[file_path]
        else:
            mime_type, _ = mimetypes.guess_type(file_path)
            self.mime_cache[file_path] = mime_type
        
        if mime_type:
            return mime_type.startswith('text/') or mime_type in [
                'application/json',
                'application/xml',
                'application/javascript',
                'application/x-yaml'
            ]
        
        # Check extension
        text_extensions = {
            '.txt', '.md', '.rst', '.log', '.cfg', '.conf', '.ini',
            '.env', '.yaml', '.yml', '.json', '.xml', '.csv', '.tsv',
            '.py', '.js', '.ts', '.html', '.css', '.sql', '.sh', '.bat'
        }
        
        extension = Path(file_path).suffix.lower()
        return extension in text_extensions
    
    def prioritize_files(self, file_list: List[str]) -> List[str]:
        """Prioritize files for scanning (high-risk files first)
        
        Args:
            file_list: List of file paths
            
        Returns:
            Prioritized list of file paths
        """
        priority_files = []
        normal_files = []
        
        for file_path in file_list:
            extension = Path(file_path).suffix.lower()
            file_name = Path(file_path).name.lower()
            
            # Check if high priority
            is_priority = (
                extension in self.priority_extensions or
                any(pattern.match(file_path) for pattern in self.allowlist_patterns) or
                any(keyword in file_name for keyword in ['env', 'config', 'secret', 'key', 'credential'])
            )
            
            if is_priority:
                priority_files.append(file_path)
            else:
                normal_files.append(file_path)
        
        # Sort priority files by risk (env files first, then config, etc.)
        priority_files.sort(key=self._get_file_priority_score, reverse=True)
        
        return priority_files + normal_files
    
    def _get_file_priority_score(self, file_path: str) -> int:
        """Get priority score for file (higher = more important)"""
        file_name = Path(file_path).name.lower()
        extension = Path(file_path).suffix.lower()
        
        score = 0
        
        # Extension-based scoring
        extension_scores = {
            '.env': 100,
            '.config': 90,
            '.conf': 85,
            '.ini': 80,
            '.yaml': 75,
            '.yml': 75,
            '.json': 70,
            '.xml': 65
        }
        score += extension_scores.get(extension, 0)
        
        # Filename-based scoring
        if 'secret' in file_name:
            score += 50
        elif 'key' in file_name:
            score += 45
        elif 'credential' in file_name:
            score += 40
        elif 'password' in file_name:
            score += 35
        elif 'auth' in file_name:
            score += 30
        elif 'config' in file_name:
            score += 25
        elif 'env' in file_name:
            score += 20
        
        return score
    
    def optimize_scan_order(self, files: List[str]) -> List[str]:
        """Optimize file scanning order for better performance
        
        Args:
            files: List of file paths to scan
            
        Returns:
            Optimized list of file paths
        """
        # Filter files that should be scanned
        scannable_files = [f for f in files if self.should_scan_file(f)]
        
        # Prioritize files
        prioritized_files = self.prioritize_files(scannable_files)
        
        logger.info(f"Optimized scan order: {len(prioritized_files)}/{len(files)} files will be scanned")
        
        return prioritized_files
    
    def parallel_file_processing(self, files: List[str], process_func, max_workers: Optional[int] = None) -> List[Any]:
        """Process files in parallel for better performance
        
        Args:
            files: List of file paths to process
            process_func: Function to process each file
            max_workers: Maximum number of worker threads
            
        Returns:
            List of processing results
        """
        if max_workers is None:
            max_workers = self.max_workers
        
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(process_func, file_path): file_path 
                for file_path in files
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    if result:  # Only add non-None results
                        results.append(result)
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")
        
        return results
    
    def get_directory_filter(self) -> callable:
        """Get a directory filtering function for os.walk"""
        
        def dir_filter(dirs):
            """Filter directories in-place for os.walk"""
            dirs[:] = [d for d in dirs if d.lower() not in self.skip_directories]
        
        return dir_filter
    
    def clear_caches(self):
        """Clear all caches to free memory"""
        self.encoding_cache.clear()
        self.mime_cache.clear()
        self.skip_cache.clear()
        logger.info("Performance optimizer caches cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            'encoding_cache_size': len(self.encoding_cache),
            'mime_cache_size': len(self.mime_cache),
            'skip_cache_size': len(self.skip_cache),
            'total_cached_items': len(self.encoding_cache) + len(self.mime_cache) + len(self.skip_cache)
        }
    
    def estimate_scan_time(self, file_count: int, avg_file_size: int) -> float:
        """Estimate scanning time based on file count and size
        
        Args:
            file_count: Number of files to scan
            avg_file_size: Average file size in bytes
            
        Returns:
            Estimated scan time in seconds
        """
        # Base processing rate (files per second)
        base_rate = 50  # Conservative estimate
        
        # Adjust for file size
        if avg_file_size > 100 * 1024:  # 100KB
            base_rate *= 0.5
        elif avg_file_size > 1024 * 1024:  # 1MB
            base_rate *= 0.2
        
        # Adjust for parallelization
        effective_rate = base_rate * min(self.max_workers, 4)
        
        return max(file_count / effective_rate, 1.0)


def create_default_performance_config() -> Dict[str, Any]:
    """Create default performance configuration"""
    return {
        'max_file_size': 10 * 1024 * 1024,  # 10MB
        'max_text_file_size': 2 * 1024 * 1024,  # 2MB
        'max_workers': 4,
        'chunk_size': 1024 * 1024,  # 1MB
        'encoding_sample_size': 8192,  # 8KB
        'binary_extensions': [],  # Use defaults
        'skip_directories': [],  # Use defaults
        'skip_file_patterns': [],  # Use defaults
        'priority_extensions': [],  # Use defaults
        'allowlist_patterns': []  # Use defaults
    }