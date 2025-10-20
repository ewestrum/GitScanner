"""
Git History Analyzer for scanning commit history and detecting leaked secrets
"""

import os
import subprocess
import logging
import json
import tempfile
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
import hashlib
import time

logger = logging.getLogger(__name__)


class GitHistoryAnalyzer:
    """Analyze git history for secrets and sensitive information"""
    
    def __init__(self, content_analyzer, max_commits: int = 500, max_blob_size: int = 10 * 1024 * 1024):
        """Initialize git history analyzer
        
        Args:
            content_analyzer: Enhanced content analyzer instance
            max_commits: Maximum number of commits to analyze
            max_blob_size: Maximum blob size to analyze (10MB default)
        """
        self.content_analyzer = content_analyzer
        self.max_commits = max_commits
        self.max_blob_size = max_blob_size
        self.blob_cache = {}  # Cache for blob content
        self.analyzed_blobs = set()  # Track analyzed blobs to avoid duplicates
        
        logger.info(f"Git history analyzer initialized (max_commits: {max_commits})")
    
    def analyze_repository_history(self, repo_path: str) -> Dict[str, Any]:
        """Analyze entire repository git history
        
        Args:
            repo_path: Path to git repository
            
        Returns:
            Dictionary containing analysis results
        """
        if not self._is_git_repository(repo_path):
            logger.warning(f"Not a git repository: {repo_path}")
            return {'error': 'Not a git repository', 'matches': []}
        
        try:
            # Get commit list
            commits = self._get_commit_list(repo_path)
            if not commits:
                logger.warning(f"No commits found in {repo_path}")
                return {'commits_analyzed': 0, 'matches': []}
            
            logger.info(f"Analyzing {len(commits)} commits in {repo_path}")
            
            all_matches = []
            analyzed_commits = 0
            
            for commit_info in commits[:self.max_commits]:
                try:
                    commit_matches = self._analyze_commit(repo_path, commit_info)
                    all_matches.extend(commit_matches)
                    analyzed_commits += 1
                    
                    # Progress logging every 50 commits
                    if analyzed_commits % 50 == 0:
                        logger.info(f"Analyzed {analyzed_commits}/{len(commits)} commits")
                        
                except Exception as e:
                    logger.error(f"Error analyzing commit {commit_info.get('hash', 'unknown')}: {e}")
                    continue
            
            # Group matches by commit and file
            grouped_matches = self._group_matches_by_commit(all_matches)
            
            return {
                'commits_analyzed': analyzed_commits,
                'total_commits': len(commits),
                'matches': all_matches,
                'grouped_matches': grouped_matches,
                'blob_cache_size': len(self.blob_cache),
                'unique_blobs_analyzed': len(self.analyzed_blobs)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing repository history: {e}")
            return {'error': str(e), 'matches': []}
    
    def analyze_recent_commits(self, repo_path: str, days: int = 30) -> Dict[str, Any]:
        """Analyze recent commits within specified days
        
        Args:
            repo_path: Path to git repository
            days: Number of days to look back
            
        Returns:
            Dictionary containing analysis results
        """
        if not self._is_git_repository(repo_path):
            return {'error': 'Not a git repository', 'matches': []}
        
        try:
            # Get recent commits
            since_date = f"--since='{days} days ago'"
            commits = self._get_commit_list(repo_path, additional_args=[since_date])
            
            if not commits:
                return {'commits_analyzed': 0, 'matches': [], 'days_analyzed': days}
            
            logger.info(f"Analyzing {len(commits)} recent commits (last {days} days)")
            
            all_matches = []
            for commit_info in commits:
                try:
                    commit_matches = self._analyze_commit(repo_path, commit_info)
                    all_matches.extend(commit_matches)
                except Exception as e:
                    logger.error(f"Error analyzing commit {commit_info.get('hash', 'unknown')}: {e}")
                    continue
            
            return {
                'commits_analyzed': len(commits),
                'days_analyzed': days,
                'matches': all_matches,
                'grouped_matches': self._group_matches_by_commit(all_matches)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing recent commits: {e}")
            return {'error': str(e), 'matches': []}
    
    def analyze_specific_commits(self, repo_path: str, commit_hashes: List[str]) -> Dict[str, Any]:
        """Analyze specific commits by hash
        
        Args:
            repo_path: Path to git repository
            commit_hashes: List of commit hashes to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        if not self._is_git_repository(repo_path):
            return {'error': 'Not a git repository', 'matches': []}
        
        all_matches = []
        analyzed_commits = []
        
        for commit_hash in commit_hashes:
            try:
                commit_info = self._get_commit_info(repo_path, commit_hash)
                if commit_info:
                    commit_matches = self._analyze_commit(repo_path, commit_info)
                    all_matches.extend(commit_matches)
                    analyzed_commits.append(commit_hash)
                else:
                    logger.warning(f"Commit not found: {commit_hash}")
                    
            except Exception as e:
                logger.error(f"Error analyzing commit {commit_hash}: {e}")
                continue
        
        return {
            'requested_commits': len(commit_hashes),
            'analyzed_commits': len(analyzed_commits),
            'analyzed_commit_hashes': analyzed_commits,
            'matches': all_matches,
            'grouped_matches': self._group_matches_by_commit(all_matches)
        }
    
    def _is_git_repository(self, repo_path: str) -> bool:
        """Check if directory is a git repository"""
        git_dir = os.path.join(repo_path, '.git')
        return os.path.exists(git_dir)
    
    def _get_commit_list(self, repo_path: str, additional_args: List[str] = None) -> List[Dict[str, Any]]:
        """Get list of commits with metadata"""
        try:
            cmd = [
                'git', 'rev-list',
                '--all',
                '--pretty=format:%H|%an|%ae|%ad|%s',
                '--date=iso',
                '--no-merges'  # Skip merge commits to focus on actual changes
            ]
            
            if additional_args:
                cmd.extend(additional_args)
            
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.error(f"Git rev-list failed: {result.stderr}")
                return []
            
            commits = []
            lines = result.stdout.strip().split('\\n')
            
            for line in lines:
                if line.startswith('commit '):
                    continue  # Skip commit prefix lines
                
                if '|' in line:
                    parts = line.split('|', 4)
                    if len(parts) >= 5:
                        commits.append({
                            'hash': parts[0],
                            'author_name': parts[1],
                            'author_email': parts[2],
                            'date': parts[3],
                            'message': parts[4]
                        })
            
            return commits
            
        except subprocess.TimeoutExpired:
            logger.error(f"Git rev-list timeout for {repo_path}")
            return []
        except Exception as e:
            logger.error(f"Error getting commit list: {e}")
            return []
    
    def _get_commit_info(self, repo_path: str, commit_hash: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific commit"""
        try:
            cmd = [
                'git', 'show',
                '--pretty=format:%H|%an|%ae|%ad|%s',
                '--date=iso',
                '--name-only',
                commit_hash
            ]
            
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return None
            
            lines = result.stdout.strip().split('\\n')
            if not lines:
                return None
            
            # Parse commit info from first line
            parts = lines[0].split('|', 4)
            if len(parts) < 5:
                return None
            
            return {
                'hash': parts[0],
                'author_name': parts[1],
                'author_email': parts[2],
                'date': parts[3],
                'message': parts[4]
            }
            
        except Exception as e:
            logger.error(f"Error getting commit info for {commit_hash}: {e}")
            return None
    
    def _analyze_commit(self, repo_path: str, commit_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze a single commit for secrets"""
        commit_hash = commit_info['hash']
        matches = []
        
        try:
            # Get changed files in this commit
            changed_files = self._get_changed_files(repo_path, commit_hash)
            
            for file_path in changed_files:
                try:
                    # Get file content from this commit
                    content = self._get_file_content_at_commit(repo_path, commit_hash, file_path)
                    
                    if content is None:
                        continue
                    
                    # Create blob hash for caching
                    blob_hash = hashlib.sha256(content.encode('utf-8', errors='ignore')).hexdigest()
                    
                    # Skip if we've already analyzed this exact content
                    if blob_hash in self.analyzed_blobs:
                        continue
                    
                    # Analyze content for secrets
                    file_matches = self.content_analyzer.analyze_content(content, file_path)
                    
                    # Add commit context to matches
                    for match in file_matches:
                        match.update({
                            'commit_hash': commit_hash,
                            'commit_author': commit_info['author_name'],
                            'commit_email': commit_info['author_email'],
                            'commit_date': commit_info['date'],
                            'commit_message': commit_info['message'],
                            'blob_hash': blob_hash
                        })
                    
                    matches.extend(file_matches)
                    
                    # Cache the blob content
                    self.blob_cache[blob_hash] = {
                        'content': content,
                        'file_path': file_path,
                        'commit_hash': commit_hash,
                        'timestamp': time.time()
                    }
                    
                    # Mark blob as analyzed
                    self.analyzed_blobs.add(blob_hash)
                    
                except Exception as e:
                    logger.error(f"Error analyzing file {file_path} in commit {commit_hash}: {e}")
                    continue
            
            return matches
            
        except Exception as e:
            logger.error(f"Error analyzing commit {commit_hash}: {e}")
            return []
    
    def _get_changed_files(self, repo_path: str, commit_hash: str) -> List[str]:
        """Get list of files changed in a commit"""
        try:
            cmd = [
                'git', 'diff-tree',
                '--no-commit-id',
                '--name-only',
                '-r',
                commit_hash
            ]
            
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return []
            
            files = [f.strip() for f in result.stdout.strip().split('\\n') if f.strip()]
            
            # Filter out binary files and large files we don't want to analyze
            filtered_files = []
            for file_path in files:
                if self._should_analyze_file(file_path):
                    filtered_files.append(file_path)
            
            return filtered_files
            
        except Exception as e:
            logger.error(f"Error getting changed files for commit {commit_hash}: {e}")
            return []
    
    def _get_file_content_at_commit(self, repo_path: str, commit_hash: str, file_path: str) -> Optional[str]:
        """Get file content at specific commit"""
        try:
            cmd = [
                'git', 'show',
                f'{commit_hash}:{file_path}'
            ]
            
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                # File might have been deleted or is binary
                return None
            
            content = result.stdout
            
            # Check file size
            if len(content.encode('utf-8')) > self.max_blob_size:
                logger.warning(f"Skipping large file {file_path} in commit {commit_hash}")
                return None
            
            return content
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout getting content for {file_path} in commit {commit_hash}")
            return None
        except Exception as e:
            logger.error(f"Error getting file content: {e}")
            return None
    
    def _should_analyze_file(self, file_path: str) -> bool:
        """Determine if file should be analyzed based on extension and path"""
        
        # Skip binary file extensions
        binary_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg',
            '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
            '.mp3', '.wav', '.flac', '.aac', '.ogg',
            '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2',
            '.exe', '.dll', '.so', '.dylib', '.app',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.class', '.jar', '.war', '.ear',
            '.pyc', '.pyo', '.pyd',
            '.o', '.obj', '.lib', '.a',
            '.ico', '.woff', '.woff2', '.ttf', '.eot'
        }
        
        file_ext = Path(file_path).suffix.lower()
        if file_ext in binary_extensions:
            return False
        
        # Skip certain directories
        skip_dirs = {
            '.git', 'node_modules', '__pycache__', '.venv', 'venv',
            'vendor', 'build', 'dist', 'target', '.idea', '.vscode',
            'coverage', '.nyc_output', 'logs', 'tmp', 'temp'
        }
        
        path_parts = Path(file_path).parts
        if any(part in skip_dirs for part in path_parts):
            return False
        
        # Skip very long paths (potential minified files)
        if len(file_path) > 200:
            return False
        
        return True
    
    def _group_matches_by_commit(self, matches: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Group matches by commit hash"""
        grouped = {}
        
        for match in matches:
            commit_hash = match.get('commit_hash', 'unknown')
            
            if commit_hash not in grouped:
                grouped[commit_hash] = {
                    'commit_info': {
                        'hash': commit_hash,
                        'author': match.get('commit_author', ''),
                        'email': match.get('commit_email', ''),
                        'date': match.get('commit_date', ''),
                        'message': match.get('commit_message', '')
                    },
                    'matches': [],
                    'files_affected': set(),
                    'severity_counts': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                }
            
            grouped[commit_hash]['matches'].append(match)
            grouped[commit_hash]['files_affected'].add(match.get('file_path', ''))
            
            severity = match.get('severity', 'LOW')
            if severity in grouped[commit_hash]['severity_counts']:
                grouped[commit_hash]['severity_counts'][severity] += 1
        
        # Convert sets to lists for JSON serialization
        for commit_data in grouped.values():
            commit_data['files_affected'] = list(commit_data['files_affected'])
            commit_data['total_matches'] = len(commit_data['matches'])
        
        return grouped
    
    def clear_cache(self):
        """Clear blob cache to free memory"""
        self.blob_cache.clear()
        self.analyzed_blobs.clear()
        logger.info("Git history analyzer cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_size = sum(len(blob['content'].encode('utf-8')) for blob in self.blob_cache.values())
        
        return {
            'cached_blobs': len(self.blob_cache),
            'analyzed_blobs': len(self.analyzed_blobs),
            'cache_size_bytes': total_size,
            'cache_size_mb': round(total_size / (1024 * 1024), 2)
        }