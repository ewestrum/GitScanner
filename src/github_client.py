"""
GitHub API Client for repository monitoring and content analysis
"""

import requests
import logging
from typing import List, Dict, Any, Optional
import time
from urllib.parse import urljoin
import base64

logger = logging.getLogger(__name__)


class GitHubClient:
    """GitHub API client for repository monitoring"""
    
    def __init__(self, token: str):
        """Initialize GitHub client
        
        Args:
            token: GitHub personal access token
        """
        if not token:
            raise ValueError("GitHub token is required")
        
        self.token = token
        self.base_url = "https://api.github.com"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitHubMonitor/1.0"
        })
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 1.0  # seconds
        
        logger.info("GitHub client initialized")
    
    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make authenticated request to GitHub API with rate limiting
        
        Args:
            endpoint: API endpoint
            params: Query parameters
            
        Returns:
            API response data
            
        Raises:
            requests.RequestException: If API request fails
        """
        # Rate limiting
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.min_request_interval:
            time.sleep(self.min_request_interval - time_since_last_request)
        
        url = urljoin(self.base_url, endpoint)
        
        try:
            response = self.session.get(url, params=params)
            self.last_request_time = time.time()
            
            # Check rate limiting headers
            remaining = response.headers.get('X-RateLimit-Remaining')
            if remaining and int(remaining) < 100:
                logger.warning(f"GitHub API rate limit low: {remaining} requests remaining")
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub API request failed for {endpoint}: {e}")
            if hasattr(e.response, 'status_code') and e.response.status_code == 403:
                logger.error("Rate limit exceeded or insufficient permissions")
            raise
    
    def get_user_repositories(self) -> List[Dict[str, Any]]:
        """Get all repositories for the authenticated user
        
        Returns:
            List of repository information
        """
        logger.info("Fetching user repositories")
        
        repositories = []
        page = 1
        per_page = 100
        
        # First, let's try to get user info to verify authentication
        try:
            user_info = self._make_request('/user')
            logger.info(f"Authenticated as user: {user_info.get('login', 'Unknown')}")
            logger.info(f"User has {user_info.get('public_repos', 0)} public repos, {user_info.get('total_private_repos', 0)} private repos")
        except Exception as e:
            logger.error(f"Failed to get user info - authentication may have failed: {e}")
            return []
        
        while True:
            try:
                params = {
                    'page': page,
                    'per_page': per_page,
                    'type': 'all',  # Get all repositories (owner + collaborator)
                    'sort': 'updated',
                    'direction': 'desc'
                }
                
                logger.info(f"Requesting repositories page {page} with params: {params}")
                repos_page = self._make_request('/user/repos', params)
                
                if not repos_page:
                    logger.info(f"No more repositories found on page {page}")
                    break
                
                logger.info(f"Found {len(repos_page)} repositories on page {page}")
                for repo in repos_page:
                    logger.debug(f"Repository: {repo.get('name', 'Unknown')} - Private: {repo.get('private', False)}")
                
                repositories.extend(repos_page)
                
                # Check if we got fewer results than requested (last page)
                if len(repos_page) < per_page:
                    logger.info(f"Reached last page - got {len(repos_page)} repos (less than {per_page})")
                    break
                
                page += 1
                
            except Exception as e:
                logger.error(f"Error fetching repositories page {page}: {e}")
                break
        
        logger.info(f"Found {len(repositories)} repositories")
        return repositories
    
    def get_repository_contents(self, full_name: str, path: str = "") -> List[Dict[str, Any]]:
        """Get contents of a repository
        
        Args:
            full_name: Repository full name (owner/repo)
            path: Path within repository (default: root)
            
        Returns:
            List of repository contents
        """
        endpoint = f"/repos/{full_name}/contents/{path}"
        
        try:
            contents = self._make_request(endpoint)
            
            # If it's a single file, wrap in list
            if isinstance(contents, dict):
                contents = [contents]
            
            # Recursively get contents of directories (up to 2 levels deep)
            all_contents = []
            for item in contents:
                all_contents.append(item)
                
                if item['type'] == 'dir' and path.count('/') < 2:  # Limit depth
                    try:
                        subcontents = self.get_repository_contents(full_name, item['path'])
                        all_contents.extend(subcontents)
                    except Exception as e:
                        logger.warning(f"Could not access directory {item['path']}: {e}")
            
            return all_contents
            
        except Exception as e:
            logger.error(f"Error getting repository contents for {full_name}: {e}")
            return []
    
    def get_file_content(self, download_url: str) -> Optional[str]:
        """Download and decode file content
        
        Args:
            download_url: Direct download URL for the file
            
        Returns:
            File content as string, or None if unable to download/decode
        """
        try:
            response = requests.get(download_url, timeout=30)
            response.raise_for_status()
            
            # Try to decode as text
            try:
                content = response.content.decode('utf-8')
                return content
            except UnicodeDecodeError:
                # Try other encodings
                for encoding in ['latin1', 'cp1252']:
                    try:
                        content = response.content.decode(encoding)
                        return content
                    except UnicodeDecodeError:
                        continue
                
                # If all else fails, return None for binary files
                logger.debug(f"Could not decode file content from {download_url}")
                return None
                
        except Exception as e:
            logger.warning(f"Error downloading file content from {download_url}: {e}")
            return None
    
    def get_repository_info(self, full_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed repository information
        
        Args:
            full_name: Repository full name (owner/repo)
            
        Returns:
            Repository information or None if not found
        """
        endpoint = f"/repos/{full_name}"
        
        try:
            return self._make_request(endpoint)
        except Exception as e:
            logger.error(f"Error getting repository info for {full_name}: {e}")
            return None
    
    def get_commits(self, full_name: str, since: Optional[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent commits for a repository
        
        Args:
            full_name: Repository full name (owner/repo)
            since: ISO 8601 date string to get commits after
            limit: Maximum number of commits to return
            
        Returns:
            List of commit information
        """
        endpoint = f"/repos/{full_name}/commits"
        params = {'per_page': min(limit, 100)}
        
        if since:
            params['since'] = since
        
        try:
            return self._make_request(endpoint, params)
        except Exception as e:
            logger.error(f"Error getting commits for {full_name}: {e}")
            return []