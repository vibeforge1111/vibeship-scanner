"""
URL validation for vibeship scanner.

Prevents SSRF by ensuring repo URLs point to valid GitHub/GitLab repositories.
"""

import re
from urllib.parse import urlparse
from typing import Optional


# Allowed git hosting domains (lowercase)
ALLOWED_HOSTS = {
    'github.com',
    'gitlab.com',
    'bitbucket.org',
    'codeberg.org',
    'gitea.com',
    'gitee.com',
}

# Pattern for valid repo paths: owner/repo or owner/repo.git
REPO_PATH_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+(?:\.git)?$')

# Allowed schemes
ALLOWED_SCHEMES = {'https', 'http', 'git', 'ssh'}


def validate_repo_url(url: str) -> Optional[str]:
    """
    Validate that a URL points to a supported git hosting service.
    
    Returns None if valid, or an error message if invalid.
    Prevents SSRF by rejecting:
    - file:// URLs
    - Internal/private network addresses
    - Non-git protocols
    - URLs not on allowed hosting services
    """
    if not url or not isinstance(url, str):
        return "URL is required"
    
    url = url.strip()
    
    # Reject file:// and other dangerous schemes
    if url.startswith('file://'):
        return "file:// URLs are not allowed"
    
    # Handle git@ SSH URLs
    if url.startswith('git@'):
        # Format: git@github.com:owner/repo.git
        match = re.match(r'^git@([a-zA-Z0-9._-]+):([a-zA-Z0-9._/-]+(?:\.git)?)$', url)
        if not match:
            return "Invalid SSH URL format"
        
        host = match.group(1).lower()
        path = match.group(2).strip('/')
        
        if host not in ALLOWED_HOSTS:
            return f"Git host '{host}' is not supported. Allowed: {', '.join(sorted(ALLOWED_HOSTS))}"
        
        if not REPO_PATH_PATTERN.match(path):
            return "Invalid repository path format (expected: owner/repo)"
        
        return None  # Valid
    
    # Parse HTTP/HTTPS URLs
    try:
        parsed = urlparse(url)
    except Exception:
        return "Invalid URL format"
    
    # Check scheme
    scheme = (parsed.scheme or '').lower()
    if scheme not in ALLOWED_SCHEMES:
        return f"URL scheme '{scheme}' is not supported. Allowed: {', '.join(sorted(ALLOWED_SCHEMES))}"
    
    # Check host (strip www. prefix)
    host = (parsed.hostname or '').lower()
    if host.startswith('www.'):
        host = host[4:]
    
    # Reject internal/private IPs
    if host in ('localhost', '127.0.0.1', '0.0.0.0', '::1', ''):
        return "Local/internal URLs are not allowed"
    
    # Reject private IP ranges
    private_ip_patterns = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[01])\.',
        r'^192\.168\.',
        r'^169\.254\.',
    ]
    for pattern in private_ip_patterns:
        if re.match(pattern, host):
            return "Private/internal IP addresses are not allowed"
    
    # Check against allowed hosts
    # Strip .git suffix for matching
    check_host = host
    if check_host.endswith('.git'):
        check_host = check_host[:-4]
    
    if check_host not in ALLOWED_HOSTS:
        return f"Git host '{host}' is not supported. Allowed: {', '.join(sorted(ALLOWED_HOSTS))}"
    
    # Validate path format
    path = (parsed.path or '').strip('/')
    if path.endswith('.git'):
        path = path[:-4]
    
    if not path:
        return "Repository path is required (e.g., https://github.com/owner/repo)"
    
    if not REPO_PATH_PATTERN.match(path):
        return "Invalid repository path format (expected: owner/repo)"
    
    return None  # Valid
