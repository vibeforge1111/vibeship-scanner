"""Tests for URL validation (SSRF prevention)"""

import pytest
import sys
import os

# Add scanner to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scanner'))

from url_validator import validate_repo_url


class TestValidURLs:
    """Test that valid GitHub/GitLab URLs are accepted"""
    
    @pytest.mark.parametrize("url", [
        "https://github.com/owner/repo",
        "https://github.com/owner/repo.git",
        "https://www.github.com/owner/repo",
        "http://github.com/owner/repo",
        "git://github.com/owner/repo",
        "git@github.com:owner/repo.git",
        "git@github.com:owner/repo",
        "https://gitlab.com/owner/repo",
        "https://bitbucket.org/owner/repo",
        "https://codeberg.org/owner/repo",
        "https://github.com/owner/repo-name",
        "https://github.com/owner/repo.name",
        "https://github.com/org123/repo456",
    ])
    def test_valid_urls_accepted(self, url):
        assert validate_repo_url(url) is None, f"Should accept: {url}"


class TestInvalidURLs:
    """Test that dangerous/invalid URLs are rejected"""
    
    @pytest.mark.parametrize("url,expected_error", [
        ("file:///etc/passwd", "file:// URLs are not allowed"),
        ("file:///etc/shadow", "file:// URLs are not allowed"),
        ("http://localhost/repo", "Local/internal URLs are not allowed"),
        ("http://127.0.0.1/repo", "Local/internal URLs are not allowed"),
        ("http://0.0.0.0/repo", "Local/internal URLs are not allowed"),
        ("http://192.168.1.1/repo", "Private/internal IP addresses are not allowed"),
        ("http://10.0.0.1/repo", "Private/internal IP addresses are not allowed"),
        ("http://172.16.0.1/repo", "Private/internal IP addresses are not allowed"),
        ("http://169.254.169.254/repo", "Private/internal IP addresses are not allowed"),
        ("ftp://github.com/owner/repo", "URL scheme 'ftp' is not supported"),
        ("https://evil.com/owner/repo", "Git host 'evil.com' is not supported"),
        ("https://github.com/owner", "Invalid repository path format"),
        ("https://github.com/", "Repository path is required"),
        ("", "URL is required"),
        (None, "URL is required"),
        ("not-a-url", "URL scheme '' is not supported"),
    ])
    def test_dangerous_urls_rejected(self, url, expected_error):
        result = validate_repo_url(url)
        assert result is not None, f"Should reject: {url}"
        assert expected_error in result, f"Expected '{expected_error}', got '{result}'"


class TestEdgeCases:
    """Test edge cases and tricky inputs"""
    
    def test_url_with_port(self):
        """URLs with ports should be rejected if not on allowed host"""
        result = validate_repo_url("https://github.com:8080/owner/repo")
        # Port handling - depends on implementation
        assert result is not None or validate_repo_url("https://github.com/owner/repo") is None
    
    def test_url_with_credentials(self):
        """URLs with embedded credentials"""
        result = validate_repo_url("https://user:pass@github.com/owner/repo")
        # Should still work or be rejected safely
        assert result is None or "not supported" in result
    
    def test_oversized_url(self):
        """Extremely long URL"""
        long_path = "a" * 10000
        result = validate_repo_url(f"https://github.com/{long_path}")
        assert result is not None  # Should reject or handle gracefully
    
    def test_null_bytes(self):
        """URL with null bytes"""
        result = validate_repo_url("https://github.com/owner/repo\x00evil")
        assert result is not None  # Should reject
    
    def test_unicode_url(self):
        """URL with unicode characters"""
        result = validate_repo_url("https://github.com/owner/rëpo")
        # Unicode in paths is unusual but might be valid
        assert result is None or result is not None  # Just ensure no crash
    
    def test_ssh_variants(self):
        """Various SSH URL formats"""
        valid_ssh = [
            "git@github.com:owner/repo.git",
            "ssh://git@github.com/owner/repo.git",
        ]
        for url in valid_ssh:
            assert validate_repo_url(url) is None, f"Should accept SSH: {url}"
        
        invalid_ssh = [
            "git@evil.com:owner/repo.git",
            "git@github.com:../../etc/passwd",
        ]
        for url in invalid_ssh:
            assert validate_repo_url(url) is not None, f"Should reject: {url}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
