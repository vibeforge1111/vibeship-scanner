## Bug Summary
Server-Side Request Forgery (SSRF) vulnerability in repository URL handling. The repo_url parameter is passed directly to git clone without validation, allowing attackers to scan internal services, private IPs, or arbitrary file paths.

## Root Cause
The execute_scan() function in mcp_endpoint.py and the CLI entry point in scan.py accept any URL string and pass it directly to git clone via subprocess.run(). No validation is performed to ensure the URL points to a supported git hosting service.

## Impact
- **SSRF**: Attackers can scan internal network services (e.g., cloud metadata endpoints)
- **Local file access**: file:// URLs could expose sensitive files
- **Resource exhaustion**: Scanning arbitrary internal services could consume resources

## Fix
Added url_validator.py that validates repository URLs before cloning:
- Whitelist of allowed git hosts (github.com, gitlab.com, bitbucket.org, etc.)
- Rejects file:// URLs and private IP ranges
- Validates URL scheme and path format
- Applied to both MCP endpoint and CLI entry point

## Before (The Bug)
In mcp_endpoint.py execute_scan():
```python
repo_url = args.get('repo_url')
# No validation - directly passed to git clone
thread = threading.Thread(target=run_scan, args=(scan_id, repo_url, branch, token))
```

In scan.py main():
```python
repo_url = sys.argv[1]
# No validation - directly passed to git clone
clone_repo(repo_url, repo_dir, branch)
```

**Reproduction:**
```bash
python3 scanner/scan.py "http://169.254.169.254/latest/meta-data/"
# Silently attempts to clone internal metadata endpoint
```

## After (The Fix)
In mcp_endpoint.py execute_scan():
```python
from url_validator import validate_repo_url

repo_url = args.get('repo_url')
if not repo_url:
    return {"error": "repo_url is required"}

# Validate URL to prevent SSRF
url_error = validate_repo_url(repo_url)
if url_error:
    return {"error": f"Invalid repository URL: {url_error}"}
```

In scan.py main():
```python
from url_validator import validate_repo_url

repo_url = sys.argv[1]
url_error = validate_repo_url(repo_url)
if url_error:
    print(f"Error: {url_error}", file=sys.stderr)
    sys.exit(1)
```

**After fix:**
```bash
$ python3 scanner/scan.py "http://169.254.169.254/latest/meta-data/"
Error: Private/internal IP addresses are not allowed

$ python3 scanner/scan.py "file:///etc/passwd"
Error: file:// URLs are not allowed

$ python3 scanner/scan.py "https://github.com/owner/repo"
# Proceeds with scan normally
```

## Testing
```bash
python3 -m pytest tests/test_url_validator.py -v
# Expected: 35 passed
# Tests cover: valid URLs, dangerous URLs, edge cases, SSH variants
```

## Maintainer Smoke Path
Maintainer can verify this fix by running the test suite and confirming all 35 tests pass, then attempting to scan a blocked URL to confirm rejection.

## Evidence
- 35/35 new tests pass
- Blocks file://, localhost, private IPs, non-github hosts
- Allows valid GitHub/GitLab/Bitbucket URLs

## Files Changed
- scanner/url_validator.py (NEW) - URL validation utility
- scanner/mcp_endpoint.py - Added validation before scan
- scanner/scan.py - Added validation in CLI entry point
- tests/test_url_validator.py (NEW) - 35 test cases

---
**Packet:**
{
  "repo": "vibeship-scanner",
  "pr_number": "PR_NUMBER",
  "title": "fix: add SSRF protection for repository URLs",
  "author": "ifeoluwaaj",
  "team": "Sequence",
  "llm_device_holder": "ifesn",
  "bug_summary": "SSRF vulnerability in repository URL handling allows scanning internal services and private IPs",
  "root_cause": "No URL validation before git clone - repo_url passed directly to subprocess",
  "fix_description": "Added url_validator.py with whitelist of allowed git hosts, rejection of file:// and private IPs",
  "evidence_types": ["passing_test", "smoke_test"],
  "severity": "high",
  "category": "security"
}
