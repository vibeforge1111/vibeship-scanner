"""
MCP (Model Context Protocol) HTTP Endpoint for Vibeship Scanner

Exposes scanner functionality via JSON-RPC over HTTP for use with mcp-remote.
This enables Claude Code plugins to trigger scans, check status, and get fix prompts.
"""

import os
import json
import uuid
import threading
import requests
from flask import Blueprint, request, jsonify
from supabase import create_client, Client

# Import the scan runner from the main module
from scan import clone_repo, detect_stack, run_opengrep, run_trivy, run_gitleaks, run_retirejs, calculate_score, calculate_grade, calculate_ship_status, deduplicate_findings

mcp_bp = Blueprint('mcp', __name__)

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_SERVICE_KEY = os.environ.get('SUPABASE_SERVICE_ROLE_KEY')

def get_supabase() -> Client:
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)


# =============================================================================
# MCP Tool Definitions
# =============================================================================

TOOLS = [
    {
        "name": "scanner_auth",
        "description": "Authenticate to enable private repo scanning. Returns a URL - open it in your browser to sign in with GitHub. Then use scanner_auth_status to check when complete.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "scanner_auth_status",
        "description": "Check if authentication is complete. Call this after the user has opened the auth URL. Returns the GitHub token when authenticated.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "The auth token from scanner_auth"}
            },
            "required": ["token"]
        }
    },
    {
        "name": "scanner_scan",
        "description": "Start a security scan on a GitHub repository. Returns scan ID to check status. Scans for vulnerabilities using Opengrep (SAST), Trivy (dependencies), and Gitleaks (secrets). For private repos, pass the github_token from scanner_auth_status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_url": {"type": "string", "description": "GitHub repository URL (e.g., https://github.com/owner/repo)"},
                "branch": {"type": "string", "description": "Branch to scan (default: main)"},
                "github_token": {"type": "string", "description": "GitHub token for private repos (get from scanner_auth_status after authenticating)"}
            },
            "required": ["repo_url"]
        }
    },
    {
        "name": "scanner_status",
        "description": "Get the status and results of a security scan. Returns findings summary when complete.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Scan ID returned from scanner_scan"}
            },
            "required": ["scan_id"]
        }
    },
    {
        "name": "scanner_lookup_cve",
        "description": "Look up details for a CVE (Common Vulnerabilities and Exposures) ID from the NVD database.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE ID (e.g., CVE-2021-44228)"}
            },
            "required": ["cve_id"]
        }
    },
    {
        "name": "scanner_lookup_cwe",
        "description": "Look up details for a CWE (Common Weakness Enumeration) ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cwe_id": {"type": "string", "description": "CWE ID number (e.g., 79 for XSS, 89 for SQL Injection)"}
            },
            "required": ["cwe_id"]
        }
    },
    {
        "name": "scanner_get_fix",
        "description": "Get a detailed fix guide for a specific vulnerability type found in a scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Scan ID"},
                "finding_index": {"type": "integer", "description": "Index of the finding (0-based) from scanner_status results"}
            },
            "required": ["scan_id", "finding_index"]
        }
    },
    {
        "name": "scanner_master_prompt",
        "description": "Get a comprehensive fix guide for ALL vulnerabilities in a scan. This is the master prompt you can use to fix all issues at once. Returns a structured guide organized by vulnerability type with code examples.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Scan ID"},
                "severity_filter": {"type": "string", "enum": ["all", "critical", "high", "medium"], "description": "Minimum severity to include (default: all)"},
                "include_info": {"type": "boolean", "description": "Include informational findings (default: false)"}
            },
            "required": ["scan_id"]
        }
    },
    {
        "name": "scanner_export_report",
        "description": "Export a full security report as markdown. Includes UTC timestamp, repository info, git commit reference, severity breakdown, and all vulnerabilities with locations and details.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Scan ID to export"}
            },
            "required": ["scan_id"]
        }
    }
]


# =============================================================================
# MCP HTTP Endpoint
# =============================================================================

@mcp_bp.route('/mcp', methods=['GET', 'POST', 'OPTIONS'])
def mcp_handler():
    """Handle MCP JSON-RPC requests"""

    # CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-GitHub-Token'
        return response

    # GET request - return server info / health check
    if request.method == 'GET':
        response = jsonify({
            "name": "vibeship-scanner",
            "version": "1.0.0",
            "status": "ok",
            "protocol": "MCP JSON-RPC over HTTP",
            "usage": "POST JSON-RPC requests to this endpoint",
            "tools": [t["name"] for t in TOOLS]
        })
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response

    # Extract GitHub token from header (passed by proxy when API key is validated)
    github_token = request.headers.get('X-GitHub-Token')

    try:
        data = request.get_json()
        method = data.get('method')
        params = data.get('params', {})
        request_id = data.get('id')

        # Route to handler
        if method == 'initialize':
            result = handle_initialize(params)
        elif method == 'tools/list':
            result = handle_tools_list()
        elif method == 'tools/call':
            result = handle_tools_call(params, github_token=github_token)
        else:
            return jsonify_response(request_id, error={"code": -32601, "message": f"Method not found: {method}"})

        return jsonify_response(request_id, result=result)

    except Exception as e:
        import traceback
        print(f"MCP Error: {e}\n{traceback.format_exc()}", flush=True)
        return jsonify_response(
            data.get('id') if 'data' in dir() else None,
            error={"code": -32603, "message": f"Internal error: {str(e)}"}
        )


def jsonify_response(request_id, result=None, error=None):
    """Create a JSON-RPC response with CORS headers"""
    response_data = {"jsonrpc": "2.0", "id": request_id}
    if error:
        response_data["error"] = error
    else:
        response_data["result"] = result

    response = jsonify(response_data)
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response


def handle_initialize(params):
    """Handle MCP initialize request"""
    return {
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "vibeship-scanner",
            "version": "1.0.0"
        }
    }


def handle_tools_list():
    """Return list of available tools"""
    return {"tools": TOOLS}


def handle_tools_call(params, github_token=None):
    """Execute a tool call"""
    tool_name = params.get('name')
    arguments = params.get('arguments', {})

    try:
        if tool_name == 'scanner_auth':
            result = execute_auth(arguments)
        elif tool_name == 'scanner_auth_status':
            result = execute_auth_status(arguments)
        elif tool_name == 'scanner_scan':
            result = execute_scan(arguments, github_token=github_token)
        elif tool_name == 'scanner_status':
            result = execute_status(arguments)
        elif tool_name == 'scanner_lookup_cve':
            result = execute_cve_lookup(arguments)
        elif tool_name == 'scanner_lookup_cwe':
            result = execute_cwe_lookup(arguments)
        elif tool_name == 'scanner_get_fix':
            result = execute_get_fix(arguments)
        elif tool_name == 'scanner_master_prompt':
            result = execute_master_prompt(arguments)
        elif tool_name == 'scanner_export_report':
            result = execute_export_report(arguments)
        else:
            return {
                "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                "isError": True
            }

        # Return as text content for MCP
        if isinstance(result, str):
            return {"content": [{"type": "text", "text": result}]}
        else:
            return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}

    except Exception as e:
        import traceback
        return {
            "content": [{"type": "text", "text": f"Error: {str(e)}\n{traceback.format_exc()}"}],
            "isError": True
        }


# =============================================================================
# Tool Implementations
# =============================================================================

# Base URL for the SvelteKit API
API_BASE_URL = "https://scanner.vibeship.co"


def execute_auth(args):
    """Start device authentication flow - returns URL for user to visit"""
    try:
        response = requests.post(f"{API_BASE_URL}/api/auth/device", timeout=10)

        if response.status_code != 200:
            return {"error": f"Failed to start auth: {response.text}"}

        data = response.json()

        return {
            "status": "pending",
            "auth_url": data.get("auth_url"),
            "token": data.get("token"),
            "expires_in": data.get("expires_in", 600),
            "message": "Open the auth_url in your browser to sign in with GitHub. Then use scanner_auth_status to check when complete.",
            "next_step": f"After opening the URL, call scanner_auth_status with token: {data.get('token')}"
        }

    except requests.exceptions.Timeout:
        return {"error": "Auth service timeout - try again"}
    except Exception as e:
        return {"error": f"Failed to start auth: {str(e)}"}


def execute_auth_status(args):
    """Check if device authentication is complete - returns GitHub token when done"""
    token = args.get("token")

    if not token:
        return {"error": "token is required - use the token from scanner_auth"}

    try:
        response = requests.get(
            f"{API_BASE_URL}/api/auth/device/poll",
            params={"token": token},
            timeout=10
        )

        if response.status_code == 404:
            return {"error": "Token not found or expired - start a new auth with scanner_auth"}

        if response.status_code != 200:
            return {"error": f"Failed to check auth status: {response.text}"}

        data = response.json()
        status = data.get("status")

        if status == "pending":
            return {
                "status": "pending",
                "message": "Waiting for user to authenticate in browser...",
                "tip": "User should open the auth_url and sign in with GitHub. Check again in a few seconds."
            }
        elif status == "authenticated":
            github_token = data.get("github_token")
            if github_token:
                return {
                    "status": "authenticated",
                    "github_token": github_token,
                    "message": "Authentication successful! You can now scan private repos.",
                    "note": "The GitHub token is now available for private repo scanning."
                }
            else:
                return {
                    "status": "authenticated",
                    "message": "Authenticated but no GitHub token received",
                    "error": "Token may have already been retrieved"
                }
        elif status == "expired":
            return {
                "status": "expired",
                "message": "Auth link expired. Start a new auth with scanner_auth."
            }
        elif status == "used":
            return {
                "status": "used",
                "message": "Token already used. Start a new auth with scanner_auth if needed."
            }
        else:
            return {"status": status, "message": data.get("message", "Unknown status")}

    except requests.exceptions.Timeout:
        return {"error": "Auth service timeout - try again"}
    except Exception as e:
        return {"error": f"Failed to check auth status: {str(e)}"}


def execute_scan(args, github_token=None):
    """Start a new security scan"""
    # Import here to avoid circular import - server.py imports mcp_endpoint
    # We need the run_scan function which handles the full scan pipeline
    import importlib
    server_module = importlib.import_module('server')
    run_scan = server_module.run_scan

    repo_url = args.get('repo_url')
    branch = args.get('branch', 'main')

    # GitHub token can come from args (device auth) or header (legacy)
    token = args.get('github_token') or github_token

    if not repo_url:
        return {"error": "repo_url is required"}

    # Generate scan ID
    scan_id = str(uuid.uuid4())

    # Determine if this is a private repo scan
    is_private = token is not None

    # Start scan in background thread (same as /scan endpoint)
    thread = threading.Thread(target=run_scan, args=(scan_id, repo_url, branch, token))
    thread.start()

    message = f"Scan started for {repo_url}"
    if is_private:
        message += " (private repo - using your GitHub token)"

    return {
        "scan_id": scan_id,
        "status": "started",
        "message": message,
        "is_private": is_private,
        "check_status": f"Use scanner_status with scan_id: {scan_id}",
        "view_results": f"https://scanner.vibeship.co/scan/{scan_id}"
    }


def execute_status(args):
    """Get scan status and results from Supabase"""
    scan_id = args.get('scan_id')

    if not scan_id:
        return {"error": "scan_id is required"}

    supabase = get_supabase()
    result = supabase.table('scans').select('*').eq('id', scan_id).execute()

    if not result.data:
        return {"error": f"Scan not found: {scan_id}"}

    scan = result.data[0]
    status = scan.get('status', 'unknown')

    if status == 'complete':
        findings = scan.get('findings', [])
        counts = scan.get('finding_counts', {})
        repo_url = scan.get('target_url', 'Unknown')

        return {
            "status": "complete",
            "score": scan.get('score'),
            "grade": scan.get('grade'),
            "ship_status": scan.get('ship_status'),
            "repository": repo_url,
            "summary": {
                "total_findings": len(findings),
                "critical": counts.get('critical', 0),
                "high": counts.get('high', 0),
                "medium": counts.get('medium', 0),
                "low": counts.get('low', 0),
                "info": counts.get('info', 0)
            },
            "findings_preview": findings[:10],  # First 10 findings
            "has_more": len(findings) > 10,
            "view_all": f"https://scanner.vibeship.co/scan/{scan_id}",
            "output_options": {
                "message": "How would you like the scan results?",
                "options": [
                    {
                        "choice": "1",
                        "name": "Full Security Report",
                        "description": "Markdown file with UTC timestamp, git commit reference, all vulnerabilities with locations and severity",
                        "action": f"Call scanner_export_report with scan_id: {scan_id}, then save the result to vibeship_scanner_report.md"
                    },
                    {
                        "choice": "2",
                        "name": "Master AI Fix Prompt",
                        "description": "Markdown file with actionable fix instructions you can use to remediate all issues",
                        "action": f"Call scanner_master_prompt with scan_id: {scan_id}, then save the result to vibeship_scanner_master_fix_prompt.md"
                    },
                    {
                        "choice": "3",
                        "name": "Both Reports",
                        "description": "Get both the Full Security Report and the Master AI Fix Prompt",
                        "action": f"Call scanner_export_report with scan_id: {scan_id} and save to vibeship_scanner_report.md, then call scanner_master_prompt with scan_id: {scan_id} and save to vibeship_scanner_master_fix_prompt.md"
                    },
                    {
                        "choice": "4",
                        "name": "View Online Only",
                        "description": "Just view results in the web dashboard",
                        "action": f"Open: https://scanner.vibeship.co/scan/{scan_id}"
                    }
                ],
                "prompt": "Reply with 1, 2, 3, or 4 (or just check the link above)"
            }
        }
    elif status == 'scanning':
        return {
            "status": "scanning",
            "message": "Scan in progress...",
            "tip": "Check again in a few seconds"
        }
    elif status == 'failed':
        return {
            "status": "failed",
            "error": scan.get('error_message', 'Unknown error')
        }
    else:
        return {
            "status": status,
            "message": "Scan status unknown"
        }


def execute_cve_lookup(args):
    """Look up CVE details from NVD"""
    cve_id = args.get('cve_id', '').upper()

    if not cve_id:
        return {"error": "cve_id is required"}

    if not cve_id.startswith('CVE-'):
        cve_id = f"CVE-{cve_id}"

    try:
        # Query NVD API
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return {"error": f"NVD API returned {response.status_code}"}

        data = response.json()
        vulns = data.get('vulnerabilities', [])

        if not vulns:
            return {"error": f"CVE not found: {cve_id}"}

        cve_data = vulns[0].get('cve', {})

        # Extract description
        descriptions = cve_data.get('descriptions', [])
        description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), 'No description')

        # Extract CVSS score
        metrics = cve_data.get('metrics', {})
        cvss_v31 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}) if metrics.get('cvssMetricV31') else {}
        cvss_v30 = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}) if metrics.get('cvssMetricV30') else {}
        cvss_v2 = metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {}) if metrics.get('cvssMetricV2') else {}

        cvss = cvss_v31 or cvss_v30 or cvss_v2

        # Extract CWEs
        weaknesses = cve_data.get('weaknesses', [])
        cwes = []
        for w in weaknesses:
            for desc in w.get('description', []):
                if desc.get('value', '').startswith('CWE-'):
                    cwes.append(desc['value'])

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss.get('baseScore'),
            "cvss_severity": cvss.get('baseSeverity'),
            "cvss_vector": cvss.get('vectorString'),
            "cwes": cwes,
            "published": cve_data.get('published'),
            "last_modified": cve_data.get('lastModified'),
            "references": [ref.get('url') for ref in cve_data.get('references', [])[:5]]
        }

    except requests.exceptions.Timeout:
        return {"error": "NVD API timeout - try again"}
    except Exception as e:
        return {"error": f"Failed to lookup CVE: {str(e)}"}


def execute_cwe_lookup(args):
    """Look up CWE details"""
    cwe_id = args.get('cwe_id', '')

    # Extract number from various formats
    if isinstance(cwe_id, str):
        cwe_id = cwe_id.upper().replace('CWE-', '').replace('CWE', '')

    try:
        cwe_num = int(cwe_id)
    except (ValueError, TypeError):
        return {"error": f"Invalid CWE ID: {cwe_id}"}

    # Common CWE database (top vulnerabilities)
    CWE_DATABASE = {
        79: {
            "name": "Improper Neutralization of Input During Web Page Generation (XSS)",
            "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
            "severity": "High",
            "owasp": "A7:2017 - Cross-Site Scripting (XSS)",
            "fix_summary": "Encode output, use Content Security Policy, sanitize HTML input"
        },
        89: {
            "name": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
            "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
            "severity": "Critical",
            "owasp": "A1:2017 - Injection",
            "fix_summary": "Use parameterized queries, prepared statements, or ORM methods"
        },
        78: {
            "name": "Improper Neutralization of Special Elements used in an OS Command (Command Injection)",
            "description": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command.",
            "severity": "Critical",
            "owasp": "A1:2017 - Injection",
            "fix_summary": "Avoid shell commands, use safe APIs, validate/sanitize input"
        },
        22: {
            "name": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
            "description": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname.",
            "severity": "High",
            "owasp": "A5:2017 - Broken Access Control",
            "fix_summary": "Validate paths, use allowlists, canonicalize paths before checking"
        },
        352: {
            "name": "Cross-Site Request Forgery (CSRF)",
            "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
            "severity": "Medium",
            "owasp": "A8:2013 - Cross-Site Request Forgery",
            "fix_summary": "Use anti-CSRF tokens, SameSite cookies, verify Origin header"
        },
        434: {
            "name": "Unrestricted Upload of File with Dangerous Type",
            "description": "The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.",
            "severity": "High",
            "owasp": "A8:2017 - Insecure Deserialization",
            "fix_summary": "Validate file types, rename uploads, store outside webroot"
        },
        798: {
            "name": "Use of Hard-coded Credentials",
            "description": "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
            "severity": "Critical",
            "owasp": "A2:2017 - Broken Authentication",
            "fix_summary": "Use environment variables, secrets manager, or secure vaults"
        },
        327: {
            "name": "Use of a Broken or Risky Cryptographic Algorithm",
            "description": "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.",
            "severity": "High",
            "owasp": "A3:2017 - Sensitive Data Exposure",
            "fix_summary": "Use modern algorithms (AES-256, SHA-256+, bcrypt/argon2)"
        },
        918: {
            "name": "Server-Side Request Forgery (SSRF)",
            "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
            "severity": "High",
            "owasp": "A10:2021 - Server-Side Request Forgery",
            "fix_summary": "Validate URLs, use allowlists, block internal IPs"
        },
        502: {
            "name": "Deserialization of Untrusted Data",
            "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
            "severity": "Critical",
            "owasp": "A8:2017 - Insecure Deserialization",
            "fix_summary": "Avoid deserializing untrusted data, use safe formats (JSON), validate schemas"
        },
        611: {
            "name": "Improper Restriction of XML External Entity Reference (XXE)",
            "description": "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control.",
            "severity": "High",
            "owasp": "A4:2017 - XML External Entities",
            "fix_summary": "Disable external entities and DTDs in XML parsers"
        },
        200: {
            "name": "Exposure of Sensitive Information to an Unauthorized Actor",
            "description": "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
            "severity": "Medium",
            "owasp": "A3:2017 - Sensitive Data Exposure",
            "fix_summary": "Minimize data exposure, implement proper access controls"
        },
        287: {
            "name": "Improper Authentication",
            "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
            "severity": "Critical",
            "owasp": "A2:2017 - Broken Authentication",
            "fix_summary": "Use proven auth libraries, implement MFA, secure session management"
        },
        862: {
            "name": "Missing Authorization",
            "description": "The software does not perform an authorization check when an actor attempts to access a resource or perform an action.",
            "severity": "High",
            "owasp": "A5:2017 - Broken Access Control",
            "fix_summary": "Implement authorization checks on all protected resources"
        },
        306: {
            "name": "Missing Authentication for Critical Function",
            "description": "The software does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.",
            "severity": "Critical",
            "owasp": "A2:2017 - Broken Authentication",
            "fix_summary": "Require authentication for all sensitive operations"
        }
    }

    if cwe_num in CWE_DATABASE:
        cwe = CWE_DATABASE[cwe_num]
        return {
            "cwe_id": f"CWE-{cwe_num}",
            "name": cwe["name"],
            "description": cwe["description"],
            "severity": cwe["severity"],
            "owasp_mapping": cwe["owasp"],
            "fix_summary": cwe["fix_summary"],
            "reference": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
        }
    else:
        return {
            "cwe_id": f"CWE-{cwe_num}",
            "name": "Unknown",
            "description": f"CWE-{cwe_num} details not in local database",
            "reference": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
            "note": "Visit the reference URL for full details"
        }


def execute_get_fix(args):
    """Get fix guide for a specific finding"""
    scan_id = args.get('scan_id')
    finding_index = args.get('finding_index', 0)

    if not scan_id:
        return {"error": "scan_id is required"}

    # Fetch scan from Supabase
    supabase = get_supabase()
    result = supabase.table('scans').select('findings').eq('id', scan_id).execute()

    if not result.data:
        return {"error": f"Scan not found: {scan_id}"}

    findings = result.data[0].get('findings', [])

    if not findings:
        return {"message": "No findings in this scan"}

    if finding_index >= len(findings):
        return {"error": f"Finding index {finding_index} out of range (0-{len(findings)-1})"}

    finding = findings[finding_index]
    vuln_type = categorize_vulnerability(finding)
    guide = get_vulnerability_guide(vuln_type)

    location = finding.get('location', {})
    file_path = location.get('file', 'unknown')
    line = location.get('line', '')

    return f"""## {guide['title']}

**Finding:** {finding.get('title', 'Unknown')}
**Severity:** {finding.get('severity', 'unknown').upper()}
**Location:** `{file_path}{f':{line}' if line else ''}`

**What's Wrong:**
{guide['problem']}

**How to Fix:**

{guide['solution']}

**After Fixing:**
{guide['verification']}
"""


def execute_master_prompt(args):
    """Generate master fix prompt - THE KEY FEATURE"""
    scan_id = args.get('scan_id')
    severity_filter = args.get('severity_filter', 'all')
    include_info = args.get('include_info', False)

    if not scan_id:
        return {"error": "scan_id is required"}

    # Fetch scan from Supabase
    supabase = get_supabase()
    result = supabase.table('scans').select('findings, target_url').eq('id', scan_id).execute()

    if not result.data:
        return {"error": f"Scan not found: {scan_id}"}

    findings = result.data[0].get('findings', [])
    repo_url = result.data[0].get('target_url', 'Unknown repository')

    if not findings:
        return "No security findings to fix! Your code looks clean. 🎉"

    # Calculate ORIGINAL raw counts from ALL findings (before any filtering)
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    original_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        sev = f.get('severity', 'info').lower()
        if sev in original_counts:
            original_counts[sev] += 1
    total_original = len(findings)

    # Filter by severity
    min_severity = {'all': 4, 'critical': 0, 'high': 1, 'medium': 2}.get(severity_filter, 4)

    filtered = [f for f in findings if severity_order.get(f.get('severity', 'info').lower(), 4) <= min_severity]

    if not include_info:
        filtered = [f for f in filtered if f.get('severity', '').lower() != 'info']

    if not filtered:
        return f"No findings match the filter (severity_filter={severity_filter}, include_info={include_info})"

    # Sort by severity
    sorted_findings = sorted(filtered, key=lambda f: severity_order.get(f.get('severity', 'info').lower(), 4))

    # Deduplicate similar findings
    deduplicated, duplicate_groups = deduplicate_similar_findings(sorted_findings)

    # Group by vulnerability type
    grouped = {}
    for f in deduplicated:
        vuln_type = categorize_vulnerability(f)
        if vuln_type not in grouped:
            grouped[vuln_type] = []
        grouped[vuln_type].append(f)

    # Sort groups by highest severity
    def get_group_severity(group_findings):
        return min(severity_order.get(f.get('severity', 'info').lower(), 4) for f in group_findings)

    sorted_groups = sorted(grouped.items(), key=lambda x: get_group_severity(x[1]))

    # Calculate counts
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in deduplicated:
        sev = f.get('severity', 'info').lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Build summary list
    summary_lines = []
    for i, f in enumerate(deduplicated):
        loc = f.get('location', {})
        file_path = loc.get('file', 'unknown')
        line = loc.get('line', '')
        location_str = f"{file_path}{f':{line}' if line else ''}"
        sev = f.get('severity', 'INFO').upper()
        title = f.get('title', 'Unknown issue')

        # Check for duplicates
        key = get_finding_key(f)
        dups = duplicate_groups.get(key, [])
        count_suffix = f" ({len(dups)} occurrences)" if len(dups) > 1 else ""

        summary_lines.append(f"{i+1}. [{sev}] {title} → `{location_str}`{count_suffix}")

    # Build detailed fix guides
    fix_guides = []
    for vuln_type, type_findings in sorted_groups:
        guide = get_vulnerability_guide(vuln_type)

        locations = []
        for f in type_findings:
            loc = f.get('location', {})
            file_path = loc.get('file', 'unknown')
            line = loc.get('line', '')
            sev = f.get('severity', 'INFO').upper()
            title = f.get('title', '')
            locations.append(f"- `{file_path}{f':{line}' if line else ''}` [{sev}] {title}")

        fix_guides.append(f"""## {guide['title']}

**Affected Locations:**
{chr(10).join(locations)}

**What's Wrong:**
{guide['problem']}

**How to Fix:**

{guide['solution']}

**After Fixing:**
{guide['verification']}""")

    # Build ORIGINAL severity summary (raw scan results)
    original_parts = []
    if original_counts['critical'] > 0:
        original_parts.append(f"🔴 {original_counts['critical']} Critical")
    if original_counts['high'] > 0:
        original_parts.append(f"🟠 {original_counts['high']} High")
    if original_counts['medium'] > 0:
        original_parts.append(f"🟡 {original_counts['medium']} Medium")
    if original_counts['low'] > 0:
        original_parts.append(f"⚪ {original_counts['low']} Low")
    if original_counts['info'] > 0:
        original_parts.append(f"ℹ️ {original_counts['info']} Info")

    original_summary = ' | '.join(original_parts) if original_parts else "No findings"

    # Build DEDUPLICATED severity summary (actionable issues)
    dedup_parts = []
    if severity_counts['critical'] > 0:
        dedup_parts.append(f"🔴 {severity_counts['critical']} Critical")
    if severity_counts['high'] > 0:
        dedup_parts.append(f"🟠 {severity_counts['high']} High")
    if severity_counts['medium'] > 0:
        dedup_parts.append(f"🟡 {severity_counts['medium']} Medium")
    if severity_counts['low'] > 0:
        dedup_parts.append(f"⚪ {severity_counts['low']} Low")
    if severity_counts['info'] > 0:
        dedup_parts.append(f"ℹ️ {severity_counts['info']} Info")

    dedup_summary = ' | '.join(dedup_parts) if dedup_parts else "No actionable issues"

    unique_count = len(deduplicated)

    # Final prompt
    return f"""# Security Fix Guide

I need help fixing security vulnerabilities in my codebase.

**Repository:** {repo_url}

---

## Scan Results

**Raw Findings:** {total_original} total
{original_summary}

---

## Actionable Issues

After consolidating duplicate findings (same vulnerability in same file) and excluding informational items, you have **{unique_count} unique issues** to fix:

{dedup_summary}

---

## Quick Summary ({unique_count} unique issues)

{chr(10).join(summary_lines)}

---

## Detailed Fix Instructions

*Sections are ordered by severity - most critical vulnerability types appear first.*

{chr(10).join(f'{guide}{chr(10)}{chr(10)}---{chr(10)}' for guide in fix_guides)}

## How to Work Through This

1. **Go section by section** - Start with the first vulnerability type (most critical)
2. **Read the file** - Open each listed file and find the vulnerable code at the specified line
3. **Apply the fix pattern** - Use the code examples provided as templates
4. **Search for similar issues** - After fixing, grep the codebase for similar vulnerable patterns
5. **Verify the fix** - Make sure the code still works after your changes
6. **Move to the next** - Continue until all issues are resolved

## After All Fixes

- Run the application and test that everything works
- Run any existing tests: `npm test` or equivalent
- List all files you modified
- Summarize what you changed

Let's start! Begin with the first section above."""


def execute_export_report(args):
    """Generate full security report markdown"""
    from datetime import datetime, timezone

    scan_id = args.get('scan_id')

    if not scan_id:
        return {"error": "scan_id is required"}

    # Fetch scan from Supabase
    supabase = get_supabase()
    result = supabase.table('scans').select('*').eq('id', scan_id).execute()

    if not result.data:
        return {"error": f"Scan not found: {scan_id}"}

    scan = result.data[0]
    findings = scan.get('findings', [])
    counts = scan.get('finding_counts', {})
    repo_url = scan.get('target_url', 'Unknown repository')
    branch = scan.get('target_branch', 'main')
    score = scan.get('score', 'N/A')
    grade = scan.get('grade', 'N/A')
    ship_status = scan.get('ship_status', 'N/A')
    created_at = scan.get('created_at', '')

    # Generate UTC timestamp
    utc_now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    # Parse repo for git reference
    repo_parts = repo_url.replace('https://github.com/', '').split('/')
    repo_name = '/'.join(repo_parts[:2]) if len(repo_parts) >= 2 else repo_url

    # Build severity breakdown with colors
    severity_breakdown = []
    if counts.get('critical', 0) > 0:
        severity_breakdown.append(f"- 🔴 **Critical:** {counts['critical']}")
    if counts.get('high', 0) > 0:
        severity_breakdown.append(f"- 🟠 **High:** {counts['high']}")
    if counts.get('medium', 0) > 0:
        severity_breakdown.append(f"- 🟡 **Medium:** {counts['medium']}")
    if counts.get('low', 0) > 0:
        severity_breakdown.append(f"- ⚪ **Low:** {counts['low']}")
    if counts.get('info', 0) > 0:
        severity_breakdown.append(f"- ℹ️ **Info:** {counts['info']}")

    severity_section = '\n'.join(severity_breakdown) if severity_breakdown else "No vulnerabilities found"

    # Sort findings by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get('severity', 'info').lower(), 4))

    # Severity color mapping
    severity_colors = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '⚪',
        'info': 'ℹ️'
    }

    # Build findings table
    findings_rows = []
    for i, f in enumerate(sorted_findings, 1):
        sev = f.get('severity', 'info').lower()
        sev_color = severity_colors.get(sev, '⚪')
        sev_display = f"{sev_color} {sev.upper()}"
        title = f.get('title', 'Unknown')
        loc = f.get('location', {})
        file_path = loc.get('file', 'unknown')
        line = loc.get('line', '')
        location_str = f"`{file_path}:{line}`" if line else f"`{file_path}`"
        rule_id = f.get('ruleId', '-')
        scanner = f.get('scanner', '-')

        findings_rows.append(f"| {i} | {sev_display} | {title} | {location_str} | {scanner} |")

    findings_table = '\n'.join(findings_rows) if findings_rows else "| - | - | No vulnerabilities found | - | - |"

    # Build detailed findings section
    detailed_findings = []
    for i, f in enumerate(sorted_findings, 1):
        sev = f.get('severity', 'info').lower()
        sev_color = severity_colors.get(sev, '⚪')
        sev_display = f"{sev_color} {sev.upper()}"
        title = f.get('title', 'Unknown')
        message = f.get('message', 'No description available')
        loc = f.get('location', {})
        file_path = loc.get('file', 'unknown')
        line = loc.get('line', '')
        rule_id = f.get('ruleId', 'N/A')
        scanner = f.get('scanner', 'N/A')
        cwe = f.get('cwe', '')

        location_str = f"{file_path}:{line}" if line else file_path
        cwe_line = f"\n- **CWE:** {cwe}" if cwe else ""

        detailed_findings.append(f"""### {i}. [{sev_display}] {title}

- **Location:** `{location_str}`
- **Rule ID:** {rule_id}
- **Scanner:** {scanner}{cwe_line}

**Description:** {message}
""")

    detailed_section = '\n'.join(detailed_findings) if detailed_findings else "No vulnerabilities found."

    # Generate the full report
    return f"""# Security Scan Report

**Generated:** {utc_now}
**Scan ID:** `{scan_id}`

---

## Repository Information

| Field | Value |
|-------|-------|
| Repository | [{repo_name}]({repo_url}) |
| Branch | `{branch}` |
| Scan Date | {created_at[:10] if created_at else 'N/A'} |

---

## Security Score

| Metric | Value |
|--------|-------|
| Score | **{score}/100** |
| Grade | **{grade}** |
| Status | **{ship_status}** |

---

## Severity Breakdown

{severity_section}

**Total Findings:** {len(findings)}

---

## Findings Summary

| # | Severity | Finding | Location | Scanner |
|---|----------|---------|----------|---------|
{findings_table}

---

## Detailed Findings

{detailed_section}

---

## Next Steps

1. **Prioritize Critical/High findings** - These pose the greatest risk
2. **Use `scanner_master_prompt`** - Get actionable fix instructions for all issues
3. **Re-scan after fixes** - Verify vulnerabilities are resolved
4. **View online:** https://scanner.vibeship.co/scan/{scan_id}

---

*Report generated by [Vibeship Scanner](https://vibeship.co)*
"""


# =============================================================================
# Helper Functions for Master Prompt Generation
# =============================================================================

def get_finding_key(finding):
    """Generate a key for deduplication"""
    rule_id = finding.get('ruleId', finding.get('title', ''))
    file_path = finding.get('location', {}).get('file', '')
    return f"{rule_id}:{file_path}"


def deduplicate_similar_findings(findings):
    """Deduplicate findings that are the same rule in the same file"""
    seen = {}
    deduplicated = []
    duplicate_groups = {}

    for f in findings:
        key = get_finding_key(f)
        if key not in seen:
            seen[key] = f
            deduplicated.append(f)
            duplicate_groups[key] = [f]
        else:
            duplicate_groups[key].append(f)

    return deduplicated, duplicate_groups


def categorize_vulnerability(finding):
    """Categorize a finding into a vulnerability type"""
    search_key = f"{finding.get('ruleId', '')} {finding.get('title', '')} {finding.get('message', '')}".lower()

    # SQL Injection
    if 'sql' in search_key and ('inject' in search_key or 'query' in search_key):
        return 'sql-injection'

    # NoSQL Injection
    if 'nosql' in search_key or '$where' in search_key or ('mongo' in search_key and ('inject' in search_key or 'query' in search_key)):
        return 'nosql-injection'

    # XSS
    if 'xss' in search_key or 'innerhtml' in search_key or 'dangerously' in search_key or 'cross-site scripting' in search_key:
        return 'xss'

    # Command Injection
    if ('command' in search_key or 'shell' in search_key or 'exec' in search_key or 'spawn' in search_key) and 'inject' in search_key:
        return 'command-injection'
    if 'child_process' in search_key or 'subprocess' in search_key or 'os.system' in search_key:
        return 'command-injection'

    # Path Traversal
    if 'path' in search_key and ('traversal' in search_key or 'injection' in search_key):
        return 'path-traversal'
    if 'directory' in search_key and 'traversal' in search_key:
        return 'path-traversal'

    # SSRF
    if 'ssrf' in search_key or 'server-side request' in search_key:
        return 'ssrf'

    # Hardcoded Secrets
    if 'secret' in search_key or 'hardcode' in search_key or 'password' in search_key or 'api.key' in search_key or 'apikey' in search_key:
        return 'hardcoded-secrets'
    if 'credential' in search_key or 'token' in search_key:
        return 'hardcoded-secrets'

    # Insecure Crypto
    if 'crypto' in search_key or 'cipher' in search_key or 'hash' in search_key or 'md5' in search_key or 'sha1' in search_key:
        return 'weak-crypto'

    # CSRF
    if 'csrf' in search_key or 'cross-site request' in search_key:
        return 'csrf'

    # XXE
    if 'xxe' in search_key or 'xml external' in search_key or 'entity' in search_key:
        return 'xxe'

    # Deserialization
    if 'deserializ' in search_key or 'pickle' in search_key or 'yaml.load' in search_key:
        return 'insecure-deserialization'

    # Vulnerable Dependencies
    if 'vulnerab' in search_key and ('depend' in search_key or 'package' in search_key or 'library' in search_key):
        return 'vulnerable-dependency'
    if 'cve-' in search_key or 'outdated' in search_key:
        return 'vulnerable-dependency'

    # Auth issues
    if 'auth' in search_key and ('broken' in search_key or 'bypass' in search_key or 'missing' in search_key):
        return 'broken-auth'

    # Security misconfiguration
    if 'debug' in search_key or 'cors' in search_key or 'header' in search_key:
        return 'security-misconfiguration'

    return 'other'


def get_vulnerability_guide(vuln_type):
    """Get detailed fix guide for a vulnerability type"""
    guides = {
        'sql-injection': {
            'title': '🔴 SQL Injection',
            'problem': 'User input is being concatenated directly into SQL queries, allowing attackers to execute arbitrary database commands, steal data, or delete records.',
            'solution': '''Use parameterized queries (prepared statements) instead of string concatenation:

**JavaScript (node-postgres):**
```javascript
// ❌ VULNERABLE
const result = await db.query("SELECT * FROM users WHERE id = " + userId);

// ✅ FIXED
const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
```

**Python:**
```python
# ❌ VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ✅ FIXED
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

**Using an ORM (Prisma, Sequelize):**
```javascript
// ✅ Use ORM methods instead of raw queries
const user = await prisma.user.findUnique({ where: { id: userId } });
```''',
            'verification': '''- Search for other SQL queries: `grep -r "query.*\\$\\{" --include="*.js"`
- Test with payload: `' OR '1'='1`
- Ensure no user input reaches SQL without parameterization'''
        },

        'xss': {
            'title': '🔴 Cross-Site Scripting (XSS)',
            'problem': 'User input is rendered in the browser without sanitization, allowing attackers to inject malicious scripts that steal cookies, credentials, or perform actions as the user.',
            'solution': '''Never insert untrusted data directly into HTML:

**React:**
```jsx
// ✅ SAFE by default
<div>{userInput}</div>

// ❌ VULNERABLE
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// ✅ If you must render HTML
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />
```

**Vanilla JavaScript:**
```javascript
// ❌ VULNERABLE
element.innerHTML = userInput;

// ✅ FIXED
element.textContent = userInput;
```''',
            'verification': '''- Search for innerHTML usage: `grep -r "innerHTML" --include="*.js"`
- Test with: `<script>alert('xss')</script>`
- Add Content-Security-Policy header'''
        },

        'command-injection': {
            'title': '🔴 Command Injection',
            'problem': 'User input is passed to shell commands without sanitization, allowing attackers to execute arbitrary system commands.',
            'solution': '''Avoid shell commands when possible. If needed, never pass user input directly:

**Node.js:**
```javascript
// ❌ VULNERABLE
exec(`ls ${userInput}`);
exec('grep ' + pattern + ' file.txt');

// ✅ FIXED - use spawn with array args (no shell)
spawn('ls', [userInput], { shell: false });

// ✅ BETTER - use native APIs
const files = fs.readdirSync(directory);
```

**Python:**
```python
# ❌ VULNERABLE
os.system(f"ls {user_input}")
subprocess.call(f"grep {pattern} file.txt", shell=True)

# ✅ FIXED
subprocess.run(['ls', user_input], shell=False)
subprocess.run(['grep', pattern, 'file.txt'])
```''',
            'verification': '''- Search for: `grep -r "exec\\|system\\|spawn.*shell" --include="*.js" --include="*.py"`
- Test with: `; cat /etc/passwd`
- Consider using libraries instead of shell commands'''
        },

        'hardcoded-secrets': {
            'title': '🔴 Hardcoded Secrets',
            'problem': 'Sensitive credentials (API keys, passwords, tokens) are committed to source code, exposing them to anyone with repository access.',
            'solution': '''Move secrets to environment variables or a secrets manager:

```javascript
// ❌ VULNERABLE
const apiKey = "sk-1234567890abcdef";
const dbPassword = "admin123";

// ✅ FIXED
const apiKey = process.env.API_KEY;
const dbPassword = process.env.DB_PASSWORD;
```

**Setup:**
1. Create `.env` file (add to `.gitignore`!):
   ```
   API_KEY=sk-1234567890abcdef
   DB_PASSWORD=admin123
   ```

2. Load with dotenv:
   ```javascript
   require('dotenv').config();
   ```

3. For production, use your platform's secrets management (Vercel, Fly.io, AWS Secrets Manager)''',
            'verification': '''- Add `.env` to `.gitignore`
- Run: `gitleaks detect` to find remaining secrets
- Rotate any exposed credentials immediately'''
        },

        'path-traversal': {
            'title': '🟠 Path Traversal',
            'problem': 'User input is used to construct file paths without validation, allowing attackers to access files outside the intended directory.',
            'solution': '''Validate and sanitize file paths:

```javascript
// ❌ VULNERABLE
const filePath = `./uploads/${req.params.filename}`;
fs.readFile(filePath);

// ✅ FIXED
const path = require('path');
const safePath = path.join('./uploads', path.basename(req.params.filename));
// Verify it's still under uploads
if (!safePath.startsWith(path.resolve('./uploads'))) {
  throw new Error('Invalid path');
}
fs.readFile(safePath);
```

```python
# ❌ VULNERABLE
file_path = f"./uploads/{filename}"

# ✅ FIXED
import os
safe_path = os.path.join('./uploads', os.path.basename(filename))
if not os.path.abspath(safe_path).startswith(os.path.abspath('./uploads')):
    raise ValueError('Invalid path')
```''',
            'verification': '''- Test with: `../../../etc/passwd`
- Ensure all file operations validate paths
- Use allowlists when possible'''
        },

        'ssrf': {
            'title': '🟠 Server-Side Request Forgery (SSRF)',
            'problem': 'User-supplied URLs are fetched by the server without validation, allowing attackers to access internal services or cloud metadata.',
            'solution': '''Validate URLs before fetching:

```javascript
// ❌ VULNERABLE
const response = await fetch(userProvidedUrl);

// ✅ FIXED
const url = new URL(userProvidedUrl);
const blockedHosts = ['localhost', '127.0.0.1', '169.254.169.254', '0.0.0.0'];
const blockedProtocols = ['file:', 'ftp:', 'gopher:'];

if (blockedHosts.includes(url.hostname) ||
    blockedProtocols.includes(url.protocol) ||
    url.hostname.endsWith('.internal')) {
  throw new Error('URL not allowed');
}
const response = await fetch(url.toString());
```''',
            'verification': '''- Test with: `http://169.254.169.254/latest/meta-data/`
- Test with: `http://localhost:3000/admin`
- Block internal IP ranges and cloud metadata endpoints'''
        },

        'vulnerable-dependency': {
            'title': '🟠 Vulnerable Dependencies',
            'problem': 'The project uses packages with known security vulnerabilities that could be exploited.',
            'solution': '''Update vulnerable packages:

```bash
# Check for vulnerabilities
npm audit

# Auto-fix what's possible
npm audit fix

# For breaking changes, update manually
npm update package-name
# or for major versions:
npm install package-name@latest
```

**For specific CVEs:**
1. Check the CVE details for affected versions
2. Update to the patched version
3. Test your application after updating

**Lock file maintenance:**
```bash
# Regenerate lock file
rm package-lock.json && npm install
```''',
            'verification': '''- Run `npm audit` and ensure 0 vulnerabilities
- Check changelogs for breaking changes
- Run tests after updating'''
        },

        'weak-crypto': {
            'title': '🟠 Weak Cryptography',
            'problem': 'Using outdated or weak cryptographic algorithms (MD5, SHA1, DES) that can be broken or don\'t provide adequate security.',
            'solution': '''Use modern cryptographic algorithms:

**Password Hashing:**
```javascript
// ❌ VULNERABLE
const hash = crypto.createHash('md5').update(password).digest('hex');

// ✅ FIXED - use bcrypt
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);
const isValid = await bcrypt.compare(password, hash);
```

**General Hashing:**
```javascript
// ❌ VULNERABLE
crypto.createHash('sha1')

// ✅ FIXED
crypto.createHash('sha256')
```

**Encryption:**
```javascript
// ❌ VULNERABLE
crypto.createCipheriv('des', key, iv)

// ✅ FIXED
crypto.createCipheriv('aes-256-gcm', key, iv)
```''',
            'verification': '''- Search for: `grep -r "md5\\|sha1\\|des" --include="*.js"`
- Use bcrypt/argon2 for passwords
- Use AES-256-GCM for encryption'''
        },

        'nosql-injection': {
            'title': '🔴 NoSQL Injection',
            'problem': 'User input is used in MongoDB queries without sanitization, allowing attackers to bypass authentication or extract data.',
            'solution': '''Sanitize query inputs:

```javascript
// ❌ VULNERABLE
db.users.find({ username: req.body.username, password: req.body.password });
// Attacker sends: { "username": "admin", "password": { "$ne": "" } }

// ✅ FIXED - validate types
const username = String(req.body.username);
const password = String(req.body.password);
db.users.find({ username, password });

// ✅ BETTER - use a schema validator
const { body, validationResult } = require('express-validator');
app.post('/login',
  body('username').isString().trim(),
  body('password').isString(),
  (req, res) => { ... }
);
```''',
            'verification': '''- Test with: `{"$gt": ""}` as input
- Ensure all query inputs are type-validated
- Use schema validation libraries'''
        },

        'csrf': {
            'title': '🟡 Cross-Site Request Forgery (CSRF)',
            'problem': 'State-changing requests don\'t verify the request origin, allowing attackers to trick users into performing actions.',
            'solution': '''Implement CSRF protection:

```javascript
// Express with csurf
const csrf = require('csurf');
app.use(csrf({ cookie: true }));

// Include token in forms
<input type="hidden" name="_csrf" value="<%= csrfToken %>">

// Or use SameSite cookies
app.use(session({
  cookie: { sameSite: 'strict', secure: true }
}));
```''',
            'verification': '''- Ensure all state-changing endpoints check CSRF tokens
- Set SameSite=Strict on session cookies
- Verify Origin header on sensitive requests'''
        },

        'security-misconfiguration': {
            'title': '🟡 Security Misconfiguration',
            'problem': 'Insecure default configurations, debug mode enabled in production, or missing security headers.',
            'solution': '''Apply secure configurations:

```javascript
// Disable debug in production
if (process.env.NODE_ENV === 'production') {
  app.set('env', 'production');
}

// Add security headers (helmet)
const helmet = require('helmet');
app.use(helmet());

// Configure CORS properly
app.use(cors({
  origin: ['https://yourdomain.com'],
  credentials: true
}));

// Disable X-Powered-By
app.disable('x-powered-by');
```''',
            'verification': '''- Check NODE_ENV in production
- Verify security headers with securityheaders.com
- Ensure debug/verbose logging is disabled'''
        },

        'xxe': {
            'title': '🟠 XML External Entity (XXE)',
            'problem': 'XML parsers process external entities, allowing attackers to read local files or make server-side requests.',
            'solution': '''Disable external entities in XML parsers:

```javascript
// Node.js with libxmljs
const libxmljs = require('libxmljs');
const doc = libxmljs.parseXml(xml, { noent: false, dtdload: false });
```

```python
# Python with defusedxml (recommended)
import defusedxml.ElementTree as ET
tree = ET.parse(xml_file)

# Or disable entities manually
from lxml import etree
parser = etree.XMLParser(resolve_entities=False)
```''',
            'verification': '''- Test with XXE payload containing file:// URI
- Ensure external entities are disabled
- Consider using JSON instead of XML'''
        },

        'insecure-deserialization': {
            'title': '🔴 Insecure Deserialization',
            'problem': 'Untrusted data is deserialized, potentially allowing remote code execution.',
            'solution': '''Avoid deserializing untrusted data:

```python
# ❌ VULNERABLE
import pickle
data = pickle.loads(user_input)

import yaml
data = yaml.load(user_input)  # unsafe loader

# ✅ FIXED
import json
data = json.loads(user_input)  # JSON is safe

import yaml
data = yaml.safe_load(user_input)  # safe loader
```

```javascript
// Avoid eval and Function constructor
// ❌ VULNERABLE
eval(userInput);
new Function(userInput)();

// ✅ Use JSON.parse for data
JSON.parse(userInput);
```''',
            'verification': '''- Search for: `pickle.loads`, `yaml.load`, `eval`
- Use JSON for data serialization
- If binary formats needed, use signing/validation'''
        },

        'broken-auth': {
            'title': '🔴 Broken Authentication',
            'problem': 'Authentication mechanisms are improperly implemented, allowing attackers to compromise user accounts.',
            'solution': '''Implement secure authentication:

```javascript
// Use proven auth libraries
// Next.js: next-auth
// Express: passport.js with secure strategies

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET, // Strong random secret
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,      // HTTPS only
    httpOnly: true,    // No JS access
    sameSite: 'strict',
    maxAge: 3600000    // 1 hour
  }
}));

// Password requirements
// - Minimum 12 characters
// - Use bcrypt with cost factor 12+
// - Implement rate limiting on login
```''',
            'verification': '''- Test session fixation
- Verify password hashing uses bcrypt/argon2
- Check for rate limiting on auth endpoints'''
        },

        'other': {
            'title': '⚠️ Security Issue',
            'problem': 'A security issue was detected that requires attention.',
            'solution': '''Review the specific finding details and apply appropriate fixes based on the vulnerability type. General security principles:

1. **Validate all input** - Never trust user input
2. **Encode all output** - Prevent injection attacks
3. **Use parameterized queries** - Prevent SQL injection
4. **Implement proper authentication** - Verify identity
5. **Apply authorization checks** - Verify permissions
6. **Use HTTPS everywhere** - Encrypt data in transit
7. **Keep dependencies updated** - Patch known vulnerabilities''',
            'verification': '''- Review the specific CVE/CWE if provided
- Test the fix manually
- Consider security code review'''
        }
    }

    return guides.get(vuln_type, guides['other'])
