import requests
import json

SUPABASE_URL = "https://kgxjubeaddrocooklyib.supabase.co"
ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtneGp1YmVhZGRyb2Nvb2tseWliIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjQ2MjQzOTUsImV4cCI6MjA4MDIwMDM5NX0.fqSuSBYV2P_sfy9e6owEDtxMpakzqyHkgGnkKMIB_2g"

scan_id = "f1dd5154-6e18-4d9c-ad10-2646db66505f"

resp = requests.get(
    f"{SUPABASE_URL}/rest/v1/scans",
    params={"id": f"eq.{scan_id}", "select": "findings"},
    headers={
        "apikey": ANON_KEY,
        "Authorization": f"Bearer {ANON_KEY}"
    }
)

data = resp.json()
if not data:
    print("No data found")
    exit(1)

findings = data[0].get("findings", [])
print(f"Total findings: {len(findings)}")

by_file = {}
for f in findings:
    path = f.get("path", "")
    filename = path.split("/")[-1] if path else "unknown"
    if filename not in by_file:
        by_file[filename] = []
    by_file[filename].append({
        "rule": f.get("ruleId", ""),
        "severity": f.get("severity", ""),
        "source": f.get("source", "")
    })

vuln_files = ["sqli.py", "xss.py", "ssti.py", "lfi.py", "rfi.py", "hhi.py"]
print()
print("COVERAGE ANALYSIS")
print("=" * 50)
for vf in vuln_files:
    findings_list = by_file.get(vf, [])
    status = "✅" if findings_list else "❌"
    high = len([x for x in findings_list if x["severity"] in ["high", "error", "ERROR"]])
    print(f"{status} {vf}: {len(findings_list)} findings ({high} high)")
    for finding in findings_list[:5]:
        print(f"    - {finding['rule']} [{finding['severity']}]")
    if len(findings_list) > 5:
        print(f"    ... and {len(findings_list) - 5} more")

print()
print("Other files:")
for f in sorted(by_file.keys()):
    if f not in vuln_files:
        print(f"  {f}: {len(by_file[f])} findings")
