import requests
import json

API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtneGp1YmVhZGRyb2Nvb2tseWliIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjQ2MjQzOTUsImV4cCI6MjA4MDIwMDM5NX0.fqSuSBYV2P_sfy9e6owEDtxMpakzqyHkgGnkKMIB_2g"
BASE_URL = "https://kgxjubeaddrocooklyib.supabase.co/rest/v1"

headers = {
    "apikey": API_KEY,
    "Authorization": f"Bearer {API_KEY}"
}

# Get recent scans
resp = requests.get(
    f"{BASE_URL}/scans?select=id,target_url,finding_counts&order=created_at.desc&limit=50",
    headers=headers
)
data = resp.json()

seen = set()
print("SCAN ID      REPOSITORY                               FINDINGS")
print("-" * 70)
for d in data:
    url = d.get('target_url', '')
    if url and url not in seen:
        seen.add(url)
        repo = url.split('/')[-1] if '/' in url else url
        counts = d.get('finding_counts', {})
        total = sum(counts.values()) if counts else 0
        print(f"{d['id'][:12]}  {repo:40} {total:>5}")
