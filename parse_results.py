import json
import sys

data = json.load(sys.stdin)
results = data.get('results', [])

print('=' * 60)
print('SCAN RESULTS: michealkeines/Vulnerable-API')
print(f'Total Findings: {len(results)}')
print('=' * 60)

by_severity = {'ERROR': [], 'WARNING': [], 'INFO': []}
for r in results:
    sev = r.get('extra', {}).get('severity', 'INFO')
    by_severity.setdefault(sev, []).append(r)

for sev in ['ERROR', 'WARNING', 'INFO']:
    findings = by_severity.get(sev, [])
    if findings:
        print(f'\n### {sev} ({len(findings)} findings)')
        print('-' * 50)
        for r in findings:
            path = r.get('path', '')
            if 'Vulnerable-API' in path:
                path = path.split('Vulnerable-API')[-1].lstrip('/\\')
            line = r.get('start', {}).get('line', 0)
            rule = r.get('check_id', '').split('.')[-1]
            msg = r.get('extra', {}).get('message', '')
            cwe = r.get('extra', {}).get('metadata', {}).get('cwe', '')
            print(f'  [{path}:{line}]')
            print(f'     Rule: {rule}')
            print(f'     {msg[:100]}')
            if cwe:
                print(f'     CWE: {cwe}')
            print()
