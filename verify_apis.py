import requests

base = 'http://localhost:5000'
headers = {'Authorization': 'Bearer su_test_session_token'}

endpoints_to_test = [
    ('GET', '/api/health', None, None),
    ('GET', '/api/dashboard/stats', headers, None),
    ('GET', '/api/endpoints', headers, None),
    ('GET', '/api/alerts', headers, None),
    ('GET', '/api/ai-tools', headers, None),
    ('GET', '/api/incidents', headers, None),
    ('GET', '/api/policies', headers, None),
    ('GET', '/api/awareness', None, None),
    ('GET', '/api/audit-logs', headers, None),
    ('GET', '/api/traffic/history', headers, None),
    ('GET', '/api/reports/export-csv', headers, None),
    ('POST', '/api/sensitive-data/check', None, {'text': 'sk-proj-test1234567890abcdef user@company.com'}),
]

print('=' * 60)
print('COMPREHENSIVE BACKEND API INTEGRITY CHECK')
print('=' * 60)

passed = 0
for item in endpoints_to_test:
    method = item[0]
    path = item[1]
    hdrs = item[2]
    body = item[3]

    url = f'{base}{path}'
    if method == 'GET':
        r = requests.get(url, headers=hdrs, timeout=5)
    elif method == 'POST':
        r = requests.post(url, json=body, headers=hdrs, timeout=5)

    status_ok = r.status_code in [200, 201]
    mark = '[PASS]' if status_ok else '[FAIL]'
    print(f'{mark} [{method}] {path:<28} -> HTTP {r.status_code}')
    if status_ok:
        passed += 1

print('=' * 60)
print(f'Test Summary: {passed}/{len(endpoints_to_test)} endpoints passed perfectly.')
print('=' * 60)
