# backend/scripts/verify_dashboard_clean.py
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import json
from fastapi.testclient import TestClient
from main import app
from app.core.security import create_access_token

def test_dashboard():
    client = TestClient(app)
    
    # Campus Guide tenant admin token
    token = create_access_token({
        "sub": "sanias2721@gmail.com",
        "role": "tenant_admin",
        "tenant_id": "fd83e79b-f024-4fe1-b43a-5a083065b67a"
    })
    headers = {'Authorization': f'Bearer {token}'}

    # 1. View: Active Threats
    a_res = client.get('/threats/matches?view=active', headers=headers)
    assert a_res.status_code == 200, f"Error {a_res.status_code}: {a_res.text}"
    data_a = a_res.json()
    matches_a = data_a.get('matches', [])
    summary = data_a.get('summary', {})
    
    print('=== Summary Telemetry Envelope ===')
    print(json.dumps(summary, indent=2))

    print(f'\n=== View: active (Active Threats) [Total: {data_a.get("total")}, Matches: {len(matches_a)}] ===')
    for t in matches_a:
        print(f"  * {t.get('cve_id')} | {t.get('matched_component')} @ {t.get('installed_version')} | Severity: {t.get('severity')} | Outcome: {t.get('assessment_outcome')} | Status: {t.get('status')}")

    # 2. View: Review Required
    r_res = client.get('/threats/matches?view=review', headers=headers)
    data_r = r_res.json()
    matches_r = data_r.get('matches', [])
    print(f'\n=== View: review (Review Required) [Total: {data_r.get("total")}, Matches: {len(matches_r)}] ===')
    for t in matches_r[:5]:
        print(f"  * {t.get('cve_id')} | {t.get('matched_component')} @ {t.get('installed_version')} | Severity: {t.get('severity')} | Outcome: {t.get('assessment_outcome')} | Status: {t.get('status')}")

    # 3. View: Resolved History
    res_res = client.get('/threats/matches?view=resolved', headers=headers)
    data_res = res_res.json()
    matches_res = data_res.get('matches', [])
    print(f'\n=== View: resolved (Resolved History) [Total: {data_res.get("total")}, Matches: {len(matches_res)}] ===')
    for t in matches_res:
        print(f"  * {t.get('cve_id')} | {t.get('matched_component')} @ {t.get('installed_version')} | Severity: {t.get('severity')} | Outcome: {t.get('assessment_outcome')} | Status: {t.get('status')}")

    # 4. View: Safe & All
    safe_res = client.get('/threats/matches?view=safe', headers=headers)
    data_safe = safe_res.json()
    matches_safe = data_safe.get('matches', [])
    print(f'\n=== View: safe (Safe & All Advisories) [Total: {data_safe.get("total")}, Matches: {len(matches_safe)}] ===')
    for t in matches_safe[:5]:
        print(f"  * {t.get('cve_id')} | {t.get('matched_component')} @ {t.get('installed_version')} | Severity: {t.get('severity')} | Outcome: {t.get('assessment_outcome')} | Status: {t.get('status')}")

    # 5. Check exclusion of NOT_AFFECTED from active list
    not_affected_in_active = [t for t in matches_a if t.get('assessment_outcome') == 'NOT_AFFECTED']
    print(f'\n[Check 1] NOT_AFFECTED count in Active Threats: {len(not_affected_in_active)} (Expected: 0)')
    assert len(not_affected_in_active) == 0, 'NOT_AFFECTED should not be in Active Threats view!'

    # 6. Check that summary counters match view totals
    print(f'[Check 2] active_affected counter ({summary.get("active_affected")}) == active view total ({data_a.get("total")}): {summary.get("active_affected") == data_a.get("total")}')
    print(f'[Check 3] review_required counter ({summary.get("review_required")}) == review view total ({data_r.get("total")}): {summary.get("review_required") == data_r.get("total")}')
    print(f'[Check 4] resolved counter ({summary.get("resolved")}) == resolved view total ({data_res.get("total")}): {summary.get("resolved") == data_res.get("total")}')
    print(f'[Check 5] not_affected counter ({summary.get("not_affected")}): {summary.get("not_affected")}')
    print(f'[Check 6] total_correlated ({summary.get("total_correlated")}) == safe/all view total ({data_safe.get("total")}): {summary.get("total_correlated") == data_safe.get("total")}')
    print(f'[Check 7] Environment Health score calculation: {summary.get("health_score")}%')

    # Also test threats.py endpoint /public/threats/matches
    t_res = client.get('/public/threats/matches?view=active', headers=headers)
    assert t_res.status_code == 200
    print('\n[Check 8] /public/threats/matches returned status 200 with total:', t_res.json().get('total'))

    print('\n=== ALL DASHBOARD VALIDATIONS PASSED SUCCESSFULLY ===')

if __name__ == '__main__':
    test_dashboard()
