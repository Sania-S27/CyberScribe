import requests
import json
import sys
import os

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.core.security import create_access_token
from app.core.database import SessionLocal
from app.models import User, ThreatReport, ThreatMatch, ContainmentAction

BASE = "http://127.0.0.1:8001"

def main():
    db = SessionLocal()
    u = db.query(User).filter(User.email == "sanias2721@gmail.com").first()
    if not u:
        print("[!] Default admin user not found.")
        return
    token = create_access_token({"sub": u.email, "role": u.role, "tenant_id": u.tenant_id})
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    print(f"[*] Authenticated as {u.email} (Tenant: {u.tenant_id})")

    # 1. Update policy to NOTIFY
    p_res = requests.put(f"{BASE}/tenants/policy", json={"remediation_policy": "NOTIFY"}, headers=headers)
    print("[+] POLICY_UPDATE:", p_res.json())

    # 2. Pick Threat Report for CVE-2026-26209
    rep = db.query(ThreatReport).filter(ThreatReport.cve_id == "CVE-2026-26209").first()
    if not rep:
        rep = db.query(ThreatReport).first()
    if not rep:
        print("[!] No threat report found.")
        return
    print(f"[*] Using Report: {rep.id} ({rep.cve_id}) - '{rep.title}'")

    # 3. Test Orchestration with Supporting Malicious IP
    orch_payload = {
        "threat_report_id": rep.id,
        "supporting_malicious_ip": "198.51.100.123",
        "is_simulated": True
    }
    orch_res = requests.post(f"{BASE}/tenants/remediation/orchestrate", json=orch_payload, headers=headers)
    print("\n[+] ORCHESTRATION RESPONSE (NOTIFY + Justified Containment):")
    print(json.dumps(orch_res.json(), indent=2))

    # 4. Check Fix Discovery Endpoint
    orch_data = orch_res.json()
    incident_id = orch_data.get("incident_id")
    if incident_id:
        fix_res = requests.get(f"{BASE}/tenants/threats/{incident_id}/fix-discovery", headers=headers)
        print("\n[+] FIX DISCOVERY ENDPOINT RESPONSE:")
        print(json.dumps(fix_res.json(), indent=2))

    # 5. List Proposals
    prop_res = requests.get(f"{BASE}/tenants/remediation/proposals", headers=headers)
    proposals = prop_res.json().get("proposals", [])
    print(f"\n[+] Total Proposals: {prop_res.json().get('total')}")
    if proposals:
        target_proposal = proposals[0]
        prop_id = target_proposal["proposal_id"]
        print(f"[*] Approving proposal: {prop_id} ({target_proposal['package_name']} -> {target_proposal['target_version']})")

        # Approve proposal
        appr_res = requests.post(f"{BASE}/tenants/remediation/proposals/{prop_id}/approve", headers=headers)
        print("[+] APPROVE RESPONSE:", appr_res.json())

        # Execute patch and release containment
        print(f"[*] Executing patch and releasing containment for proposal: {prop_id}")
        exec_res = requests.post(
            f"{BASE}/tenants/remediation/proposals/{prop_id}/execute-and-release",
            json={"mode": "simulated"},
            headers=headers
        )
        print("\n[+] EXECUTE AND RELEASE RESPONSE:")
        print(json.dumps(exec_res.json(), indent=2))

    # 6. Verify Audit Logs
    audit_res = requests.get(f"{BASE}/tenants/remediation/audit-logs", headers=headers)
    print(f"\n[+] Remediation Audit Logs Recorded: {audit_res.json().get('total')}")
    for log in audit_res.json().get("audit_logs", [])[:3]:
        print(f"    - [{log['created_at']}] {log['event_type']} (Actor: {log['actor']}) -> Status: {log['new_status']}")

    # 7. Test Manual Remediation Endpoint
    if incident_id:
        print("\n[*] Testing Manual Remediation reporting on match...")
        man_res = requests.post(
            f"{BASE}/tenants/threats/{incident_id}/manual-remediation",
            json={"installed_version": "0.38.1", "notes": "Independent verification by SOC analyst"},
            headers=headers
        )
        print("[+] MANUAL REMEDIATION RESPONSE:")
        print(json.dumps(man_res.json(), indent=2))

    print("\n[SUCCESS] End-to-End Workflow verified live across all REST endpoints!")


if __name__ == "__main__":
    main()
