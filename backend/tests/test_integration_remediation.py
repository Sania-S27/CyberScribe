import unittest
import os
import sys

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from tests.base import BaseTestCase
from app.models import PatchProposal, PatchAuditLog


class TestRemediationIntegration(BaseTestCase):
    def test_remediation_proposal_api_lifecycle(self):
        # 1. Create a remediation proposal
        payload = {
            "package_name": "openssh-server",
            "current_version": "8.5p1",
            "target_version": "9.7p1",
            "priority": "CRITICAL",
            "package_manager": "dnf"
        }
        res_create = self.client.post("/tenants/remediation/proposals", json=payload, headers=self.user_headers)
        self.assertEqual(res_create.status_code, 201)
        data = res_create.json()
        self.assertEqual(data["status"], "CREATED")
        proposal_id = data["proposal_id"]

        # 2. List proposals
        res_list = self.client.get("/tenants/remediation/proposals", headers=self.user_headers)
        self.assertEqual(res_list.status_code, 200)
        proposals = res_list.json()["proposals"]
        self.assertTrue(any(p["proposal_id"] == proposal_id for p in proposals))

        # 3. Approve proposal
        res_approve = self.client.post(f"/tenants/remediation/proposals/{proposal_id}/approve", headers=self.user_headers)
        self.assertEqual(res_approve.status_code, 200)
        self.assertEqual(res_approve.json()["status"], "APPROVED")

        # 4. Execute simulated patch
        res_exec = self.client.post(
            f"/tenants/remediation/proposals/{proposal_id}/execute",
            json={"mode": "simulated"},
            headers=self.user_headers
        )
        self.assertEqual(res_exec.status_code, 200)
        exec_data = res_exec.json()
        self.assertEqual(exec_data["status"], "SIMULATED")
        self.assertTrue(exec_data["is_simulated"])
        self.assertIn("SIMULATION DRY-RUN", exec_data["output"])

        # 5. Check audit logs
        res_audit = self.client.get("/tenants/remediation/audit-logs", headers=self.user_headers)
        self.assertEqual(res_audit.status_code, 200)
        logs = res_audit.json()["audit_logs"]
        self.assertGreaterEqual(len(logs), 3)
        event_types = [l["event_type"] for l in logs]
        self.assertIn("PROPOSAL_CREATED", event_types)
        self.assertIn("PROPOSAL_APPROVED", event_types)
        self.assertIn("PATCH_SIMULATED", event_types)


if __name__ == "__main__":
    unittest.main()
