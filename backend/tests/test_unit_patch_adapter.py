import unittest
import os
import sys

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from tests.base import BaseTestCase
from app.models import Tenant, ThreatMatch, AssetComponent, PatchProposal, PatchAuditLog
from app.services.patch_adapter import (
    PatchManagementAdapter,
    PatchSecurityError,
    PatchStateError
)


class TestPatchManagementAdapter(BaseTestCase):
    def setUp(self):
        super().setUp()

    def test_01_package_input_validation_and_injection_defense(self):
        """Rejects dangerous shell metacharacters and invalid package names."""
        # Valid names
        clean_pkg, ver = PatchManagementAdapter.validate_package_spec("openssh-server", "9.7p1")
        self.assertEqual(clean_pkg, "openssh-server")
        self.assertEqual(ver, "9.7p1")

        # Invalid: command chaining
        with self.assertRaises(PatchSecurityError):
            PatchManagementAdapter.validate_package_spec("openssh; rm -rf /")

        # Invalid: pipe
        with self.assertRaises(PatchSecurityError):
            PatchManagementAdapter.validate_package_spec("curl | bash")

        # Invalid: backticks
        with self.assertRaises(PatchSecurityError):
            PatchManagementAdapter.validate_package_spec("`whoami`")

        # Invalid: version injection
        with self.assertRaises(PatchSecurityError):
            PatchManagementAdapter.validate_package_spec("openssh", "1.0; cat /etc/passwd")

    def test_02_proposal_creation_and_audit_logging(self):
        """Creates patch proposal in PROPOSED state and logs audit record."""
        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            package_name="openssh-server",
            current_version="8.5p1",
            target_version="9.7p1",
            priority="CRITICAL",
            package_manager="dnf",
            actor="SOC_ANALYST"
        )

        self.assertEqual(proposal.status, "PROPOSED")
        self.assertEqual(proposal.package_name, "openssh-server")
        self.assertEqual(proposal.package_manager, "dnf")
        self.assertTrue(proposal.proposal_id.startswith("patch-"))

        # Check audit log
        audit = self.db.query(PatchAuditLog).filter(PatchAuditLog.proposal_id == proposal.id).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.event_type, "PROPOSAL_CREATED")
        self.assertEqual(audit.actor, "SOC_ANALYST")

    def test_03_approval_and_rejection_lifecycle(self):
        """Tests approval and rejection state transitions."""
        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            package_name="nginx",
            target_version="1.24.0"
        )

        # Reject
        rejected = PatchManagementAdapter.reject_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            reason="Component deprecation pending",
            actor="SOC_LEAD"
        )
        self.assertEqual(rejected.status, "REJECTED")

        # Cannot approve rejected
        with self.assertRaises(PatchStateError):
            PatchManagementAdapter.approve_proposal(
                db=self.db,
                proposal_id=proposal.proposal_id,
                approver="SOC_LEAD"
            )

        # Create new and approve
        proposal2 = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            package_name="python3-cryptography",
            target_version="42.0.0"
        )
        approved = PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal2.proposal_id,
            approver="DEVSECOPS_ADMIN"
        )
        self.assertEqual(approved.status, "APPROVED")
        self.assertEqual(approved.approved_by, "DEVSECOPS_ADMIN")

    def test_04_simulated_execution_and_verification(self):
        """Tests safe simulated patch execution (default mode)."""
        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            package_name="bind",
            target_version="9.18.24"
        )

        # Cannot execute unapproved proposal
        with self.assertRaises(PatchStateError):
            PatchManagementAdapter.execute_patch(
                db=self.db,
                proposal_id=proposal.proposal_id,
                mode="simulated"
            )

        # Approve and execute simulation
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="SOC_ADMIN"
        )

        res = PatchManagementAdapter.execute_patch(
            db=self.db,
            proposal_id=proposal.proposal_id,
            mode="simulated"
        )

        self.assertEqual(res["status"], "SIMULATED")
        self.assertTrue(res["is_simulated"])
        self.assertIn("SIMULATION DRY-RUN", res["output"])
        self.assertIn("SIMULATION VERIFICATION", res["verification"])

        # Check DB state
        refreshed = self.db.query(PatchProposal).filter(PatchProposal.id == proposal.id).first()
        self.assertEqual(refreshed.status, "SIMULATED")
        self.assertTrue(refreshed.is_simulated)

        # Audit logs present
        audits = self.db.query(PatchAuditLog).filter(PatchAuditLog.proposal_id == proposal.id).all()
        event_types = [a.event_type for a in audits]
        self.assertIn("PROPOSAL_CREATED", event_types)
        self.assertIn("PROPOSAL_APPROVED", event_types)
        self.assertIn("PATCH_SIMULATED", event_types)

    def test_05_tenant_isolation_enforcement(self):
        """Ensures operations cannot cross tenant boundaries."""
        other_tenant = Tenant(
            id="tenant-patch-other",
            company_name="Other Tenant",
            tech_stack="Ubuntu:22.04"
        )
        self.db.add(other_tenant)
        self.db.commit()

        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            package_name="redis",
            target_version="7.2.4"
        )

        # Other tenant cannot approve
        with self.assertRaises(PatchStateError):
            PatchManagementAdapter.approve_proposal(
                db=self.db,
                proposal_id=proposal.proposal_id,
                approver="ATTACKER",
                tenant_id=other_tenant.id
            )

        # Other tenant cannot execute
        with self.assertRaises(PatchStateError):
            PatchManagementAdapter.execute_patch(
                db=self.db,
                proposal_id=proposal.proposal_id,
                mode="simulated",
                tenant_id=other_tenant.id
            )


if __name__ == "__main__":
    unittest.main()
