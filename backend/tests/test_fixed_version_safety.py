"""
Step 3 Focused Regression Tests: Verified-Version Safety Gaps
------------------------------------------------------------
Validates:
1. PyPI timeout or server error does not produce PACKAGE_AVAILABLE.
2. Non-Python packages (e.g. RPM, DNF, APT, NPM) are never queried against PyPI.
3. Inferred version from constraint boundary (< X) is distinguished as INFERRED_CANDIDATE,
   not labeled as vendor-verified, and blocked from live execution.
4. Simulated patch execution retains incident OPEN and does not release containment.
5. Authoritative Python-package discovery, registry confirmation, and post-install checks remain intact.
"""

import uuid
import requests
from unittest.mock import patch, MagicMock

from tests.base import BaseTestCase
from app import models
from app.services.fixed_version_service import (
    FixedVersionDiscoveryService,
    RegistryCheckResult
)
from app.services.autonomous_response_orchestrator import AutonomousResponseOrchestrator
from app.services.patch_adapter import (
    PatchManagementAdapter,
    verify_version_match,
    parse_installed_version
)


class TestFixedVersionSafetyStep3(BaseTestCase):

    def setUp(self):
        super().setUp()
        self.tenant = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Apex Security Labs",
            tech_stack="Python, FastAPI, Linux",
            webhook_url="http://127.0.0.1:8000/webhook",
            remediation_policy="NOTIFY"
        )
        self.db.add(self.tenant)

        # Asset: uvicorn 0.38.0
        self.asset_uvicorn = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant.id,
            software_name="uvicorn",
            software_version="0.38.0",
            environment="production"
        )
        self.db.add(self.asset_uvicorn)

        # Asset: nginx 1.20.1 (system / non-python)
        self.asset_nginx = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant.id,
            software_name="nginx",
            software_version="1.20.1",
            environment="production"
        )
        self.db.add(self.asset_nginx)

        # Threat report with explicit advisory fix
        self.report_explicit = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-99001",
            title="Uvicorn Header Desync",
            summary="Uvicorn before 0.38.1 is vulnerable to request smuggling. Fixed in version 0.38.1.",
            severity="high"
        )
        self.db.add(self.report_explicit)

        # Threat report with ONLY an inferred upper-bound constraint (< 2.0.0)
        self.report_inferred = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-99002",
            title="Generic Prototype Pollution",
            summary="Vulnerability in example-pkg < 2.0.0 without upstream vendor fix announcement.",
            severity="medium"
        )
        self.db.add(self.report_inferred)
        self.db.commit()

    # -------------------------------------------------------------------------
    # 1. Registry Availability: Network error, timeout, server error fail-safe
    # -------------------------------------------------------------------------

    @patch("requests.get")
    def test_pypi_timeout_does_not_produce_package_available(self, mock_get):
        """Network timeout during PyPI lookup must produce is_available=False and FIX_ANNOUNCED, never PACKAGE_AVAILABLE."""
        mock_get.side_effect = requests.Timeout("Connection timed out after 5.0s")

        # Test check_registry_availability directly
        reg_res = FixedVersionDiscoveryService.check_registry_availability("uvicorn", "0.38.1", package_manager="pip")
        self.assertFalse(bool(reg_res))
        self.assertFalse(reg_res.is_available)
        self.assertEqual(reg_res.status, "REGISTRY_UNAVAILABLE")
        self.assertIn("timed out", reg_res.message.lower())

        # Test discover_and_verify_fix workflow
        disc = FixedVersionDiscoveryService.discover_and_verify_fix(
            package_name="uvicorn",
            current_version="0.38.0",
            threat_report=self.report_explicit,
            package_manager="pip"
        )
        self.assertNotEqual(disc["status"], "PACKAGE_AVAILABLE")
        self.assertEqual(disc["status"], "FIX_ANNOUNCED")
        self.assertEqual(disc["registry_status"], "REGISTRY_UNAVAILABLE")
        self.assertTrue(disc["is_verified"])
        self.assertTrue(disc["live_execution_blocked"])

    @patch("requests.get")
    def test_pypi_server_error_500_does_not_produce_package_available(self, mock_get):
        """HTTP 500 from PyPI must not produce PACKAGE_AVAILABLE."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp

        reg_res = FixedVersionDiscoveryService.check_registry_availability("uvicorn", "0.38.1", package_manager="pip")
        self.assertFalse(bool(reg_res))
        self.assertEqual(reg_res.status, "REGISTRY_UNAVAILABLE")

        disc = FixedVersionDiscoveryService.discover_and_verify_fix(
            package_name="uvicorn",
            current_version="0.38.0",
            threat_report=self.report_explicit,
            package_manager="pip"
        )
        self.assertEqual(disc["status"], "FIX_ANNOUNCED")
        self.assertEqual(disc["registry_status"], "REGISTRY_UNAVAILABLE")
        self.assertTrue(disc["live_execution_blocked"])

    @patch("requests.get")
    def test_pypi_release_not_found_distinguished_from_registry_failure(self, mock_get):
        """Release not found in registry (200 with missing release) must be distinguished from network failure."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"releases": {"0.38.0": [], "0.37.0": []}}
        mock_get.return_value = mock_resp

        reg_res = FixedVersionDiscoveryService.check_registry_availability("uvicorn", "0.38.1", package_manager="pip")
        self.assertFalse(bool(reg_res))
        self.assertEqual(reg_res.status, "RELEASE_NOT_FOUND")
        self.assertIn("not published", reg_res.message)

    # -------------------------------------------------------------------------
    # 2. Ecosystem Safety: Non-Python packages are NOT checked against PyPI
    # -------------------------------------------------------------------------

    @patch("requests.get")
    def test_non_python_package_not_checked_against_pypi(self, mock_get):
        """RPM/Debian/NPM package managers and system packages must never query PyPI."""
        # A: explicit non-python package_manager: dnf
        reg_dnf = FixedVersionDiscoveryService.check_registry_availability("libssl", "3.0.2", package_manager="dnf")
        self.assertFalse(bool(reg_dnf))
        self.assertEqual(reg_dnf.status, "UNSUPPORTED_ECOSYSTEM")
        mock_get.assert_not_called()

        # B: explicit non-python package_manager: npm
        reg_npm = FixedVersionDiscoveryService.check_registry_availability("express", "4.19.2", package_manager="npm")
        self.assertFalse(bool(reg_npm))
        self.assertEqual(reg_npm.status, "UNSUPPORTED_ECOSYSTEM")
        mock_get.assert_not_called()

        # C: system package name (nginx) with package_manager=None
        reg_nginx = FixedVersionDiscoveryService.check_registry_availability("nginx", "1.24.0", package_manager=None)
        self.assertFalse(bool(reg_nginx))
        self.assertEqual(reg_nginx.status, "UNSUPPORTED_ECOSYSTEM")
        mock_get.assert_not_called()

    # -------------------------------------------------------------------------
    # 3. Unsupported Fixed-Version Inference: Inferred upper bounds (< X)
    # -------------------------------------------------------------------------

    def test_inferred_upper_bound_produces_inferred_candidate_and_blocks_live(self):
        """Heuristic constraint upper bound (< 2.0.0) must be labeled INFERRED_CANDIDATE, is_verified=False, and blocked."""
        disc = FixedVersionDiscoveryService.discover_and_verify_fix(
            package_name="example-pkg",
            current_version="1.0.0",
            threat_report=self.report_inferred,
            package_manager="pip"
        )

        self.assertEqual(disc["status"], "INFERRED_CANDIDATE")
        self.assertEqual(disc["fixed_version"], "2.0.0")
        self.assertFalse(disc["is_verified"])
        self.assertFalse(disc["is_authoritative"])
        self.assertEqual(disc["evidence_type"], "INFERRED_UPPER_BOUND")
        self.assertTrue(disc["live_execution_blocked"])
        self.assertIn("inferred from vulnerability constraint boundary", disc["blocking_reason"])

    def test_inferred_candidate_blocks_live_execution_in_patch_adapter(self):
        """Proposal created from inferred candidate must be rejected from live execution."""
        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            package_name="uvicorn",
            current_version="0.38.0",
            target_version="0.39.0",
            package_manager="pip",
            is_authoritative=False,
            live_execution_blocked=True,
            blocking_reason="Inferred candidate from constraint '< 0.39.0'"
        )
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="TEST_ADMIN",
            tenant_id=self.tenant.id
        )

        # Attempt live execution
        res = PatchManagementAdapter.execute_patch(
            db=self.db,
            proposal_id=proposal.proposal_id,
            mode="live",
            tenant_id=self.tenant.id
        )
        self.assertEqual(res["status"], "FAILED")
        self.assertIn("Inferred candidate", res["error"])

    # -------------------------------------------------------------------------
    # 4. Simulated Patch Status: Never resolves incident or releases containment
    # -------------------------------------------------------------------------

    def test_simulated_patch_does_not_resolve_incident_or_release_containment(self):
        """Simulated patch execution must leave ThreatMatch OPEN and must NEVER release containment."""
        match = models.ThreatMatch(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant.id,
            asset_component_id=self.asset_uvicorn.id,
            threat_report_id=self.report_explicit.id,
            status="OPEN",
            ai_confidence_score=95.0,
            ai_matching_reason="Uvicorn vulnerable"
        )
        self.db.add(match)

        action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id="act-test-sim-01",
            tenant_id=self.tenant.id,
            threat_report_id=self.report_explicit.id,
            threat_match_id=match.id,
            indicator_value="198.51.100.99",
            indicator_type="ipv4",
            action_type="BLOCK_INBOUND_PORT_8000",
            policy_decision="QUALIFIED",
            policy_rule="JUSTIFIED_INCIDENT_EXPLOIT_CONTAINMENT",
            status="SIMULATED",
            ttl_seconds=3600
        )
        self.db.add(action)

        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            package_name="uvicorn",
            current_version="0.38.0",
            target_version="0.38.1",
            package_manager="pip",
            threat_match_id=match.id,
            asset_component_id=self.asset_uvicorn.id
        )
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="SEC_OPS",
            tenant_id=self.tenant.id
        )

        # Execute in SIMULATED mode
        res = AutonomousResponseOrchestrator.execute_patch_and_release(
            db=self.db,
            proposal_id=proposal.proposal_id,
            tenant_id=self.tenant.id,
            is_simulated=True
        )

        self.assertEqual(res["status"], "SIMULATED_PATCH_SUCCEEDED")
        self.assertEqual(res["vulnerability_status"], "OPEN")
        self.assertEqual(res["containment_released"], [])

        # Incident status MUST NOT BE RESOLVED
        self.db.refresh(match)
        self.assertEqual(match.status, "OPEN")

        # Containment action MUST NOT BE ROLLED BACK
        self.db.refresh(action)
        self.assertEqual(action.status, "SIMULATED")
        self.assertIsNone(action.rolled_back_at)

        # Asset version MUST NOT BE OVERWRITTEN
        self.db.refresh(self.asset_uvicorn)
        self.assertEqual(self.asset_uvicorn.software_version, "0.38.0")

    # -------------------------------------------------------------------------
    # 5. Authoritative Python Discovery and Post-Install Verification Intact
    # -------------------------------------------------------------------------

    @patch("requests.get")
    def test_successful_python_package_discovery_and_verification_intact(self, mock_get):
        """Authoritative Python advisory + confirmed PyPI release produces PACKAGE_AVAILABLE and verified fix."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"releases": {"0.38.1": [{"filename": "uvicorn-0.38.1.tar.gz"}]}}
        mock_get.return_value = mock_resp

        disc = FixedVersionDiscoveryService.discover_and_verify_fix(
            package_name="uvicorn",
            current_version="0.38.0",
            threat_report=self.report_explicit,
            package_manager="pip"
        )
        self.assertEqual(disc["status"], "PACKAGE_AVAILABLE")
        self.assertEqual(disc["fixed_version"], "0.38.1")
        self.assertTrue(disc["is_verified"])
        self.assertTrue(disc["is_authoritative"])
        self.assertFalse(disc["live_execution_blocked"])
        self.assertEqual(disc["evaluation_outcome"], "NOT_AFFECTED")

    def test_independent_post_install_version_verification_intact(self):
        """Independent version parser and matcher functions remain accurate."""
        self.assertTrue(verify_version_match("0.38.1", "0.38.1"))
        self.assertTrue(verify_version_match("v0.38.1", "0.38.1"))
        self.assertFalse(verify_version_match("0.38.0", "0.38.1"))

        pip_out = "Name: uvicorn\nVersion: 0.38.1\nSummary: ASGI web server"
        parsed = parse_installed_version("pip", pip_out, "uvicorn")
        self.assertEqual(parsed, "0.38.1")

        dnf_out = "uvicorn-0.38.1-1.fc40"
        parsed_dnf = parse_installed_version("dnf", dnf_out, "uvicorn")
        self.assertEqual(parsed_dnf, "0.38.1")
