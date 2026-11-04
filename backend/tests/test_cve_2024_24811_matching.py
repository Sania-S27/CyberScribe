# backend/tests/test_cve_2024_24811_matching.py
import unittest
import sys
import os

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.services.version_matcher import (
    evaluate_version_applicability,
    extract_version_constraints,
    check_product_identity_mismatch
)
from app.services.osint_collector import check_threat_match_for_tenant
from app.agents.mitigation import generate_soar_playbook
from app.services.containment_policy import (
    AutonomousPolicyEngine,
    NetworkIndicatorCandidate
)
from app.core.database import SessionLocal
from app import models


class TestCVE202424811MatchingAccuracy(unittest.TestCase):
    """
    Regression test suite for Milestone 1: Audit CVE-2024-24811 Matching Accuracy.
    Verifies that package name similarity does not cause false-positive AFFECTED classifications,
    that unverified product identities yield NEEDS_REVIEW with clear explanations,
    that SOAR playbooks and advisories remain consistent, and that uncertain matches
    cannot authorize automatic containment.
    """

    def setUp(self):
        self.cve_2024_24811_text = (
            "SQLAlchemyDA is a generic database adapter for ZSQL methods. "
            "A vulnerability found in versions prior to 2.2 allows unauthenticated execution "
            "of arbitrary SQL statements on the database to which the SQLAlchemyDA instance is connected. "
            "All users are affected. The problem has been patched in version 2.2. "
            "There is no workaround for the problem."
        )
        self.cve_2024_24811_corpus = (
            f"Sqlalchemy Advisory: CVE-2024-24811 {self.cve_2024_24811_text}"
        )

    def test_sqlalchemydam_does_not_match_sqlalchemy_as_affected(self):
        """
        Requirement 7.1: SQLAlchemyDA must not automatically match the unrelated
        sqlalchemy package based on name similarity alone.
        """
        outcome, conf, reason = evaluate_version_applicability(
            installed_version="2.0.44",
            threat_text=self.cve_2024_24811_corpus,
            pkg_name="sqlalchemy"
        )

        self.assertNotEqual(outcome, "AFFECTED", "sqlalchemy must NOT be classified as AFFECTED by SQLAlchemyDA advisory")
        self.assertEqual(outcome, "NEEDS_REVIEW")
        self.assertIn("SQLAlchemyDA", reason)
        self.assertIn("mismatch with installed 'sqlalchemy'", reason)
        self.assertEqual(conf, 50.0, "Heuristic review score should be 50.0%, not 95%")
        self.assertIn("not a measured probability", reason)

        # Ensure no false constraints like '< 2.2' are extracted for sqlalchemy
        constraints = extract_version_constraints(self.cve_2024_24811_corpus, "sqlalchemy")
        self.assertEqual(constraints, [], "Version constraints for SQLAlchemyDA must not be assigned to sqlalchemy")

    def test_unverified_product_identity_results_in_needs_review(self):
        """
        Requirement 7.2: Unverified product identity results in NEEDS_REVIEW.
        Derivative, adapter, or compound products sharing prefixes must not be assumed identical.
        """
        # Case A: fastapi-admin vs fastapi
        fastapi_admin_text = "fastapi-admin pro v0.1.4 allows XSS in Config-Create function. Fixed in 0.1.5."
        outcome_fa, conf_fa, reason_fa = evaluate_version_applicability(
            installed_version="0.120.1",
            threat_text=fastapi_admin_text,
            pkg_name="fastapi"
        )
        self.assertEqual(outcome_fa, "NEEDS_REVIEW")
        self.assertIn("fastapi-admin", reason_fa)
        self.assertNotEqual(outcome_fa, "AFFECTED")

        # Case B: ReactOS vs react
        reactos_text = "Unspecified vulnerability in ReactOS 0.3.1 has unknown impact."
        outcome_ro, conf_ro, reason_ro = evaluate_version_applicability(
            installed_version="19.2.0",
            threat_text=reactos_text,
            pkg_name="react"
        )
        self.assertEqual(outcome_ro, "NEEDS_REVIEW")
        self.assertIn("ReactOS", reason_ro)
        self.assertNotEqual(outcome_ro, "AFFECTED")

        # Case C: Flask-SQLAlchemy vs sqlalchemy
        flask_sqla_text = "Flask-SQLAlchemy before 2.5.1 does not sanitize connection strings."
        outcome_fsqla, conf_fsqla, reason_fsqla = evaluate_version_applicability(
            installed_version="2.0.44",
            threat_text=flask_sqla_text,
            pkg_name="sqlalchemy"
        )
        self.assertEqual(outcome_fsqla, "NEEDS_REVIEW")
        self.assertIn("Flask-SQLAlchemy", reason_fsqla)
        self.assertNotEqual(outcome_fsqla, "AFFECTED")

    def test_confirmed_match_requires_evidence_for_actual_product_and_version(self):
        """
        Requirement 7.3: A confirmed match requires evidence supporting the actual product
        and vulnerable version constraints.
        """
        # Genuine SQLAlchemy CVE-2019-7164 text
        genuine_sqla_text = (
            "SQLAlchemy before 1.2.18 and 1.3.x before 1.3.0b3 allows SQL injection "
            "via the order_by parameter."
        )

        # 1. Old vulnerable version of core sqlalchemy -> AFFECTED
        outcome_vuln, conf_vuln, reason_vuln = evaluate_version_applicability(
            installed_version="1.2.10",
            threat_text=genuine_sqla_text,
            pkg_name="sqlalchemy"
        )
        self.assertEqual(outcome_vuln, "AFFECTED")
        self.assertGreaterEqual(conf_vuln, 90.0)
        self.assertIn("satisfies vulnerable constraint", reason_vuln)

        # 2. Modern safe version of core sqlalchemy (Campus Guide inventory 2.0.44) -> NOT_AFFECTED
        outcome_safe, conf_safe, reason_safe = evaluate_version_applicability(
            installed_version="2.0.44",
            threat_text=genuine_sqla_text,
            pkg_name="sqlalchemy"
        )
        self.assertEqual(outcome_safe, "NOT_AFFECTED")
        self.assertIn("outside vulnerable range", reason_safe)

        # 3. If tenant actually has SQLAlchemyDA installed, CVE-2024-24811 evaluates it against its own version range
        outcome_sda, conf_sda, reason_sda = evaluate_version_applicability(
            installed_version="2.0.0",
            threat_text=self.cve_2024_24811_corpus,
            pkg_name="SQLAlchemyDA"
        )
        self.assertEqual(outcome_sda, "AFFECTED")
        self.assertIn("< 2.2", reason_sda)

        # 4. Safe / patched version of SQLAlchemyDA (2.2.0) -> NOT_AFFECTED
        outcome_sda_safe, conf_sda_safe, reason_sda_safe = evaluate_version_applicability(
            installed_version="2.2.0",
            threat_text=self.cve_2024_24811_corpus,
            pkg_name="SQLAlchemyDA"
        )
        self.assertEqual(outcome_sda_safe, "NOT_AFFECTED")
        self.assertIn("outside vulnerable range", reason_sda_safe)

    def test_advisory_and_playbook_outputs_remain_consistent(self):
        """
        Requirement 7.4: Advisory and playbook outputs remain consistent.
        A NEEDS_REVIEW finding must not produce a definitive package-upgrade instruction
        or prescribe upgrading an unrelated package.
        """
        playbook = generate_soar_playbook(
            threat_title="SQLAlchemyDA Advisory: CVE-2024-24811",
            summary=self.cve_2024_24811_text,
            mitre_tactics=[],
            assessment_outcome="NEEDS_REVIEW",
            matched_component="sqlalchemy"
        )

        # Verify recommended action requires manual verification
        rec_action = playbook.get("recommended_action", "")
        self.assertIn("Manual verification required", rec_action)
        self.assertIn("SQLAlchemyDA", rec_action)

        # Verify patch guidance does NOT instruct upgrading core sqlalchemy
        patch_guidance = playbook.get("patch_guidance", "")
        self.assertIn("no patch or upgrade is required for 'sqlalchemy'", patch_guidance)
        self.assertIn("SQLAlchemyDA", patch_guidance)

        # Verify firewall rules are empty (no automated blocking on unverified match)
        self.assertEqual(playbook.get("firewall_rules"), [])

    def test_uncertain_matches_cannot_authorize_containment(self):
        """
        Requirement 7.5: Uncertain matches cannot independently authorize containment.
        The deterministic policy engine must reject NEEDS_REVIEW candidates.
        """
        db = SessionLocal()
        try:
            tenant = db.query(models.Tenant).first()
            self.assertIsNotNone(tenant, "A tenant record must exist for policy evaluation test")

            # Candidate with NEEDS_REVIEW vulnerability status and no independent network IOC corroboration
            candidate = NetworkIndicatorCandidate(
                indicator_value="93.184.216.34",
                tenant_id=tenant.id,
                confidence_score=50.0,
                evidence_source="NIST_NVD_VERIFIED",
                is_structured_ioc=False,  # Unstructured/uncertain
                evidence_summary="Candidate IP associated with unverified CVE-2024-24811 match",
                vulnerability_status="NEEDS_REVIEW"
            )

            qualified, action, reason = AutonomousPolicyEngine.evaluate_candidate(
                candidate=candidate,
                db=db,
                actor="TEST_CONTAINMENT_AUDIT"
            )

            self.assertFalse(qualified, "NEEDS_REVIEW candidate must NOT qualify for autonomous containment")
            self.assertIsNone(action, "No ContainmentAction should be executed")
            self.assertIn(
                reason,
                [
                    "REJECTED_NEEDS_REVIEW_WITHOUT_INDEPENDENT_CORROBORATION",
                    "REJECTED_UNSTRUCTURED_OR_ARBITRARY_INDICATOR",
                    "REJECTED_INSUFFICIENT_CONFIDENCE_50.0_BELOW_85.0"
                ]
            )
        finally:
            db.close()


if __name__ == '__main__':
    unittest.main()
