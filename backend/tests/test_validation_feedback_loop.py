import unittest
from unittest.mock import patch
from app.schemas.analyst import ThreatAnalysisResult, MitreMapping
from app.agents.validator import verify_claims_against_evidence, validate_threat_analysis
from app.agents.orchestrator import cyber_scribe_orchestrator, should_continue
from app.agents.reporter import generate_stix_report
from app.agents.mitigation import generate_soar_playbook

class TestValidationFeedbackLoop(unittest.TestCase):
    """Targeted test suite for Milestone 2: Multi-Agent Validation Feedback Loop."""

    def test_verify_claims_flags_unsupported_cve(self):
        """Claims containing a CVE not supported by the raw evidence must fail validation."""
        raw_evidence = "Advisory: A security vulnerability was discovered in Nginx server."
        claims = {
            "title": "Nginx Remote Code Execution",
            "cve_id": "CVE-2023-99999", # Hallucinated CVE not in text
            "affected_products": ["Nginx"],
            "affected_versions": ["1.18.0"],
            "supporting_evidence": ["Remote code execution flaw"]
        }
        errors, corrections = verify_claims_against_evidence(raw_evidence, claims)
        self.assertGreaterEqual(len(errors), 1)
        self.assertTrue(any("CVE-2023-99999" in err for err in errors))
        self.assertGreaterEqual(len(corrections), 1)

    def test_verify_claims_flags_product_identity_mismatch(self):
        """SQLAlchemyDA must not be confused with core sqlalchemy."""
        raw_evidence = "Advisory for Products.SQLAlchemyDA versions 0.6.0 through 0.6.1. Relates to Zope DA."
        claims = {
            "title": "SQLAlchemy Vulnerability",
            "cve_id": None,
            "affected_products": ["sqlalchemy"], # False attribution to core sqlalchemy
            "affected_versions": ["0.6.0"],
            "supporting_evidence": ["Products.SQLAlchemyDA"]
        }
        errors, corrections = verify_claims_against_evidence(raw_evidence, claims)
        self.assertGreaterEqual(len(errors), 1)
        self.assertTrue(any("SQLAlchemyDA" in err or "product identity mismatch" in err for err in errors))
        self.assertGreaterEqual(len(corrections), 1)

    def test_verify_claims_passes_grounded_claims(self):
        """Claims strictly supported by the raw text must pass verification."""
        raw_evidence = "CVE-2021-41773 affects Apache HTTP Server 2.4.49 and allows path traversal."
        claims = {
            "title": "Apache HTTP Server Path Traversal",
            "cve_id": "CVE-2021-41773",
            "affected_products": ["Apache HTTP Server"],
            "affected_versions": ["2.4.49"],
            "supporting_evidence": ["allows path traversal"]
        }
        errors, corrections = verify_claims_against_evidence(raw_evidence, claims)
        self.assertEqual(len(errors), 0)

    def test_validator_returns_reasons_and_instructions_on_failure(self):
        """When validation fails before max retries, validator returns reasons and correction instructions."""
        draft = {
            "title": "SQLAlchemy RCE",
            "summary": "Critical vulnerability in sqlalchemy",
            "cve_id": "CVE-2099-0001",
            "severity": "critical",
            "affected_products": ["sqlalchemy"],
            "affected_versions": ["2.0.44"],
            "supporting_evidence": ["Advisory mentions Products.SQLAlchemyDA"],
            "mitre_mappings": []
        }
        raw_text = "Products.SQLAlchemyDA 0.6.0 vulnerability disclosed."
        
        result = validate_threat_analysis(raw_text, draft, iteration=1, max_retries=2)
        
        self.assertEqual(result.get("validation_status"), "FAILED")
        self.assertIn("validation_errors", result)
        self.assertGreaterEqual(len(result["validation_errors"]), 1)
        self.assertIn("revision_instructions", result)
        self.assertTrue(len(result["revision_instructions"]) > 0)
        self.assertTrue(
            "SQLAlchemyDA" in result["revision_instructions"] or 
            "CVE-2099-0001" in result["revision_instructions"]
        )

    def test_validator_enforces_needs_review_when_retries_exhausted(self):
        """When retries are exhausted (iteration >= max_retries), validator marks finding as NEEDS_REVIEW."""
        draft = {
            "title": "Unverified Exploit Claim",
            "summary": "Unconfirmed zero day in proprietary component",
            "cve_id": "CVE-2099-9999",
            "severity": "critical",
            "affected_products": ["UnknownWidget"],
            "affected_versions": ["9.9.9"],
            "supporting_evidence": [],
            "mitre_mappings": []
        }
        raw_text = "Vague rumor on forum with no official advisory or confirmed CVE."
        
        result = validate_threat_analysis(raw_text, draft, iteration=2, max_retries=2)
        
        self.assertEqual(result.get("validation_status"), "NEEDS_REVIEW")
        self.assertEqual(result.get("assessment_outcome"), "NEEDS_REVIEW")
        self.assertTrue(result.get("title", "").startswith("[NEEDS REVIEW]"))
        # Hallucinated CVE must be stripped on safe fallback
        self.assertIsNone(result.get("cve_id"))

    def test_orchestrator_routes_to_analyst_on_failure(self):
        """Conditional edge should_continue routes back to Security Analyst Agent on failure within retry limits."""
        state = {
            "iteration": 1,
            "max_retries": 2,
            "validation_status": "FAILED",
            "analyst_draft": {"validation_status": "FAILED"}
        }
        next_node = should_continue(state)
        self.assertEqual(next_node, "Security Analyst Agent")

    def test_orchestrator_terminates_to_tech_writer_on_needs_review(self):
        """Conditional edge should_continue routes to Tech Writer Agent when status is NEEDS_REVIEW."""
        state = {
            "iteration": 2,
            "max_retries": 2,
            "validation_status": "NEEDS_REVIEW",
            "analyst_draft": {"validation_status": "NEEDS_REVIEW"}
        }
        next_node = should_continue(state)
        self.assertEqual(next_node, "Tech Writer Agent")

    def test_orchestrator_terminates_to_tech_writer_on_pass(self):
        """Conditional edge should_continue routes to Tech Writer Agent when validation passes."""
        state = {
            "iteration": 1,
            "max_retries": 2,
            "validation_status": "PASSED",
            "analyst_draft": {"validation_status": "PASSED"}
        }
        next_node = should_continue(state)
        self.assertEqual(next_node, "Tech Writer Agent")

    def test_orchestrator_feedback_loop_revision_cycle(self):
        """Orchestrator invokes Analyst revision and reaches completion."""
        # Initial draft with hallucinated CVE
        draft_iter1 = {
            "title": "Advisory Claim",
            "summary": "Flaw in Apache 2.4.49",
            "severity": "high",
            "cve_id": "CVE-9999-0000", # unevidenced
            "affected_products": ["Apache HTTP Server"],
            "affected_versions": ["2.4.49"],
            "supporting_evidence": ["Apache 2.4.49 path traversal"],
            "mitre_mappings": []
        }
        # Revised draft fixing the CVE
        draft_iter2 = {
            "title": "Advisory Claim",
            "summary": "Flaw in Apache 2.4.49",
            "severity": "high",
            "cve_id": "CVE-2021-41773", # grounded
            "affected_products": ["Apache HTTP Server"],
            "affected_versions": ["2.4.49"],
            "supporting_evidence": ["CVE-2021-41773 Apache 2.4.49 path traversal"],
            "mitre_mappings": []
        }

        call_count = {"analyst": 0}
        def mock_analyst_func(*args, **kwargs):
            call_count["analyst"] += 1
            return draft_iter1

        def mock_revise_func(*args, **kwargs):
            call_count["analyst"] += 1
            return draft_iter2

        raw_text = "CVE-2021-41773 affects Apache HTTP Server 2.4.49"

        with patch("app.agents.orchestrator.analyze_threat_with_llm", side_effect=mock_analyst_func), \
             patch("app.agents.orchestrator.revise_threat_analysis_with_llm", side_effect=mock_revise_func):
            
            result = cyber_scribe_orchestrator.invoke({"raw_text": raw_text})
            
            self.assertIn("final_report", result)
            self.assertEqual(result["final_report"]["validation_status"], "PASSED")
            self.assertEqual(result["final_report"]["cve_id"], "CVE-2021-41773")
            self.assertIn("stix_bundle", result)
            # Confirms feedback loop ran (initial analyst call + at least 1 revision call)
            self.assertGreaterEqual(call_count["analyst"], 2)

    def test_reporter_preserves_uncertainty_for_needs_review(self):
        """Reporter marks STIX bundle as uncertain and unverified when assessment is NEEDS_REVIEW."""
        needs_review_obj = ThreatAnalysisResult(
            title="[NEEDS REVIEW] Unconfirmed Zero Day",
            summary="Rumor of vulnerability without proof",
            severity="medium",
            assessment_outcome="NEEDS_REVIEW",
            validation_status="NEEDS_REVIEW",
            mitre_mappings=[
                MitreMapping(
                    technique_id="T1190",
                    technique_name="Exploit Public-Facing Application",
                    tactic="initial-access",
                    confidence=0.95 # Higher confidence should be capped
                )
            ]
        )
        stix = generate_stix_report(needs_review_obj)
        stix_dict = stix.model_dump()
        
        objects = stix_dict.get("objects", [])
        vuln_objs = [o for o in objects if o.get("type") == "vulnerability"]
        attack_patterns = [o for o in objects if o.get("type") == "attack-pattern"]

        self.assertTrue(len(vuln_objs) > 0)
        self.assertIn("[NEEDS REVIEW]", vuln_objs[0].get("name", ""))
        self.assertIn("[UNCERTAIN FINDING - NEEDS SOC REVIEW]", vuln_objs[0].get("description", ""))

        if attack_patterns:
            desc = attack_patterns[0].get("description", "")
            self.assertIn("Status: unverified", desc)
            self.assertIn("Confidence: 0.50", desc)

    def test_mitigation_refuses_automated_containment_for_needs_review(self):
        """Mitigation agent produces zero firewall rules and no IOC blocks for NEEDS_REVIEW findings."""
        playbook = generate_soar_playbook(
            threat_title="[NEEDS REVIEW] Disputed Package Vulnerability",
            summary="Potential name confusion with SQLAlchemyDA",
            assessment_outcome="NEEDS_REVIEW",
            matched_component="sqlalchemy"
        )
        self.assertEqual(playbook["firewall_rules"], [])
        self.assertEqual(playbook["iocs"], {"ip_addresses": []})
        self.assertIn("Manual verification required", playbook["recommended_action"])

if __name__ == "__main__":
    unittest.main()
