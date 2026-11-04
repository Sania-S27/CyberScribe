# backend/tests/test_unit_mitre.py
import unittest
import sys
import os
from unittest.mock import patch, MagicMock

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.services.mitre_service import (
    get_technique,
    is_valid_active_technique,
    find_candidate_techniques_for_threat,
    validate_and_ground_mitre_mappings,
    get_dataset_metadata,
    load_mitre_knowledge_base
)
from app.schemas.analyst import ThreatAnalysisResult, MitreMapping
from app.agents.reporter import generate_stix_report
from app.agents.validator import validate_threat_analysis

class TestMitreAttackMapping(unittest.TestCase):
    def setUp(self):
        # Ensure knowledge base is loaded
        load_mitre_knowledge_base()

    def test_official_dataset_metadata(self):
        """Test dataset metadata contains official STIX versioning and provenance."""
        meta = get_dataset_metadata()
        self.assertIn("dataset_name", meta)
        self.assertEqual(meta["dataset_name"], "MITRE ATT&CK Enterprise")
        self.assertIn("v16.1", meta["dataset_version"])
        self.assertIn("github.com/mitre-attack/attack-stix-data", meta["source_url"])

    def test_valid_technique_id_and_authoritative_name(self):
        """Test retrieving valid technique returns authoritative official name and tactic."""
        # T1059: Command and Scripting Interpreter
        t1059 = get_technique("T1059")
        self.assertIsNotNone(t1059)
        self.assertEqual(t1059["technique_id"], "T1059")
        self.assertEqual(t1059["name"], "Command and Scripting Interpreter")
        self.assertEqual(t1059["primary_tactic"], "execution")
        self.assertFalse(t1059["is_revoked"])
        self.assertFalse(t1059["is_deprecated"])

        # T1190: Exploit Public-Facing Application
        t1190 = get_technique("T1190")
        self.assertIsNotNone(t1190)
        self.assertEqual(t1190["name"], "Exploit Public-Facing Application")
        self.assertEqual(t1190["primary_tactic"], "initial-access")

    def test_invented_or_hallucinated_technique_id(self):
        """Test that fake or invented technique IDs (e.g. T9999) are strictly rejected."""
        self.assertFalse(is_valid_active_technique("T9999"))
        self.assertFalse(is_valid_active_technique("T0000"))
        self.assertFalse(is_valid_active_technique("INVALID_ID"))
        self.assertIsNone(get_technique("T9999"))

        raw_text = "Attacker exploited remote code execution vulnerability in web application."
        proposed = [{"technique_id": "T9999", "technique_name": "Fake Exploit Technique", "tactic": "initial-access"}]
        grounded = validate_and_ground_mitre_mappings(raw_text, proposed)
        self.assertEqual(len(grounded), 0, "Invented technique IDs must be completely discarded.")

    def test_valid_id_with_incorrect_llm_name(self):
        """Test that when an LLM supplies a valid ID but a hallucinated name, the authoritative name is restored."""
        raw_text = "The attacker used command injection in bash to execute arbitrary shell commands."
        proposed = [{
            "technique_id": "T1059",
            "technique_name": "Hallucinated Custom Shell Script Exploit",  # Wrong name
            "tactic": "privilege-escalation"  # Wrong tactic
        }]
        grounded = validate_and_ground_mitre_mappings(raw_text, proposed)
        self.assertEqual(len(grounded), 1)
        # Must be corrected to official MITRE Enterprise name and tactic
        self.assertEqual(grounded[0]["technique_id"], "T1059")
        self.assertEqual(grounded[0]["technique_name"], "Command and Scripting Interpreter")
        self.assertEqual(grounded[0]["tactic"], "execution")
        self.assertEqual(grounded[0]["validation_status"], "confirmed")
        self.assertGreaterEqual(grounded[0]["confidence"], 0.85)

    def test_revoked_or_deprecated_technique_rejected(self):
        """Test that revoked and deprecated techniques are filtered out of active mappings."""
        # T1086 (PowerShell) is revoked in favor of T1059.001
        revoked_item = get_technique("T1086", allow_deprecated_or_revoked=True)
        if revoked_item:
            self.assertTrue(revoked_item["is_revoked"] or revoked_item["is_deprecated"])
            # Should be rejected when active techniques only are queried
            self.assertFalse(is_valid_active_technique("T1086"))

            raw_text = "Attacker ran PowerShell script to execute commands."
            proposed = [{"technique_id": "T1086", "technique_name": "PowerShell"}]
            grounded = validate_and_ground_mitre_mappings(raw_text, proposed)
            self.assertEqual(len(grounded), 0, "Revoked techniques must not be accepted.")

    def test_unsupported_mapping_with_insufficient_evidence(self):
        """Test that candidate techniques lacking technical evidence in raw advisory are discarded."""
        # Advisory discusses a denial of service memory leak with no remote execution or credential theft
        raw_text = "A memory leak in the parser causes denial of service when processing large files."
        proposed = [
            {"technique_id": "T1003", "technique_name": "OS Credential Dumping"},  # No evidence
            {"technique_id": "T1078", "technique_name": "Valid Accounts"}           # No evidence
        ]
        grounded = validate_and_ground_mitre_mappings(raw_text, proposed)
        self.assertEqual(len(grounded), 0, "Mappings lacking technical evidence must be discarded.")

    def test_pure_vulnerability_advisory_produces_no_mapping(self):
        """Test that a pure software defect or CVE announcement without adversary behavior produces empty mappings."""
        raw_text = "CVE-2026-1234: Null pointer dereference in libfoo when parsing malformed headers."
        candidates = find_candidate_techniques_for_threat(raw_text)
        self.assertEqual(len(candidates), 0, "Pure software defect without adversary behavior must not map to ATT&CK.")

        grounded = validate_and_ground_mitre_mappings(raw_text, [{"technique_id": "T1059"}])
        self.assertEqual(len(grounded), 0)

    def test_safe_error_handling_on_dataset_missing(self):
        """Test fallback behavior when dataset index fails to load."""
        with patch("app.services.mitre_service.TECHNIQUES_FILE") as mock_file:
            mock_file.exists.return_value = False
            with patch("app.services.mitre_service._TECHNIQUES_CACHE", None):
                kb = load_mitre_knowledge_base()
                self.assertEqual(kb, {})
                tech = get_technique("T1059")
                self.assertIsNone(tech)

    def test_regression_stix_export_with_mitre_mappings(self):
        """Regression test ensuring STIX 2.1 report generation produces compliant AttackPattern objects."""
        mapping = MitreMapping(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            evidence="Technical advisory indicates: 'remote code execution'",
            confidence=0.95,
            validation_status="confirmed"
        )
        analysis = ThreatAnalysisResult(
            title="Spring Framework Remote Code Execution",
            summary="Unauthenticated attacker can exploit Spring MVC endpoint to achieve remote code execution.",
            severity="critical",
            cve_id="CVE-2022-22965",
            mitre_mappings=[mapping]
        )

        stix_bundle = generate_stix_report(analysis)
        bundle_dict = stix_bundle.model_dump()
        self.assertIn("objects", bundle_dict)

        objects = bundle_dict["objects"]
        attack_patterns = [o for o in objects if o.get("type") == "attack-pattern"]
        self.assertEqual(len(attack_patterns), 1)

        ap = attack_patterns[0]
        self.assertEqual(ap["name"], "Exploit Public-Facing Application")
        self.assertIn("initial-access", ap["description"])
        self.assertIn("Confidence: 0.95", ap["description"])
        self.assertEqual(len(ap["external_references"]), 1)
        self.assertEqual(ap["external_references"][0]["external_id"], "T1190")
        self.assertEqual(ap["external_references"][0]["url"], "https://attack.mitre.org/techniques/T1190")

    def test_curated_evaluation_benchmark(self):
        """
        Curated Evaluation Benchmark:
        Evaluates precision and recall across representative ground-truth security advisories.
        """
        test_cases = [
            {
                "name": "Web RCE Advisory",
                "text": "Critical vulnerability allows unauthenticated remote code execution via exploit of public-facing web server endpoint.",
                "expected_techniques": {"T1190"}
            },
            {
                "name": "Command Injection Advisory",
                "text": "Vulnerability allows command injection allowing attacker to execute arbitrary bash shell commands.",
                "expected_techniques": {"T1059"}
            },
            {
                "name": "Client Document Exploit",
                "text": "Buffer overflow in client application allows exploitation for client execution via malicious attachment.",
                "expected_techniques": {"T1203", "T1566"}
            },
            {
                "name": "Local Privilege Escalation",
                "text": "Kernel flaw allows local privilege escalation from unprivileged user to root system privileges.",
                "expected_techniques": {"T1068"}
            },
            {
                "name": "Web Shell Persistence",
                "text": "Threat actors deploy web shell for persistent backdoor access to compromised server.",
                "expected_techniques": {"T1505.003"}
            },
            {
                "name": "Ransomware Encryption",
                "text": "Ransomware payload encrypts user files and deletes shadow copies for impact.",
                "expected_techniques": {"T1486"}
            },
            {
                "name": "Benign Config Flaw (No adversary behavior)",
                "text": "Documentation error in example configuration file causes syntax warning on startup.",
                "expected_techniques": set()
            }
        ]

        total_true_positives = 0
        total_false_positives = 0
        total_false_negatives = 0

        for tc in test_cases:
            candidates = find_candidate_techniques_for_threat(tc["text"])
            mapped_ids = {c["technique_id"] for c in candidates}
            
            ground_truth = tc["expected_techniques"]
            
            tp = len(mapped_ids.intersection(ground_truth))
            fp = len(mapped_ids - ground_truth)
            fn = len(ground_truth - mapped_ids)

            total_true_positives += tp
            total_false_positives += fp
            total_false_negatives += fn

        precision = total_true_positives / (total_true_positives + total_false_positives) if (total_true_positives + total_false_positives) > 0 else 1.0
        recall = total_true_positives / (total_true_positives + total_false_negatives) if (total_true_positives + total_false_negatives) > 0 else 1.0

        print(f"\n[MITRE Evaluation Benchmark Results]")
        print(f"  - Test Cases: {len(test_cases)}")
        print(f"  - True Positives: {total_true_positives}")
        print(f"  - False Positives: {total_false_positives}")
        print(f"  - False Negatives: {total_false_negatives}")
        print(f"  - Precision: {precision * 100:.1f}%")
        print(f"  - Recall: {recall * 100:.1f}%")

        self.assertGreaterEqual(precision, 0.85, "Precision on curated benchmark should exceed 85%")
        self.assertGreaterEqual(recall, 0.85, "Recall on curated benchmark should exceed 85%")

if __name__ == '__main__':
    unittest.main()
