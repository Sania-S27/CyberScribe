import unittest
import sys
import os

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.schemas.analyst import ThreatAnalysisResult, MitreMapping
from app.agents.reporter import generate_stix_report

class TestStixReporter(unittest.TestCase):
    def test_stix_report_generation(self):
        analysis = ThreatAnalysisResult(
            title="OpenSSL Heap Overflow",
            summary="A buffer overflow vulnerability in OpenSSL certificate verification.",
            severity="high",
            cve_id="CVE-2026-0001",
            mitre_mappings=[
                MitreMapping(
                    technique_id="T1190",
                    technique_name="Exploit Public-Facing Application",
                    tactic="initial-access"
                )
            ]
        )

        bundle = generate_stix_report(analysis)
        bundle_dict = bundle.model_dump()

        self.assertEqual(bundle_dict["type"], "bundle")
        self.assertTrue(bundle_dict["id"].startswith("bundle--"))
        self.assertEqual(len(bundle_dict["objects"]), 2)

        vuln_obj = next(o for o in bundle_dict["objects"] if o["type"] == "vulnerability")
        self.assertEqual(vuln_obj["spec_version"], "2.1")
        self.assertEqual(vuln_obj["name"], "Threat Report: OpenSSL Heap Overflow")

        attack_obj = next(o for o in bundle_dict["objects"] if o["type"] == "attack-pattern")
        self.assertEqual(attack_obj["spec_version"], "2.1")
        self.assertEqual(attack_obj["external_references"][0]["external_id"], "T1190")

if __name__ == '__main__':
    unittest.main()
