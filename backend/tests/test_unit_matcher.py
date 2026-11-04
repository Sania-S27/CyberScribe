import unittest
import sys
import os

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.services.osint_collector import clean_package_name, check_threat_match_for_tenant
from app.services.version_matcher import evaluate_version_applicability, extract_version_constraints

class TestThreatMatcher(unittest.TestCase):
    def test_clean_package_name(self):
        self.assertEqual(clean_package_name("FastAPI==0.110.0"), ("fastapi", "0.110.0"))
        self.assertEqual(clean_package_name("docker>=24.0.5"), ("docker", "24.0.5"))
        self.assertEqual(clean_package_name("psycopg2-binary~=2.9.9"), ("psycopg2-binary", "2.9.9"))
        self.assertEqual(clean_package_name("cryptography[bcrypt]>=42.0.0"), ("cryptography", "42.0.0"))
        self.assertEqual(clean_package_name("nginx:1.24"), ("nginx", "1.24"))
        self.assertEqual(clean_package_name("redis"), ("redis", None))
        self.assertEqual(clean_package_name("react 19.2.0"), ("react", "19.2.0"))

    def test_extract_version_constraints(self):
        c1 = extract_version_constraints("FastAPI < 0.65.0 is vulnerable", "fastapi")
        self.assertIn("< 0.65.0", c1)
        
        c2 = extract_version_constraints("Uvicorn before 0.11.7 allows response splitting", "uvicorn")
        self.assertIn("< 0.11.7", c2)

        c3 = extract_version_constraints("python-jose through 3.3.0 has algorithm confusion", "python-jose")
        self.assertIn("<= 3.3.0", c3)

        c4 = extract_version_constraints("SQLAlchemy before 1.2.19 and 1.3.x before 1.3.0", "sqlalchemy")
        self.assertTrue(any("< 1.2.19" in c or "< 1.3.0" in c for c in c4))

    def test_threat_matching_affected(self):
        # Installed 0.60.0 is affected by < 0.65.0
        tech_stack = "fastapi:0.60.0, uvicorn:0.38.0"
        is_match, conf, reason = check_threat_match_for_tenant(
            threat_title="FastAPI CSRF vulnerability",
            threat_summary="FastAPI versions lower than 0.65.2 that used cookies for authentication were vulnerable.",
            tenant_tech_stack=tech_stack
        )
        self.assertTrue(is_match)
        self.assertGreaterEqual(conf, 90.0)
        self.assertIn("[AFFECTED]", reason)

    def test_threat_matching_not_affected(self):
        # Installed 0.120.1 is safe from < 0.65.2
        tech_stack = "fastapi:0.120.1, sqlalchemy:2.0.44"
        is_match, conf, reason = check_threat_match_for_tenant(
            threat_title="FastAPI CSRF vulnerability",
            threat_summary="FastAPI versions lower than 0.65.2 that used cookies for authentication were vulnerable.",
            tenant_tech_stack=tech_stack
        )
        self.assertFalse(is_match)
        self.assertEqual(conf, 0.0)

    def test_threat_matching_needs_review(self):
        # Unpinned or advisory without explicit bounds
        tech_stack = "thefuzz:latest"
        is_match, conf, reason = check_threat_match_for_tenant(
            threat_title="Vulnerability in thefuzz",
            threat_summary="Memory corruption in fuzzy string comparison algorithms.",
            tenant_tech_stack=tech_stack
        )
        self.assertTrue(is_match)
        self.assertIn("[NEEDS REVIEW]", reason)

    def test_cross_package_isolation_prevents_false_positives(self):
        # Threat is for 'Search Guard' with bcrypt mentioned in passing
        text = "Search Guard versions before 23.1 had an issue that an administrative user is able to retrieve bcrypt password hashes."
        constraints = extract_version_constraints(text, "bcrypt")
        self.assertEqual(constraints, [], "Should not attribute Search Guard's version constraint to bcrypt")
        
        # Threat is for 'cbor2' with uvicorn mentioned in title
        text_cbor = "cbor2 provides encoding for CBOR. Versions prior to 5.9.0 are vulnerable to DoS."
        constraints_uv = extract_version_constraints(text_cbor, "uvicorn")
        self.assertEqual(constraints_uv, [], "Should not attribute cbor2's version constraint to uvicorn")

    def test_compound_package_name_prefix_isolation(self):
        # Threat is for 'SQLAlchemyDA', installed package is core 'sqlalchemy'
        text_sda = "SQLAlchemyDA is a generic database adapter. Versions prior to 2.2 allow SQL injection."
        constraints_sqla = extract_version_constraints(text_sda, "sqlalchemy")
        self.assertEqual(constraints_sqla, [], "Should not match SQLAlchemyDA as core sqlalchemy")

if __name__ == '__main__':
    unittest.main()
