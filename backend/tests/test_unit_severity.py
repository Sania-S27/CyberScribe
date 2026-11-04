import unittest
import sys
import os

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.services.triage import predict_threat_severity

class TestThreatSeverity(unittest.TestCase):
    def test_predict_threat_severity_heuristics(self):
        self.assertEqual(predict_threat_severity("Unauthenticated RCE in OpenSSH server allowing root access"), "critical")
        self.assertEqual(predict_threat_severity("Zero-day vulnerability actively exploited in the wild"), "critical")
        self.assertEqual(predict_threat_severity("Local privilege escalation via setuid binary"), "high")
        self.assertEqual(predict_threat_severity("SQL injection in authentication endpoint"), "high")
        self.assertEqual(predict_threat_severity("Denial of service via regex exponential backtracking"), "medium")
        self.assertEqual(predict_threat_severity("Minor styling inconsistency and banner grab"), "low")
        self.assertEqual(predict_threat_severity(""), "medium")

    def test_word_boundary_isolation(self):
        # "Windows Server" contains the substring "dos", but should not trigger denial of service (medium)
        # Instead, it should classify as low or whatever fits the actual context
        self.assertEqual(predict_threat_severity("Informational telemetry update on Windows Server 2022"), "low")
        self.assertEqual(predict_threat_severity("Denial of service crash in network daemon"), "medium")
        self.assertEqual(predict_threat_severity("Targeted DoS condition triggered by malformed packets"), "medium")

    def test_negation_handling(self):
        # Negated critical/high terms should not inflate severity
        self.assertEqual(predict_threat_severity("Audit report confirms host is not vulnerable to RCE or zero-day exploits"), "low")
        self.assertEqual(predict_threat_severity("Firmware update does not allow privilege escalation"), "low")
        self.assertEqual(predict_threat_severity("Configuration prevents any denial of service condition"), "low")
        self.assertEqual(predict_threat_severity("Component is not susceptible to sql injection attacks"), "low")

    def test_trusted_severity_preservation(self):
        # Trusted severity should always take precedence over heuristics
        self.assertEqual(predict_threat_severity("Critical RCE exploit in core", trusted_severity="low"), "low")
        self.assertEqual(predict_threat_severity("Minor banner grab", trusted_severity="critical"), "critical")
        self.assertEqual(predict_threat_severity("Informational log", trusted_severity="HIGH"), "high")
        # Empty or unknown trusted_severity falls back to heuristic triage
        self.assertEqual(predict_threat_severity("RCE in server", trusted_severity="unknown"), "critical")
        self.assertEqual(predict_threat_severity("RCE in server", trusted_severity=None), "critical")

if __name__ == '__main__':
    unittest.main()

