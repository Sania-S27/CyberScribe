"""
Focused Authenticated Negative-Input Test Suite for Fedora Executor Daemon
-------------------------------------------------------------------------
Validates port 8088 endpoints (/apply, /verify, /rollback):
1. Unauthorized requests (missing token, invalid bearer token) are rejected with 401.
2. Malformed or non-JSON payloads are rejected with 400.
3. Oversized payloads (>64KB) are rejected with 400.
4. Bogon, loopback, private, link-local, multicast, broadcast, and reserved IPs are rejected with 400.
5. Protected DNS infrastructure IPs (8.8.8.8, 1.1.1.1, 9.9.9.9) are rejected with 400.
6. Shell injection and malformed action_ids are rejected with 400.
7. Disallowed HTTP methods (PUT, DELETE) return 405.
8. Malformed endpoints return 404.
9. Simulation mode guarantee: firewall state is never altered during any rejected call.

Note: Uses raw http.client.HTTPConnection so tests interact with the real port 8088
socket even under pytest environments where requests.post is globally mocked for SOAR tests.
"""

import os
import sys
import json
import time
import socket
import threading
import unittest
import http.client
from http.server import HTTPServer

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.services.fedora_executor.executor_daemon import (
    ExecutorRequestHandler,
    NftablesController
)


class TestFedoraExecutorPort8088NegativeInputs(unittest.TestCase):
    HOST = "127.0.0.1"
    PORT = 8088
    AUTH_TOKEN = "FEDORA_TEST_SECURE_BEARER_TOKEN_2026"

    @classmethod
    def setUpClass(cls):
        # Configure controller in strict dry_run / simulation mode (no live kernel changes)
        cls.controller = NftablesController(
            table_name="cyberscribe",
            dry_run=True,
            sudo=False
        )
        ExecutorRequestHandler.controller = cls.controller
        ExecutorRequestHandler.auth_token = cls.AUTH_TOKEN

        try:
            cls.server = HTTPServer((cls.HOST, cls.PORT), ExecutorRequestHandler)
        except OSError:
            # Port 8088 may be in use by the active Fedora VM or host port forwarding; fall back to an available port
            cls.server = HTTPServer((cls.HOST, 0), ExecutorRequestHandler)
            cls.PORT = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

        # Wait until port is responding
        for _ in range(30):
            try:
                with socket.create_connection((cls.HOST, cls.PORT), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=5)

    def _request(self, method: str, path: str, body=None, headers=None):
        req_headers = headers.copy() if headers else {}
        if body is not None and not isinstance(body, (str, bytes)):
            body = json.dumps(body)
            if "Content-Type" not in req_headers:
                req_headers["Content-Type"] = "application/json"

        conn = http.client.HTTPConnection(self.HOST, self.PORT, timeout=5)
        try:
            conn.request(method, path, body=body, headers=req_headers)
            resp = conn.getresponse()
            resp_body = resp.read().decode("utf-8")
            try:
                json_data = json.loads(resp_body)
            except Exception:
                json_data = {"raw": resp_body}
            return resp.status, json_data
        finally:
            conn.close()

    def _auth_headers(self, token=None):
        tok = token or self.AUTH_TOKEN
        return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}

    # -------------------------------------------------------------------------
    # 1. Unauthorized Access Tests (Missing, Empty, Invalid Token)
    # -------------------------------------------------------------------------

    def test_unauthorized_apply_rejected_401(self):
        # Missing auth header
        status, data = self._request(
            "POST",
            "/apply",
            body={"action_id": "act-neg-001", "ip_address": "185.220.101.5"}
        )
        self.assertEqual(status, 401)
        self.assertIn("Unauthorized", data.get("error", ""))

        # Wrong token
        status_bad, _ = self._request(
            "POST",
            "/apply",
            body={"action_id": "act-neg-001", "ip_address": "185.220.101.5"},
            headers=self._auth_headers(token="INVALID_TOKEN_9999")
        )
        self.assertEqual(status_bad, 401)

    def test_unauthorized_verify_rejected_401(self):
        status, _ = self._request("GET", "/verify/act-neg-001")
        self.assertEqual(status, 401)

        status_bad, _ = self._request(
            "GET",
            "/verify/act-neg-001",
            headers=self._auth_headers(token="INVALID_TOKEN_9999")
        )
        self.assertEqual(status_bad, 401)

    def test_unauthorized_rollback_rejected_401(self):
        status1, _ = self._request("POST", "/rollback/act-neg-001")
        self.assertEqual(status1, 401)

        status2, _ = self._request(
            "POST",
            "/rollback",
            body={"action_id": "act-neg-001"}
        )
        self.assertEqual(status2, 401)

    # -------------------------------------------------------------------------
    # 2. Malformed Body and Request Parsing Tests
    # -------------------------------------------------------------------------

    def test_apply_malformed_json_syntax_rejected_400(self):
        status, data = self._request(
            "POST",
            "/apply",
            body="{this is not valid json}",
            headers=self._auth_headers()
        )
        self.assertEqual(status, 400)
        self.assertIn("Malformed JSON body", data.get("error", ""))

    def test_apply_non_dict_json_rejected_400(self):
        status, data = self._request(
            "POST",
            "/apply",
            body=json.dumps(["item1", "item2"]),
            headers=self._auth_headers()
        )
        self.assertEqual(status, 400)
        self.assertIn("must be an object/dict", data.get("error", ""))

    def test_apply_oversized_payload_rejected_400(self):
        large_padding = "x" * 70000  # Exceeds 64 KB limit
        payload = json.dumps({"action_id": "act-neg-002", "ip_address": "185.220.101.5", "padding": large_padding})
        status, data = self._request(
            "POST",
            "/apply",
            body=payload,
            headers=self._auth_headers()
        )
        self.assertEqual(status, 400)
        self.assertIn("exceeds maximum size", data.get("error", ""))

    def test_apply_empty_body_rejected_400(self):
        status, data = self._request(
            "POST",
            "/apply",
            body="",
            headers=self._auth_headers()
        )
        self.assertEqual(status, 400)
        self.assertIn("action_id", data.get("error", ""))

    # -------------------------------------------------------------------------
    # 3. /apply Negative Input Tests (IP Validation & Bogon Defense)
    # -------------------------------------------------------------------------

    def test_apply_missing_required_fields_rejected_400(self):
        # Missing ip_address
        status1, data1 = self._request(
            "POST",
            "/apply",
            body={"action_id": "act-neg-003"},
            headers=self._auth_headers()
        )
        self.assertEqual(status1, 400)
        self.assertIn("ip_address", data1.get("error", ""))

        # Missing action_id
        status2, data2 = self._request(
            "POST",
            "/apply",
            body={"ip_address": "185.220.101.5"},
            headers=self._auth_headers()
        )
        self.assertEqual(status2, 400)
        self.assertIn("action_id", data2.get("error", ""))

    def test_apply_bogons_private_and_loopback_ips_rejected_400(self):
        dangerous_ips = [
            "127.0.0.1",       # Loopback
            "10.0.0.1",        # RFC 1918 Private
            "192.168.1.1",     # RFC 1918 Private
            "172.16.5.10",     # RFC 1918 Private
            "169.254.1.1",     # Link-local
            "224.0.0.1",       # Multicast
            "240.0.0.1",       # Reserved
            "255.255.255.255", # Broadcast
            "0.0.0.0",         # Unspecified
            "192.0.2.1",       # TEST-NET-1 (RFC 5737)
            "198.51.100.1",    # TEST-NET-2 (RFC 5737)
            "203.0.113.1",     # TEST-NET-3 (RFC 5737)
            "198.18.0.1",      # Benchmarking (RFC 2544)
            "100.64.0.1",      # Shared Address Space / CGNAT (RFC 6598)
        ]
        for bad_ip in dangerous_ips:
            with self.subTest(bad_ip=bad_ip):
                status, data = self._request(
                    "POST",
                    "/apply",
                    body={"action_id": "act-neg-bogon", "ip_address": bad_ip},
                    headers=self._auth_headers()
                )
                self.assertEqual(status, 400, f"Expected 400 for dangerous IP {bad_ip}")
                self.assertEqual(data.get("status"), "FAILED")

    def test_apply_protected_dns_infrastructure_rejected_400(self):
        dns_ips = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]
        for dns_ip in dns_ips:
            with self.subTest(dns_ip=dns_ip):
                status, data = self._request(
                    "POST",
                    "/apply",
                    body={"action_id": "act-neg-dns", "ip_address": dns_ip},
                    headers=self._auth_headers()
                )
                self.assertEqual(status, 400, f"Expected 400 for protected DNS {dns_ip}")
                self.assertIn("protected", data.get("error", "").lower())

    def test_apply_malformed_ip_strings_rejected_400(self):
        malformed = ["not-an-ip", "999.999.999.999", "185.220.101.5/24", "2001:db8::1"]
        for bad in malformed:
            with self.subTest(bad=bad):
                status, _ = self._request(
                    "POST",
                    "/apply",
                    body={"action_id": "act-neg-malform", "ip_address": bad},
                    headers=self._auth_headers()
                )
                self.assertEqual(status, 400)

    def test_apply_shell_injection_action_id_rejected_400(self):
        injection_ids = [
            "act-1; rm -rf /",
            "act-$(whoami)",
            "act-`id`",
            "act with spaces",
            "a" * 80,  # exceeds 64 chars
            ""
        ]
        for bad_id in injection_ids:
            with self.subTest(bad_id=bad_id):
                status, _ = self._request(
                    "POST",
                    "/apply",
                    body={"action_id": bad_id, "ip_address": "185.220.101.5"},
                    headers=self._auth_headers()
                )
                self.assertEqual(status, 400)

    def test_apply_invalid_direction_rejected_400(self):
        status, data = self._request(
            "POST",
            "/apply",
            body={"action_id": "act-neg-dir", "ip_address": "185.220.101.5", "direction": "invalid_direction"},
            headers=self._auth_headers()
        )
        self.assertEqual(status, 400)
        self.assertIn("direction", data.get("error", "").lower())

    # -------------------------------------------------------------------------
    # 4. /verify Negative Input Tests
    # -------------------------------------------------------------------------

    def test_verify_malformed_action_id_in_path_rejected_404(self):
        malformed_paths = [
            "/verify/../etc/passwd",
            "/verify/act-1;cat",
            "/verify/act%20space",
            "/verify/"
        ]
        for path in malformed_paths:
            with self.subTest(path=path):
                status, _ = self._request("GET", path, headers=self._auth_headers())
                self.assertIn(status, [400, 404])

    # -------------------------------------------------------------------------
    # 5. /rollback Negative Input Tests
    # -------------------------------------------------------------------------

    def test_rollback_missing_or_malformed_action_id_rejected_400_or_404(self):
        # Empty json body to /rollback
        status1, _ = self._request("POST", "/rollback", body={}, headers=self._auth_headers())
        self.assertEqual(status1, 400)

        # Malformed action_id in body
        status2, _ = self._request(
            "POST",
            "/rollback",
            body={"action_id": "; drop table"},
            headers=self._auth_headers()
        )
        self.assertEqual(status2, 400)

        # Malformed action_id in URL path
        status3, _ = self._request("POST", "/rollback/;;malformed", headers=self._auth_headers())
        self.assertEqual(status3, 404)

    # -------------------------------------------------------------------------
    # 6. Disallowed Methods & Firewall State Preservation
    # -------------------------------------------------------------------------

    def test_disallowed_http_methods_return_405(self):
        status_put, _ = self._request("PUT", "/apply", headers=self._auth_headers())
        self.assertEqual(status_put, 405)

        status_del, _ = self._request("DELETE", "/apply", headers=self._auth_headers())
        self.assertEqual(status_del, 405)

    def test_firewall_state_unchanged_after_negative_tests(self):
        """
        Confirms that across all negative, malformed, and unauthorized tests,
        zero live firewall rules were created or changed.
        """
        rules = self.controller.list_managed_rules()
        self.assertEqual(rules, [], "Expected zero firewall rules to be altered or active.")
