# backend/tests/test_admin_containment_controls.py
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    from tests.base import BaseTestCase
except ImportError:
    from base import BaseTestCase

from app import models


class TestAdminContainmentControls(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.mock_sweep_patcher = patch("app.services.osint_collector.run_sync_sweep")
        self.mock_sweep = self.mock_sweep_patcher.start()

    def tearDown(self):
        self.mock_sweep_patcher.stop()
        super().tearDown()

    def test_admin_trigger_requires_super_admin(self):
        """Tenant users and unauthenticated requests must be rejected from triggering containment."""
        payload = {
            "target_ip": "192.168.56.101",
            "target_port": 8000,
            "direction": "inbound",
            "protocol": "tcp"
        }

        # 1. Unauthenticated request
        res_unauth = self.client.post("/admin/containment/actions/trigger", json=payload)
        self.assertEqual(res_unauth.status_code, 401)

        # 2. Tenant user request
        res_user = self.client.post(
            "/admin/containment/actions/trigger",
            json=payload,
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        self.assertEqual(res_user.status_code, 403)

    def test_admin_trigger_invalid_direction(self):
        """Safety restriction: Only inbound containment is permitted for live demo."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        payload = {
            "target_ip": "192.168.56.101",
            "target_port": 8000,
            "direction": "outbound",
            "protocol": "tcp"
        }
        res = self.client.post("/admin/containment/actions/trigger", json=payload, headers=headers)
        self.assertEqual(res.status_code, 400)
        self.assertIn("Safety restriction: Invalid direction", res.json().get("detail", ""))

    def test_admin_trigger_invalid_protocol(self):
        """Safety restriction: Only TCP protocol is permitted."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        payload = {
            "target_ip": "192.168.56.101",
            "target_port": 8000,
            "direction": "inbound",
            "protocol": "udp"
        }
        res = self.client.post("/admin/containment/actions/trigger", json=payload, headers=headers)
        self.assertEqual(res.status_code, 400)
        self.assertIn("Safety restriction: Invalid protocol", res.json().get("detail", ""))

    def test_admin_trigger_invalid_port(self):
        """Safety restriction: Only target port 8000 (Campus Guide) is permitted."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        payload = {
            "target_ip": "192.168.56.101",
            "target_port": 22,
            "direction": "inbound",
            "protocol": "tcp"
        }
        res = self.client.post("/admin/containment/actions/trigger", json=payload, headers=headers)
        self.assertEqual(res.status_code, 400)
        self.assertIn("Safety restriction: Invalid target port", res.json().get("detail", ""))

    def test_admin_trigger_invalid_ip_addresses(self):
        """Malformed, loopback, and broadcast IP addresses must be rejected."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        bad_ips = [
            "not-an-ip",
            "127.0.0.1",
            "255.255.255.255",
            "0.0.0.0"
        ]

        for bad_ip in bad_ips:
            with self.subTest(ip=bad_ip):
                payload = {
                    "target_ip": bad_ip,
                    "target_port": 8000,
                    "direction": "inbound",
                    "protocol": "tcp"
                }
                res = self.client.post("/admin/containment/actions/trigger", json=payload, headers=headers)
                self.assertEqual(res.status_code, 400)

    @patch.dict(os.environ, {"CONTAINMENT_ADAPTER_MODE": "windows_firewall", "ALLOW_LAB_FEDORA_HOST_CONTAINMENT": "false"})
    def test_admin_trigger_live_mode_rejected_when_not_authorized(self):
        """In live mode, trigger without lab authorization flag enabled must be rejected."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        payload = {
            "target_ip": "192.168.56.101",
            "target_port": 8000,
            "direction": "inbound",
            "protocol": "tcp"
        }
        res = self.client.post("/admin/containment/actions/trigger", json=payload, headers=headers)
        self.assertEqual(res.status_code, 403)
        self.assertIn("ALLOW_LAB_FEDORA_HOST_CONTAINMENT", res.json().get("detail", ""))

    @patch.dict(os.environ, {"CONTAINMENT_ADAPTER_MODE": "windows_firewall", "ALLOW_LAB_FEDORA_HOST_CONTAINMENT": "true"})
    def test_admin_trigger_live_mode_rejected_unauthorized_ip(self):
        """In live mode, arbitrary IPs other than 192.168.56.101 must be rejected."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        payload = {
            "target_ip": "10.0.0.5",
            "target_port": 8000,
            "direction": "inbound",
            "protocol": "tcp"
        }
        res = self.client.post("/admin/containment/actions/trigger", json=payload, headers=headers)
        self.assertEqual(res.status_code, 400)
        self.assertIn("strictly limited to authorized lab target", res.json().get("detail", ""))

    def test_admin_trigger_successful_simulation_and_duplicate_prevention(self):
        """Valid trigger creates ContainmentAction and prevents duplicate submissions."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        payload = {
            "target_ip": "192.168.56.101",
            "target_port": 8000,
            "direction": "inbound",
            "protocol": "tcp",
            "reason": "Automated regression test demo containment"
        }

        # 1. First trigger execution
        res1 = self.client.post("/admin/containment/actions/trigger", json=payload, headers=headers)
        self.assertEqual(res1.status_code, 200)
        data1 = res1.json()
        self.assertIn("action_id", data1)
        self.assertEqual(data1["target_ip"], "192.168.56.101")
        self.assertEqual(data1["target_port"], 8000)
        self.assertEqual(data1["status"], "SIMULATED")

        # Verify action exists in DB with audit log
        action = self.db.query(models.ContainmentAction).filter_by(action_id=data1["action_id"]).first()
        self.assertIsNotNone(action)
        self.assertEqual(action.status, "SIMULATED")
        self.assertEqual(action.indicator_value, "192.168.56.101")

        audit_logs = self.db.query(models.ContainmentAuditLog).filter_by(action_id=action.id).all()
        self.assertGreater(len(audit_logs), 0)

        # 2. Duplicate submission attempt while active -> Expect 409 Conflict
        res2 = self.client.post("/admin/containment/actions/trigger", json=payload, headers=headers)
        self.assertEqual(res2.status_code, 409)
        self.assertIn("already exists", res2.json().get("detail", ""))

    def test_admin_rollback_lifecycle(self):
        """Rollback transitions active action to ROLLED_BACK and rejects ineligible actions."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # Create simulated action
        payload = {
            "target_ip": "192.168.56.101",
            "target_port": 8000,
            "direction": "inbound",
            "protocol": "tcp"
        }
        res_trigger = self.client.post("/admin/containment/actions/trigger", json=payload, headers=headers)
        self.assertEqual(res_trigger.status_code, 200)
        action_id = res_trigger.json()["action_id"]

        # 1. Execute rollback on active action -> Success
        res_rb = self.client.post(f"/admin/containment/actions/{action_id}/rollback", headers=headers)
        self.assertEqual(res_rb.status_code, 200)
        self.assertEqual(res_rb.json().get("status"), "ROLLED_BACK")

        # DB status should now be ROLLED_BACK
        self.db.expire_all()
        action = self.db.query(models.ContainmentAction).filter_by(action_id=action_id).first()
        self.assertEqual(action.status, "ROLLED_BACK")

        # 2. Ineligible action rollback (already rolled back) -> 400 Bad Request
        res_rb2 = self.client.post(f"/admin/containment/actions/{action_id}/rollback", headers=headers)
        self.assertEqual(res_rb2.status_code, 400)
        self.assertIn("Cannot rollback", res_rb2.json().get("detail", ""))

    def test_admin_containment_actions_listing(self):
        """GET /admin/containment/actions returns formatted actions with rule_spec and active mode."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        res = self.client.get("/admin/containment/actions", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("actions", data)
        self.assertIn("mode", data)
        self.assertIn("total", data)
