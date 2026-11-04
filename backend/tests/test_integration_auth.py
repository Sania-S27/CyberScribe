import unittest
import sys
import os

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    from tests.base import BaseTestCase
except ImportError:
    from base import BaseTestCase

class TestAuthIntegration(BaseTestCase):
    def test_register_and_login_flow(self):
        reg_payload = {
            "company_name": "Nexus Defense Labs",
            "email": "lead@nexusdefense.local",
            "password": "Password123!"
        }
        
        # 1. Register
        reg_res = self.client.post("/auth/register", json=reg_payload)
        self.assertEqual(reg_res.status_code, 200)
        self.assertEqual(reg_res.json()["status"], "success")

        # 2. Login
        login_res = self.client.post("/auth/login", json={
            "email": "lead@nexusdefense.local",
            "password": "Password123!"
        })
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["access_token"]
        self.assertIsNotNone(token)

        # 3. Profile /me
        me_res = self.client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_res.status_code, 200)
        self.assertEqual(me_res.json()["email"], "lead@nexusdefense.local")
        self.assertEqual(me_res.json()["company_name"], "Nexus Defense Labs")

    def test_login_invalid_password(self):
        res = self.client.post("/auth/login", json={
            "email": self.user.email,
            "password": "WrongPassword123"
        })
        self.assertEqual(res.status_code, 401)

    def test_admin_profile_access(self):
        res = self.client.get("/auth/me", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["role"], "super_admin")
        self.assertEqual(res.json()["company_name"], "Platform Operations")

if __name__ == '__main__':
    unittest.main()
