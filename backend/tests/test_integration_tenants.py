import unittest
import io
import sys
import os

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    from tests.base import BaseTestCase
except ImportError:
    from base import BaseTestCase

class TestTenantsIntegration(BaseTestCase):
    def test_tenant_profile_and_tech_stack_update(self):
        # 1. Get initial profile
        res = self.client.get("/tenants/profile", headers={"Authorization": f"Bearer {self.user_token}"})
        self.assertEqual(res.status_code, 200)
        self.assertIn("company_name", res.json())

        # 2. Update tech stack & webhook
        update_res = self.client.put(
            "/tenants/tech-stack",
            headers={"Authorization": f"Bearer {self.user_token}"},
            json={
                "tech_stack": "FastAPI:0.110.0, Docker:24.0, Kubernetes:1.29",
                "webhook_url": "https://soar.acme.local/webhook",
                "auth_token": "UPDATED_TOKEN_123"
            }
        )
        self.assertEqual(update_res.status_code, 200)
        self.assertEqual(update_res.json()["status"], "success")

    def test_upload_manifest_requirements_txt(self):
        manifest_content = """
        fastapi==0.110.0
        sqlalchemy>=2.0.25
        cryptography~=42.0.0
        # comments should be ignored
        redis==5.0.1
        """
        file_obj = io.BytesIO(manifest_content.strip().encode("utf-8"))
        
        res = self.client.post(
            "/tenants/upload-manifest",
            headers={"Authorization": f"Bearer {self.user_token}"},
            files={"file": ("requirements.txt", file_obj, "text/plain")}
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("Successfully parsed", res.json()["message"])

    def test_upload_manifest_package_json(self):
        package_json = """
        {
            "dependencies": {
                "react": "^18.2.0",
                "axios": "^1.6.0"
            }
        }
        """
        file_obj = io.BytesIO(package_json.strip().encode("utf-8"))
        
        res = self.client.post(
            "/tenants/upload-manifest",
            headers={"Authorization": f"Bearer {self.user_token}"},
            files={"file": ("package.json", file_obj, "application/json")}
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("Successfully parsed", res.json()["message"])

if __name__ == '__main__':
    unittest.main()
