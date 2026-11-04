import unittest
import sys
import os
from datetime import timedelta

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from jose import jwt
from app.core.security import get_password_hash, verify_password, create_access_token, SECRET_KEY, ALGORITHM

class TestSecurity(unittest.TestCase):
    def test_password_hashing_and_verification(self):
        raw_password = "SuperSecurePassword2026!"
        hashed = get_password_hash(raw_password)
        
        self.assertNotEqual(hashed, raw_password)
        self.assertTrue(verify_password(raw_password, hashed))
        self.assertFalse(verify_password("WrongPassword!", hashed))

    def test_jwt_creation_and_decoding(self):
        payload_data = {"sub": "analyst@enterprise.com", "role": "tenant_admin", "tenant_id": "test-uuid-123"}
        token = create_access_token(data=payload_data, expires_delta=timedelta(minutes=15))
        
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        self.assertEqual(decoded["sub"], "analyst@enterprise.com")
        self.assertEqual(decoded["role"], "tenant_admin")
        self.assertEqual(decoded["tenant_id"], "test-uuid-123")
        self.assertIn("exp", decoded)

    def test_jwt_invalid_signature_rejection(self):
        payload_data = {"sub": "attacker@evil.com", "role": "super_admin"}
        forged_token = jwt.encode(payload_data, "forged-secret-key-12345", algorithm=ALGORITHM)
        
        with self.assertRaises(Exception):
            jwt.decode(forged_token, SECRET_KEY, algorithms=[ALGORITHM])

if __name__ == '__main__':
    unittest.main()
