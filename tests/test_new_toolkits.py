import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools import crypto_toolkit, web_recon, forensics_toolkit, osint_toolkit


class TestCryptoToolkit(unittest.TestCase):
    def test_identify_common_hash_shapes(self):
        self.assertIn("MD5", crypto_toolkit.identify_hash("d41d8cd98f00b204e9800998ecf8427e"))
        self.assertIn("SHA-256", crypto_toolkit.identify_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))


class TestWebRecon(unittest.TestCase):
    def test_decode_jwt_header_and_payload(self):
        token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ."
        out = web_recon.decode_jwt(token)
        self.assertIn('"alg": "none"', out)
        self.assertIn('"role": "admin"', out)

    def test_get_headers_rejects_non_http_scheme(self):
        self.assertIn("refusing to fetch URL", web_recon.get_headers("file:///etc/passwd"))


class TestForensicsToolkit(unittest.TestCase):
    def test_missing_file_degrades(self):
        out = forensics_toolkit.gather_forensics_evidence("/no/such/file")
        self.assertIsInstance(out, dict)


class TestOSINTToolkit(unittest.TestCase):
    def test_manual_steps_are_non_automated(self):
        out = osint_toolkit.manual_osint_steps()
        self.assertIn("reverse image", out.lower())


if __name__ == "__main__":
    unittest.main()
