"""Tests for Ciphey-inspired auto_decode and skill packs."""

import base64
import unittest


class TestAutoDecode(unittest.TestCase):
    def test_peel_base64_hex(self):
        from agent.auto_decode import auto_decode
        inner = b"flag{layered_decode_works}"
        layer1 = inner.hex().encode()
        layer2 = base64.b64encode(layer1)
        r = auto_decode(layer2, timeout_sec=2.0)
        self.assertTrue(r.success)
        self.assertTrue(any("flag{" in f for f in r.flags) or "flag{" in r.final_text)

    def test_timeout_bound(self):
        from agent.auto_decode import auto_decode
        import time
        t0 = time.time()
        auto_decode(b"not_really_encoded_data_xxx", timeout_sec=0.5)
        self.assertLess(time.time() - t0, 1.5)

    def test_flag_scan(self):
        from agent.auto_decode import scan_for_flags
        flags = scan_for_flags("prefix flag{abc123} suffix CTF{xyz}")
        self.assertTrue(len(flags) >= 1)


class TestSkillPacks(unittest.TestCase):
    def test_web_pack(self):
        from agent.skill_packs import get_pack, pack_summary, suggest_tools_for_category
        self.assertIsNotNone(get_pack("web"))
        self.assertIn("JWT", pack_summary("web") or pack_summary("web"))
        tools = suggest_tools_for_category("crypto")
        self.assertIn("auto_decode", tools)


if __name__ == "__main__":
    unittest.main()
