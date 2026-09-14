import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools import decode_toolkit as dt


class TestBase64(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(dt.from_base64(dt.to_base64("flag{test}")), b"flag{test}")

    def test_tolerates_missing_padding(self):
        # "flag{a}" -> base64 without its trailing '=' padding
        padded = dt.to_base64("flag{a}")
        unpadded = padded.rstrip("=")
        self.assertEqual(dt.from_base64(unpadded), b"flag{a}")


class TestHex(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(dt.from_hex(dt.to_hex("hello")), b"hello")

    def test_ignores_whitespace_and_prefixes(self):
        self.assertEqual(dt.from_hex("68 65 6c 6c 6f"), b"hello")


class TestUrlEncoding(unittest.TestCase):
    def test_roundtrip(self):
        original = "flag{a b&c=d}"
        self.assertEqual(dt.from_url(dt.to_url(original)), original)


class TestRot13AndCaesar(unittest.TestCase):
    def test_rot13_is_involution(self):
        text = "Uryyb, Jbeyq!"
        self.assertEqual(dt.rot13(text), "Hello, World!")
        self.assertEqual(dt.rot13(dt.rot13(text)), text)

    def test_caesar_shift_wraps_and_preserves_case(self):
        self.assertEqual(dt.caesar_shift("xyz", 3), "abc")
        self.assertEqual(dt.caesar_shift("XYZ", 3), "ABC")

    def test_caesar_shift_preserves_non_alpha(self):
        self.assertEqual(dt.caesar_shift("a-1!", 1), "b-1!")


class TestXor(unittest.TestCase):
    def test_roundtrip_with_repeating_key(self):
        data = b"the flag is hidden here"
        key = b"key"
        ciphertext = dt.xor_bytes(data, key)
        self.assertEqual(dt.xor_bytes(ciphertext, key), data)

    def test_empty_key_raises(self):
        with self.assertRaises(ValueError):
            dt.xor_bytes(b"data", b"")

    def test_single_byte_bruteforce_finds_the_key(self):
        plaintext = b"flag{single_byte_xor_is_easy}"
        secret_key = 0x42
        ciphertext = bytes(b ^ secret_key for b in plaintext)
        candidates = dt.xor_bruteforce_single_byte(ciphertext)
        self.assertTrue(any(c["key"] == secret_key and c["output"] == plaintext for c in candidates))


class TestGzipZlib(unittest.TestCase):
    def test_gzip_roundtrip(self):
        self.assertEqual(dt.gunzip_bytes(dt.gzip_bytes(b"payload")), b"payload")

    def test_zlib_roundtrip(self):
        self.assertEqual(dt.zlib_inflate(dt.zlib_deflate(b"payload")), b"payload")


class TestRunRecipe(unittest.TestCase):
    def test_chains_operations_in_order(self):
        original = b"nested secret"
        encoded = dt.to_base64(dt.to_hex(original))
        result = dt.run_recipe(encoded, ["from_base64", "from_hex"])
        self.assertEqual(result, original)

    def test_unknown_step_raises_with_helpful_message(self):
        with self.assertRaises(ValueError) as ctx:
            dt.run_recipe("data", ["not_a_real_step"])
        self.assertIn("not_a_real_step", str(ctx.exception))

    def test_failing_step_raises_with_step_name_attached(self):
        with self.assertRaises(ValueError) as ctx:
            dt.run_recipe("not valid hex!!", ["from_hex"])
        self.assertIn("from_hex", str(ctx.exception))


class TestMagicDecode(unittest.TestCase):
    def test_detects_plain_base64(self):
        secret = "flag{magic_wand_found_me}"
        blob = dt.to_base64(secret)
        results = dt.magic_decode(blob)
        self.assertTrue(any(r["output"] == secret.encode() for r in results))
        # the winning recipe should be the shortest one that works
        best = results[0]
        self.assertEqual(best["recipe"], ["from_base64"])

    def test_detects_double_layered_encoding(self):
        secret = "flag{layers_of_encoding}"
        blob = dt.to_base64(dt.to_hex(secret))
        results = dt.magic_decode(blob, max_depth=3)
        self.assertTrue(any(r["output"] == secret.encode() for r in results))

    def test_no_false_positive_on_plain_short_text(self):
        # short, clearly-not-encoded text shouldn't spuriously "decode" into junk
        results = dt.magic_decode("hi")
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
