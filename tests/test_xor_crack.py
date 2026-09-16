import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools import xor_crack

SAMPLE_PLAINTEXT = (
    b"THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG. "
    b"PACK MY BOX WITH FIVE DOZEN LIQUOR JUGS. HOW VEXINGLY QUICK DAFT "
    b"ZEBRAS JUMP. THE FIVE BOXING WIZARDS JUMP QUICKLY. "
) * 20


def _encrypt(plaintext: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(plaintext))


class TestXorCrackWhicheverBackendIsActive(unittest.TestCase):
    """Runs against whatever backend is actually loaded (native if the
    extension is built, pure Python otherwise) -- exercises the real
    code path a user of this repo would hit."""

    def test_recovers_short_key(self):
        ciphertext = _encrypt(SAMPLE_PLAINTEXT, b"KEY")
        results = xor_crack.crack_repeating_xor(ciphertext, max_keysize=20, candidates=3)
        self.assertTrue(results)
        key, plaintext, _ = results[0]
        self.assertEqual(key, b"KEY")
        self.assertEqual(plaintext, SAMPLE_PLAINTEXT)

    def test_recovers_longer_key_not_a_multiple_false_positive(self):
        # Regression test: a naive top-N-by-Hamming-distance search can
        # rank a coincidentally-low-distance short keysize above the true,
        # longer key. This must resolve to the *actual* key, not a
        # garbage shorter one.
        ciphertext = _encrypt(SAMPLE_PLAINTEXT, b"SuperSecretKey7")
        results = xor_crack.crack_repeating_xor(ciphertext, max_keysize=40, candidates=3)
        self.assertEqual(results[0][0], b"SuperSecretKey7")
        self.assertEqual(results[0][1], SAMPLE_PLAINTEXT)

    def test_multiples_of_true_keysize_collapse_to_shortest_key(self):
        ciphertext = _encrypt(SAMPLE_PLAINTEXT, b"KEY")
        results = xor_crack.crack_repeating_xor(ciphertext, max_keysize=20, candidates=5)
        keys = [k for k, _, _ in results]
        # "KEYKEY" / "KEYKEYKEY" would be functionally-identical duplicates
        # of "KEY" -- they should not appear as separate candidates.
        self.assertNotIn(b"KEYKEY", keys)
        self.assertNotIn(b"KEYKEYKEY", keys)

    def test_empty_input_returns_no_candidates(self):
        self.assertEqual(xor_crack.crack_repeating_xor(b""), [])

    def test_rejects_non_bytes_input(self):
        with self.assertRaises(TypeError):
            xor_crack.crack_repeating_xor("not bytes")  # type: ignore[arg-type]

    def test_rejects_invalid_max_keysize(self):
        with self.assertRaises(ValueError):
            xor_crack.crack_repeating_xor(b"data", max_keysize=1)

    def test_rejects_invalid_candidates(self):
        with self.assertRaises(ValueError):
            xor_crack.crack_repeating_xor(b"data", candidates=0)

    def test_results_sorted_best_first(self):
        ciphertext = _encrypt(SAMPLE_PLAINTEXT, b"KEY")
        results = xor_crack.crack_repeating_xor(ciphertext, max_keysize=20, candidates=5)
        scores = [score for _, _, score in results]
        self.assertEqual(scores, sorted(scores, reverse=True))


class TestPurePythonPathExplicitly(unittest.TestCase):
    """Forces the pure-Python fallback regardless of whether the native
    extension is installed, so this path is never silently skipped in CI
    environments that happen to have the Rust extension built."""

    def setUp(self):
        self._saved_native = xor_crack._native
        self._saved_backend = xor_crack._BACKEND
        xor_crack._native = None
        xor_crack._BACKEND = "python"

    def tearDown(self):
        xor_crack._native = self._saved_native
        xor_crack._BACKEND = self._saved_backend

    def test_python_path_recovers_key(self):
        self.assertEqual(xor_crack.backend(), "python")
        ciphertext = _encrypt(SAMPLE_PLAINTEXT, b"KEY")
        results = xor_crack.crack_repeating_xor(ciphertext, max_keysize=20, candidates=3)
        self.assertEqual(results[0][0], b"KEY")


@unittest.skipUnless(xor_crack._native is not None, "native extension not built")
class TestNativeAndPythonAgree(unittest.TestCase):
    """When the native extension IS available, cross-check it against the
    pure-Python implementation on the same input to catch behavioral
    drift between the two if either is edited independently."""

    def test_both_backends_agree_on_key(self):
        ciphertext = _encrypt(SAMPLE_PLAINTEXT, b"KEY")

        native_result = xor_crack._native.crack_repeating_xor(ciphertext, 20, 3)
        python_result = xor_crack._crack_repeating_xor_python(ciphertext, 20, 3)

        self.assertEqual(native_result[0][0], python_result[0][0])
        self.assertEqual(native_result[0][1], python_result[0][1])


if __name__ == "__main__":
    unittest.main()
