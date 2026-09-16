import json
import sys
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import eval as evaluator


class TestEval(unittest.TestCase):
    def test_metrics(self):
        self.assertEqual(evaluator._metrics(["a", "b"], ["a", "c"]), (0.5, 0.5, 0.5))

    def test_run_uses_ground_truth_and_reports_accuracy(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "gt.json"
            path.write_text(json.dumps([
                {"id": "one", "description": "JWT login admin panel", "expected_category": "web"},
                {"id": "two", "description": "RSA modulus prime", "expected_category": "crypto"},
            ]))
            with patch("builtins.print") as p:
                rc = evaluator.run(path)
            self.assertEqual(rc, 0)
            output = "\n".join(str(call.args[0]) for call in p.call_args_list)
            self.assertIn("classification accuracy", output)


if __name__ == "__main__":
    unittest.main()
