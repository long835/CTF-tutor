import sys
import os
import json
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from schema import SubProblem
import depth_guide
from depth_guide import (
    HintLevel,
    level_from_str,
    get_hint,
    get_hint_ladder,
    build_user_prompt,
)


def make_sub_problem(id="sp1", description="looks like a buffer overflow"):
    return SubProblem(id=id, description=description, likely_techniques=["stack-buffer-overflow"])


class TestHintLevel(unittest.TestCase):
    def test_ordering(self):
        self.assertLess(HintLevel.NAME, HintLevel.APPROACH)
        self.assertLess(HintLevel.APPROACH, HintLevel.COMMANDS)
        self.assertLess(HintLevel.COMMANDS, HintLevel.WALKTHROUGH)

    def test_level_from_str_valid(self):
        self.assertEqual(level_from_str("name"), HintLevel.NAME)
        self.assertEqual(level_from_str("Walkthrough"), HintLevel.WALKTHROUGH)
        self.assertEqual(level_from_str("  commands  "), HintLevel.COMMANDS)

    def test_level_from_str_invalid_lists_valid_options(self):
        with self.assertRaises(ValueError) as ctx:
            level_from_str("bogus")
        message = str(ctx.exception)
        self.assertIn("name", message)
        self.assertIn("walkthrough", message)


class TestBuildUserPrompt(unittest.TestCase):
    def test_includes_requested_level_and_description(self):
        sp = make_sub_problem()
        prompt = build_user_prompt(sp, [], HintLevel.APPROACH)
        self.assertIn("approach", prompt)
        self.assertIn("looks like a buffer overflow", prompt)


class TestGetHint(unittest.TestCase):
    def test_each_level_uses_its_own_system_prompt(self):
        sp = make_sub_problem()
        seen_prompts = []

        def fake_call_ollama(system_prompt, user_prompt, model=None):
            seen_prompts.append(system_prompt)
            return json.dumps({"hint": "some hint", "cited_entries": []})

        with patch.object(depth_guide, "call_ollama", side_effect=fake_call_ollama):
            for level in HintLevel:
                get_hint(sp, [], level)

        # every level must use a distinct system prompt
        self.assertEqual(len(set(seen_prompts)), len(HintLevel))

    def test_parses_hint_text_and_citations(self):
        sp = make_sub_problem()
        fake_reply = json.dumps({"hint": "try pwntools ropgadget", "cited_entries": ["ret2libc chal"]})
        with patch.object(depth_guide, "call_ollama", return_value=fake_reply):
            hint = get_hint(sp, [], HintLevel.COMMANDS)
        self.assertEqual(hint.text, "try pwntools ropgadget")
        self.assertEqual(hint.cited_entries, ["ret2libc chal"])
        self.assertEqual(hint.level, HintLevel.COMMANDS)
        self.assertEqual(hint.sub_problem_id, "sp1")

    def test_falls_back_gracefully_on_non_json_reply(self):
        sp = make_sub_problem()
        with patch.object(depth_guide, "call_ollama", return_value="stack-buffer-overflow"):
            hint = get_hint(sp, [], HintLevel.NAME)
        self.assertEqual(hint.text, "stack-buffer-overflow")
        self.assertEqual(hint.cited_entries, [])


class TestGetHintLadder(unittest.TestCase):
    def test_returns_levels_in_order_up_to_cap(self):
        sp = make_sub_problem()
        with patch.object(
            depth_guide, "call_ollama",
            return_value='{"hint": "x", "cited_entries": []}',
        ) as mock_call:
            hints = get_hint_ladder(sp, [], up_to=HintLevel.COMMANDS)

        self.assertEqual([h.level for h in hints], [HintLevel.NAME, HintLevel.APPROACH, HintLevel.COMMANDS])
        self.assertEqual(mock_call.call_count, 3)

    def test_default_cap_is_full_walkthrough(self):
        sp = make_sub_problem()
        with patch.object(depth_guide, "call_ollama", return_value='{"hint": "x"}'):
            hints = get_hint_ladder(sp, [])
        self.assertEqual(len(hints), 4)
        self.assertEqual(hints[-1].level, HintLevel.WALKTHROUGH)


if __name__ == "__main__":
    unittest.main()