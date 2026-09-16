"""Tests for the misconception engine and personalised curriculum (Phase 4)."""

import unittest


class TestMisconceptionDetection(unittest.TestCase):
    def test_strong_phrase_fires_with_high_confidence(self):
        from agent.misconception import detect
        hits = detect("I need to decrypt the base64 to get the flag")
        self.assertTrue(hits)
        self.assertEqual(hits[0].misconception.id, "encoding-is-encryption")
        self.assertGreaterEqual(hits[0].confidence, 0.8)

    def test_negation_suppresses_the_card(self):
        from agent.misconception import detect
        hits = detect("base64 is just encoding, not encryption, so I decoded it")
        ids = [h.misconception.id for h in hits]
        self.assertNotIn("encoding-is-encryption", ids)

    def test_topic_mention_alone_does_not_fire(self):
        from agent.misconception import detect
        hits = detect("This is a web challenge about SQL injection in the login form")
        self.assertEqual(hits, [])

    def test_trigger_plus_context_fires(self):
        from agent.misconception import detect
        hits = detect("The JWT payload is encrypted so the role is hidden")
        self.assertIn("jwt-is-encrypted", [h.misconception.id for h in hits])

    def test_empty_input_is_safe(self):
        from agent.misconception import detect
        self.assertEqual(detect(""), [])
        self.assertEqual(detect(None), [])

    def test_threshold_is_respected(self):
        from agent.misconception import detect
        text = "high entropy means encrypted"
        self.assertTrue(detect(text, threshold=0.5))
        self.assertEqual(detect(text, threshold=0.99), [])

    def test_remediation_contains_correction_and_probe(self):
        from agent.misconception import detect, remediation
        hit = detect("ASLR prevents buffer overflow")[0]
        text = remediation(hit)
        self.assertIn("Worth double-checking", text)
        self.assertIn("Try this", text)

    def test_report_is_empty_when_nothing_fires(self):
        from agent.misconception import remediation_report
        self.assertEqual(remediation_report("a perfectly ordinary sentence"), "")

    def test_catalogue_entries_are_well_formed(self):
        from agent.misconception import CATALOGUE
        seen = set()
        for card in CATALOGUE:
            self.assertNotIn(card.id, seen, f"duplicate id {card.id}")
            seen.add(card.id)
            self.assertTrue(card.summary and card.correction and card.probe)
            self.assertTrue(card.triggers or card.strong_phrases)


class TestMisconceptionMemory(unittest.TestCase):
    def test_records_into_learner_memory(self):
        from agent.memory import LearnerMemory
        from agent.misconception import concepts_to_review, record_to_memory
        mem = LearnerMemory()
        ids = record_to_memory("I will decrypt the base64 string", mem)
        self.assertIn("encoding-is-encryption", ids)
        self.assertTrue(mem.misconceptions)
        self.assertIn("encoding-basics", concepts_to_review(mem))

    def test_concepts_to_review_handles_empty_memory(self):
        from agent.memory import LearnerMemory
        from agent.misconception import concepts_to_review
        self.assertEqual(concepts_to_review(LearnerMemory()), [])


class TestTeachingIntegration(unittest.TestCase):
    def test_legacy_helper_still_returns_strings(self):
        from agent.teaching import detect_misconceptions
        hits = detect_misconceptions("the jwt is encrypted so nobody can read it")
        self.assertTrue(hits)
        self.assertTrue(all(isinstance(h, str) for h in hits))

    def test_misconception_block_is_optional(self):
        from agent.teaching import misconception_block
        self.assertEqual(misconception_block("nothing to see here"), "")


class TestCurriculum(unittest.TestCase):
    def _memory(self):
        from agent.memory import LearnerMemory
        mem = LearnerMemory()
        for _ in range(3):
            mem.record_attempt("sql-injection", True)
        mem.record_attempt("xor-single-byte", True)
        mem.record_attempt("xor-single-byte", True)
        mem.record_attempt("ret2libc", False, hints=3)
        mem.record_attempt("ret2libc", False, hints=4)
        mem.total_sessions = 7
        return mem

    def test_profile_reflects_memory(self):
        from agent.curriculum import build_profile
        profile = build_profile(self._memory())
        self.assertIn("sql-injection", profile.mastered)
        self.assertIn("ret2libc", profile.weak)

    def test_no_memory_is_a_beginner(self):
        from agent.curriculum import build_profile
        profile = build_profile(None)
        self.assertEqual(profile.level, "easy")
        self.assertEqual(profile.mastered, set())

    def test_level_estimate_climbs_with_mastery(self):
        from agent.curriculum import estimate_level
        many = {f"t{i}": 0.9 for i in range(10)}
        attempts = {f"t{i}": 5 for i in range(10)}
        self.assertEqual(estimate_level({}, {}), "easy")
        self.assertEqual(estimate_level(many, attempts), "insane")

    def test_difficulty_nudges_both_directions(self):
        from agent.curriculum import LearnerProfile, next_difficulty
        profile = LearnerProfile(level="medium")
        self.assertEqual(next_difficulty(profile, last_success=True), "hard")
        self.assertEqual(next_difficulty(profile, last_success=False), "easy")
        self.assertEqual(next_difficulty(profile, last_success=None), "medium")

    def test_difficulty_clamps_at_the_ends(self):
        from agent.curriculum import LearnerProfile, next_difficulty
        self.assertEqual(next_difficulty(LearnerProfile(level="easy"), False), "easy")
        self.assertEqual(next_difficulty(LearnerProfile(level="insane"), True), "insane")

    def test_hint_level_drops_as_mastery_rises(self):
        from agent.curriculum import LearnerProfile, recommended_hint_level
        profile = LearnerProfile(mastery={"known": 0.9, "shaky": 0.5, "new": 0.1})
        self.assertLess(
            recommended_hint_level(profile, "known"),
            recommended_hint_level(profile, "new"),
        )

    def test_plan_has_lessons_and_profile(self):
        from agent.curriculum import build_curriculum
        plan = build_curriculum(self._memory(), length=4)
        self.assertIn("profile", plan)
        self.assertLessEqual(len(plan["lessons"]), 4)
        self.assertTrue(plan["lessons"])

    def test_goal_schedules_prerequisites_first(self):
        from agent.curriculum import build_curriculum
        plan = build_curriculum(self._memory(), goal="ret2libc", length=5)
        topics = [l["topic"] for l in plan["lessons"]]
        kinds = [l["kind"] for l in plan["lessons"]]
        self.assertIn("prerequisite", kinds)
        self.assertIn("stack-buffer-overflow", topics)

    def test_misconceptions_are_scheduled_first(self):
        from agent.curriculum import build_curriculum
        mem = self._memory()
        mem.add_misconception("encoding-is-encryption: Treating an encoding as encryption.")
        plan = build_curriculum(mem, length=5)
        self.assertEqual(plan["lessons"][0]["kind"], "repair")

    def test_render_is_readable(self):
        from agent.curriculum import build_curriculum, render_curriculum
        text = render_curriculum(build_curriculum(self._memory(), length=3))
        self.assertIn("Your next steps", text)
        self.assertIn("Legend", text)

    def test_render_handles_empty_plan(self):
        from agent.curriculum import render_curriculum
        text = render_curriculum({"profile": {}, "lessons": []})
        self.assertIn("Not enough history", text)


if __name__ == "__main__":
    unittest.main()
