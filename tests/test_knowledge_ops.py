"""Tests for provenance, corpus, dashboard, plugins, and provider failover."""

import json
import os
import tempfile
import unittest
from pathlib import Path


SAMPLE = {
    "challenge_name": "Example JWT",
    "category": "web",
    "techniques": ["jwt-none-bypass"],
    "difficulty": "medium",
    "description": "A token is trusted without checking the algorithm.",
    "explanation": "The verifier honours the header's algorithm field.",
    "solve_steps": ["decode the token", "inspect the verification call"],
    "references": ["local:test"],
}


class TestContentHashing(unittest.TestCase):
    def test_stable_across_key_order(self):
        from agent.provenance import content_hash
        a = dict(SAMPLE)
        b = {k: SAMPLE[k] for k in reversed(list(SAMPLE))}
        self.assertEqual(content_hash(a), content_hash(b))

    def test_changes_when_content_changes(self):
        from agent.provenance import content_hash
        changed = dict(SAMPLE, description="something else entirely")
        self.assertNotEqual(content_hash(SAMPLE), content_hash(changed))

    def test_bookkeeping_fields_are_ignored(self):
        from agent.provenance import content_hash
        noisy = dict(SAMPLE, version=9, added_at="2020-01-01", updated_at="2021-01-01")
        self.assertEqual(content_hash(SAMPLE), content_hash(noisy))


class TestProvenanceStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "provenance.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_record_is_version_one(self):
        from agent.provenance import ProvenanceStore
        store = ProvenanceStore(self.path)
        prov = store.record("e1", SAMPLE, source_type="curated")
        self.assertEqual(prov.version, 1)
        self.assertEqual(prov.history, [])

    def test_unchanged_content_does_not_bump_version(self):
        from agent.provenance import ProvenanceStore
        store = ProvenanceStore(self.path)
        store.record("e1", SAMPLE)
        again = store.record("e1", SAMPLE)
        self.assertEqual(again.version, 1)

    def test_changed_content_bumps_version_and_keeps_history(self):
        from agent.provenance import ProvenanceStore
        store = ProvenanceStore(self.path)
        store.record("e1", SAMPLE)
        updated = store.record("e1", dict(SAMPLE, description="revised wording"))
        self.assertEqual(updated.version, 2)
        self.assertEqual(len(updated.history), 1)
        self.assertFalse(updated.verified)

    def test_round_trip_through_disk(self):
        from agent.provenance import ProvenanceStore
        store = ProvenanceStore(self.path)
        store.record("e1", SAMPLE, source_type="curated", license="CC-BY")
        store.save()
        reloaded = ProvenanceStore(self.path)
        self.assertIn("e1", reloaded.records)
        self.assertEqual(reloaded.records["e1"].license, "CC-BY")

    def test_verification_flag(self):
        from agent.provenance import ProvenanceStore
        store = ProvenanceStore(self.path)
        store.record("e1", SAMPLE)
        self.assertTrue(store.mark_verified("e1"))
        self.assertFalse(store.mark_verified("missing"))

    def test_trust_ordering(self):
        from agent.provenance import Provenance
        curated = Provenance(entry_id="a", source_type="curated")
        synthetic = Provenance(entry_id="b", source_type="synthetic")
        self.assertGreater(curated.trust, synthetic.trust)


class TestContradictions(unittest.TestCase):
    def test_opposing_claims_are_flagged(self):
        from agent.provenance import find_contradictions
        entries = {
            "a": dict(SAMPLE, explanation="The payload is encrypted end to end."),
            "b": dict(SAMPLE, explanation="The payload is signed, not encrypted."),
        }
        found = find_contradictions(entries)
        self.assertTrue(found)
        self.assertEqual(found[0].technique, "jwt-none-bypass")

    def test_unrelated_entries_are_not_compared(self):
        from agent.provenance import find_contradictions
        entries = {
            "a": dict(SAMPLE, explanation="This is encrypted."),
            "b": dict(SAMPLE, techniques=["rop-chain"], explanation="This is signed."),
        }
        self.assertEqual(find_contradictions(entries), [])

    def test_agreeing_entries_are_clean(self):
        from agent.provenance import find_contradictions
        entries = {"a": dict(SAMPLE), "b": dict(SAMPLE, challenge_name="Another")}
        self.assertEqual(find_contradictions(entries), [])


class TestArchiveAudit(unittest.TestCase):
    def test_every_shipped_entry_loads_and_validates(self):
        from archive_quality import validate_entry
        from schema import ArchiveEntry
        problems = []
        for fp in sorted(Path("data/archive").glob("*.json")):
            try:
                errors = validate_entry(ArchiveEntry.load(str(fp)))
            except Exception as exc:  # noqa: BLE001
                errors = [str(exc)]
            if errors:
                problems.append((fp.name, errors))
        self.assertEqual(problems, [], f"archive entries failing checks: {problems}")

    def test_audit_report_shape(self):
        from agent.provenance import audit_archive
        report = audit_archive()
        for key in ("entries", "provenance_coverage", "contradictions", "invalid", "clean"):
            self.assertIn(key, report)

    def test_render_audit_is_a_string(self):
        from agent.provenance import render_audit
        text = render_audit({"entries": 3, "provenance_coverage": 1.0, "clean": True})
        self.assertIn("Archive audit", text)


class TestSchemaAliases(unittest.TestCase):
    def test_legacy_field_names_are_mapped(self):
        from schema import ArchiveEntry
        entry = ArchiveEntry.from_dict({
            "name": "Legacy card",
            "category": "pwn",
            "tags": ["stack-buffer-overflow"],
            "approach": "Look at the bounds check.",
            "tools": ["gdb"],
        })
        self.assertEqual(entry.challenge_name, "Legacy card")
        self.assertEqual(entry.explanation, "Look at the bounds check.")
        self.assertEqual(entry.tools_used, ["gdb"])

    def test_unknown_keys_are_preserved_in_notes(self):
        from schema import ArchiveEntry
        entry = ArchiveEntry.from_dict({
            "challenge_name": "X", "category": "web", "techniques": ["ssti"],
            "mystery_field": "keep me",
        })
        self.assertIn("mystery_field", entry.notes)

    def test_missing_required_fields_raise(self):
        from schema import ArchiveEntry
        with self.assertRaises(ValueError):
            ArchiveEntry.from_dict({"category": "web"})


class TestCorpusBuilder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from agent.corpus_builder import build_corpus
        cls.summary = build_corpus(500)

    def test_meets_the_five_hundred_target(self):
        self.assertGreaterEqual(self.summary["total"], 500)
        self.assertTrue(self.summary["meets_minimum"])

    def test_all_card_kinds_present(self):
        from agent.corpus_builder import CARD_KINDS
        for kind in CARD_KINDS:
            self.assertIn(kind, self.summary["by_kind"], f"missing card kind: {kind}")

    def test_ids_are_unique_on_disk(self):
        from agent.corpus_builder import OUT_FILE
        ids = [json.loads(line)["id"] for line in Path(OUT_FILE).read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_cards_are_not_near_duplicates(self):
        """The old builder padded with (v2)/(v3) clones; descriptions should differ."""
        from agent.corpus_builder import OUT_FILE
        rows = [json.loads(l) for l in Path(OUT_FILE).read_text(encoding="utf-8").splitlines() if l.strip()]
        descriptions = [r["description"] for r in rows if r.get("description")]
        unique_ratio = len(set(descriptions)) / max(1, len(descriptions))
        self.assertGreater(unique_ratio, 0.95)

    def test_builds_deterministically(self):
        from agent.corpus_builder import build_corpus
        again = build_corpus(500)
        self.assertEqual(again["total"], self.summary["total"])
        self.assertEqual(again["by_kind"], self.summary["by_kind"])

    def test_technique_library_is_well_formed(self):
        from agent.corpus_builder import load_library
        library = load_library()
        self.assertGreater(len(library), 30)
        seen = set()
        for entry in library:
            self.assertNotIn(entry["technique"], seen)
            seen.add(entry["technique"])
            self.assertTrue(entry.get("concept"))
            self.assertTrue(entry.get("scenarios"))
            self.assertIn(entry.get("difficulty"), {"easy", "medium", "hard", "insane"})


class TestDashboard(unittest.TestCase):
    def test_empty_dashboard_still_renders(self):
        from agent.dashboard import build_dashboard
        html = build_dashboard()
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("No results yet", html)

    def test_metrics_appear(self):
        from agent.dashboard import build_dashboard
        html = build_dashboard(eval_summary={
            "n": 20, "category_accuracy": 0.9, "technique_hit_rate": 0.95,
            "avg_steps": 3.0, "statuses": {"verified": 20}, "results": [],
        })
        self.assertIn("90%", html)
        self.assertIn("95%", html)

    def test_output_is_self_contained(self):
        from agent.dashboard import build_dashboard
        html = build_dashboard(corpus_summary={"total": 560, "distinct_techniques": 118, "by_kind": {}})
        for marker in ("http://", "https://", "<script"):
            self.assertNotIn(marker, html, f"dashboard must not reference {marker}")

    def test_html_escaping(self):
        from agent.dashboard import build_dashboard
        html = build_dashboard(leaderboard=[{"id": "<script>x</script>", "status": "ok",
                                             "confidence": 0.5, "steps": 1, "duration_sec": 1}])
        self.assertNotIn("<script>x</script>", html)

    def test_trace_view_handles_empty(self):
        from agent.dashboard import build_trace_view
        self.assertIn("empty", build_trace_view([]))

    def test_trace_view_renders_events(self):
        from agent.dashboard import build_trace_view
        events = [
            {"event": "state_snapshot", "ts": "2026-01-01T00:00:00+00:00", "status": "investigating",
             "step": 1, "confidence": 0.4,
             "hypotheses": [{"id": "h1", "conf": 0.6, "tech": "ssti", "stmt": "template injection"}]},
            {"event": "tool_end", "ts": "2026-01-01T00:00:01+00:00", "tool": "web_recon"},
        ]
        html = build_trace_view(events, source="test.jsonl")
        self.assertIn("ssti", html)
        self.assertIn("Timeline", html)

    def test_writes_files_to_disk(self):
        from agent.dashboard import write_dashboard
        with tempfile.TemporaryDirectory() as tmp:
            out = write_dashboard(out_path=os.path.join(tmp, "d.html"), run_eval=False)
            self.assertTrue(Path(out).is_file())


class TestPlugins(unittest.TestCase):
    def test_discovery_of_missing_directory(self):
        from agent.plugins import discover
        self.assertEqual(discover("definitely/not/here"), [])

    def test_example_plugin_loads_and_registers(self):
        from agent import tools_registry
        from agent.plugins import load_all
        infos = load_all("plugins", force=True)
        self.assertTrue(infos, "expected the example plugin to be discovered")
        example = next((i for i in infos if i.name == "example_flagcheck"), None)
        self.assertIsNotNone(example)
        self.assertTrue(example.loaded, example.error)
        self.assertIn("example_flagcheck.check", example.tools)
        self.assertIsNotNone(tools_registry.get("example_flagcheck.check"))

    def test_plugin_tool_runs(self):
        from agent import tools_registry
        from agent.plugins import load_all
        load_all("plugins", force=True)
        ok, out, err = tools_registry.run_tool(
            "example_flagcheck.check", {"text": "picoCTF{abc123}"}
        )
        self.assertTrue(ok, err)
        self.assertIn("picoCTF{abc123}", out)

    def test_permission_is_clamped(self):
        from agent.permissions import Permission
        from agent.plugins import _clamp
        self.assertEqual(_clamp(Permission.FULL_APPROVAL), Permission.ANALYSIS)
        self.assertEqual(_clamp(Permission.READ_ONLY), Permission.READ_ONLY)

    def test_broken_plugin_is_isolated(self):
        from agent.plugins import load_plugin
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp, "broken.py")
            bad.write_text("raise RuntimeError('boom')", encoding="utf-8")
            info = load_plugin(bad)
            self.assertFalse(info.loaded)
            self.assertIn("boom", info.error)

    def test_plugin_without_register_is_reported(self):
        from agent.plugins import load_plugin
        with tempfile.TemporaryDirectory() as tmp:
            noreg = Path(tmp, "noreg.py")
            noreg.write_text("x = 1", encoding="utf-8")
            info = load_plugin(noreg)
            self.assertFalse(info.loaded)
            self.assertIn("register", info.error)

    def test_handler_exceptions_do_not_escape(self):
        from agent import tools_registry
        from agent.plugins import PluginAPI, PluginInfo
        api = PluginAPI("t_isolation", PluginInfo(name="t_isolation", path="<test>"))

        def boom(args):
            raise ValueError("inner failure")

        name = api.register_tool("boom", boom)
        ok, out, err = tools_registry.run_tool(name, {})
        self.assertFalse(ok)
        self.assertIn("inner failure", err)

    def test_tools_are_namespaced(self):
        from agent.plugins import PluginAPI, PluginInfo
        api = PluginAPI("t_ns", PluginInfo(name="t_ns", path="<test>"))
        name = api.register_tool("classify", lambda args: (True, "", ""))
        self.assertEqual(name, "t_ns.classify")

    def test_status_report_shape(self):
        from agent.plugins import render_status, status
        report = status("plugins")
        self.assertIn("discovered", report)
        self.assertIn("Plugins", render_status(report))


class TestProviderFailover(unittest.TestCase):
    def _providers(self):
        from agent.providers import LLMProvider

        class Broken(LLMProvider):
            def chat(self, system, user, model=None):
                raise RuntimeError("connection refused")

            def embed(self, texts, model=None):
                raise RuntimeError("connection refused")

            @property
            def name(self):
                return "broken"

        class Working(LLMProvider):
            def __init__(self):
                self.calls = 0

            def chat(self, system, user, model=None):
                self.calls += 1
                return "answer"

            def embed(self, texts, model=None):
                return [[0.1] for _ in texts]

            @property
            def name(self):
                return "working"

        return Broken(), Working()

    def test_falls_through_to_a_working_provider(self):
        from agent.providers import FailoverProvider
        broken, working = self._providers()
        chain = FailoverProvider([broken, working])
        self.assertEqual(chain.chat("s", "u"), "answer")
        self.assertEqual(chain.last_used, "working")

    def test_failed_provider_is_skipped_afterwards(self):
        from agent.providers import FailoverProvider
        broken, working = self._providers()
        chain = FailoverProvider([broken, working], cooldown_seconds=60)
        chain.chat("s", "u")
        chain.chat("s", "u")
        self.assertIn("broken", chain.health()["cooling_down"])
        self.assertEqual(working.calls, 2)

    def test_all_broken_returns_empty_not_exception(self):
        from agent.providers import FailoverProvider
        broken, _ = self._providers()
        chain = FailoverProvider([broken])
        self.assertEqual(chain.chat("s", "u"), "")

    def test_embeddings_fall_through(self):
        from agent.providers import FailoverProvider
        broken, working = self._providers()
        chain = FailoverProvider([broken, working])
        self.assertEqual(chain.embed(["a"]), [[0.1]])

    def test_offline_provider_is_quiet(self):
        from agent.providers import OfflineProvider
        p = OfflineProvider()
        self.assertEqual(p.chat("s", "u"), "")
        self.assertEqual(p.embed(["a", "b"]), [[], []])

    def test_single_provider_when_no_fallback_configured(self):
        from agent.providers import FailoverProvider, get_provider
        old = os.environ.pop("LLM_PROVIDER_FALLBACK", None)
        try:
            self.assertNotIsInstance(get_provider(), FailoverProvider)
        finally:
            if old is not None:
                os.environ["LLM_PROVIDER_FALLBACK"] = old

    def test_chain_is_built_from_environment(self):
        from agent.providers import FailoverProvider, get_provider
        old = os.environ.get("LLM_PROVIDER_FALLBACK")
        os.environ["LLM_PROVIDER_FALLBACK"] = "offline"
        try:
            provider = get_provider()
            self.assertIsInstance(provider, FailoverProvider)
            self.assertIn("offline", provider.name)
        finally:
            if old is None:
                os.environ.pop("LLM_PROVIDER_FALLBACK", None)
            else:
                os.environ["LLM_PROVIDER_FALLBACK"] = old


if __name__ == "__main__":
    unittest.main()
