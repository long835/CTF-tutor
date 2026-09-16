"""Tests for the retrieval reranker and the challenge graph (Phase 3)."""

import unittest


class TestRerank(unittest.TestCase):
    def _candidates(self):
        return [
            {"name": "JWT none bypass", "category": "web", "techniques": ["jwt-none-bypass"],
             "difficulty": "medium", "score": 1.0},
            {"name": "JWT none bypass copy", "category": "web", "techniques": ["jwt-none-bypass"],
             "difficulty": "medium", "score": 0.95},
            {"name": "Stack overflow", "category": "pwn", "techniques": ["stack-buffer-overflow"],
             "difficulty": "easy", "score": 0.9},
        ]

    def test_empty_input(self):
        from agent.rerank import rerank
        self.assertEqual(rerank([], "anything"), [])

    def test_adds_scores_and_respects_top_k(self):
        from agent.rerank import rerank
        out = rerank(self._candidates(), "jwt none algorithm bypass", top_k=2)
        self.assertEqual(len(out), 2)
        for row in out:
            self.assertIn("rerank_score", row)
            self.assertIn("first_stage_score", row)

    def test_category_match_outranks_raw_score(self):
        from agent.rerank import RerankContext, rerank
        candidates = [
            {"name": "Off topic", "category": "pwn", "techniques": ["rop-chain"], "score": 1.0},
            {"name": "On topic", "category": "web", "techniques": ["sql-injection"], "score": 0.6},
        ]
        out = rerank(candidates, "sql injection login form", ctx=RerankContext(category="web"), top_k=2)
        self.assertEqual(out[0]["name"], "On topic")

    def test_diversity_demotes_near_duplicate(self):
        from agent.rerank import rerank
        out = rerank(self._candidates(), "jwt none bypass", top_k=3, diversity=0.9)
        # The duplicate JWT card should not sit directly behind the original.
        self.assertNotEqual(out[1]["name"], "JWT none bypass copy")

    def test_explain_includes_feature_breakdown(self):
        from agent.rerank import explain_ranking, rerank
        out = rerank(self._candidates(), "jwt bypass", top_k=2, explain=True)
        self.assertIn("rerank_features", out[0])
        self.assertIn("Rerank breakdown", explain_ranking(out))

    def test_weak_techniques_get_a_boost(self):
        from agent.rerank import RerankContext, score_candidate
        candidate = {"name": "x", "category": "web", "techniques": ["sql-injection"], "score": 0.5}
        neutral = score_candidate(candidate, "sql injection", RerankContext())
        weak = score_candidate(candidate, "sql injection", RerankContext(weak={"sql-injection"}))
        self.assertGreater(weak.prereq, neutral.prereq)

    def test_query_expansion_uses_vocabulary(self):
        from agent.rerank import expand_query
        expanded = expand_query("sqli union", {"union": {"sqli-union", "sqli"}})
        self.assertIn("sqli-union", expanded)


class TestHybridSearchIntegration(unittest.TestCase):
    def test_rerank_flag_is_honoured(self):
        from agent.hybrid_retrieve import hybrid_search
        plain = hybrid_search("jwt alg none admin", category="web", top_k=3, rerank=False)
        ranked = hybrid_search("jwt alg none admin", category="web", top_k=3, rerank=True)
        self.assertTrue(all("rerank_score" not in r for r in plain))
        if ranked:
            self.assertIn("rerank_score", ranked[0])


class TestChallengeGraph(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from agent.challenge_graph import build_graph
        cls.graph = build_graph()

    def test_graph_has_nodes_and_edges(self):
        stats = self.graph.stats()
        self.assertGreater(stats["nodes"], 10)
        self.assertGreater(stats["edges"], 0)

    def test_find_by_technique(self):
        hits = self.graph.find("stack-buffer-overflow")
        self.assertTrue(hits)

    def test_neighbors_are_sorted_by_weight(self):
        hits = self.graph.find("stack-buffer-overflow", limit=1)
        if not hits:
            self.skipTest("no matching node in this archive")
        edges = self.graph.neighbors(hits[0].id, limit=5)
        weights = [e.weight for e in edges]
        self.assertEqual(weights, sorted(weights, reverse=True))

    def test_easier_and_harder_respect_difficulty(self):
        hits = self.graph.find("ret2libc", limit=1)
        if not hits:
            self.skipTest("no ret2libc node")
        node = hits[0]
        for easier in self.graph.easier_siblings(node.id):
            self.assertLess(easier.difficulty_index, node.difficulty_index)
        for harder in self.graph.next_steps(node.id):
            self.assertGreater(harder.difficulty_index, node.difficulty_index)

    def test_shortest_path_to_self(self):
        node_id = next(iter(self.graph.nodes))
        self.assertEqual(self.graph.shortest_path(node_id, node_id), [node_id])

    def test_shortest_path_between_related_nodes(self):
        a = self.graph.find("stack-buffer-overflow", limit=1)
        b = self.graph.find("ret2libc", limit=1)
        if not (a and b):
            self.skipTest("endpoints not present")
        path = self.graph.shortest_path(a[0].id, b[0].id)
        self.assertTrue(path)
        self.assertEqual(path[0], a[0].id)
        self.assertEqual(path[-1], b[0].id)

    def test_unknown_node_is_handled(self):
        self.assertEqual(self.graph.neighbors("nope:does-not-exist"), [])
        self.assertEqual(self.graph.shortest_path("nope:a", "nope:b"), [])

    def test_export_shapes(self):
        data = self.graph.to_dict(max_edges=5)
        self.assertIn("nodes", data)
        self.assertLessEqual(len(data["edges"]), 5)
        self.assertTrue(self.graph.to_dot(max_edges=5).startswith("graph challenges"))

    def test_render_neighborhood_handles_miss(self):
        from agent.challenge_graph import render_neighborhood
        text = render_neighborhood(self.graph, "definitely-not-a-technique")
        self.assertIn("No challenge", text)


if __name__ == "__main__":
    unittest.main()
