"""HTTP API, embeddings, config, telemetry, model compare."""

from __future__ import annotations

import json
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from agent.http_api import TutorHandler
from http.server import ThreadingHTTPServer


class TestEmbeddings(unittest.TestCase):
    def test_hash_backend(self):
        from agent.embeddings import embed_texts, embedding_backend_info
        vecs = embed_texts(["hello world", "hello world"], backend="hash")
        self.assertEqual(len(vecs), 2)
        self.assertEqual(len(vecs[0]), 256)
        # deterministic
        self.assertEqual(vecs[0], vecs[1])
        info = embedding_backend_info()
        self.assertIn("backend", info)


class TestConfigTelemetry(unittest.TestCase):
    def test_config_public(self):
        from agent.app_config import get_config
        d = get_config(reload=True).public_dict()
        self.assertIn("ollama_model", d)
        self.assertFalse(d.get("telemetry_enabled"))

    def test_telemetry_policy(self):
        from agent.telemetry import policy
        p = policy()
        self.assertFalse(p["phones_home"])
        self.assertFalse(p["stores_challenge_text"])


class TestModelCompare(unittest.TestCase):
    def test_compare(self):
        from agent.model_compare import compare_models
        r = compare_models(models=["qwen3:8b", "llava"], tasks=["classify", "vision"])
        self.assertEqual(len(r["profiles"]), 2)
        self.assertIn("recommendation", r)


class TestResourceConcurrency(unittest.TestCase):
    def test_workers_cap(self):
        from agent.resource_concurrency import recommended_workers
        w = recommended_workers("qwen3:0.5b")
        self.assertGreaterEqual(w, 1)
        self.assertLessEqual(w, 4)


class TestHttpApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), TutorHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _req(self, method, path, body=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=10)
        raw = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if body is not None else {}
        conn.request(method, path, body=raw, headers=headers)
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
        conn.close()
        return resp.status, data

    def test_health(self):
        status, data = self._req("GET", "/health")
        self.assertEqual(status, 200)
        self.assertTrue(data.get("ok"))

    def test_classify(self):
        status, data = self._req(
            "POST",
            "/v1/classify",
            {"description": "Stack buffer overflow with gets and return address control"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(data.get("category"), "pwn")

    def test_knowledge(self):
        status, data = self._req("GET", "/v1/knowledge/health")
        self.assertEqual(status, 200)
        self.assertEqual(data.get("uncovered_signals"), {})


class TestOfflinePolicy(unittest.TestCase):
    def test_offline_policy(self):
        from agent.offline_ingest import policy
        p = policy()
        self.assertEqual(p["default"], "offline")


if __name__ == "__main__":
    unittest.main()
