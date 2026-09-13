import sys
import os
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import requests

import llm_client
from tests.fakes import FakeOllamaHTTP


class TestCallOllamaEmbed(unittest.TestCase):
    def test_single_string_returns_one_vector(self):
        fake = FakeOllamaHTTP(embed_dim=4)
        with patch("requests.post", side_effect=fake):
            vectors = llm_client.call_ollama_embed("hello world")
        self.assertEqual(len(vectors), 1)
        self.assertEqual(len(vectors[0]), 4)
        # single string in -> input list of length 1 sent to Ollama
        self.assertEqual(fake.calls[0]["json"]["input"], ["hello world"])
        self.assertEqual(fake.calls[0]["url"], llm_client.OLLAMA_EMBED_URL)

    def test_batches_multiple_strings_in_one_call(self):
        fake = FakeOllamaHTTP(embed_dim=3)
        texts = ["doc one", "doc two", "doc three"]
        with patch("requests.post", side_effect=fake):
            vectors = llm_client.call_ollama_embed(texts)
        self.assertEqual(len(fake.calls), 1, "should be a single batched HTTP call")
        self.assertEqual(len(vectors), 3)
        self.assertEqual(fake.calls[0]["json"]["input"], texts)

    def test_empty_list_returns_empty_without_http_call(self):
        with patch("requests.post") as mock_post:
            vectors = llm_client.call_ollama_embed([])
        self.assertEqual(vectors, [])
        mock_post.assert_not_called()

    def test_custom_model_is_sent(self):
        fake = FakeOllamaHTTP()
        with patch("requests.post", side_effect=fake):
            llm_client.call_ollama_embed("x", model="custom-embed-model")
        self.assertEqual(fake.calls[0]["json"]["model"], "custom-embed-model")

    def test_connection_error_raises_helpful_runtime_error(self):
        with patch("requests.post", side_effect=requests.exceptions.ConnectionError()):
            with self.assertRaises(RuntimeError) as ctx:
                llm_client.call_ollama_embed("hello")
        self.assertIn("Could not reach Ollama", str(ctx.exception))

    def test_timeout_raises_helpful_runtime_error(self):
        with patch("requests.post", side_effect=requests.exceptions.ReadTimeout()):
            with self.assertRaises(RuntimeError) as ctx:
                llm_client.call_ollama_embed("hello")
        self.assertIn("60s", str(ctx.exception))

    def test_missing_embeddings_key_raises_runtime_error(self):
        class BadResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {"unexpected": "shape"}

        with patch("requests.post", return_value=BadResponse()):
            with self.assertRaises(RuntimeError) as ctx:
                llm_client.call_ollama_embed("hello")
        self.assertIn("embeddings", str(ctx.exception))


class TestCallOllamaChat(unittest.TestCase):
    def test_returns_message_content(self):
        fake = FakeOllamaHTTP(chat_reply="hi there")
        with patch("requests.post", side_effect=fake):
            result = llm_client.call_ollama("system", "user")
        self.assertEqual(result, "hi there")
        self.assertEqual(fake.calls[0]["url"], llm_client.OLLAMA_URL)


class TestExtractJsonObjectLenient(unittest.TestCase):
    def test_returns_parsed_json_when_present(self):
        text = 'Here you go: {"hint": "jwt-alg-confusion"} thanks'
        parsed = llm_client.extract_json_object_lenient(text, fallback_key="hint")
        self.assertEqual(parsed, {"hint": "jwt-alg-confusion"})

    def test_falls_back_to_raw_text_when_no_json(self):
        text = "It's probably a padding oracle, no JSON here."
        parsed = llm_client.extract_json_object_lenient(text, fallback_key="hint")
        self.assertEqual(parsed, {"hint": text})

    def test_fallback_strips_think_blocks(self):
        text = "<think>let me reason about this</think>Just use sqlmap."
        parsed = llm_client.extract_json_object_lenient(text, fallback_key="hint")
        self.assertEqual(parsed["hint"], "Just use sqlmap.")

    def test_think_block_with_stray_braces_does_not_break_strict_extraction(self):
        # Regression test for the README-documented qwen3 fix: reasoning
        # text containing its own { } must not corrupt extraction of the
        # real JSON object that follows it.
        text = (
            "<think>I'm thinking about {this} and [that] before answering</think>"
            '{"explanation": "uses a padding oracle", "cited_entries": []}'
        )
        parsed = llm_client.extract_json_object(text)
        self.assertEqual(parsed["explanation"], "uses a padding oracle")


if __name__ == "__main__":
    unittest.main()