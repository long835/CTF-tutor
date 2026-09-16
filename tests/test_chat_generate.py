import json, os, sys, unittest
from unittest.mock import patch
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import chat_generate, main

class TestChatGenerate(unittest.TestCase):
    def test_chat_uses_local_model(self):
        with patch.object(chat_generate, 'call_ollama', return_value='answer') as call:
            self.assertEqual(chat_generate.chat('hello'), 'answer'); call.assert_called_once()
    def test_generate_validates_schema(self):
        obj={'challenge_name':'x','category':'web','difficulty':'easy','description':'d','learning_objectives':['x'],'files':[],'validation_notes':'local'}
        with patch.object(chat_generate, 'call_ollama', return_value=json.dumps(obj)):
            self.assertEqual(chat_generate.generate('jwt'), obj)
    def test_dispatch_names(self):
        self.assertIn('chat', main.SUBCOMMAND_NAMES); self.assertIn('generate', main.SUBCOMMAND_NAMES); self.assertIn('session', main.SUBCOMMAND_NAMES)
