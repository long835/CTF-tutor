# Test tiers

| Tier | Command | Target |
|------|---------|--------|
| **Fast / release** | `python main.py gate` | < ~2 min, must be green to ship |
| **Full discover** | `python main.py gate --full` | full `unittest discover` (may be slow) |
| **External hard** | `python main.py eval --external` | generalization probe |

If full discover exceeds several minutes, investigate network/LLM/subprocess tests;
prefer mocks from `tests/fakes.py`.
