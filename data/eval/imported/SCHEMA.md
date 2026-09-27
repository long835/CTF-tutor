# Imported challenge cases — provenance schema

Every imported case **must** include:

```json
{
  "id": "imp-...",
  "description": "...",
  "expected_category": "web",
  "expected_techniques": ["sql-injection"],
  "difficulty": "medium",
  "provenance": {
    "type": "imported",
    "source_url": "https://...",
    "license": "CC-BY-4.0 | unknown | public-domain | contest-terms",
    "attribution": "Author / CTF name / year",
    "retrieved": "YYYY-MM-DD",
    "notes": "rewritten summary; not a full writeup dump"
  }
}
```

Rules:
- `provenance.type` is always `"imported"` (never `"curated"`).
- Prefer rewritten public descriptions; do not paste full writeups.
- If license is unknown, say so and keep text minimal.
