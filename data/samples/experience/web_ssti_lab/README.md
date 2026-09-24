# web_ssti_lab (teaching lab)

Stdlib HTTP server that reflects `?name=` via `str.format` — an **SSTI-style** teaching analogue (not a full Jinja sandbox escape).

**Expected techniques:** ssti, server-side-template-injection

**Run (localhost only):**
```bash
python server.py
# open http://127.0.0.1:8766/?name=World
```

**Teaching goal:** observe reflection / format behaviour; do not treat as a real exploit target outside a lab.

**Provenance:** synthetic-lab
