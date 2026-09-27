# web_jwt_ambiguous (teaching lab)

**Ambiguous on purpose.** A JWT is present, but the useful bug may be **authorization**, not the algorithm.

Artifacts:
- `token.txt` — HS256-looking token with a bad signature segment
- `notes.txt` — server behavior hint

**Teaching goal:** form two hypotheses (alg/crypto vs authZ), gather evidence, eliminate.

**Expected techniques:** jwt validation *or* auth-bypass — do not assume the first guess.

**Provenance:** synthetic-lab
