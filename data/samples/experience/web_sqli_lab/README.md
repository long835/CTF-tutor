# web_sqli_lab (teaching lab)

Stdlib HTTP + sqlite3 login lookup with **string-built SQL**.

**Expected techniques:** sql-injection

```bash
python server.py
# http://127.0.0.1:8767/?user=admin
# try classic OR-based injection offline only
```

**Provenance:** synthetic-lab  
**Safety:** binds 127.0.0.1 only; intentional vulnerability for teaching.
