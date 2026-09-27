# web_path_lab (teaching lab)

Local file server with naive path join. Secret is outside `files/`.

```bash
python server.py
# http://127.0.0.1:8768/?file=public.txt
# try: ?file=../secret.txt
```

**Expected techniques:** path-traversal  
**Provenance:** synthetic-lab
