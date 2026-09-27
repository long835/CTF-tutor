#!/usr/bin/env python3
"""Teaching-only SQLi lab using stdlib + sqlite3. Localhost only."""
from __future__ import annotations

import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HOST, PORT = "127.0.0.1", 8767
DB = Path(__file__).with_name("lab.db")


def init_db() -> None:
    if DB.exists():
        return
    conn = sqlite3.connect(DB)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT, secret TEXT)"
    )
    conn.execute(
        "INSERT INTO users (name, role, secret) VALUES ('admin', 'admin', 'flag{sqli_lab}')"
    )
    conn.execute(
        "INSERT INTO users (name, role, secret) VALUES ('bob', 'user', 'not_the_flag')"
    )
    conn.commit()
    conn.close()


PAGE = """<!doctype html>
<html><body>
<h1>SQLi teaching lab</h1>
<form method="get">
  <input name="user" value="{user}" placeholder="username"/>
  <button>Lookup</button>
</form>
<pre>{result}</pre>
<p><small>Localhost only. Intentionally vulnerable.</small></p>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        user = (qs.get("user") or [""])[0]
        result = ""
        if user:
            q = "SELECT name, role, secret FROM users WHERE name = '" + user + "'"
            try:
                conn = sqlite3.connect(DB)
                rows = conn.execute(q).fetchall()
                conn.close()
                result = chr(10).join(str(r) for r in rows) if rows else "(no rows)"
            except Exception as e:
                result = "SQL error: " + str(e)
        body = PAGE.format(user=user, result=result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("[sqli-lab]", fmt % args)


if __name__ == "__main__":
    init_db()
    print("SQLi lab http://%s:%s/?user=admin" % (HOST, PORT))
    HTTPServer((HOST, PORT), Handler).serve_forever()
