#!/usr/bin/env python3
"""Teaching-only local web lab: naive template render (SSTI-style).

Run:  python server.py
Open: http://127.0.0.1:8766/?name=World

WARNING: intentionally unsafe. Bind is localhost only.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

HOST, PORT = "127.0.0.1", 8766

PAGE = """<!doctype html>
<html><head><title>SSTI lab</title></head>
<body>
<h1>Greeting lab</h1>
<p>Hello, {name}</p>
<form method="get"><input name="name" value="{name}"/><button>Go</button></form>
<p><small>Teaching fixture — do not expose publicly.</small></p>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        name = (qs.get("name") or ["World"])[0]
        # Intentionally unsafe: format with user input (SSTI teaching analogue)
        try:
            body = PAGE.format(name=name)
        except Exception as e:
            body = f"<pre>render error: {e}</pre>"
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print("[lab]", fmt % args)


if __name__ == "__main__":
    print(f"SSTI teaching lab on http://{HOST}:{PORT}/?name=World")
    print("Try observing how input is reflected. Localhost only.")
    HTTPServer((HOST, PORT), Handler).serve_forever()
