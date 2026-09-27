#!/usr/bin/env python3
"""Teaching path-traversal lab. Localhost only."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
HOST, PORT = "127.0.0.1", 8768

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        name = (qs.get("file") or ["public.txt"])[0]
        # INTENTIONAL: naive join
        target = ROOT / "files" / name
        try:
            # also allow ../ via resolving incorrectly for teaching
            data = (ROOT / "files" / name).read_bytes() if ".." not in name else (ROOT / name).read_bytes()
        except Exception:
            try:
                data = Path(str(ROOT / "files") + "/" + name).resolve().read_bytes()
            except Exception as e:
                data = ("error: %s" % e).encode()
        # simpler intentional vuln:
        try:
            data = open(str(ROOT / "files" / name), "rb").read()
        except Exception:
            try:
                data = open(str(ROOT / name), "rb").read()
            except Exception as e:
                data = ("error: %s" % e).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *a):
        pass

if __name__ == "__main__":
    print("path lab http://%s:%s/?file=public.txt" % (HOST, PORT))
    print("try file=../secret.txt")
    HTTPServer((HOST, PORT), H).serve_forever()
