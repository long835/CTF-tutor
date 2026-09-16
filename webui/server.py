"""
webui/server.py

MVP interactive UI for CTF-Tutor (stdlib only — no FastAPI required).

  python -m webui.server
  open http://127.0.0.1:8765

Endpoints:
  GET  /           HTML UI
  POST /api/agent  JSON {description, path?, max_steps?, hint_level?}
  GET  /api/health
"""

from __future__ import annotations

import json
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

# ensure project root on path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

HOST = "127.0.0.1"
PORT = int(__import__("os").getenv("CTF_TUTOR_WEBUI_PORT", "8765"))

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>CTF-Tutor</title>
<style>
  :root { --bg:#0b1220; --card:#111827; --line:#1f2937; --text:#e7ecf3; --acc:#38bdf8; --ok:#34d399; --bad:#f87171; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: ui-sans-serif, system-ui, sans-serif; background:var(--bg); color:var(--text); }
  header { padding:1rem 1.5rem; border-bottom:1px solid var(--line); display:flex; gap:1rem; align-items:center; }
  header h1 { margin:0; font-size:1.25rem; color:var(--acc); }
  main { display:grid; grid-template-columns: 1fr 1fr; gap:1rem; padding:1rem; min-height: calc(100vh - 60px); }
  @media (max-width: 900px) { main { grid-template-columns: 1fr; } }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:1rem; display:flex; flex-direction:column; }
  label { font-size:0.85rem; color:#94a3b8; display:block; margin:0.5rem 0 0.25rem; }
  textarea, input, select { width:100%; background:#0f172a; border:1px solid var(--line); color:var(--text); border-radius:8px; padding:0.6rem; }
  textarea { min-height:120px; resize:vertical; }
  button { margin-top:0.75rem; background:var(--acc); color:#0b1220; border:0; border-radius:8px; padding:0.65rem 1rem; font-weight:600; cursor:pointer; }
  button:disabled { opacity:0.5; cursor:wait; }
  pre { white-space:pre-wrap; word-break:break-word; background:#0f172a; border-radius:8px; padding:0.75rem; flex:1; overflow:auto; font-size:0.85rem; }
  .meta { font-size:0.8rem; color:#94a3b8; margin-top:0.5rem; }
  .ok { color:var(--ok); } .bad { color:var(--bad); }
</style>
</head>
<body>
<header>
  <h1>CTF-Tutor</h1>
  <span class="meta">Local agent UI · no cloud required</span>
</header>
<main>
  <section class="card">
    <label>Challenge description</label>
    <textarea id="desc" placeholder="JWT login accepts alg=none..."></textarea>
    <label>Optional local path (--path)</label>
    <input id="path" placeholder="data/samples/crypto_b64_hex"/>
    <label>Max steps</label>
    <input id="steps" type="number" value="6" min="1" max="20"/>
    <label>Hint level (1-6)</label>
    <input id="hint" type="number" value="2" min="1" max="6"/>
    <button id="run">Run agent</button>
    <div class="meta" id="status">Idle</div>
  </section>
  <section class="card">
    <label>Output</label>
    <pre id="out">Results appear here.</pre>
  </section>
</main>
<script>
async function run() {
  const btn = document.getElementById('run');
  const status = document.getElementById('status');
  const out = document.getElementById('out');
  btn.disabled = true; status.textContent = 'Running...'; out.textContent = '';
  try {
    const body = {
      description: document.getElementById('desc').value,
      path: document.getElementById('path').value || null,
      max_steps: parseInt(document.getElementById('steps').value || '6', 10),
      hint_level: parseInt(document.getElementById('hint').value || '2', 10),
    };
    const r = await fetch('/api/agent', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || r.statusText);
    status.innerHTML = '<span class="ok">Done · ' + (data.status||'') + ' · conf ' + (data.confidence||0).toFixed(2) + '</span>';
    out.textContent = data.teaching || data.writeup || JSON.stringify(data, null, 2);
  } catch (e) {
    status.innerHTML = '<span class="bad">Error: ' + e.message + '</span>';
    out.textContent = String(e);
  } finally { btn.disabled = false; }
}
document.getElementById('run').onclick = run;
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body: bytes, content_type: str = "text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, HTML.encode("utf-8"))
            return
        if path == "/api/health":
            self._send(200, b'{"ok":true}', "application/json")
            return
        self._send(404, b"not found")

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/agent":
            self._send(404, b'{"error":"not found"}', "application/json")
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._send(400, b'{"error":"invalid json"}', "application/json")
            return
        desc = (payload.get("description") or "").strip()
        if not desc:
            self._send(400, b'{"error":"description required"}', "application/json")
            return
        try:
            from agent.loop import AgentLoop
            from agent.writeup import render_writeup
            agent = AgentLoop(
                challenge_summary=desc,
                category=payload.get("category"),
                max_steps=int(payload.get("max_steps") or 6),
                challenge_path=payload.get("path") or None,
                enable_trace=False,
            )
            agent.hint_level = int(payload.get("hint_level") or 2)
            state = agent.run(verify_at_end=True)
            body = {
                "ok": True,
                "status": state.status,
                "confidence": state.overall_confidence,
                "category": state.category,
                "flag_candidate": state.flag_candidate,
                "steps": state.step_count,
                "teaching": agent.teaching_summary(),
                "writeup": render_writeup(state),
            }
            self._send(200, json.dumps(body).encode("utf-8"), "application/json")
        except Exception as e:
            err = {"error": str(e), "trace": traceback.format_exc()[-1500:]}
            self._send(500, json.dumps(err).encode("utf-8"), "application/json")


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"CTF-Tutor Web UI → http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
