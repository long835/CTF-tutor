"""
agent/http_api.py — local HTTP API wrapping core_api (item 39).

Stdlib-only (http.server). Bind defaults to 127.0.0.1 so it is not exposed
on the network unless the user opts in.

  python -m agent.http_api
  python main.py serve --port 8765

Endpoints (JSON):
  GET  /health
  GET  /v1/knowledge/health
  POST /v1/classify          {"description": "...", "artifacts": []}
  POST /v1/route             {"task": "plan", "model": null}
  POST /v1/eval              {"set": "public"}
  POST /v1/triage            {"description": "...", "artifacts": []}
  POST /v1/vision            {"path": "...", "use_model": false}
  POST /v1/research          {"query": "...", "online": false}
  GET  /v1/config
  GET  /v1/models/compare    (query: tasks=classify,plan)
  GET  /v1/cost
  GET  /v1/languages
"""

from __future__ import annotations

import json
import os
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse


def _json_response(handler: BaseHTTPRequestHandler, status: int, body: Any) -> None:
    data = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.end_headers()
    handler.wfile.write(data)


def _read_json(handler: BaseHTTPRequestHandler) -> Dict[str, Any]:
    length = int(handler.headers.get("Content-Length") or 0)
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        return json.loads(raw.decode("utf-8") or "{}")
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON: {e}") from e


def handle(method: str, path: str, body: Dict[str, Any], query: Dict[str, list]) -> Tuple[int, Any]:
    from agent import core_api

    if path in ("/", "/index.html") and method == "GET":
        return 200, {"_static": "frontend/index.html", "content_type": "text/html; charset=utf-8"}

    if path == "/health" and method == "GET":
        return 200, {"ok": True, "service": "ctf-tutor", "version": "0.3.2"}

    if path == "/v1/knowledge/health" and method == "GET":
        return 200, core_api.knowledge_health()

    if path == "/v1/classify" and method == "POST":
        desc = str(body.get("description") or "")
        if not desc:
            return 400, {"error": "description required"}
        return 200, core_api.classify(desc, artifacts=body.get("artifacts"))

    if path == "/v1/route" and method == "POST":
        task = str(body.get("task") or "plan")
        return 200, core_api.route(task, model=body.get("model"))

    if path == "/v1/eval" and method == "POST":
        which = str(body.get("set") or "ground_truth")
        return 200, core_api.run_eval(which)

    if path == "/v1/triage" and method == "POST":
        desc = str(body.get("description") or "")
        if not desc:
            return 400, {"error": "description required"}
        return 200, core_api.tutor_triage(desc, artifacts=body.get("artifacts"))

    if path == "/v1/vision" and method == "POST":
        p = body.get("path")
        if not p:
            return 400, {"error": "path required"}
        return 200, {
            "observations": core_api.observe_images(
                str(p),
                use_model=bool(body.get("use_model", False)),
                limit=int(body.get("limit") or 5),
            )
        }

    if path == "/v1/research" and method == "POST":
        from agent.research import research
        q = str(body.get("query") or "")
        if not q:
            return 400, {"error": "query required"}
        hits = research(
            q,
            category=body.get("category"),
            online=bool(body.get("online", False)),
            top_k=int(body.get("top_k") or 5),
        )
        return 200, {"hits": [h.to_dict() for h in hits]}

    if path == "/v1/config" and method == "GET":
        from agent.app_config import get_config
        return 200, get_config().public_dict()

    if path == "/v1/models/compare" and method == "GET":
        from agent.model_compare import compare_models
        models = (query.get("models") or [None])[0]
        tasks = (query.get("tasks") or ["classify,plan,teach"])[0]
        model_list = [m for m in (models or "").split(",") if m] or None
        task_list = [t for t in tasks.split(",") if t]
        return 200, compare_models(models=model_list, tasks=task_list)

    if path == "/v1/cost" and method == "GET":
        from agent.cost_meters import ledger_summary
        return 200, ledger_summary()

    if path == "/v1/languages" and method == "GET":
        from multilang import SUPPORTED_LANGUAGES
        return 200, {"languages": list(SUPPORTED_LANGUAGES)}

    if path == "/v1/embeddings/info" and method == "GET":
        from agent.embeddings import embedding_backend_info
        return 200, embedding_backend_info()

    return 404, {"error": "not found", "path": path}


class TutorHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        if os.getenv("CTF_TUTOR_API_LOG", "0") in ("1", "true", "True"):
            super().log_message(fmt, *args)

    def do_OPTIONS(self) -> None:  # noqa: N802
        _json_response(self, 204, {})

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        try:
            body = _read_json(self) if method == "POST" else {}
            status, payload = handle(method, parsed.path, body, parse_qs(parsed.query))
        except ValueError as e:
            status, payload = 400, {"error": str(e)}
        except Exception as e:
            status, payload = 500, {
                "error": str(e),
                "trace": traceback.format_exc() if os.getenv("CTF_TUTOR_API_DEBUG") else None,
            }
        if isinstance(payload, dict) and payload.get("_static"):
            self._serve_static(status, payload["_static"], payload.get("content_type") or "text/html")
            return
        _json_response(self, status, payload)

    def _serve_static(self, status: int, rel: str, content_type: str) -> None:
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        path = root / rel
        if not path.is_file():
            _json_response(self, 404, {"error": "static file missing", "path": rel})
            return
        data = path.read_bytes()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    httpd = ThreadingHTTPServer((host, port), TutorHandler)
    print(f"ctf-tutor API on http://{host}:{port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        httpd.server_close()


def main(argv: Optional[list] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(description="CTF-Tutor local HTTP API")
    p.add_argument("--host", default=os.getenv("CTF_TUTOR_API_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.getenv("CTF_TUTOR_API_PORT", "8765")))
    args = p.parse_args(argv)
    serve(args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
