"""
agent/dashboard.py

Static HTML reporting: benchmark dashboard and trace viewer (Phase 7).

Two things were hard to look at before this module existed. Benchmark
results lived in JSON that you had to read by eye, and agent traces were
JSONL that you had to reconstruct mentally to understand why a run went
the way it did.

Both outputs here are single self-contained HTML files — no CDN, no build
step, no server. They open from disk, which matters for a tool whose whole
premise is that it works offline.
"""

from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

EXP_DIR = Path("data/experiments")
TRACE_DIR = Path("data/traces")
REPORT_DIR = Path("data/reports")

_STYLE = """
:root {
  --bg:#0b1220; --card:#111827; --line:#1f2937; --text:#e7ecf3;
  --muted:#94a3b8; --acc:#38bdf8; --ok:#34d399; --warn:#fbbf24; --bad:#f87171;
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text);
  font-family:ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; line-height:1.55; }
header { padding:1.5rem 2rem; border-bottom:1px solid var(--line); }
header h1 { margin:0 0 .25rem; font-size:1.4rem; color:var(--acc); }
header .sub { color:var(--muted); font-size:.85rem; }
main { padding:1.5rem 2rem; max-width:1100px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:1rem; margin-bottom:1.5rem; }
.metric { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:1rem; }
.metric .label { color:var(--muted); font-size:.78rem; text-transform:uppercase; letter-spacing:.04em; }
.metric .value { font-size:1.9rem; font-weight:650; margin-top:.35rem; }
.card { background:var(--card); border:1px solid var(--line); border-radius:12px;
  padding:1.1rem 1.25rem; margin-bottom:1.25rem; }
.card h2 { margin:0 0 .75rem; font-size:1.05rem; color:var(--acc); }
table { width:100%; border-collapse:collapse; font-size:.88rem; }
th, td { text-align:left; padding:.5rem .6rem; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:.78rem; text-transform:uppercase; letter-spacing:.03em; }
tr:last-child td { border-bottom:0; }
.ok { color:var(--ok); } .warn { color:var(--warn); } .bad { color:var(--bad); }
.muted { color:var(--muted); }
.bar { height:7px; border-radius:4px; background:#1e293b; overflow:hidden; min-width:70px; }
.bar > span { display:block; height:100%; background:var(--acc); }
.pill { display:inline-block; padding:.1rem .5rem; border-radius:999px;
  font-size:.74rem; border:1px solid var(--line); color:var(--muted); }
.empty { color:var(--muted); font-style:italic; }
details { border-left:2px solid var(--line); padding-left:.85rem; margin:.4rem 0; }
details[open] { border-left-color:var(--acc); }
summary { cursor:pointer; padding:.3rem 0; }
summary::marker { color:var(--muted); }
pre { background:#0f172a; border-radius:8px; padding:.7rem; overflow:auto;
  font-size:.8rem; white-space:pre-wrap; word-break:break-word; margin:.4rem 0 0; }
.step { color:var(--muted); font-variant-numeric:tabular-nums; font-size:.8rem; }
footer { padding:1.5rem 2rem; color:var(--muted); font-size:.78rem; border-top:1px solid var(--line); }
"""


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _pct(value: Any) -> str:
    try:
        return f"{float(value) * 100:.0f}%"
    except (TypeError, ValueError):
        return "—"


def _rate_class(value: Any, good: float = 0.7, ok: float = 0.4) -> str:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "muted"
    if v >= good:
        return "ok"
    if v >= ok:
        return "warn"
    return "bad"


def _bar(value: Any) -> str:
    try:
        pct = max(0.0, min(1.0, float(value))) * 100
    except (TypeError, ValueError):
        pct = 0.0
    return f'<div class="bar"><span style="width:{pct:.0f}%"></span></div>'


def _page(title: str, subtitle: str, body: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{_esc(title)}</title>
<style>{_STYLE}</style>
</head>
<body>
<header>
  <h1>{_esc(title)}</h1>
  <div class="sub">{_esc(subtitle)}</div>
</header>
<main>
{body}
</main>
<footer>Generated {stamp} by CTF-Tutor · offline, self-contained, no external requests.</footer>
</body>
</html>
"""


# ------------------------------------------------------------------ loading


def load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def load_jsonl(path: Path, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return rows
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if limit:
        rows = rows[-limit:]
    return rows


def latest_trace(trace_dir: Path = TRACE_DIR) -> Optional[Path]:
    root = Path(trace_dir)
    if not root.is_dir():
        return None
    traces = sorted(root.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    return traces[0] if traces else None


# ---------------------------------------------------------------- dashboard


def _metric(label: str, value: str, klass: str = "") -> str:
    cls = f' class="value {klass}"' if klass else ' class="value"'
    return f'<div class="metric"><div class="label">{_esc(label)}</div><div{cls}>{value}</div></div>'


def _eval_section(summary: Dict[str, Any]) -> str:
    rows = summary.get("results") or []
    if not rows:
        return ""
    body = []
    for r in rows:
        hit = r.get("technique_hit")
        cat_ok = r.get("category_ok")
        body.append(
            "<tr>"
            f"<td>{_esc(r.get('id'))}</td>"
            f"<td><span class='pill'>{_esc(r.get('difficulty') or '—')}</span></td>"
            f"<td>{_esc(r.get('expected_category'))} → {_esc(r.get('got_category'))} "
            f"<span class='{'ok' if cat_ok else 'bad'}'>{'✓' if cat_ok else '✗'}</span></td>"
            f"<td class='{'ok' if hit else 'bad'}'>{'hit' if hit else 'miss'}</td>"
            f"<td class='muted'>{_esc(', '.join((r.get('found_techniques') or [])[:3]) or '—')}</td>"
            f"<td class='step'>{_esc(r.get('steps'))}</td>"
            "</tr>"
        )
    return (
        '<div class="card"><h2>Per-case results</h2><table>'
        "<tr><th>case</th><th>difficulty</th><th>category</th><th>technique</th>"
        "<th>found</th><th>steps</th></tr>"
        + "".join(body)
        + "</table></div>"
    )


def _matrix_section(matrix: Dict[str, Dict[str, float]]) -> str:
    if not matrix:
        return ""
    categories = sorted({c for row in matrix.values() for c in row})
    head = "".join(f"<th>{_esc(c)}</th>" for c in categories)
    body = []
    for difficulty in sorted(matrix, key=lambda d: ["easy", "medium", "hard", "insane"].index(d)
                             if d in ("easy", "medium", "hard", "insane") else 99):
        cells = []
        for c in categories:
            v = matrix[difficulty].get(c)
            if v is None:
                cells.append('<td class="muted">—</td>')
            else:
                cells.append(f'<td class="{_rate_class(v)}">{_pct(v)}</td>')
        body.append(f"<tr><th>{_esc(difficulty)}</th>{''.join(cells)}</tr>")
    return (
        '<div class="card"><h2>Technique hit rate by difficulty and category</h2>'
        f"<table><tr><th></th>{head}</tr>{''.join(body)}</table></div>"
    )


def _leaderboard_section(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return ""
    body = []
    for r in rows[-15:][::-1]:
        body.append(
            "<tr>"
            f"<td class='muted'>{_esc(r.get('id'))}</td>"
            f"<td>{_esc(r.get('category') or '—')}</td>"
            f"<td>{_esc(r.get('status'))}</td>"
            f"<td>{_bar(r.get('confidence'))}</td>"
            f"<td class='step'>{_esc(r.get('steps'))}</td>"
            f"<td class='step'>{_esc(r.get('duration_sec'))}s</td>"
            "</tr>"
        )
    return (
        '<div class="card"><h2>Recent runs</h2><table>'
        "<tr><th>run</th><th>category</th><th>status</th><th>confidence</th>"
        "<th>steps</th><th>time</th></tr>" + "".join(body) + "</table></div>"
    )


def build_dashboard(
    eval_summary: Optional[Dict[str, Any]] = None,
    benchmark: Optional[Dict[str, Any]] = None,
    leaderboard: Optional[List[Dict[str, Any]]] = None,
    corpus_summary: Optional[Dict[str, Any]] = None,
    audit: Optional[Dict[str, Any]] = None,
) -> str:
    """Render the benchmark dashboard as one self-contained HTML string."""
    sections: List[str] = []
    metrics: List[str] = []

    if eval_summary:
        cat = eval_summary.get("category_accuracy")
        tech = eval_summary.get("technique_hit_rate")
        metrics += [
            _metric("Eval cases", str(eval_summary.get("n", 0))),
            _metric("Category accuracy", _pct(cat), _rate_class(cat)),
            _metric("Technique hit rate", _pct(tech), _rate_class(tech)),
            _metric("Avg steps", f"{eval_summary.get('avg_steps', 0):.1f}"),
        ]

    if benchmark:
        solved = benchmark.get("solved_or_verified")
        metrics += [
            _metric("Benchmark cases", str(benchmark.get("n", 0))),
            _metric("Solved / verified", _pct(solved), _rate_class(solved)),
            _metric("Avg run time", f"{benchmark.get('avg_duration_sec', 0):.1f}s"),
        ]

    if corpus_summary:
        metrics += [
            _metric("Corpus cards", str(corpus_summary.get("total", 0))),
            _metric("Distinct techniques", str(corpus_summary.get("distinct_techniques", 0))),
        ]

    if audit:
        contradictions = len(audit.get("contradictions") or [])
        metrics += [
            _metric("Archive entries", str(audit.get("entries", 0))),
            _metric(
                "Provenance coverage",
                _pct(audit.get("provenance_coverage")),
                _rate_class(audit.get("provenance_coverage"), 0.99, 0.8),
            ),
            _metric(
                "Contradictions",
                str(contradictions),
                "ok" if contradictions == 0 else "warn",
            ),
        ]

    if metrics:
        sections.append(f'<div class="grid">{"".join(metrics)}</div>')

    if eval_summary:
        sections.append(_matrix_section(eval_summary.get("difficulty_matrix") or {}))
        statuses = eval_summary.get("statuses") or {}
        if statuses:
            pills = " ".join(
                f'<span class="pill">{_esc(k)}: {_esc(v)}</span>' for k, v in sorted(statuses.items())
            )
            sections.append(f'<div class="card"><h2>Run outcomes</h2>{pills}</div>')
        sections.append(_eval_section(eval_summary))

    if corpus_summary and corpus_summary.get("by_kind"):
        rows = "".join(
            f"<tr><td>{_esc(k)}</td><td class='step'>{_esc(v)}</td></tr>"
            for k, v in (corpus_summary.get("by_kind") or {}).items()
        )
        sections.append(
            f'<div class="card"><h2>Corpus composition</h2><table>'
            f"<tr><th>card kind</th><th>count</th></tr>{rows}</table></div>"
        )

    if audit and (audit.get("contradictions") or audit.get("invalid")):
        rows = []
        for c in (audit.get("contradictions") or [])[:20]:
            rows.append(
                f"<tr><td>{_esc(c.get('technique'))}</td>"
                f"<td class='muted'>{_esc(c.get('entry_a'))} vs {_esc(c.get('entry_b'))}</td>"
                f"<td class='warn'>{_esc(c.get('reason'))}</td></tr>"
            )
        for v in (audit.get("invalid") or [])[:20]:
            rows.append(
                f"<tr><td class='bad'>invalid</td><td class='muted'>{_esc(v.get('entry'))}</td>"
                f"<td class='bad'>{_esc('; '.join(v.get('errors') or []))}</td></tr>"
            )
        sections.append(
            '<div class="card"><h2>Archive issues</h2><table>'
            "<tr><th>technique</th><th>entries</th><th>issue</th></tr>"
            + "".join(rows)
            + "</table></div>"
        )

    if leaderboard:
        sections.append(_leaderboard_section(leaderboard))

    if not sections:
        sections.append(
            '<div class="card"><p class="empty">No results yet. '
            "Run <code>python -m agent.eval_agent</code> or "
            "<code>python main.py experiment --benchmark</code> first.</p></div>"
        )

    return _page(
        "CTF-Tutor · benchmark dashboard",
        "Offline evaluation, corpus health, and archive quality at a glance.",
        "\n".join(s for s in sections if s),
    )


# -------------------------------------------------------------- trace viewer

_EVENT_HINTS = {
    "state_snapshot": ("snapshot", "muted"),
    "plan": ("planned", "warn"),
    "tool_start": ("tool", "muted"),
    "tool_end": ("tool done", "ok"),
    "observation": ("observed", "ok"),
    "hypothesis_update": ("hypotheses", "warn"),
    "verify": ("verify", "ok"),
    "error": ("error", "bad"),
}


def build_trace_view(events: List[Dict[str, Any]], source: str = "") -> str:
    """
    Render one JSONL trace as a readable timeline.

    The point is to answer "why did it do that?" — so hypotheses and their
    confidences get promoted out of the raw payload, and everything else
    stays collapsed until you ask for it.
    """
    if not events:
        return _page(
            "CTF-Tutor · trace viewer",
            source or "no trace",
            '<div class="card"><p class="empty">This trace is empty. Run the agent with tracing enabled.</p></div>',
        )

    counts: Dict[str, int] = {}
    for e in events:
        counts[e.get("event", "?")] = counts.get(e.get("event", "?"), 0) + 1

    snapshots = [e for e in events if e.get("event") == "state_snapshot"]
    final = snapshots[-1] if snapshots else {}

    metrics = [
        _metric("Events", str(len(events))),
        _metric("Steps", str(final.get("step", "—"))),
        _metric("Final status", _esc(final.get("status", "—"))),
        _metric(
            "Confidence",
            _pct(final.get("confidence")) if final.get("confidence") is not None else "—",
            _rate_class(final.get("confidence")),
        ),
    ]

    timeline: List[str] = []
    for i, e in enumerate(events, 1):
        name = e.get("event", "?")
        label, klass = _EVENT_HINTS.get(name, (name, "muted"))
        ts = str(e.get("ts", ""))[11:19]
        payload = {k: v for k, v in e.items() if k not in ("event", "ts")}

        headline = ""
        if name == "state_snapshot":
            hyps = payload.get("hypotheses") or []
            if hyps:
                top = hyps[0]
                headline = f"top: {top.get('tech') or '—'} ({float(top.get('conf', 0)):.2f}) — {top.get('stmt', '')}"
        elif payload.get("tool"):
            headline = f"{payload.get('tool')} {payload.get('reason', '')}"
        elif payload.get("summary"):
            headline = str(payload["summary"])
        headline = headline[:200]

        timeline.append(
            "<details>"
            f"<summary><span class='step'>{i:>3}</span> "
            f"<span class='{klass}'>{_esc(label)}</span> "
            f"<span class='muted'>{_esc(ts)}</span> {_esc(headline)}</summary>"
            f"<pre>{_esc(json.dumps(payload, indent=2, default=str)[:4000])}</pre>"
            "</details>"
        )

    hypothesis_card = ""
    if final.get("hypotheses"):
        rows = "".join(
            f"<tr><td>{_esc(h.get('tech') or '—')}</td>"
            f"<td>{_bar(h.get('conf'))}</td>"
            f"<td class='step'>{float(h.get('conf', 0)):.2f}</td>"
            f"<td class='muted'>{_esc(h.get('stmt'))}</td></tr>"
            for h in final["hypotheses"]
        )
        hypothesis_card = (
            '<div class="card"><h2>Final hypotheses</h2><table>'
            "<tr><th>technique</th><th>confidence</th><th></th><th>claim</th></tr>"
            f"{rows}</table></div>"
        )

    breakdown = " ".join(
        f'<span class="pill">{_esc(k)}: {_esc(v)}</span>' for k, v in sorted(counts.items())
    )

    body = (
        f'<div class="grid">{"".join(metrics)}</div>'
        f'<div class="card"><h2>Event mix</h2>{breakdown}</div>'
        f"{hypothesis_card}"
        f'<div class="card"><h2>Timeline</h2><p class="muted">Click any row to expand its payload.</p>'
        f'{"".join(timeline)}</div>'
    )
    return _page("CTF-Tutor · trace viewer", source or "agent trace", body)


# ------------------------------------------------------------------ entry


def write_dashboard(
    out_path: str = str(REPORT_DIR / "dashboard.html"),
    run_eval: bool = False,
) -> str:
    """
    Collect whatever results exist on disk and write the dashboard.

    With `run_eval=True` the offline evaluator runs first so the dashboard
    has something to show on a fresh checkout.
    """
    eval_summary: Optional[Dict[str, Any]] = None
    if run_eval:
        try:
            from agent.eval_agent import run_eval as _run

            eval_summary = _run()
        except Exception:
            eval_summary = None
    if eval_summary is None:
        eval_summary = load_json(EXP_DIR / "last_eval.json")

    benchmark = load_json(EXP_DIR / "last_benchmark.json")
    leaderboard = load_jsonl(EXP_DIR / "leaderboard.jsonl", limit=50)

    corpus_summary = None
    try:
        corpus_path = Path("data/corpus/challenges.jsonl")
        if corpus_path.is_file():
            rows = load_jsonl(corpus_path)
            kinds: Dict[str, int] = {}
            techs = set()
            for r in rows:
                kinds[r.get("kind", "unknown")] = kinds.get(r.get("kind", "unknown"), 0) + 1
                techs |= {str(t) for t in (r.get("techniques") or [])}
            corpus_summary = {
                "total": len(rows),
                "distinct_techniques": len(techs),
                "by_kind": dict(sorted(kinds.items())),
            }
    except Exception:
        corpus_summary = None

    audit = None
    try:
        from agent.provenance import audit_archive

        audit = audit_archive()
    except Exception:
        audit = None

    html_doc = build_dashboard(
        eval_summary=eval_summary,
        benchmark=benchmark,
        leaderboard=leaderboard,
        corpus_summary=corpus_summary,
        audit=audit,
    )
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_doc, encoding="utf-8")
    return str(out)


def write_trace_view(
    trace_path: Optional[str] = None,
    out_path: str = str(REPORT_DIR / "trace.html"),
) -> Optional[str]:
    """Render a trace (the newest one by default) to HTML."""
    path = Path(trace_path) if trace_path else latest_trace()
    if not path or not Path(path).is_file():
        return None
    events = load_jsonl(Path(path))
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_trace_view(events, source=str(path)), encoding="utf-8")
    return str(out)


if __name__ == "__main__":
    print(write_dashboard(run_eval=False))
