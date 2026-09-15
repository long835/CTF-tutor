"""
agent/loop.py

Closed investigative loop:

  understand → form hypotheses → plan action → execute → observe
  → update hypotheses → (repeat) → verify

This is the core behavior that turns CTF-Tutor from a one-shot pipeline
into an actual agent.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

from agent.state import AgentState, ActionStatus, new_challenge_state
from agent.hypothesis import generate_initial_hypotheses, rank_hypotheses
from agent.planner import plan_next_action, action_to_record
from agent.executor import execute_action
from agent.observer import observe
from agent.verifier import verify_solution, apply_verification


class AgentLoop:
    """
    Stateful CTF investigation agent.

    Usage:
        agent = AgentLoop(summary="...", category="web")
        final_state = agent.run()
        # or step-by-step:
        agent.bootstrap()
        while agent.can_continue():
            step = agent.step()
    """

    def __init__(
        self,
        challenge_summary: str,
        category: Optional[str] = None,
        challenge_id: Optional[str] = None,
        max_steps: int = 12,
        on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        model: Optional[str] = None,
        challenge_path: Optional[str] = None,
        enable_trace: bool = True,
    ):
        self.state = new_challenge_state(
            summary=challenge_summary,
            category=category,
            challenge_id=challenge_id,
            max_steps=max_steps,
        )
        self.on_event = on_event or (lambda *_: None)
        self.model = model
        self.challenge_path = challenge_path
        self._bootstrapped = False
        self.trace = None
        self.workspace = None
        self.learner = None
        self.hint_level = 2
        self.step_timeout_sec = 25.0
        if enable_trace:
            try:
                from agent.trace import TraceLogger
                self.trace = TraceLogger(enabled=True)
            except Exception:
                self.trace = None
        try:
            from agent.memory import load_memory
            self.learner = load_memory()
        except Exception:
            self.learner = None

    def _emit(self, event: str, **payload: Any) -> None:
        self.on_event(event, payload)

    def bootstrap(self) -> AgentState:
        """Triage (optional) + classification seed + first hypotheses."""
        if self._bootstrapped:
            return self.state
        self._emit("bootstrap_start", challenge=self.state.challenge_summary[:200])
        if self.trace:
            self.trace.log("bootstrap_start", summary=self.state.challenge_summary[:300])

        # Challenge triage if a path was provided
        if self.challenge_path:
            try:
                from agent.triage import inventory_path, apply_inventory_to_state
                inv = inventory_path(self.challenge_path)
                apply_inventory_to_state(self.state, inv)
                self._emit(
                    "triage_done",
                    files=inv.file_count,
                    categories=inv.categories_hint,
                    tools=inv.recommended_tools,
                )
                if self.trace:
                    self.trace.log("triage", inventory=inv.to_dict())
            except Exception as e:
                self.state.add_fact(f"Triage failed: {e}")

        # Seed category if missing (heuristic only — no LLM required)
        if not self.state.category:
            try:
                from classifier import classify_heuristic
                cat, scores = classify_heuristic(self.state.challenge_summary)
                if cat:
                    self.state.category = cat
                    self.state.add_fact(f"Heuristic category: {cat} (scores={scores})")
            except Exception as e:
                self.state.add_fact(f"Classification seed failed: {e}")

        # Skill pack playbook
        try:
            from agent.skill_packs import pack_summary
            summary = pack_summary(self.state.category)
            if summary:
                self.state.add_fact(summary.split(chr(10))[0])
                self.state.lessons.append(summary)
        except Exception:
            pass

        # Initial hypotheses
        generate_initial_hypotheses(self.state, model=self.model or None)

        # If category still unknown, take it from the strongest hypothesis
        if not self.state.category:
            top = self.state.top_hypothesis()
            if top and top.category:
                self.state.category = top.category
                self.state.add_fact(f"Category inferred from hypothesis: {top.category}")
        # Workspace persistence
        try:
            from agent.workspace import ChallengeWorkspace
            self.workspace = ChallengeWorkspace(self.state.challenge_id).ensure()
            if self.challenge_path:
                try:
                    self.workspace.import_path(self.challenge_path)
                except Exception as e:
                    self.state.add_fact(f"Workspace import note: {e}")
            self.workspace.save_state(self.state)
        except Exception as e:
            self.state.add_fact(f"Workspace unavailable: {e}")

        # Surface weak techniques from learner memory
        if self.learner:
            weak = self.learner.weak_techniques()
            if weak:
                self.state.add_fact(f"Learner weak techniques: {', '.join(weak[:5])}")
                self.state.lessons.append(
                    "Review prerequisites for: " + ", ".join(weak[:3])
                )

        self._bootstrapped = True
        self._emit(
            "bootstrap_done",
            category=self.state.category,
            hypothesis_count=len(self.state.hypotheses),
            top=[h.statement for h in rank_hypotheses(self.state)[:3]],
        )
        if self.trace:
            self.trace.log_state_snapshot(self.state)
        return self.state

    def can_continue(self) -> bool:
        if self.state.status in ("verified", "solved", "failed"):
            return False
        if self.state.flag_candidate and self.state.overall_confidence >= 0.85:
            self.state.status = "solved"
            if not self.state.hypotheses:
                self.state.add_hypothesis(
                    statement=f"Recovered flag material: {self.state.flag_candidate}",
                    technique="flag-recovery",
                    category=self.state.category or "misc",
                    confidence=0.95,
                )
            return False
        if self.state.step_count >= self.state.max_steps:
            return False
        return True

    def step(self) -> Dict[str, Any]:
        """
        Execute one full plan → act → observe → update cycle.
        Returns a dict describing what happened.
        """
        if not self._bootstrapped:
            self.bootstrap()

        if not self.can_continue():
            return {"stopped": True, "reason": self.state.status, "state": self.state}

        self.state.step_count += 1
        plan = plan_next_action(self.state)
        if plan is None:
            self.state.status = "stuck"
            self._emit("stuck", step=self.state.step_count)
            return {"stopped": True, "reason": "no_action", "state": self.state}

        # Permission gate
        try:
            from agent.permissions import allowed, required_permission
            if not allowed(plan.tool):
                self.state.add_fact(
                    f"Blocked tool {plan.tool} (needs {required_permission(plan.tool).value})"
                )
                self._emit("permission_denied", tool=plan.tool)
                # count step but skip execution
                return {"step": self.state.step_count, "tool": plan.tool, "success": False,
                        "blocked": True, "state": self.state}
        except Exception:
            pass

        record = action_to_record(plan, self.state)
        self._emit(
            "action_planned",
            step=self.state.step_count,
            tool=plan.tool,
            reason=plan.reason,
            args=plan.arguments,
        )

        # Execute
        t0 = time.time()
        record.status = ActionStatus.RUNNING.value
        record.started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            success, output, error = execute_action(record)
        except Exception as exc:
            success, output, error = False, "", f"executor crash: {exc}"
        duration_ms = int((time.time() - t0) * 1000)
        if duration_ms > self.step_timeout_sec * 1000:
            error = (error + f" | step exceeded {self.step_timeout_sec}s").strip(" |")
            success = False

        status = ActionStatus.SUCCEEDED.value if success else ActionStatus.FAILED.value
        summary = (output[:300] if success else error[:300])
        self.state.mark_action_result(
            record.id,
            status=status,
            result_summary=summary,
            raw_output=output,
            error=error,
            duration_ms=duration_ms,
        )

        # Observe → evidence → hypothesis update
        observe(
            self.state,
            tool=plan.tool,
            raw_output=output,
            success=success,
            error=error,
        )

        self._emit(
            "action_finished",
            step=self.state.step_count,
            tool=plan.tool,
            success=success,
            summary=summary[:200],
            confidence=self.state.overall_confidence,
        )

        # Early exit on user question
        if plan.tool == "ask_user" and success:
            self.state.status = "stuck"  # waiting for user
            return {
                "needs_user": True,
                "question": plan.arguments.get("question", ""),
                "state": self.state,
            }

        return {
            "step": self.state.step_count,
            "tool": plan.tool,
            "success": success,
            "state": self.state,
        }

    def run(self, verify_at_end: bool = True) -> AgentState:
        """Run until budget exhausted, verified, or stuck."""
        self.bootstrap()
        while self.can_continue():
            result = self.step()
            if result.get("needs_user") or result.get("stopped"):
                break

        if verify_at_end and self.state.status not in ("verified", "failed"):
            # Try to form a candidate from top hypothesis + evidence
            top = self.state.top_hypothesis()
            if top and not self.state.solution_summary:
                self.state.solution_summary = (
                    f"Leading hypothesis ({top.confidence:.2f}): {top.statement}"
                )
            verdict = verify_solution(self.state, self.state.solution_summary or self.state.flag_candidate)
            apply_verification(self.state, verdict)
            self._emit("verification", **verdict)

        if self.state.step_count >= self.state.max_steps and self.state.status == "investigating":
            self.state.status = "stuck"

        # Persist workspace + learner stats
        if self.workspace:
            try:
                self.workspace.save_state(self.state)
            except Exception:
                pass
        if self.learner:
            try:
                from agent.memory import save_memory
                success = self.state.status in ("verified", "solved")
                # Only track confirmed/high-confidence techniques to reduce noise
                for h in self.state.hypotheses:
                    if h.technique and (h.status == "confirmed" or h.confidence >= 0.55):
                        self.learner.record_attempt(
                            h.technique, success=success, hints=self.state.hint_level_reached
                        )
                save_memory(self.learner)
            except Exception:
                pass

        self._emit("finished", status=self.state.status, confidence=self.state.overall_confidence)
        return self.state

    def teaching_summary(self) -> str:
        """Human-readable investigation narrative for the learner."""
        lines = [
            f"## Investigation: {self.state.challenge_summary[:120]}",
            f"Category: {self.state.category or 'unknown'} | "
            f"Status: {self.state.status} | Confidence: {self.state.overall_confidence:.2f}",
            "",
            "### Hypotheses considered",
        ]
        for h in rank_hypotheses(self.state):
            lines.append(f"- [{h.confidence:.2f}] {h.statement}  ({h.technique or '—'})")
        lines.append("")
        lines.append("### Evidence collected")
        for e in self.state.evidence[-8:]:
            lines.append(f"- [{e.source}] {e.finding or e.content[:100]}")
        if self.state.solution_summary:
            lines.append("")
            lines.append("### Current conclusion")
            lines.append(self.state.solution_summary)
        if self.state.lessons:
            lines.append("")
            lines.append("### Lessons")
            for L in self.state.lessons:
                lines.append(f"- {L}")
        try:
            from agent.teaching import teaching_report
            lines.append("")
            lines.append(teaching_report(self.state, hint_level=self.hint_level))
        except Exception:
            pass
        try:
            from agent.writeup import render_writeup
            lines.append("")
            lines.append("---")
            lines.append(render_writeup(self.state))
        except Exception:
            pass
        return "\n".join(lines)


def run_agent(
    challenge: str,
    category: Optional[str] = None,
    max_steps: int = 10,
    verbose: bool = True,
    challenge_path: Optional[str] = None,
) -> AgentState:
    """Convenience entry point used by the CLI."""
    events: List[str] = []

    def on_event(name: str, payload: Dict[str, Any]) -> None:
        if not verbose:
            return
        if name == "triage_done":
            events.append(
                f"⊞ triage: {payload.get('files', 0)} files | "
                f"cats={payload.get('categories')} | tools={payload.get('tools')}"
            )
        elif name == "action_planned":
            events.append(f"→ plan: {payload.get('tool')} — {payload.get('reason', '')[:80]}")
        elif name == "action_finished":
            ok = "ok" if payload.get("success") else "FAIL"
            events.append(f"  [{ok}] {payload.get('tool')}: {payload.get('summary', '')[:100]}")
        elif name == "verification":
            events.append(f"✓ verify: {payload.get('verdict')} ({payload.get('confidence', 0):.2f})")
        elif name == "finished":
            events.append(f"done: status={payload.get('status')} conf={payload.get('confidence', 0):.2f}")

    agent = AgentLoop(
        challenge_summary=challenge,
        category=category,
        max_steps=max_steps,
        on_event=on_event,
        challenge_path=challenge_path,
    )
    state = agent.run()
    if verbose:
        print("\n".join(events))
        print()
        print(agent.teaching_summary())
    return state
