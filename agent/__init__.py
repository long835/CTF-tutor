"""
CTF-Tutor Agent package.

Closed-loop investigative agent with explicit state, hypotheses,
tool planning, observation feedback, verification, triage, and traces.
"""

from agent.state import AgentState, Hypothesis, Evidence, ActionRecord, new_challenge_state
from agent.loop import AgentLoop, run_agent

__all__ = [
    "AgentState",
    "Hypothesis",
    "Evidence",
    "ActionRecord",
    "new_challenge_state",
    "AgentLoop",
    "run_agent",
]
