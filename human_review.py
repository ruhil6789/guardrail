"""
Human-in-the-loop approvals — pause before irreversible side effects.

Lifecycle (same as vendor SDKs, framework-agnostic):
  1. Model/planner decides a tool is needed
  2. Runner records ApprovalRequest instead of executing
  3. Result returns interruptions + resumable RunState
  4. App / reviewer approves or rejects
  5. Resume THE SAME RUN from state (not a new user turn)

If review is slow: serialize state, store it, resume later.
"""

from __future__ import annotations

from core import ApprovalDecision, ApprovalRequest, RunState


def summarize_interruptions(state: RunState) -> str:
    if not state.pending_approvals:
        return "No pending approvals."
    lines = [f"Run {state.run_id} paused with {len(state.pending_approvals)} interruption(s):"]
    for req in state.pending_approvals:
        decided = state.decisions.get(req.id)
        status = "pending"
        if decided is not None:
            status = "approved" if decided.approved else "rejected"
        lines.append(
            f"  - [{status}] {req.id[:8]}…  tool={req.tool_name} args={req.arguments}  ({req.reason})"
        )
    return "\n".join(lines)


def auto_approve_all(state: RunState, reviewer: str = "policy:auto_allow") -> RunState:
    """Demo helper — production should never blanket-approve sensitive tools."""
    for req in state.pending_approvals:
        if req.id not in state.decisions:
            state.approve(req, reviewer=reviewer, note="auto-approved for demo")
    return state


def auto_reject_all(state: RunState, reviewer: str = "policy:auto_deny") -> RunState:
    for req in state.pending_approvals:
        if req.id not in state.decisions:
            state.reject(req, reviewer=reviewer, note="auto-rejected for demo")
    return state


def pending_without_decision(state: RunState) -> list[ApprovalRequest]:
    return [r for r in state.pending_approvals if r.id not in state.decisions]


def all_resolved(state: RunState) -> bool:
    return len(pending_without_decision(state)) == 0
