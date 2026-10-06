"""
Runner — orchestrates input rails → plan/act → tool rails / HITL → output rails.

Decisions:
  ALLOW  → continue
  PAUSE  → return interruptions + state
  BLOCK  → raise tripwire (fail closed)
  REDACT → mutate egress value, continue

Security invariants enforced here:
  1. Input rails run only on a fresh user turn (not on resume).
  2. On resume, re-validate tool args against live policy BEFORE execute
     (approval is not a blank check if scope tightened meanwhile).
  3. Reject fingerprint-mismatched / tampered ApprovalRequest payloads.
  4. Post-tool result rails run before results enter the transcript.
  5. Output rails gate final egress.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Optional

from agent import Agent, FunctionTool
from core import (
    ApprovalRequest,
    Decision,
    GuardrailVerdict,
    InputGuardrailTripwire,
    OutputGuardrailTripwire,
    RunState,
    ToolGuardrailTripwire,
)
from human_review import all_resolved, pending_without_decision
from input_guardrail import run_input_guardrails
from output_guardrail import run_output_guardrails
from tool_guardrail import (
    argument_schema_guardrail,
    result_exfiltration_guardrail,
    run_tool_guardrails,
    scope_guardrail,
    sensitive_tool_pause_guardrail,
)


@dataclass
class RunResult:
    final_output: Optional[str]
    state: RunState
    interruptions: list  # ApprovalRequest

    @property
    def paused(self) -> bool:
        return self.state.status == "paused"


# Naive intent → tool routing for demos (stand-in for an LLM planner)
_CANCEL_RE = re.compile(r"cancel\s+order\s+(\d+)", re.I)
_LOOKUP_RE = re.compile(r"(?:lookup|status|check).*order\s+(\d+)", re.I)
_ECHO_RE = re.compile(r"echo[:\s]+(.+)$", re.I)
_SHELL_HOST_RE = re.compile(r"(?:scan|ping|probe)\s+(\S+)", re.I)


def _default_respond(user_input: str, agent: Agent) -> str:
    return f"[{agent.name}] {agent.instructions.split('.')[0]}. Re: {user_input[:120]}"


def _plan_tool_calls(user_input: str, agent: Agent) -> list[tuple[str, dict]]:
    """Return list of (tool_name, args). Empty → pure text response."""
    tools = agent.tool_map()
    calls: list[tuple[str, dict]] = []

    m = _CANCEL_RE.search(user_input)
    if m and "cancel_order" in tools:
        calls.append(("cancel_order", {"order_id": int(m.group(1))}))

    m = _LOOKUP_RE.search(user_input)
    if m and "lookup_order" in tools:
        calls.append(("lookup_order", {"order_id": int(m.group(1))}))

    m = _ECHO_RE.search(user_input)
    if m and "echo" in tools:
        calls.append(("echo", {"text": m.group(1).strip()}))

    m = _SHELL_HOST_RE.search(user_input)
    if m and "probe_host" in tools:
        calls.append(("probe_host", {"host": m.group(1), "action": "scan"}))

    return calls


def _blocking_tool_rails(rails: list) -> list:
    """On resume after HITL, re-check BLOCK policies but skip PAUSE rails."""
    skip = {sensitive_tool_pause_guardrail}
    return [g for g in rails if g not in skip]


def _audit_verdict(stage: str, verdict, **extra) -> dict:
    payload = {"stage": stage, "verdict": verdict.to_audit_dict()}
    payload.update(extra)
    return payload


class Runner:
    @staticmethod
    def run(
        agent: Agent,
        user_input: str | RunState,
        *,
        context: dict | None = None,
        default_tool_guardrails: list | None = None,
        approval_timeout_seconds: float | None = None,
    ) -> RunResult:
        context = dict(context or {})
        default_tool_guardrails = default_tool_guardrails or [
            argument_schema_guardrail,
            scope_guardrail,
            sensitive_tool_pause_guardrail,
        ]

        # Resume path -------------------------------------------------------
        if isinstance(user_input, RunState):
            state = user_input
            if approval_timeout_seconds is not None:
                state.expire_stale(max_age_seconds=approval_timeout_seconds)
            if state.status == "completed":
                return RunResult(state.final_output, state, [])
            return Runner._resume(agent, state, context, default_tool_guardrails)

        # Fresh run ---------------------------------------------------------
        state = RunState(run_id=str(uuid.uuid4()), user_input=user_input)
        state.messages.append({"role": "user", "content": user_input})

        # 1) Input guardrails (first agent / user turn only)
        if agent.input_guardrails:
            verdicts = run_input_guardrails(user_input, agent.input_guardrails, context)
            for v in verdicts:
                state.audit_log.append(_audit_verdict("input", v))
                if v.decision == Decision.BLOCK or v.tripwire_triggered:
                    state.status = "blocked"
                    raise InputGuardrailTripwire(v)

        # 2) Plan tool calls (stub planner)
        planned = _plan_tool_calls(user_input, agent)
        if not planned:
            text = (agent.respond or _default_respond)(user_input, agent)
            return Runner._finalize(agent, state, text, context)

        # 3) Execute / pause tools
        return Runner._execute_planned(agent, state, planned, context, default_tool_guardrails)

    @staticmethod
    def _execute_tool_safely(tool: FunctionTool, args: dict, state: RunState, context: dict) -> str:
        result = tool(**args)
        # Post-tool result rail (egress from tool → transcript)
        post = result_exfiltration_guardrail(tool.name, result, context)
        state.audit_log.append(_audit_verdict("tool_post", post, tool=tool.name))
        if post.decision == Decision.BLOCK or post.tripwire_triggered:
            state.status = "blocked"
            raise ToolGuardrailTripwire(post)
        return str(result)

    @staticmethod
    def _resume(agent, state, context, default_tool_guardrails) -> RunResult:
        if not all_resolved(state):
            state.status = "paused"
            return RunResult(None, state, pending_without_decision(state))

        tool_map = agent.tool_map()
        outputs = []
        for req in state.pending_approvals:
            if not req.matches_fingerprint():
                state.status = "blocked"
                raise ToolGuardrailTripwire(
                    GuardrailVerdict.block(
                        reason="Tampered ApprovalRequest (fingerprint mismatch)",
                        policy_id="tool.integrity",
                        output_info={"tool": req.tool_name, "id": req.id},
                    )
                )

            decision = state.decisions[req.id]
            if not decision.approved:
                outputs.append(f"REJECTED {req.tool_name}: {decision.note or decision.reviewer}")
                state.audit_log.append(
                    {"stage": "tool", "event": "rejected", "tool": req.tool_name}
                )
                continue

            tool = tool_map[req.tool_name]
            # Re-validate live policy (scope may have tightened since pause)
            rails = _blocking_tool_rails(list(default_tool_guardrails) + list(tool.guardrails))
            verdict = run_tool_guardrails(req.tool_name, req.arguments, rails, context)
            state.audit_log.append(
                _audit_verdict("tool_recheck", verdict, tool=req.tool_name)
            )
            if verdict.decision == Decision.BLOCK or verdict.tripwire_triggered:
                state.status = "blocked"
                raise ToolGuardrailTripwire(verdict)

            result = Runner._execute_tool_safely(tool, req.arguments, state, context)
            outputs.append(result)
            state.audit_log.append(
                {"stage": "tool", "event": "executed", "tool": req.tool_name, "result": result}
            )

        state.pending_approvals = []
        text = " | ".join(outputs) if outputs else "No actions taken."
        return Runner._finalize(agent, state, text, context)

    @staticmethod
    def _execute_planned(agent, state, planned, context, default_tool_guardrails) -> RunResult:
        tool_map = agent.tool_map()
        executed_bits: list[str] = []
        interruptions: list[ApprovalRequest] = []

        for name, args in planned:
            tool: FunctionTool = tool_map[name]
            rails = list(default_tool_guardrails) + list(tool.guardrails)

            # Force PAUSE if tool declares needs_approval
            if tool.needs_approval:
                context = {
                    **context,
                    "sensitive_tools": set(context.get("sensitive_tools", set())) | {name},
                }

            verdict = run_tool_guardrails(name, args, rails, context)
            state.audit_log.append(_audit_verdict("tool_pre", verdict, tool=name))

            if verdict.decision == Decision.BLOCK or verdict.tripwire_triggered:
                state.status = "blocked"
                raise ToolGuardrailTripwire(verdict)

            if verdict.decision == Decision.PAUSE or tool.needs_approval:
                req = ApprovalRequest.create(
                    tool_name=name,
                    arguments=args,
                    reason=verdict.reason or "needs_approval",
                )
                interruptions.append(req)
                continue

            result = Runner._execute_tool_safely(tool, args, state, context)
            executed_bits.append(result)
            state.audit_log.append(
                {"stage": "tool", "event": "executed", "tool": name, "result": result}
            )

        if interruptions:
            state.pending_approvals = interruptions
            state.status = "paused"
            return RunResult(None, state, interruptions)

        text = (
            " | ".join(executed_bits)
            if executed_bits
            else _default_respond(state.user_input, agent)
        )
        return Runner._finalize(agent, state, text, context)

    @staticmethod
    def _finalize(agent: Agent, state: RunState, text: str, context: dict) -> RunResult:
        if agent.output_guardrails:
            text, verdicts = run_output_guardrails(text, agent.output_guardrails, context)
            for v in verdicts:
                state.audit_log.append(_audit_verdict("output", v))
                if v.decision == Decision.BLOCK or v.tripwire_triggered:
                    state.status = "blocked"
                    raise OutputGuardrailTripwire(v)

        state.final_output = text
        state.status = "completed"
        state.messages.append({"role": "assistant", "content": text})
        return RunResult(text, state, [])
