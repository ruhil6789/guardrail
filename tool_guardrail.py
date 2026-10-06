"""
Tool guardrails — check arguments *before* execution and optionally results *after*.

Research framing:
  Side effects happen at tools (shell, payments, MCP, cloud APIs). Putting
  policy *next to the tool* beats relying only on agent-level input/output rails,
  especially in manager / handoff / nested agent.as_tool() workflows.

Fail closed: if review is unavailable or times out → deny.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from core import Decision, GuardrailVerdict, ToolGuardrailFn


# Example engagement scope for authorized cyber / ops workflows
DEFAULT_SCOPE = {
    "allowed_hosts": {"127.0.0.1", "localhost", "lab.internal"},
    "allowed_tools": {"lookup_order", "cancel_order", "echo", "read_status", "probe_host"},
    "denied_actions": {
        "credential_theft",
        "persistence",
        "exfiltration",
        "destructive_change",
        "production_access",
        "policy_bypass",
    },
}


def argument_schema_guardrail(
    tool_name: str, arguments: dict, context: dict | None = None
) -> GuardrailVerdict:
    """Reject obviously malformed / oversized payloads."""
    context = context or {}
    if not isinstance(arguments, dict):
        return GuardrailVerdict.block("Arguments must be a dict", "tool.schema")
    raw = str(arguments)
    if len(raw) > 4_000:
        return GuardrailVerdict.block("Argument payload too large", "tool.schema")
    return GuardrailVerdict.allow(policy_id="tool.schema")


def scope_guardrail(
    tool_name: str, arguments: dict, context: dict | None = None
) -> GuardrailVerdict:
    """
    Enforce written engagement / product scope at the side-effect boundary.
    Deny out-of-scope hosts and high-risk actions.
    """
    context = context or {}
    scope = context.get("scope", DEFAULT_SCOPE)
    allowed_tools = scope.get("allowed_tools", set())
    if allowed_tools and tool_name not in allowed_tools:
        return GuardrailVerdict.block(
            reason=f"Tool {tool_name!r} outside allowed set",
            policy_id="tool.scope",
            output_info={"tool": tool_name},
        )

    host = arguments.get("host") or arguments.get("target")
    allowed_hosts = scope.get("allowed_hosts", set())
    if host and allowed_hosts and host not in allowed_hosts:
        return GuardrailVerdict.block(
            reason=f"Host/target {host!r} outside engagement scope",
            policy_id="tool.scope.host",
            output_info={"host": host},
        )

    action = arguments.get("action")
    denied = scope.get("denied_actions", set())
    if action and action in denied:
        return GuardrailVerdict.block(
            reason=f"Denied action {action!r}",
            policy_id="tool.scope.action",
            output_info={"action": action},
        )

    return GuardrailVerdict.allow(policy_id="tool.scope")


def sensitive_tool_pause_guardrail(
    tool_name: str, arguments: dict, context: dict | None = None
) -> GuardrailVerdict:
    """
    Ambiguous / high-risk tools should PAUSE for human approval rather than
    auto-allow. The runner converts PAUSE → ApprovalRequest interruption.
    """
    context = context or {}
    sensitive = context.get("sensitive_tools", {"cancel_order", "shell", "write_file", "transfer_funds"})
    if tool_name in sensitive:
        return GuardrailVerdict.pause(
            reason=f"Sensitive tool {tool_name!r} requires human approval",
            policy_id="tool.hitl",
            output_info={"tool": tool_name, "arguments": arguments},
        )
    return GuardrailVerdict.allow(policy_id="tool.hitl")


def result_exfiltration_guardrail(
    tool_name: str, result: Any, context: dict | None = None
) -> GuardrailVerdict:
    """Post-tool check: block results that look like mass data dumps."""
    context = context or {}
    text = str(result)
    if len(text) > 20_000:
        return GuardrailVerdict.block(
            reason="Tool result suspiciously large (possible exfil)",
            policy_id="tool.result.size",
        )
    return GuardrailVerdict.allow(policy_id="tool.result.size")


def run_tool_guardrails(
    tool_name: str,
    arguments: dict,
    guardrails: list[ToolGuardrailFn],
    context: dict | None = None,
) -> GuardrailVerdict:
    """First BLOCK or PAUSE wins; otherwise ALLOW."""
    context = context or {}
    for g in guardrails:
        v = g(tool_name, arguments, context)
        if v.decision in (Decision.BLOCK, Decision.PAUSE):
            return v
    return GuardrailVerdict.allow(policy_id="tool.all_clear")
