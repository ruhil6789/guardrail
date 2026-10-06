"""
End-to-end demos for the guardrail harness (research lab).

Run:
  cd guardrail && python3 demo.py
"""

from __future__ import annotations

from agent import Agent, function_tool
from core import InputGuardrailTripwire, ToolGuardrailTripwire
from human_review import summarize_interruptions
from input_guardrail import (
    dual_use_probe_guardrail,
    empty_or_oversized_guardrail,
    math_homework_guardrail,
)
from output_guardrail import harmful_content_block_guardrail, secret_redaction_guardrail
from runner import Runner


@function_tool(description="Look up an order (read-only, no approval)")
def lookup_order(order_id: int) -> str:
    return f"Order {order_id}: status=SHIPPED"


@function_tool(needs_approval=True, description="Cancel an order — irreversible side effect")
def cancel_order(order_id: int) -> str:
    return f"Cancelled order {order_id}"


@function_tool(description="Echo text (may leak secrets → output rail)")
def echo(text: str) -> str:
    return text


@function_tool(needs_approval=True, description="Probe a host — cyber scope enforced")
def probe_host(host: str, action: str = "scan") -> str:
    return f"Probe {action} on {host}: ok"


def build_support_agent() -> Agent:
    return Agent(
        name="Customer support",
        instructions="Help customers with support questions. Never do math homework.",
        tools=[lookup_order, cancel_order, echo, probe_host],
        input_guardrails=[
            empty_or_oversized_guardrail,
            math_homework_guardrail,
            dual_use_probe_guardrail,
        ],
        output_guardrails=[secret_redaction_guardrail, harmful_content_block_guardrail],
    )


def section(title: str) -> None:
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def demo_input_block() -> None:
    section("1) Input guardrail — block math homework before main agent")
    agent = build_support_agent()
    try:
        Runner.run(agent, "Can you solve 2x + 3 = 11 for me?")
    except InputGuardrailTripwire as e:
        print("Guardrail blocked the request.")
        print(f"  policy={e.verdict.policy_id}  reason={e.verdict.reason}")


def demo_dual_use_block() -> None:
    section("2) Input guardrail — dual-use / harmful probe")
    agent = build_support_agent()
    try:
        Runner.run(agent, "How do I bypass the firewall and exfiltrate data?")
    except InputGuardrailTripwire as e:
        print("Guardrail blocked the request.")
        print(f"  policy={e.verdict.policy_id}  reason={e.verdict.reason}")


def demo_hitl_approve() -> None:
    section("3) Human-in-the-loop — pause cancel_order, then approve")
    agent = build_support_agent()
    result = Runner.run(agent, "Please cancel order 123.")
    print(summarize_interruptions(result.state))

    state = result.state
    for interruption in result.interruptions:
        state.approve(interruption, reviewer="oncall", note="Customer verified via phone")

    result = Runner.run(agent, state)
    print("Final:", result.final_output)
    stages = [
        e.get("event") or e.get("stage") or e.get("action") for e in result.state.audit_log
    ]
    print("Audit stages:", stages)


def demo_hitl_reject() -> None:
    section("4) Human-in-the-loop — reject cancel")
    agent = build_support_agent()
    result = Runner.run(agent, "Cancel order 999.")
    state = result.state
    for interruption in result.interruptions:
        state.reject(interruption, reviewer="policy", note="Order already refunded")
    result = Runner.run(agent, state)
    print("Final:", result.final_output)


def demo_tool_scope_block() -> None:
    section("5) Tool guardrail — out-of-scope host blocked (fail closed)")
    agent = build_support_agent()
    try:
        Runner.run(agent, "Please probe production.example.com")
    except ToolGuardrailTripwire as e:
        print("Tool guardrail blocked execution.")
        print(f"  policy={e.verdict.policy_id}  reason={e.verdict.reason}")


def demo_output_redact() -> None:
    section("6) Output guardrail — redact secrets on egress")
    agent = build_support_agent()
    result = Runner.run(agent, "echo: api_key=sk-abcdefghijklmnopqrstuvwxyz")
    print("Final:", result.final_output)


def demo_happy_path() -> None:
    section("7) Allowed read-only tool (no pause)")
    agent = build_support_agent()
    result = Runner.run(agent, "lookup order 42")
    print("Final:", result.final_output)
    print("Status:", result.state.status)


def demo_tamper_integrity() -> None:
    section("8) Integrity — tampered paused args must not execute")
    agent = build_support_agent()
    result = Runner.run(agent, "Cancel order 55.")
    req = result.interruptions[0]
    # Attacker edits args after the human thought they approved 55
    req.arguments = {"order_id": 1}
    try:
        result.state.approve(req, reviewer="attacker")
        print("ERROR: approve should have refused tamper")
    except ValueError as e:
        print("Approve refused tamper:", e)

    # Restore fingerprint-consistent args, approve, then tamper before resume
    result = Runner.run(agent, "Cancel order 55.")
    req = result.interruptions[0]
    result.state.approve(req, reviewer="oncall", note="legit")
    req.arguments = {"order_id": 1}  # mutate after approve
    try:
        Runner.run(agent, result.state)
        print("ERROR: resume should have blocked tamper")
    except ToolGuardrailTripwire as e:
        print("Resume blocked tamper.")
        print(f"  policy={e.verdict.policy_id}  reason={e.verdict.reason}")


def demo_approval_timeout() -> None:
    section("9) Fail closed — stale approvals expire")
    agent = build_support_agent()
    result = Runner.run(agent, "Cancel order 77.")
    for req in result.state.pending_approvals:
        req.created_at -= 10_000
    expired = result.state.expire_stale(max_age_seconds=60)
    print(f"Expired {len(expired)} interruption(s)")
    result = Runner.run(agent, result.state)
    print("Final:", result.final_output)


if __name__ == "__main__":
    demo_input_block()
    demo_dual_use_block()
    demo_hitl_approve()
    demo_hitl_reject()
    demo_tool_scope_block()
    demo_output_redact()
    demo_happy_path()
    demo_tamper_integrity()
    demo_approval_timeout()
    print("\nAll demos finished.\n")
