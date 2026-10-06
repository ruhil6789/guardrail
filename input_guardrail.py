"""
Input guardrails — run BEFORE the main model / expensive path.

Research framing:
  Input gates are cheap, early, fail-closed controls. Use them when the cost
  or risk of *starting* the agent is higher than the cost of a quick check
  (policy classifiers, denylist regex, allowlists, homework detectors, etc.).

Boundary rule: in multi-agent chains, input rails typically apply only to the
*first* agent that receives the user turn — not every handoff.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from core import Decision, GuardrailVerdict, InputGuardrailFn


# ---------------------------------------------------------------------------
# Primitive detectors (no vendor SDK required)
# ---------------------------------------------------------------------------

MATH_HOMEWORK_PATTERNS = [
    r"\bsolve\b.+\bfor\b",
    r"\bfind\s+x\b",
    r"\b\d+\s*[xX]\s*[+\-]\s*\d+\s*=\s*\d+",
    r"\bhomework\b",
    r"\bquadratic\b",
    r"\bintegral\b|\bderivative\b",
]

DUAL_USE_PROBE_PATTERNS = [
    r"\bsynthesi[sz]e\b.+\b(virus|toxin|pathogen)\b",
    r"\bbypass\b.+\b(auth|firewall|guardrail|safety)\b",
    r"\bexfiltrat",
    r"\bransomware\b",
    r"\bmake\s+a\s+bomb\b",
]

PII_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
    (r"\b(?:\d[ -]*?){13,19}\b", "card_number"),
]


def _any_match(text: str, patterns: Iterable[str]) -> Optional[re.Match]:
    for p in patterns:
        m = re.search(p, text, flags=re.IGNORECASE | re.DOTALL)
        if m:
            return m
    return None


def math_homework_guardrail(user_input: str, context: dict | None = None) -> GuardrailVerdict:
    """
    Analog of the Agents SDK 'Homework check' example — but deterministic.

    In production you might swap this for a small classifier model; the
    *contract* (verdict + tripwire) stays the same.
    """
    context = context or {}
    m = _any_match(user_input, MATH_HOMEWORK_PATTERNS)
    if m:
        return GuardrailVerdict.block(
            reason=f"Looks like math homework help (matched: {m.group(0)!r})",
            policy_id="input.math_homework",
            output_info={"matched": m.group(0), "is_math_homework": True},
        )
    return GuardrailVerdict.allow(
        reason="Not classified as math homework",
        policy_id="input.math_homework",
        output_info={"is_math_homework": False},
    )


def dual_use_probe_guardrail(user_input: str, context: dict | None = None) -> GuardrailVerdict:
    """
    Safety research: block clear dual-use / harmful probes early.
    Prefer over-blocking here; route edge cases to human review downstream.
    """
    context = context or {}
    m = _any_match(user_input, DUAL_USE_PROBE_PATTERNS)
    if m:
        return GuardrailVerdict.block(
            reason=f"Dual-use / harmful probe detected (matched: {m.group(0)!r})",
            policy_id="input.dual_use",
            output_info={"matched": m.group(0)},
        )
    return GuardrailVerdict.allow(reason="No dual-use probe", policy_id="input.dual_use")


def empty_or_oversized_guardrail(
    user_input: str, context: dict | None = None, max_chars: int = 8_000
) -> GuardrailVerdict:
    if not user_input or not user_input.strip():
        return GuardrailVerdict.block("Empty input", "input.empty")
    if len(user_input) > max_chars:
        return GuardrailVerdict.block(
            f"Input exceeds {max_chars} chars", "input.size"
        )
    return GuardrailVerdict.allow(policy_id="input.size")


def run_input_guardrails(
    user_input: str,
    guardrails: list[InputGuardrailFn],
    context: dict | None = None,
    *,
    parallel: bool = False,
) -> list[GuardrailVerdict]:
    """
    Execute input rails. `parallel=True` is latency-oriented (fire all);
    blocking/serial is safer when you want to avoid speculative work.

    This implementation runs serially either way (no LLM cost); the flag is
    kept for API parity with vendor SDKs.
    """
    _ = parallel
    context = context or {}
    results: list[GuardrailVerdict] = []
    for g in guardrails:
        v = g(user_input, context)
        results.append(v)
        if v.tripwire_triggered or v.decision == Decision.BLOCK:
            break  # fail closed ASAP
    return results
