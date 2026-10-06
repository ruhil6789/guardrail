"""
Output guardrails — validate / redact AFTER the model produces a final answer.

Research framing:
  Output rails protect *egress*: secrets, harmful advice, policy-violating
  claims, PII leakage. Prefer REDACT when partial answers are useful;
  BLOCK when the whole response is unsafe.

Boundary rule: typically applied to the agent that produces the *final*
user-visible output — not every intermediate specialist.
"""

from __future__ import annotations

import re
from typing import Iterable

from core import Decision, GuardrailVerdict, OutputGuardrailFn


SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*\S+", "[REDACTED_SECRET]"),
    (r"sk-[A-Za-z0-9]{20,}", "[REDACTED_API_KEY]"),
    (r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
]

HARMFUL_ASSIST_PATTERNS = [
    r"(?i)here(?:'s| is) how to (?:make|build) (?:a )?bomb",
    r"(?i)step[- ]by[- ]step.{0,40}ransomware",
]


def secret_redaction_guardrail(output: str, context: dict | None = None) -> GuardrailVerdict:
    context = context or {}
    redacted = output
    hits = []
    for pattern, repl in SECRET_PATTERNS:
        if re.search(pattern, redacted):
            hits.append(pattern)
            redacted = re.sub(pattern, repl, redacted)
    if hits:
        return GuardrailVerdict.redact(
            reason=f"Redacted {len(hits)} secret-like span(s)",
            policy_id="output.secrets",
            redacted_value=redacted,
            output_info={"patterns": hits},
        )
    return GuardrailVerdict.allow(reason="No secrets", policy_id="output.secrets")


def harmful_content_block_guardrail(output: str, context: dict | None = None) -> GuardrailVerdict:
    context = context or {}
    for p in HARMFUL_ASSIST_PATTERNS:
        m = re.search(p, output)
        if m:
            return GuardrailVerdict.block(
                reason=f"Harmful assistance pattern: {m.group(0)!r}",
                policy_id="output.harmful",
                output_info={"matched": m.group(0)},
            )
    return GuardrailVerdict.allow(reason="Clean", policy_id="output.harmful")


def max_length_guardrail(
    output: str, context: dict | None = None, max_chars: int = 12_000
) -> GuardrailVerdict:
    if len(output) > max_chars:
        trimmed = output[:max_chars] + "\n…[truncated by output guardrail]"
        return GuardrailVerdict.redact(
            reason=f"Truncated to {max_chars} chars",
            policy_id="output.length",
            redacted_value=trimmed,
        )
    return GuardrailVerdict.allow(policy_id="output.length")


def run_output_guardrails(
    output: str,
    guardrails: list[OutputGuardrailFn],
    context: dict | None = None,
) -> tuple[str, list[GuardrailVerdict]]:
    """
    Apply output rails in order. REDACT mutates the working string;
    BLOCK raises via the caller's tripwire handling.
    """
    context = context or {}
    working = output
    verdicts: list[GuardrailVerdict] = []
    for g in guardrails:
        v = g(working, context)
        verdicts.append(v)
        if v.decision == Decision.BLOCK or v.tripwire_triggered:
            break
        if v.decision == Decision.REDACT and v.redacted_value is not None:
            working = v.redacted_value
    return working, verdicts
