# Guardrails Lab — Runtime Policy Enforcement for Agent Systems

**Affiliation framing:** safety-engineering lab note (MIT-style systems
research × Anthropic-style deployment safety). This is a *harness*, not a
model. It does not claim to solve alignment; it claims to make **continue /
pause / stop** decisions auditable at the boundary where irreversible effects
occur.

> **Thesis.** Training-time mitigations (RLHF, Constitutional AI, unlearning,
> capability routing such as GRAM) shape what a model *can readily express*.
> Runtime guardrails shape what a *deployment* is allowed to *do*. Neither
> replaces the other. Production safety cases need both.

---

## 1. Problem statement

An agent loop is a control system with three failure modes:

| Mode | Symptom | Primary control |
|------|---------|-----------------|
| **Unsafe start** | Disallowed request burns compute / seeds a bad plan | Input guardrail |
| **Unsafe egress** | Secrets, PII, or harmful text leave the trust boundary | Output guardrail |
| **Unsafe effect** | Tool/MCP/shell mutates the world out of policy | Tool guardrail + HITL |

Human review is not a “nice UX.” It is a **control-plane interrupt**: the
planner may *propose* an action; the harness decides whether the action may
*commit*.

```
user turn
   │
   ▼
┌──────────────┐   BLOCK → stop (tripwire)
│ Input rails  │──────────────────────────────────────►
└──────┬───────┘
       │ ALLOW
       ▼
┌──────────────┐
│ Plan / model │  (LLM or stub planner)
└──────┬───────┘
       │ tool call?
       ▼
┌──────────────┐   BLOCK → stop
│ Tool rails   │   PAUSE → ApprovalRequest + RunState
└──────┬───────┘   ALLOW → execute
       │
       ▼
┌──────────────┐   BLOCK → stop
│ Output rails │   REDACT → mutate egress
└──────────────┘   ALLOW → return
```

---

## 2. Design principles (non-negotiable)

1. **Fail closed.** Ambiguity, timeout, or reviewer unavailability → deny.
2. **Policy at the side-effect boundary.** Manager / handoff / nested
   `agent.as_tool()` graphs leak if you only rail the outer agent.
3. **HITL is a state machine**, not a log line after execution.
4. **Same run on resume.** Approving must not start a new user turn with a
   different planner context.
5. **Re-validate after approval.** Scope can tighten while a request sits in
   a queue; approval is not a forever blank check.
6. **Integrity of paused args.** Serialized `RunState` must not allow
   swapping `order_id` / `host` after the human clicked approve.
7. **Auditability.** Who approved what args, under which `policy_id`, must be
   reconstructible.
8. **Defense in depth.** Regex / classifiers here are *prototypes*. Swap in
   stronger detectors behind the same `GuardrailVerdict` contract.

---

## 3. Choose the right control

| Use case | Start with |
|----------|------------|
| Block disallowed requests before the main model | **Input guardrails** |
| Validate / redact final text before egress | **Output guardrails** |
| Check args or results around a tool call | **Tool guardrails** |
| Pause before cancel / shell / spend / sensitive MCP | **Human-in-the-loop** |

**Blocking vs parallel input rails:** use serial/blocking when starting the
main agent is costly or risky; use parallel when latency dominates. This lab
uses cheap deterministic checks (serial short-circuit on first BLOCK).

**Workflow boundaries (easy to get wrong):**

- Input rails → first agent on the user turn  
- Output rails → agent that produces final user-visible text  
- Tool rails → the tool that creates the side effect  

---

## 4. Approval lifecycle

1. Planner selects a tool with `needs_approval=True` (or a PAUSE verdict).
2. Runner records `ApprovalRequest` (args + fingerprint) — **does not execute**.
3. `RunResult.interruptions` + `RunState` returned to the application.
4. Reviewer `state.approve(req)` or `state.reject(req)`.
5. `Runner.run(agent, state)` resumes **the same run**.
6. Before execute: fingerprint check + **live** blocking tool rails again.
7. After execute: post-tool result rail; then output rails on egress.

Delayed review: `state.to_json()` → store → `RunState.from_json()` → resume.
Streaming does not invent a second approval system; settle, resolve, resume.

Timeouts: `state.expire_stale(max_age_seconds=…)` or
`Runner.run(..., approval_timeout_seconds=…)` → auto-reject (fail closed).

---

## 5. Package layout

```
guardrail/
  core.py              Verdict, tripwires, RunState, ApprovalRequest
  input_guardrail.py   Early blocks (homework, dual-use, size)
  output_guardrail.py  Egress redact / block
  tool_guardrail.py    Scope, schema, HITL pause, post-result size
  human_review.py      Approve / reject helpers
  agent.py             Agent + FunctionTool
  runner.py            Orchestrator (invariants above)
  demo.py              Runnable scenarios
  REVIEW.md            Design review & residual risks
  README.md            This document
```

No vendor Agents SDK required. Detectors are intentionally simple so the
*control plane* stays readable.

---

## 6. Quick start

```bash
cd guardrail
python3 demo.py
```

| # | Scenario | Expected control |
|---|----------|------------------|
| 1 | Math homework | Input tripwire |
| 2 | Dual-use / bypass probe | Input tripwire |
| 3 | Cancel order → approve | HITL pause → execute |
| 4 | Cancel order → reject | HITL reject |
| 5 | Probe out-of-scope host | Tool tripwire |
| 6 | Echo secret-like string | Output redaction |
| 7 | Lookup order (read-only) | Allow, no pause |
| 8 | Tamper paused args | Integrity tripwire |
| 9 | Stale approval timeout | Fail-closed reject |

Minimal API sketch:

```python
from agent import Agent, function_tool
from input_guardrail import math_homework_guardrail
from runner import Runner

@function_tool(needs_approval=True)
def cancel_order(order_id: int) -> str:
    return f"Cancelled order {order_id}"

agent = Agent(
    name="Support",
    instructions="Help customers.",
    tools=[cancel_order],
    input_guardrails=[math_homework_guardrail],
)

result = Runner.run(agent, "Cancel order 123.")
if result.paused:
    for req in result.interruptions:
        result.state.approve(req, reviewer="oncall")
    result = Runner.run(agent, result.state)
print(result.final_output)
```

---

## 7. Mapping to common SDK shapes

| Vendor / SDK idea | This harness |
|-------------------|--------------|
| `@input_guardrail` + structured output | `InputGuardrailFn` → `GuardrailVerdict` |
| Tripwire exception | `InputGuardrailTripwire` / `Tool…` / `Output…` |
| `@function_tool(needs_approval=True)` | same flag on `function_tool` |
| `result.interruptions` / `state.approve` | identical names |
| Resume via serialized state | `RunState.to_json` / `from_json` |

Swap regex detectors for classifier models without changing the control plane.

---

## 8. Relation to training-time controls (incl. GRAM)

| Layer | Question it answers |
|-------|---------------------|
| Data filtering / GRAM ablation | “Can this *weight configuration* readily perform capability X?” |
| Runtime guardrails (this lab) | “May *this deployment*, *right now*, start / emit / execute Y?” |

Ablating a module approximates a filtered model; a tool rail approximates an
access-control decision. For dual-use domains (bio, cyber, nuclear, specialized
code), use **both**: reduce latent capability *and* bind tools to scoped,
reviewed, audited execution.

---

## 9. What this lab is not

- Not a production classifier suite (regexes overfit and underfit).
- Not a substitute for authn/z, sandboxing, network policy, or secrets management.
- Not Constitutional AI / RLHF itself — those are training objectives.
- Not automatic inheritance of any vendor “auto-review” product feature.

See **[REVIEW.md](./REVIEW.md)** for the formal design review, fixes applied,
and residual risks.

---

## 10. Citation-style takeaway

> Put irreversible authority behind an explicit decision object
> (`GuardrailVerdict` or `ApprovalDecision`), make that decision
> replay-safe and integrity-checked, and measure the system by whether
> disallowed effects can still commit when the model is wrong or adversarially
> prompted.
