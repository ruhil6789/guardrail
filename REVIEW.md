# Design Review — Guardrails Harness

**Reviewers (role framing):** systems-safety research (MIT) × deployment
safety (Anthropic-style senior scientist).  
**Artifact under review:** `guardrail/` runtime policy harness.  
**Date:** 2026-10-01

---

## Verdict

**Conditional pass for a teaching / research lab.**  
Suitable to demonstrate continue / pause / stop semantics and to host stronger
detectors. **Not** production-ready as a sole safety layer.

---

## Threat model (scoped)

| Adversary | Goal | Relevant controls |
|-----------|------|-------------------|
| Malicious user | Elicit disallowed help or side effects via prompts | Input + tool rails, HITL |
| Confused deputy model | Plans a harmful tool call while “trying to help” | Tool rails + HITL + scope |
| State tamperer | Edit serialized `RunState` args after human approve | Fingerprint + re-check |
| Insider / compromised reviewer | Approves high-risk actions | Audit log, dual-control (out of scope here) |
| Supply-chain / egress leak | Secrets in tool results or final text | Post-tool + output rails |

Out of scope for this lab: OS sandbox escape, prompt-injection into connected
browsers, cryptographic reviewer identity, formal verification.

---

## Findings

### F1 — CRITICAL (fixed): execute-after-approve without re-validation

**Issue:** Resume path executed tools using paused args without re-running
blocking tool rails. If engagement scope tightened while the request sat in
queue, a previously “in-scope” host could still execute.

**Fix:** `Runner._resume` re-runs blocking rails (`schema`, `scope`, …) and
skips only the HITL PAUSE rail (approval already obtained).

### F2 — HIGH (fixed): mutable paused arguments

**Issue:** `ApprovalRequest.arguments` could be altered in serialized JSON;
human believed they approved `{order_id: 123}` but resume ran `{order_id: 1}`.

**Fix:** `args_fingerprint` at pause time; `approve()` and resume refuse
mismatches (`tool.integrity`).

### F3 — MEDIUM (fixed): post-tool result rail dead code

**Issue:** `result_exfiltration_guardrail` existed but was never called.

**Fix:** `_execute_tool_safely` always runs post-tool check before transcript.

### F4 — MEDIUM (fixed): non-JSON-safe audit payloads

**Issue:** Logging `verdict.__dict__` embedded `Decision` enums → brittle
serialization / analytics.

**Fix:** `GuardrailVerdict.to_audit_dict()`.

### F5 — MEDIUM (fixed): no approval timeout

**Issue:** Stale pauses could linger forever; “reviewer unavailable” did not
fail closed.

**Fix:** `RunState.expire_stale` + `Runner.run(..., approval_timeout_seconds=)`.

### F6 — LOW (accepted, documented): brittle detectors

Regex homework / dual-use / secret patterns are **illustrative**. They will
false-positive and false-negative under paraphrase and obfuscation.

**Mitigation path:** keep the `GuardrailVerdict` contract; replace bodies with
calibrated classifiers, embedding filters, or policy models. Evaluate with
adversarial suites, not cherry-picked demos.

### F7 — LOW (accepted): stub planner

`_plan_tool_calls` is regex routing, not an LLM. Good for unit-testing the
harness; insufficient for claiming end-to-end agent safety.

### F8 — INFO: no cryptographic audit chain

Audit log is append-only in memory, not hash-chained or signed. Fine for demos;
production needs tamper-evident storage.

---

## Evaluation checklist (lab)

Use this before claiming a new detector is “done”:

- [ ] Allowed benign requests still complete (utility / false-positive rate)
- [ ] Known-bad inputs trip the intended `policy_id`
- [ ] Paraphrase / encoding variants (base64, homoglyphs) measured, not ignored
- [ ] Tool args outside scope never execute, even after a stale approval
- [ ] Tampered `RunState` JSON cannot change executed args
- [ ] Reviewer timeout denies rather than silently allowing
- [ ] Output rail redacts secrets without dropping the whole benign answer when REDACT is appropriate
- [ ] Multi-tool plans: each side-effecting call independently gated

---

## Residual risks (explicit)

1. **Classifier gaming** — adversaries optimize against published regexes.
2. **Human fatigue** — HITL rubber-stamping under load; need rate limits,
   risk tiers, and sampling audits.
3. **Composition gaps** — nested agents / MCP bridges not modeled; attach
   rails at every new side-effect surface.
4. **Training–runtime gap** — a model may still *know* dual-use content;
   this harness only constrains *this* deployment’s I/O and tools.
5. **Over-refusal** — aggressive input rails harm legitimate research;
   dual-use policy needs scoped allowlists + reviewed exceptions, not only blocks.

---

## Recommended next experiments

1. Replace `dual_use_probe_guardrail` with a small calibrated classifier;
   report ROC on a held-out probe set.
2. Add dual-control (two reviewers) for `destructive_change` class tools.
3. Hash-chain `audit_log` entries; verify on resume.
4. Property test: ∀ paused requests, execute args == approved fingerprint.
5. Integrate with a real tool sandbox (network allowlist at OS layer) so a
   harness bug cannot be the last line of defense.

---

## Sign-off criteria for “research demo complete”

- Demos 1–9 in `demo.py` pass locally  
- F1–F5 mitigations present in `runner.py` / `core.py`  
- README states limitations honestly  
- REVIEW.md (this file) checked into the lab folder  

**Status:** research demo complete under the above criteria.
