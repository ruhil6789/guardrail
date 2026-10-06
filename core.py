"""
Core types for a framework-agnostic guardrail system.

Mental model (Safety & Security research):
  Guardrails are *policy enforcement points* in an agent loop.
  Human review is a *control plane interrupt* for irreversible side effects.

Together they answer: continue | pause | stop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional
import json
import time
import uuid


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    PAUSE = "pause"  # needs human review


@dataclass
class GuardrailVerdict:
    """Result of an automatic policy check."""

    decision: Decision
    reason: str
    policy_id: str
    output_info: Any = None
    redacted_value: Any = None
    tripwire_triggered: bool = False

    @classmethod
    def allow(cls, reason: str = "ok", policy_id: str = "default", **kwargs) -> "GuardrailVerdict":
        return cls(Decision.ALLOW, reason, policy_id, tripwire_triggered=False, **kwargs)

    @classmethod
    def block(cls, reason: str, policy_id: str, output_info: Any = None) -> "GuardrailVerdict":
        return cls(
            Decision.BLOCK,
            reason,
            policy_id,
            output_info=output_info,
            tripwire_triggered=True,
        )

    @classmethod
    def redact(
        cls, reason: str, policy_id: str, redacted_value: Any, output_info: Any = None
    ) -> "GuardrailVerdict":
        return cls(
            Decision.REDACT,
            reason,
            policy_id,
            output_info=output_info,
            redacted_value=redacted_value,
            tripwire_triggered=False,
        )

    @classmethod
    def pause(
        cls, reason: str, policy_id: str, output_info: Any = None
    ) -> "GuardrailVerdict":
        return cls(
            Decision.PAUSE,
            reason,
            policy_id,
            output_info=output_info,
            tripwire_triggered=False,
        )

    def to_audit_dict(self) -> dict:
        """JSON-safe snapshot for audit logs."""
        return {
            "decision": self.decision.value if isinstance(self.decision, Decision) else self.decision,
            "reason": self.reason,
            "policy_id": self.policy_id,
            "tripwire_triggered": self.tripwire_triggered,
            "output_info": self.output_info,
        }


class GuardrailTripwire(Exception):
    """Raised when a blocking guardrail fires (fail-closed)."""

    def __init__(self, stage: str, verdict: GuardrailVerdict):
        self.stage = stage
        self.verdict = verdict
        super().__init__(f"[{stage}] tripwire: {verdict.reason} (policy={verdict.policy_id})")


class InputGuardrailTripwire(GuardrailTripwire):
    def __init__(self, verdict: GuardrailVerdict):
        super().__init__("input", verdict)


class OutputGuardrailTripwire(GuardrailTripwire):
    def __init__(self, verdict: GuardrailVerdict):
        super().__init__("output", verdict)


class ToolGuardrailTripwire(GuardrailTripwire):
    def __init__(self, verdict: GuardrailVerdict):
        super().__init__("tool", verdict)


@dataclass
class ApprovalRequest:
    """A paused tool call awaiting human / policy approval.

    `arguments` are frozen at pause time. On resume, the runner must
    re-validate against live policy (scope may have changed) and must
    execute *these* args — never attacker-supplied replacements without
    a fresh approval.
    """

    id: str
    tool_name: str
    arguments: dict
    reason: str
    created_at: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)
    args_fingerprint: str = ""

    @staticmethod
    def create(tool_name: str, arguments: dict, reason: str, **metadata) -> "ApprovalRequest":
        # Stable fingerprint so resume can detect tampering of serialized state
        fp = json.dumps({"tool": tool_name, "args": arguments}, sort_keys=True, default=str)
        return ApprovalRequest(
            id=str(uuid.uuid4()),
            tool_name=tool_name,
            arguments=dict(arguments),
            reason=reason,
            metadata=metadata,
            args_fingerprint=fp,
        )

    def matches_fingerprint(self) -> bool:
        expected = json.dumps(
            {"tool": self.tool_name, "args": self.arguments}, sort_keys=True, default=str
        )
        return expected == self.args_fingerprint


@dataclass
class ApprovalDecision:
    request_id: str
    approved: bool
    reviewer: str = "human"
    note: str = ""


@dataclass
class RunState:
    """
    Serializable state for pause / resume (same run, not a new turn).

    Store this if review takes minutes/hours/days, then resume later.
    """

    run_id: str
    user_input: str
    messages: list = field(default_factory=list)
    pending_approvals: list = field(default_factory=list)  # ApprovalRequest
    decisions: dict = field(default_factory=dict)  # request_id -> ApprovalDecision
    audit_log: list = field(default_factory=list)
    final_output: Optional[str] = None
    status: str = "running"  # running | paused | completed | blocked

    def approve(self, interruption: ApprovalRequest, reviewer: str = "human", note: str = "") -> None:
        if not interruption.matches_fingerprint():
            raise ValueError(
                f"Approval refused: arguments for {interruption.tool_name!r} were tampered "
                f"(fingerprint mismatch). Request a new approval."
            )
        self.decisions[interruption.id] = ApprovalDecision(
            request_id=interruption.id, approved=True, reviewer=reviewer, note=note
        )
        self._log("approve", interruption.id, reviewer, note)

    def reject(self, interruption: ApprovalRequest, reviewer: str = "human", note: str = "") -> None:
        self.decisions[interruption.id] = ApprovalDecision(
            request_id=interruption.id, approved=False, reviewer=reviewer, note=note
        )
        self._log("reject", interruption.id, reviewer, note)

    def expire_stale(
        self, max_age_seconds: float = 3600.0, reviewer: str = "policy:timeout"
    ) -> list[ApprovalRequest]:
        """Fail closed: auto-reject approvals older than max_age_seconds."""
        now = time.time()
        expired = []
        for req in self.pending_approvals:
            if req.id in self.decisions:
                continue
            if now - req.created_at > max_age_seconds:
                self.reject(req, reviewer=reviewer, note=f"timed out after {max_age_seconds}s")
                expired.append(req)
        return expired

    def _log(self, action: str, request_id: str, reviewer: str, note: str) -> None:
        self.audit_log.append(
            {
                "ts": time.time(),
                "action": action,
                "request_id": request_id,
                "reviewer": reviewer,
                "note": note,
            }
        )

    def to_json(self) -> str:
        def default(o):
            if hasattr(o, "__dict__"):
                return o.__dict__
            raise TypeError(type(o))

        return json.dumps(self.__dict__, default=default, indent=2)

    @classmethod
    def from_json(cls, raw: str) -> "RunState":
        data = json.loads(raw)
        pending = [ApprovalRequest(**p) for p in data.get("pending_approvals", [])]
        decisions = {
            k: ApprovalDecision(**v) if isinstance(v, dict) else v
            for k, v in data.get("decisions", {}).items()
        }
        state = cls(
            run_id=data["run_id"],
            user_input=data["user_input"],
            messages=data.get("messages", []),
            pending_approvals=pending,
            decisions=decisions,
            audit_log=data.get("audit_log", []),
            final_output=data.get("final_output"),
            status=data.get("status", "running"),
        )
        return state


# Callables
InputGuardrailFn = Callable[[str, dict], GuardrailVerdict]
OutputGuardrailFn = Callable[[str, dict], GuardrailVerdict]
ToolGuardrailFn = Callable[[str, dict, dict], GuardrailVerdict]
