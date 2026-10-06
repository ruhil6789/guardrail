"""
Minimal agent + tool abstractions (vendor-agnostic).

Mirrors the *shape* of Agents SDK concepts without importing openai-agents:
  - Agent has instructions, tools, input/output guardrails
  - Tools may declare needs_approval=True
  - Runner orchestrates continue / pause / stop
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, Union

from core import InputGuardrailFn, OutputGuardrailFn, ToolGuardrailFn


SyncOrAsync = Union[Callable[..., Any], Callable[..., Awaitable[Any]]]


@dataclass
class FunctionTool:
    name: str
    description: str
    handler: Callable[..., Any]
    needs_approval: bool = False
    # Tool-local guardrails (preferred for side-effect boundaries)
    guardrails: list[ToolGuardrailFn] = field(default_factory=list)

    def __call__(self, **kwargs):
        return self.handler(**kwargs)


def function_tool(
    name: str | None = None,
    description: str = "",
    needs_approval: bool = False,
    guardrails: list | None = None,
):
    """Decorator → FunctionTool (sync handlers are enough for demos)."""

    def wrap(fn: Callable[..., Any]) -> FunctionTool:
        return FunctionTool(
            name=name or fn.__name__,
            description=description or (fn.__doc__ or ""),
            handler=fn,
            needs_approval=needs_approval,
            guardrails=list(guardrails or []),
        )

    return wrap


@dataclass
class Agent:
    name: str
    instructions: str
    tools: list[FunctionTool] = field(default_factory=list)
    input_guardrails: list[InputGuardrailFn] = field(default_factory=list)
    output_guardrails: list[OutputGuardrailFn] = field(default_factory=list)
    # Optional: simple rule-based "model" for demos (no API key needed)
    respond: Optional[Callable[[str, "Agent"], str]] = None

    def tool_map(self) -> dict[str, FunctionTool]:
        return {t.name: t for t in self.tools}
