"""Test-only helpers for scripted native Function Calling responses."""

from __future__ import annotations

import json
from dataclasses import replace

from packages.llm.provider import LLMCompletion, LLMTool, LLMToolCall


def as_tool_completion(
    value: str | dict[str, object] | LLMCompletion,
    tools: list[LLMTool],
    *,
    call_index: int,
) -> LLMCompletion:
    """Convert compact fixture payloads into an SDK-independent tool call."""
    completion = value if isinstance(value, LLMCompletion) else LLMCompletion(content="")
    if completion.tool_calls:
        return completion
    raw = completion.content if isinstance(value, LLMCompletion) else value
    if raw == "":
        return completion
    payload = json.loads(raw) if isinstance(raw, str) else dict(raw)
    batch = payload.get("actions")
    if isinstance(batch, list):
        return replace(
            completion,
            content="",
            finish_reason=completion.finish_reason or "tool_calls",
            tool_calls=tuple(
                LLMToolCall(
                    id=f"call_test_{call_index}_{index}",
                    name=str(item["action"]),
                    arguments={
                        key: value for key, value in dict(item).items() if key != "action"
                    },
                )
                for index, item in enumerate(batch)
            ),
        )
    action = payload.pop("action", None)
    if not isinstance(action, str):
        if len(tools) != 1:
            raise AssertionError("scripted multi-tool response requires an action")
        action = tools[0].name
    return replace(
        completion,
        content="",
        finish_reason=completion.finish_reason or "tool_calls",
        tool_calls=(
            LLMToolCall(
                id=f"call_test_{call_index}",
                name=action,
                arguments=payload,
            ),
        ),
    )

