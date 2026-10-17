"""LLM 桥（M5）：Provider（OpenAI 兼容）+ PlannerDecider 接线。

凭据只经 llm_credentials 投影注入（packages/config.resolver）；本包不读 secrets.env。
"""

from __future__ import annotations

from .provider import (
    LLMCompletion,
    LLMConfig,
    LLMError,
    LLMMessage,
    LLMTimeoutError,
    LLMTool,
    LLMToolCall,
    LLMToolChoice,
    OpenAICompatClient,
    PlannerDecider,
    build_messages,
    build_system_prompt,
    build_url,
    is_malformed_tool_protocol_error,
)

__all__ = [
    "LLMCompletion",
    "LLMConfig",
    "LLMError",
    "LLMMessage",
    "LLMTimeoutError",
    "LLMTool",
    "LLMToolCall",
    "LLMToolChoice",
    "OpenAICompatClient",
    "PlannerDecider",
    "build_messages",
    "build_system_prompt",
    "build_url",
    "is_malformed_tool_protocol_error",
]
