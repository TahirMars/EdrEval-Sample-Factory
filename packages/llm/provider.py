"""LLM Provider 桥（M5）：OpenAI SDK 兼容端点 + Planner 决策解析。

凭据经 llm_credentials 投影注入（最小权限，P6 §5.2）；
output_locale 注入 system prompt（P7 §5：生成时定语言，不事后翻译）；
Function Calling 参数经严格 schema 校验（未知字段拒绝，防模型越权输出）。
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Any, cast

import openai
from openai import OpenAI

from packages.schemas.entities import PlanDecision


class LLMError(RuntimeError):
    """LLM 调用/解析失败（网络/HTTP/JSON 不合法）。"""


class LLMTimeoutError(LLMError):
    """LLM HTTP 请求在配置的读取时限内未完成。"""


def is_malformed_tool_protocol_error(exc: BaseException) -> bool:
    """True when a tool call was emitted but arguments JSON was truncated or invalid."""
    if not isinstance(exc, LLMError) or isinstance(exc, LLMTimeoutError):
        return False
    text = str(exc)
    return "工具参数不是合法 JSON" in text or "响应结构不合法" in text


LLMMessage = dict[str, object]
LLMToolChoice = str | dict[str, object]


@dataclass(frozen=True)
class LLMTool:
    """Provider-neutral function tool definition."""

    name: str
    description: str
    parameters: dict[str, object]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.name):
            raise LLMError(f"LLM 工具名不合法：{self.name!r}")
        if self.parameters.get("type") != "object":
            raise LLMError(f"LLM 工具 {self.name!r} 的 parameters 必须是 object schema")

    def request_value(self) -> dict[str, object]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass(frozen=True)
class LLMToolCall:
    """A validated function call emitted by an OpenAI-compatible provider."""

    id: str
    name: str
    arguments: dict[str, object]

    def assistant_message(self, *, content: str = "") -> LLMMessage:
        """Render the assistant tool-call message required by the next API turn."""
        return {
            "role": "assistant",
            "content": content or None,
            "tool_calls": [
                {
                    "id": self.id,
                    "type": "function",
                    "function": {
                        "name": self.name,
                        "arguments": json.dumps(
                            self.arguments,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ),
                    },
                }
            ],
        }

    def result_message(self, result: object) -> LLMMessage:
        """Render a tool result linked to this call ID."""
        return {
            "role": "tool",
            "tool_call_id": self.id,
            "content": json.dumps(result, ensure_ascii=False, separators=(",", ":")),
        }


@dataclass(frozen=True)
class LLMCompletion:
    """Completion text plus non-sensitive provider diagnostics."""

    content: str
    finish_reason: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    reasoning_tokens: int | None = None
    reasoning_content_chars: int | None = None
    tool_calls: tuple[LLMToolCall, ...] = ()


@dataclass(frozen=True)
class LLMConfig:
    """推理所需投影（P6 llm_credentials 视图）。"""

    base_url: str
    model: str
    api_key: str | None
    output_locale: str | None = None
    timeout_sec: int = 300
    # DeepSeek reasoning models may consume most of the budget before emitting
    # the JSON/code answer; keep enough room for glue generation by default.
    max_tokens: int = 16384


def build_url(base_url: str) -> str:
    """base_url → /chat/completions 端点（P6 卫生：base_url 禁带 /chat/completions 后缀）。"""
    if base_url.endswith("/chat/completions"):
        raise LLMError(f"base_url 禁带 /chat/completions 后缀（P6 卫生规则）：{base_url}")
    return base_url.rstrip("/") + "/chat/completions"


def build_system_prompt(
    output_locale: str | None = None,
    *,
    available_actions: list[str] | None = None,
) -> str:
    """系统提示：Planner 角色 + locale 指示 + 可选动作约束（P10 改进 #1）。

    available_actions 非空时，system prompt 硬约束 test_case_id 必须从中选一
    ——不选则返回 stop（LLM 不应发明未注册动作 ID）。
    """
    locale_hint = (
        f"用 {output_locale} 回答 rationale。"
        if output_locale in {"zh-CN", "en-US"}
        else ""
    )
    action_constraint = ""
    if available_actions:
        action_list = ", ".join(available_actions)
        action_constraint = (
            f"\n**硬约束**：test_case_id 必须恰好是以下之一：[{action_list}]。"
            "不得发明新 ID、不得缩写或加前缀。如果没有合适的下一步，"
            "返回 decision=stop 并说明原因。"
        )
    return (
        "你是 EdrEvalAgent 的 Red Team Planner。必须调用 submit_plan_decision 工具提交决策。"
        "不得在正文输出决策；decision=stop 时必须给 stop_reason。"
        + locale_hint
        + action_constraint
    )


def build_messages(
    system: str,
    objective: str | None,
    facts_summary: str,
    budget_summary: str,
) -> list[LLMMessage]:
    """OpenAI 兼容 messages：system + user（结构化摘要，控制 token）。"""
    user_lines = [
        f"环境 Facts 摘要：{facts_summary or '(空)'}",
        f"预算：{budget_summary}",
    ]
    if objective:
        user_lines.insert(0, f"目标契约：{objective}")
    return [{"role": "system", "content": system}, {"role": "user", "content": "\n".join(user_lines)}]


class OpenAICompatClient:
    """OpenAI SDK-backed chat completions client for compatible providers."""

    def __init__(
        self,
        config: LLMConfig,
        sdk_client: Any | None = None,
    ) -> None:
        if config.max_tokens <= 0:
            raise LLMError("max_tokens 必须为正整数")
        self._config = config
        self._sdk = sdk_client
        if self._sdk is None and config.api_key:
            self._sdk = OpenAI(
                api_key=config.api_key,
                base_url=config.base_url,
                timeout=float(config.timeout_sec),
                max_retries=0,
            )

    def complete(self, messages: list[LLMMessage]) -> str:
        return self.complete_with_metadata(messages).content

    def complete_with_metadata(self, messages: list[LLMMessage]) -> LLMCompletion:
        return self._complete_with_metadata(messages)

    def complete_tool(
        self,
        messages: list[LLMMessage],
        tools: list[LLMTool],
        *,
        tool_choice: LLMToolChoice = "required",
    ) -> LLMToolCall:
        completion = self.complete_tool_with_metadata(
            messages,
            tools,
            tool_choice=tool_choice,
        )
        if len(completion.tool_calls) != 1:
            raise LLMError(
                "LLM 必须返回恰好一个 tool_call；"
                f"实得 {len(completion.tool_calls)}，finish_reason={completion.finish_reason!r}"
            )
        return completion.tool_calls[0]

    def complete_tool_with_metadata(
        self,
        messages: list[LLMMessage],
        tools: list[LLMTool],
        *,
        tool_choice: LLMToolChoice = "required",
    ) -> LLMCompletion:
        """Request exactly one native function call and retain safe diagnostics."""
        if not tools:
            raise LLMError("Function Calling 至少需要一个工具定义")
        names = [tool.name for tool in tools]
        if len(names) != len(set(names)):
            raise LLMError("Function Calling 工具名不得重复")
        _validate_tool_choice(tool_choice, set(names))
        completion = self._complete_with_metadata(
            messages,
            tools=tools,
            tool_choice=tool_choice,
        )
        unknown = [call.name for call in completion.tool_calls if call.name not in set(names)]
        if unknown:
            raise LLMError(f"LLM 返回未注册工具：{unknown}")
        return completion

    def _complete_with_metadata(
        self,
        messages: list[LLMMessage],
        *,
        tools: list[LLMTool] | None = None,
        tool_choice: LLMToolChoice | None = None,
    ) -> LLMCompletion:
        if not self._config.api_key:
            raise LLMError("LLM_API_KEY 未配置（secrets.env）——没有凭据不发起请求")
        if self._sdk is None:  # pragma: no cover - constructor invariant
            raise LLMError("OpenAI SDK client 未初始化")
        options: dict[str, object] = {
            "model": self._config.model,
            "messages": messages,
            "max_tokens": self._config.max_tokens,
        }
        extra_body = _model_request_options(self._config.model)
        stream = _is_glm_53_flash(self._config.model)
        options["stream"] = stream
        if extra_body:
            options["extra_body"] = extra_body
        if tools is not None:
            options["tools"] = [tool.request_value() for tool in tools]
            options["tool_choice"] = _provider_tool_choice(
                self._config.model,
                tool_choice or "required",
            )
        try:
            response = self._sdk.chat.completions.create(**options)
            return _completion_from_stream(response) if stream else _completion_from_response(response)
        except (openai.APITimeoutError, TimeoutError) as exc:
            raise LLMTimeoutError(
                f"LLM 请求超时（timeout={self._config.timeout_sec}s）"
            ) from exc
        except openai.RateLimitError as exc:
            raise LLMError("LLM 请求被限流（HTTP 429）") from exc
        except openai.APIConnectionError as exc:
            raise LLMError("LLM 网络连接失败") from exc
        except openai.APIStatusError as exc:
            request_id = getattr(exc, "request_id", None)
            suffix = f"，request_id={request_id}" if request_id else ""
            raise LLMError(f"LLM HTTP {exc.status_code}{suffix}") from exc
        except (AttributeError, IndexError, TypeError, ValueError) as exc:
            raise LLMError(f"LLM 响应结构不合法：{exc}") from exc

    def with_max_tokens(self, max_tokens: int) -> OpenAICompatClient:
        """复制一个只改变输出预算的 client，便于 Planner/Glue 分角色限额。"""
        return OpenAICompatClient(
            replace(self._config, max_tokens=max_tokens),
            sdk_client=self._sdk,
        )


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _optional_non_negative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _model_request_options(model: str) -> dict[str, object]:
    """Return model-specific OpenAI-compatible request fields.

    GLM-5.3-FLASH requires thinking to remain enabled and only accepts
    low/high/max reasoning effort. Clearing prior-turn reasoning matches this
    client's deliberate policy of retaining visible assistant content only.
    """
    if _is_glm_53_flash(model):
        return {
            "thinking": {"type": "enabled", "clear_thinking": True},
            "reasoning_effort": "high",
            "do_sample": False,
        }
    return {}


def _is_glm_53_flash(model: str) -> bool:
    return model.casefold() == "glm-5.3-flash"


def _provider_tool_choice(model: str, choice: LLMToolChoice) -> LLMToolChoice:
    """Map the control-plane requirement to each provider's accepted wire value.

    GLM and DeepSeek V4 thinking mode accept only automatic tool selection.
    The caller still fails closed unless exactly one registered call is
    returned, so this does not weaken dispatch.
    """
    normalized = model.casefold()
    if choice == "none":
        return choice
    return (
        "auto"
        if normalized.startswith("glm-") or normalized.startswith("deepseek-v4-")
        else choice
    )


def _validate_tool_choice(choice: LLMToolChoice, names: set[str]) -> None:
    if isinstance(choice, str):
        if choice not in {"none", "auto", "required"}:
            raise LLMError(f"tool_choice 非法：{choice!r}")
        return
    try:
        if set(choice) != {"type", "function"} or choice["type"] != "function":
            raise ValueError
        function = choice["function"]
        if not isinstance(function, dict) or set(function) != {"name"}:
            raise ValueError
        name = function["name"]
        if not isinstance(name, str) or name not in names:
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise LLMError("tool_choice 必须引用当前请求中的 function 工具") from exc


def _completion_from_response(response: object) -> LLMCompletion:
    choices = _field(response, "choices")
    choice = choices[0]
    message = _field(choice, "message")
    content = _text_field(message, "content")
    reasoning_content = _text_field(message, "reasoning_content")
    usage = _field(response, "usage", default=None)
    return LLMCompletion(
        content=content,
        finish_reason=_optional_string(_field(choice, "finish_reason", default=None)),
        prompt_tokens=_usage_int(usage, "prompt_tokens"),
        completion_tokens=_usage_int(usage, "completion_tokens"),
        reasoning_tokens=_reasoning_tokens(usage),
        reasoning_content_chars=len(reasoning_content) if reasoning_content else None,
        tool_calls=_tool_calls_from_message(message),
    )


def _completion_from_stream(stream: object) -> LLMCompletion:
    content_parts: list[str] = []
    reasoning_chars = 0
    finish_reason: str | None = None
    usage: object | None = None
    tool_parts: dict[int, dict[str, str]] = {}
    for chunk in cast(Iterable[object], stream):
        chunk_usage = _field(chunk, "usage", default=None)
        if chunk_usage is not None:
            usage = chunk_usage
        choices = _field(chunk, "choices", default=())
        if not choices:
            continue
        choice = choices[0]
        delta = _field(choice, "delta")
        content_parts.append(_text_field(delta, "content"))
        reasoning_chars += len(_text_field(delta, "reasoning_content"))
        delta_tool_calls = _field(delta, "tool_calls", default=()) or ()
        for fallback_index, raw_call in enumerate(delta_tool_calls):
            raw_index = _field(raw_call, "index", default=fallback_index)
            if isinstance(raw_index, bool) or not isinstance(raw_index, int) or raw_index < 0:
                raise ValueError("流式 tool_call.index 非非负整数")
            parts = tool_parts.setdefault(
                raw_index,
                {"id": "", "type": "", "name": "", "arguments": ""},
            )
            _merge_stream_identity(parts, "id", _text_field(raw_call, "id"))
            _merge_stream_identity(parts, "type", _text_field(raw_call, "type"))
            function = _field(raw_call, "function", default=None)
            if function is not None:
                _merge_stream_identity(parts, "name", _text_field(function, "name"))
                parts["arguments"] += _text_field(function, "arguments")
        current_finish = _optional_string(_field(choice, "finish_reason", default=None))
        if current_finish is not None:
            finish_reason = current_finish
    return LLMCompletion(
        content="".join(content_parts),
        finish_reason=finish_reason,
        prompt_tokens=_usage_int(usage, "prompt_tokens"),
        completion_tokens=_usage_int(usage, "completion_tokens"),
        reasoning_tokens=_reasoning_tokens(usage),
        reasoning_content_chars=reasoning_chars or None,
        tool_calls=tuple(
            _tool_call_from_values(
                call_id=parts["id"],
                call_type=parts["type"] or "function",
                name=parts["name"],
                arguments=parts["arguments"],
            )
            for _index, parts in sorted(tool_parts.items())
        ),
    )


def _merge_stream_identity(parts: dict[str, str], field: str, value: str) -> None:
    if not value:
        return
    if parts[field] and parts[field] != value:
        raise ValueError(f"流式 tool_call.{field} 前后不一致")
    parts[field] = value


def _tool_calls_from_message(message: object) -> tuple[LLMToolCall, ...]:
    raw_calls = _field(message, "tool_calls", default=()) or ()
    calls: list[LLMToolCall] = []
    for raw_call in raw_calls:
        function = _field(raw_call, "function")
        calls.append(
            _tool_call_from_values(
                call_id=_text_field(raw_call, "id"),
                call_type=_text_field(raw_call, "type") or "function",
                name=_text_field(function, "name"),
                arguments=_field(function, "arguments"),
            )
        )
    return tuple(calls)


def _tool_call_from_values(
    *,
    call_id: str,
    call_type: str,
    name: str,
    arguments: object,
) -> LLMToolCall:
    if not call_id:
        raise ValueError("tool_call 缺少 id")
    if call_type != "function":
        raise ValueError(f"tool_call.type 仅允许 function，实得 {call_type!r}")
    if not name:
        raise ValueError("tool_call.function 缺少 name")
    if isinstance(arguments, str):
        try:
            parsed = json.loads(arguments)
        except json.JSONDecodeError as exc:
            raise ValueError(f"工具参数不是合法 JSON：{exc.msg}") from exc
    else:
        parsed = arguments
    if not isinstance(parsed, dict):
        raise ValueError("tool_call.function.arguments 必须是 JSON 对象")
    return LLMToolCall(id=call_id, name=name, arguments=parsed)


_MISSING = object()


def _field(value: object, name: str, *, default: object = _MISSING) -> Any:
    if isinstance(value, dict) and name in value:
        return value[name]
    if hasattr(value, name):
        return getattr(value, name)
    model_extra = getattr(value, "model_extra", None)
    if isinstance(model_extra, dict) and name in model_extra:
        return model_extra[name]
    if default is not _MISSING:
        return default
    raise ValueError(f"缺少字段 {name}")


def _text_field(value: object, name: str) -> str:
    item = _field(value, name, default=None)
    if item is None:
        return ""
    if not isinstance(item, str):
        raise ValueError(f"{name} 非字符串")
    return item


def _usage_int(usage: object | None, name: str) -> int | None:
    return _optional_non_negative_int(_field(usage, name, default=None))


def _reasoning_tokens(usage: object | None) -> int | None:
    details = _field(usage, "completion_tokens_details", default=None)
    return _usage_int(details, "reasoning_tokens")


_PLAN_DECISION_TOOL = LLMTool(
    name="submit_plan_decision",
    description="Submit the next registered BAS action, a safe stop, or a request for human input.",
    parameters=cast(dict[str, object], PlanDecision.model_json_schema()),
)


class PlannerDecider:
    """guided.py 的 Decider 实现：Context → LLM → PlanDecision。

    P10 改进 #1：从 environment_facts_summary 尾部提取 available_actions 列表
    注入 system prompt 硬约束（格式约定 `available_actions: ["a.x", ...]`），
    并在决策后校验 test_case_id 是否命中——未命中且 decision=next_step 时
    **重试**（带错误反馈，共 2 次），仍失败返回 stop（不猜）。
    """

    _RETRY_LIMIT = 2

    def __init__(self, client: OpenAICompatClient) -> None:
        self._client = client

    @staticmethod
    def _extract_available_actions(facts_summary: str) -> list[str] | None:
        """从 facts_summary 提取 available_actions（约定格式）。"""
        marker = "available_actions: "
        idx = facts_summary.rfind(marker)
        if idx < 0:
            return None
        rest = facts_summary[idx + len(marker):].strip()
        # 提取 JSON 数组部分
        try:
            end = rest.index("]")
            parsed = json.loads(rest[:end + 1])
            return [str(a) for a in parsed] if isinstance(parsed, list) else None
        except (ValueError, json.JSONDecodeError):
            return None

    def __call__(self, context: object) -> PlanDecision:  # PlannerContext
        objective: str | None = None
        obj_contract = getattr(context, "objective_contract", None)
        if obj_contract is not None:
            objective = str(obj_contract.objective)
        facts = str(getattr(context, "environment_facts_summary", "") or "")
        available = self._extract_available_actions(facts)
        base_messages = build_messages(
            system=build_system_prompt(
                self._client._config.output_locale,
                available_actions=available,
            ),
            objective=objective,
            facts_summary=facts,
            budget_summary=str(getattr(context, "budget", None) or ""),
        )
        messages = list(base_messages)
        for _attempt in range(self._RETRY_LIMIT):
            completion = self._client.complete_tool_with_metadata(
                messages,
                [_PLAN_DECISION_TOOL],
                tool_choice={
                    "type": "function",
                    "function": {"name": _PLAN_DECISION_TOOL.name},
                },
            )
            if len(completion.tool_calls) != 1:
                raise LLMError(
                    "Planner 必须调用一次 submit_plan_decision；"
                    f"实得 {len(completion.tool_calls)}，finish_reason={completion.finish_reason!r}"
                )
            call = completion.tool_calls[0]
            try:
                decision = PlanDecision.model_validate(call.arguments)
            except Exception as exc:  # pydantic ValidationError
                raise LLMError(f"模型工具参数违反 PlanDecision schema：{exc}") from exc
            if (decision.decision != "next_step"
                    or not available
                    or decision.test_case_id in available):
                return decision
            # P10 #1：test_case_id 未命中——带反馈重试
            messages = list(base_messages) + [
                call.assistant_message(content=completion.content),
                call.result_message({
                    "ok": False,
                    "error": (
                        f"test_case_id={decision.test_case_id!r} 不在 available_actions 中；"
                        f"必须从 {available} 选择，或提交 decision=stop"
                    ),
                }),
            ]
        # 重试耗尽：诚实 stop
        from packages.schemas.enums import PlanDecisionType
        return PlanDecision(
            decision=PlanDecisionType.STOP,
            stop_reason="llm_action_constraint_exhausted",
            rationale=f"LLM 在 {self._RETRY_LIMIT} 次尝试后仍返回未注册 "
                      f"test_case_id；诚实停机（不猜）",
        )
