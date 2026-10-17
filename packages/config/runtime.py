"""统一运行配置加载器（P6：runtime.toml 为非敏感配置唯一权威源）。

卫生规则（见 docs/superpowers/specs/2026-08-22-unified-runtime-config.md §3）：
  - 顶层节封闭集 {"model"}、[model] 键封闭集（未知即拒，防"实际用了哪个配置说不清"）；
  - base_url 禁嵌用户名/密码、禁带 /chat/completions 后缀（调用方自行追加）、禁 query/fragment；
  - http:// 仅允许 loopback（本机 Ollama/vLLM）；远程一律 https；
  - 可选内部 CA 证书路径（ca_certificate，内网 vLLM 自签场景）。
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from packages.schemas.ledger import LlmFingerprint

_ALLOWED_SECTIONS = frozenset({"model"})
_ALLOWED_MODEL_KEYS = frozenset(
    {"provider", "base_url", "name", "seed", "planner_prompt_ver", "ca_certificate", "timeout_sec", "output_locale"}
)
_ALLOWED_PROVIDERS = frozenset({"llm-api", "ollama", "llm-proxy"})
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_OUTPUT_LOCALES = frozenset({"zh-CN", "en-US"})  # P7 §5：与 i18n catalog 启用集一致


class RuntimeConfigError(ValueError):
    """runtime.toml 违反卫生规则或结构契约。"""


@dataclass(frozen=True)
class ModelConfig:
    """[model] 节的类型化载体。"""

    base_url: str
    name: str
    provider: str = "llm-api"
    seed: int | None = None
    planner_prompt_ver: str | None = None
    ca_certificate: str | None = None
    timeout_sec: int = 300
    output_locale: str | None = None


@dataclass(frozen=True)
class RuntimeConfig:
    """runtime.toml 的类型化载体（[model] 缺席 = 未配置模型，合法）。"""

    model: ModelConfig | None = None

    def fingerprint(self) -> LlmFingerprint | None:
        """从 [model] 派生 RunManifest 的 LlmFingerprint（运行模式 §3.3 可比性）。"""
        if self.model is None:
            return None
        return LlmFingerprint(
            model=self.model.name,
            seed=self.model.seed,
            planner_prompt_ver=self.model.planner_prompt_ver,
        )


def load_runtime(path: str | Path) -> RuntimeConfig:
    """加载并校验 runtime.toml；文件不存在即拒（提供路径即必须存在）。"""
    p = Path(path)
    if not p.is_file():
        raise RuntimeConfigError(f"runtime.toml 不存在：{p}（未配置模型时可不提供该文件）")

    with p.open("rb") as f:
        data: dict[str, Any] = tomllib.load(f)

    unknown_sections = sorted(set(data) - _ALLOWED_SECTIONS)
    if unknown_sections:
        raise RuntimeConfigError(
            f"runtime.toml 未知顶层节：{unknown_sections}（封闭集：{sorted(_ALLOWED_SECTIONS)}）"
        )

    raw_model: dict[str, Any] | None = data.get("model")
    if raw_model is None:
        return RuntimeConfig(model=None)

    unknown_keys = sorted(set(raw_model) - _ALLOWED_MODEL_KEYS)
    if unknown_keys:
        raise RuntimeConfigError(
            f"[model] 未知键：{unknown_keys}（封闭集：{sorted(_ALLOWED_MODEL_KEYS)}）"
        )

    provider = raw_model.get("provider", "llm-api")
    if provider not in _ALLOWED_PROVIDERS:
        raise RuntimeConfigError(
            f"[model].provider 非法：{provider!r}（允许：{sorted(_ALLOWED_PROVIDERS)}）"
        )

    model = ModelConfig(
        base_url=_validated_base_url(raw_model.get("base_url")),
        name=_req_str(raw_model, "name"),
        provider=provider,
        seed=_validated_seed(raw_model.get("seed")),
        planner_prompt_ver=_opt_str(raw_model.get("planner_prompt_ver"), "planner_prompt_ver"),
        ca_certificate=_opt_str(raw_model.get("ca_certificate"), "ca_certificate"),
        timeout_sec=_validated_timeout(raw_model.get("timeout_sec", 300)),
        output_locale=_validated_output_locale(raw_model.get("output_locale")),
    )
    return RuntimeConfig(model=model)


def _validated_output_locale(value: Any) -> str | None:
    """P7 §5：封闭集与 i18n catalog 启用集一致；未配置=跟随 Provider 默认。"""
    if value is None:
        return None
    if not isinstance(value, str) or value not in _OUTPUT_LOCALES:
        raise RuntimeConfigError(
            f"[model].output_locale 非法：{value!r}（封闭集：{sorted(_OUTPUT_LOCALES)}）"
        )
    return value


def _req_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise RuntimeConfigError(f"[model].{key} 必须为非空字符串")
    return value


def _opt_str(value: Any, key: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise RuntimeConfigError(f"[model].{key} 必须为非空字符串（或省略）")
    return value


def _validated_seed(value: Any) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RuntimeConfigError("[model].seed 必须为非负整数（或省略）")
    return value


def _validated_timeout(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise RuntimeConfigError("[model].timeout_sec 必须为正整数")
    return value


def _validated_base_url(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeConfigError("[model].base_url 必须为非空字符串")
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise RuntimeConfigError(f"base_url 仅允许 http/https：{value!r}")
    if parts.username or parts.password:
        raise RuntimeConfigError("base_url 禁止嵌入用户名/密码（凭据只经 secrets.env）")
    if parts.query or parts.fragment:
        raise RuntimeConfigError("base_url 禁止携带 query/fragment")
    path = parts.path or "/"
    if path.lower().rstrip("/").endswith("/chat/completions"):
        raise RuntimeConfigError("base_url 不应带 /chat/completions 后缀（由调用方追加）")
    if parts.scheme == "http" and parts.hostname not in _LOOPBACK_HOSTS:
        raise RuntimeConfigError(
            f"http:// 仅允许 loopback（本机 Ollama/vLLM）：{parts.hostname!r} 请改用 https"
        )
    return value
