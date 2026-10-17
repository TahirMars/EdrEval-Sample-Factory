"""统一运行配置包（P6）：runtime.toml / secrets.env / URI 解析与最小权限投影。

设计契约：docs/superpowers/specs/2026-08-22-unified-runtime-config.md。
模板：deployment/runtime.example.toml、deployment/secrets.env.example。
"""

from __future__ import annotations

from .resolver import SecretResolver, adapter_store_dir, llm_credentials
from .runtime import ModelConfig, RuntimeConfig, RuntimeConfigError, load_runtime
from .secrets_env import SecretsEnv, SecretsEnvError

__all__ = [
    "ModelConfig",
    "RuntimeConfig",
    "RuntimeConfigError",
    "SecretResolver",
    "SecretsEnv",
    "SecretsEnvError",
    "adapter_store_dir",
    "llm_credentials",
    "load_runtime",
]
