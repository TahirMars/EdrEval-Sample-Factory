"""secrets.env 加载器（P6：敏感凭据唯一权威源，按数据文件解析，非 shell source）。

纪律（见统一运行配置 spec §4.3）：
  - 键封闭集：SECRET_STORE_DIR（指针）/ LLM_API_KEY（产品层 LLM 凭据，专用可撤销）；
  - 拒绝未知键、重复键、export 前缀、命令替换（$()、反引号）与 shell 变量展开（${...}）；
  - 文件权限必须 0600（组/其他可读即拒；require_private=False 仅供测试）；
  - 值按字面解析（首个 '=' 后全部为值；不做引号剥离/转义解释）；
  - SECRET_STORE_DIR 必须为绝对路径。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

_ALLOWED_KEYS = frozenset({"SECRET_STORE_DIR", "LLM_API_KEY"})
_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SHELL_SUB_RE = re.compile(r"\$\(|`|\$\{")


class SecretsEnvError(ValueError):
    """secrets.env 违反解析纪律或权限要求。"""


@dataclass(frozen=True)
class SecretsEnv:
    """已加载并校验的 secrets.env（只含封闭键集中的条目）。"""

    values: dict[str, str]

    @classmethod
    def load(cls, path: str | Path, *, require_private: bool = True) -> SecretsEnv:
        p = Path(path)
        if not p.is_file():
            raise SecretsEnvError(f"secrets.env 不存在：{p}")
        # POSIX：必须 0600。Windows/NTFS 无等价 st_mode 位，由操作员用 ACL 收口。
        if require_private and os.name != "nt" and (p.stat().st_mode & 0o077) != 0:
            raise SecretsEnvError(f"secrets.env 权限过宽（须 chmod 600）：{p}")

        values: dict[str, str] = {}
        for lineno, raw_line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                raise SecretsEnvError(
                    f"第 {lineno} 行：禁止 export 前缀（按数据文件解析，非 shell source）"
                )
            if "=" not in line:
                raise SecretsEnvError(f"第 {lineno} 行：缺少 '='：{line!r}")
            key, _, value = line.partition("=")
            key = key.strip()
            if not _KEY_RE.match(key):
                raise SecretsEnvError(f"第 {lineno} 行：键非法：{key!r}")
            if key not in _ALLOWED_KEYS:
                raise SecretsEnvError(
                    f"第 {lineno} 行：未知键 {key}（封闭集：{sorted(_ALLOWED_KEYS)}）"
                )
            if key in values:
                raise SecretsEnvError(f"第 {lineno} 行：重复键 {key}")
            if _SHELL_SUB_RE.search(value):
                raise SecretsEnvError(f"第 {lineno} 行：值含命令替换/shell 表达式，拒绝解析")
            values[key] = value

        store = values.get("SECRET_STORE_DIR")
        if store is not None and not (
            PurePosixPath(store).is_absolute()
            or PureWindowsPath(store).is_absolute()
        ):
            raise SecretsEnvError("SECRET_STORE_DIR 必须为绝对路径")
        return cls(values=values)

    @property
    def llm_api_key(self) -> str | None:
        return self.values.get("LLM_API_KEY")

    @property
    def secret_store_dir(self) -> str | None:
        return self.values.get("SECRET_STORE_DIR")
