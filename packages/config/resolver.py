"""secret:// / lab-secret:// URI 解析与最小权限投影（P6 spec §5）。

双命名空间：实验室物料（krbtgt/nthash/Sliver mTLS 证书等）走 lab-secret://<type>/<name>；
产品层通用物料走 secret://<type>/<name>。两者均从 SECRET_STORE_DIR 解析；type/name 字符集
白名单（首字符限制天然拒绝 .. 与 /，防路径穿越）+ 解析后包含性复核；缺失即
ContractGapError（复用 packages.contract_gap，不伪造、不静默）。

投影（spec §5.2）：llm_credentials 只给 LLM 桥推理所需四项；adapter_store_dir 只给
Sliver Adapter 存仓库路径——互不可见对方凭据。
"""

from __future__ import annotations

import re
from pathlib import Path

from packages.config.runtime import ModelConfig
from packages.config.secrets_env import SecretsEnv
from packages.contract_gap import ContractGap, ContractGapError

_URI_RE = re.compile(
    r"^(?P<scheme>secret|lab-secret)://"
    r"(?P<type>[a-z0-9][a-z0-9-]*)/"
    r"(?P<name>[A-Za-z0-9_][A-Za-z0-9._-]*)$"
)


class SecretResolver:
    """从 SECRET_STORE_DIR 解析双命名空间密钥引用。"""

    def __init__(self, store_dir: str | Path | None = None) -> None:
        self._store = Path(store_dir).expanduser() if store_dir is not None else None

    def resolve(self, uri: str) -> str:
        """按 URI 取物料文本内容；非法/越界/缺失分别抛 ValueError / ContractGapError。"""
        m = _URI_RE.match(uri)
        if m is None:
            raise ValueError(
                f"密钥引用格式非法（须 secret://<type>/<name> 或 lab-secret://<type>/<name>）：{uri!r}"
            )
        store = self._require_store(uri)
        target = (store / m["type"] / m["name"]).resolve()
        if not target.is_relative_to(store):
            raise ValueError(f"密钥引用越出存仓库边界：{uri!r}")
        if not target.is_file():
            raise ContractGapError(
                ContractGap(
                    capability=f"解析密钥引用 {uri}",
                    missing=f"存仓库文件不存在：{target}",
                    checked=(str(target),),
                    risk="缺失物料时伪造值会污染执行链与台账可信度（AGENTS.md §4）",
                    next_step="补齐物料（Sliver 证书走 new-operator 流程）后重试。",
                )
            )
        return target.read_text(encoding="utf-8")

    def _require_store(self, uri: str) -> Path:
        if self._store is None:
            raise ContractGapError(
                ContractGap(
                    capability=f"解析密钥引用 {uri}",
                    missing="SECRET_STORE_DIR 未配置（secrets.env 指针缺失）",
                    checked=("deployment/secrets.env",),
                    risk="凭据值无法安全解析时伪造或硬编码将违反 AGENTS.md §4/§7 硬边界",
                    next_step="在 secrets.env 配置 SECRET_STORE_DIR 后重试。",
                )
            )
        return self._store.resolve()


def llm_credentials(
    secrets: SecretsEnv, model: ModelConfig
) -> dict[str, str | int | None]:
    """LLM Planner Bridge 视图（spec §5.2）：只含推理所需；永不含 SECRET_STORE_DIR。"""
    return {
        "base_url": model.base_url,
        "model": model.name,
        "seed": model.seed,
        "api_key": secrets.llm_api_key,
        "output_locale": model.output_locale,
    }


def adapter_store_dir(secrets: SecretsEnv) -> Path:
    """Sliver Adapter 视图（spec §5.2）：只含存仓库路径；永不含 LLM 凭据。"""
    store = secrets.secret_store_dir
    if store is None:
        raise ContractGapError(
            ContractGap(
                capability="解析 lab-secret:// 物料（Adapter dispatch）",
                missing="SECRET_STORE_DIR 未配置（secrets.env 指针缺失）",
                checked=("deployment/secrets.env",),
                risk="Adapter 无法解析证书/凭据引用时伪造连接参数会破坏 mTLS 审计链",
                next_step="配置 SECRET_STORE_DIR 指针后重试。",
            )
        )
    return Path(store).expanduser()
