"""部署层：PostgreSQL combo_state 连接与租约后端工厂。

DSN 不得写入 factory-config / Markdown。解析顺序：
1. ``FACTORY_POSTGRES_DSN``（字面连接串，仅本机临时）
2. ``FACTORY_POSTGRES_DSN_FILE``（指向 0600 文件，内容为 DSN）
3. ``FACTORY_POSTGRES_DSN_URI``（默认 ``secret://db/factory-combo-dsn``）
   + ``FACTORY_SECRETS_ENV`` 或相对 ``deployment/secrets.env`` 解析 SECRET_STORE_DIR

核心包 ``PostgresComboStateStore`` 不持凭据；本模块只做连接工厂注入。
"""

from __future__ import annotations

import os
from pathlib import Path

from packages.config.resolver import SecretResolver
from packages.config.secrets_env import SecretsEnv, SecretsEnvError
from packages.contract_gap import ContractGap, ContractGapError
from packages.sample_factory.postgres import PostgresComboStateStore

_DEFAULT_DSN_URI = "secret://db/factory-combo-dsn"
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_SECRETS_ENV = _REPO_ROOT / "deployment" / "secrets.env"

_STATE: PostgresComboStateStore | None = None


def resolve_factory_postgres_dsn(
    *,
    environ: dict[str, str] | None = None,
    secrets_env_path: Path | None = None,
) -> str:
    """解析工厂 combo_state DSN；缺失时 ContractGap，不伪造。"""
    env = os.environ if environ is None else environ
    literal = (env.get("FACTORY_POSTGRES_DSN") or "").strip()
    if literal:
        return literal

    dsn_file = (env.get("FACTORY_POSTGRES_DSN_FILE") or "").strip()
    if dsn_file:
        path = Path(dsn_file).expanduser()
        if not path.is_file():
            raise ContractGapError(
                ContractGap(
                    capability="连接 PostgreSQL combo_state",
                    missing=f"FACTORY_POSTGRES_DSN_FILE 不存在：{path}",
                    checked=(str(path),),
                    risk="缺失 DSN 时硬编码凭据会违反 AGENTS.md §4/§7",
                    next_step="写入含 postgresql://… 的 0600 文件，或改用 FACTORY_POSTGRES_DSN / secret://",
                )
            )
        dsn = path.read_text(encoding="utf-8").strip()
        if not dsn:
            raise ContractGapError(
                ContractGap(
                    capability="连接 PostgreSQL combo_state",
                    missing=f"DSN 文件为空：{path}",
                    checked=(str(path),),
                    risk="空 DSN 会让租约后端静默退回错误连接",
                    next_step="在文件中写入完整 postgresql:// 连接串（单行）",
                )
            )
        return dsn

    uri = (env.get("FACTORY_POSTGRES_DSN_URI") or _DEFAULT_DSN_URI).strip()
    secrets_path = secrets_env_path
    if secrets_path is None:
        configured = (env.get("FACTORY_SECRETS_ENV") or "").strip()
        secrets_path = Path(configured).expanduser() if configured else _DEFAULT_SECRETS_ENV
    try:
        secrets = SecretsEnv.load(secrets_path, require_private=os.name != "nt")
    except SecretsEnvError as exc:
        raise ContractGapError(
            ContractGap(
                capability="连接 PostgreSQL combo_state",
                missing=f"无法加载 secrets.env：{exc}",
                checked=(str(secrets_path), "FACTORY_POSTGRES_DSN", "FACTORY_POSTGRES_DSN_FILE"),
                risk="无凭据权威源时不得把 DSN 写进配置文件",
                next_step=(
                    "设置 FACTORY_POSTGRES_DSN / FACTORY_POSTGRES_DSN_FILE，"
                    "或配置 secrets.env 的 SECRET_STORE_DIR 并放入 secret://db/factory-combo-dsn"
                ),
            )
        ) from exc
    if secrets.secret_store_dir is None:
        raise ContractGapError(
            ContractGap(
                capability="连接 PostgreSQL combo_state",
                missing="SECRET_STORE_DIR 未配置，且未提供 FACTORY_POSTGRES_DSN(_FILE)",
                checked=(str(secrets_path),),
                risk="无法解析 secret:// 时硬编码 DSN 会污染审计链",
                next_step="在 secrets.env 设置 SECRET_STORE_DIR，或改用环境变量 DSN",
            )
        )
    return SecretResolver(secrets.secret_store_dir).resolve(uri).strip()


def create_postgres_state_backend(
    *,
    environ: dict[str, str] | None = None,
    secrets_env_path: Path | None = None,
    connect=None,
) -> PostgresComboStateStore:
    """返回进程内共享的 PostgresComboStateStore，并确保 DDL 已执行。"""
    global _STATE
    if _STATE is not None and connect is None and environ is None and secrets_env_path is None:
        return _STATE

    dsn = resolve_factory_postgres_dsn(environ=environ, secrets_env_path=secrets_env_path)

    if connect is None:
        try:
            import psycopg
        except ImportError as exc:
            raise ContractGapError(
                ContractGap(
                    capability="连接 PostgreSQL combo_state",
                    missing="未安装 psycopg（PostgreSQL 驱动）",
                    checked=("requirements.txt", "import psycopg"),
                    risk="缺少驱动时回退内存租约会在多机场景撞车",
                    next_step="pip install 'psycopg[binary]>=3.1,<4' 后重试",
                )
            ) from exc

        def connect() -> object:
            return psycopg.connect(dsn)

    store = PostgresComboStateStore(connect)
    store.initialize()
    if environ is None and secrets_env_path is None:
        _STATE = store
    return store


def reset_postgres_state_backend_for_tests() -> None:
    """测试专用：清空单例。"""
    global _STATE
    _STATE = None


__all__ = [
    "create_postgres_state_backend",
    "reset_postgres_state_backend_for_tests",
    "resolve_factory_postgres_dsn",
]
