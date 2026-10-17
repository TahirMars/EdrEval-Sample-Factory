"""全息执行台账与 Run Manifest 模型（运行模式 v1.3 §2.1 / §3.3）。

硬边界（继承主设计 §0.5 硬边界2）：凭证只记引用/哈希，永不落明文。
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .entities import OracleResult
from .enums import LedgerRole, Mode


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Asset(_Strict):
    host: str
    session_ref: str | None = None


class Process(_Strict):
    name: str
    pid: int | None = None
    ppid: int | None = None
    sig: str | None = None


class NetworkFlow(_Strict):
    proto: str
    dst: str
    bytes: int | None = Field(default=None, ge=0)


class TimeWindow(_Strict):
    """时钟校正后时间窗（运行模式 §2.2.2）。"""

    start: str
    end: str
    clock_offset_ms: int = 0


class GateStamp(_Strict):
    policy_profile: str
    decision: str
    approver: str | None = None


class Cleanup(_Strict):
    """清理绑定（运行模式 §2.2.4）。"""

    required: bool = False
    executed: bool = False
    ref: str | None = None
    skipped_reason: str | None = None


_CRED_REF_PREFIXES = ("lab-secret://", "secret://")


class LedgerEntry(_Strict):
    """append-only 台账条目（运行模式 §2.1）。

    hash-chain 字段（prev_hash/entry_hash）由 packages.ledger.chain 计算与校验；
    模型本身只承载数据与凭证引用边界校验。
    """

    seq: int = Field(ge=0)
    run_id: str
    step_id: str
    mode: Mode
    role: LedgerRole = LedgerRole.ATTACK  # N7：evidence_collection 归因排除
    ttp_tags: list[str] = Field(default_factory=list)
    ht_id: str | None = None
    component: str | None = None
    tool: str | None = None
    assets: list[Asset] = Field(default_factory=list)
    credential_refs: list[str] = Field(default_factory=list)
    command_template: str | None = None
    params_hash: str | None = None
    processes: list[Process] = Field(default_factory=list)
    network: list[NetworkFlow] = Field(default_factory=list)
    time_window: TimeWindow | None = None
    oracle: OracleResult | None = None
    gate: GateStamp | None = None
    cleanup: Cleanup = Field(default_factory=Cleanup)
    prev_hash: str | None = None
    entry_hash: str | None = None

    @field_validator("credential_refs")
    @classmethod
    def _only_refs(cls, v: list[str]) -> list[str]:
        for ref in v:
            if not ref.startswith(_CRED_REF_PREFIXES):
                raise ValueError(
                    f"credential_refs 只允许 {_CRED_REF_PREFIXES} 引用，禁止明文：{ref!r}"
                )
        return v


class SigmaRuleset(_Strict):
    repo: str
    commit: str


class LlmFingerprint(_Strict):
    model: str
    seed: int | None = None
    planner_prompt_ver: str | None = None


class RunManifest(_Strict):
    """不可变指纹（运行模式 §3.3）。同 Manifest 重跑=可比；改任一项=新对照段。"""

    matrix_version: str
    playbook_ids: list[str] = Field(default_factory=list)  # 模式1/3
    objective_hash: str | None = None  # 模式2
    sigma_ruleset: SigmaRuleset | None = None
    tooling_snapshot: dict[str, str] = Field(default_factory=dict)
    edr_fingerprint: dict[str, str] = Field(default_factory=dict)
    clock_offsets: dict[str, int] = Field(default_factory=dict)
    opsec_profile: str
    llm: LlmFingerprint | None = None
    lab_profile: str
    license_mode: str
    sysmon_config_hash: str | None = None  # N4：可比性只在同 hash 段内成立
    dwell_gap_sec: int = Field(default=30, ge=0)  # C1：归因串行静默间隔，入指纹
