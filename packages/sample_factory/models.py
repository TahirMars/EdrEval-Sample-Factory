"""样本工厂冻结数据合同。

权威来源：
- host-execution sample-factory v0.5 §4-§6（AtomSpec / SampleRecipe / 可选遥测合同）；
- sample-factory pipeline v1.10 §3-§7（规划审计、租约、taxonomy、三重验证、manifest）。

本模块只描述控制面数据，不包含插件源码、载荷内容或自由命令。
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from packages.schemas.enums import ResultClass

_ATOM_ID_RE = re.compile(r"^atom\.[a-z0-9][a-z0-9._-]*$")
_PH_ID_RE = re.compile(r"^PH-[A-Z]{2}[0-9]{2}$")
_ATTCK_ID_RE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_SECRET_REF_RE = re.compile(r"^(?:lab-)?secret://[^\s]+$")
_CAPABILITY_RE = re.compile(r"^cap\.[a-z0-9][a-z0-9._-]*$")
_PlannedAtomId = Annotated[str, StringConstraints(pattern=_ATOM_ID_RE.pattern)]


def _validate_ph_sequence(value: tuple[str, ...]) -> tuple[str, ...]:
    if len(value) != len(set(value)) or any(not _PH_ID_RE.fullmatch(item) for item in value):
        raise ValueError("PH 序列必须有序、无重复且匹配 PH-XX00")
    return value


def _validate_canonical_parameters(value: dict[str, Any]) -> dict[str, Any]:
    required = {"atoms", "evasion_tier", "pointer_mode", "execution_logging"}
    legacy = {"atoms", "evasion_tier", "pointer_mode"}
    keys = frozenset(value)
    if keys not in {frozenset(required), frozenset(legacy)} or not isinstance(
        value.get("atoms"), dict
    ):
        raise ValueError(
            "parameters_canonical 必须是 v1.9 四字段或只读兼容的旧三字段身份"
        )
    if value.get("evasion_tier") not in {"E0", "E1", "E2", "E3", "E4"}:
        raise ValueError("parameters_canonical.evasion_tier 非法")
    if value.get("pointer_mode") not in {None, "sigflip", "runtime-param"}:
        raise ValueError("parameters_canonical.pointer_mode 非法")
    if "execution_logging" in value and not isinstance(value.get("execution_logging"), bool):
        raise ValueError("parameters_canonical.execution_logging 必须是布尔值")
    return value


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AtomRole(StrEnum):
    CARRIER = "carrier"
    LOADER_ATOM = "loader_atom"
    EXECUTION_ATOM = "execution_atom"


class HandoffMaterialize(StrEnum):
    """跨原子交接的物化策略；与具体 TTP 解耦。"""

    NONE = "none"
    EMBED_AT_BUILD = "embed_at_build"
    WORKSPACE_FILE = "workspace_file"
    RUNTIME_LOADER = "runtime_loader"


class IntegrationState(StrEnum):
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    PLANNED = "planned"
    RESERVED_ATOM = "reserved_atom"
    CONTRACT_GAP = "contract_gap"
    REJECTED = "rejected"


class SafetyProfile(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH_RISK = "high_risk"


class TriggerMode(StrEnum):
    USER_OPEN = "user_open"
    LAB_TRIGGER = "lab_trigger"
    OS_DEFAULT_HOST = "os_default_host"
    SESSION_REPLAY = "session_replay"


class DeliveryMode(StrEnum):
    REAL_MAIL = "real-mail"
    MOTW_STAMPED = "motw-stamped(lab)"
    PRESET_NO_MOTW = "preset(no-MotW)"


class PointerMode(StrEnum):
    SIGFLIP = "sigflip"
    RUNTIME_PARAM = "runtime-param"


class ProductionPolicy(StrEnum):
    BASELINE = "baseline"
    EVASION_FRONTIER = "evasion_frontier"


class GlueOrigin(StrEnum):
    TEMPLATE = "template"
    AGENT = "agent"


class TemplateStatus(StrEnum):
    OBSERVED = "observed"
    CANDIDATE = "candidate"
    VERIFIED = "verified"
    RETIRED = "retired"


class ComboStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class FailureTaxonomy(StrEnum):
    COMPILE_FAIL = "COMPILE_FAIL"
    RUNTIME_CRASH = "RUNTIME_CRASH"
    TELEMETRY_MISS = "TELEMETRY_MISS"
    LOADER_FAIL = "LOADER_FAIL"
    SANDBOX_BLOCKED = "SANDBOX_BLOCKED"
    TIMEOUT = "TIMEOUT"
    ANTI_ANALYSIS_SKIP = "ANTI_ANALYSIS_SKIP"


class LeaseDisposition(StrEnum):
    ACQUIRED = "acquired"
    TAKEN_OVER = "taken_over"
    BUSY = "busy"
    TERMINAL = "terminal"


class SignalKind(StrEnum):
    POSITIVE = "positive"
    ABSENCE = "absence"


class SignalLevel(StrEnum):
    REQUIRED = "required"
    OPTIONAL = "optional"


class AtomSpec(_FrozenModel):
    """可组合原子声明；八项扩展字段保持显式、可 schema 化。

    ``produces_handoffs`` / ``consumes_handoffs`` 构成类型化交接图；
    ``materialize`` 声明编译期/运行期如何闭合边。无 PH 的支撑原子
    （如静态 payload 目录项）可进入 loader 槽，但不计入评分分母。
    """

    atom_id: str
    role: AtomRole
    integration_state: IntegrationState
    ph_ids: tuple[str, ...] = ()
    attck_ids: tuple[str, ...] = ()
    variant_family: str = Field(min_length=1)
    required_capabilities: tuple[str, ...] = ()
    provided_capabilities: tuple[str, ...] = ()
    inputs_schema_ref: str = Field(min_length=1)
    param_domains: dict[str, tuple[Any, ...]] = Field(default_factory=dict)
    output_contract: str = Field(min_length=1)
    handoff_contract: str | None = None
    produces_handoffs: tuple[str, ...] = ()
    consumes_handoffs: tuple[str, ...] = ()
    materialize: HandoffMaterialize = HandoffMaterialize.NONE
    artifact_ref: str | None = None
    c2_pointer_schema: str | None = None
    env_prerequisites: tuple[str, ...] = ()
    toolchain_ref: str | None = None
    telemetry_contract_ref: str | None = None
    verification_profile: str = Field(min_length=1)
    compat_hints: tuple[str, ...] = ()
    safety_profile: SafetyProfile
    trigger_modes: tuple[TriggerMode, ...] = Field(min_length=1)
    requires_implant: bool
    tool_ref: str | None = None

    @field_validator("atom_id")
    @classmethod
    def _valid_atom_id(cls, value: str) -> str:
        if not _ATOM_ID_RE.fullmatch(value):
            raise ValueError(f"atom_id 必须匹配 {_ATOM_ID_RE.pattern}")
        return value

    @field_validator("ph_ids")
    @classmethod
    def _valid_ph_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(not _PH_ID_RE.fullmatch(item) for item in value):
            raise ValueError("ph_ids 必须是无重复的 PH-XX00 标识")
        return value

    @field_validator("attck_ids")
    @classmethod
    def _valid_attck_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(not _ATTCK_ID_RE.fullmatch(item) for item in value):
            raise ValueError("attck_ids 必须是无重复的 ATT&CK technique/sub-technique ID")
        return value

    @field_validator("required_capabilities", "provided_capabilities")
    @classmethod
    def _valid_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(
            not _CAPABILITY_RE.fullmatch(item) for item in value
        ):
            raise ValueError("capabilities 必须唯一且匹配 cap.<name>")
        return value

    @field_validator("produces_handoffs", "consumes_handoffs")
    @classmethod
    def _valid_handoffs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("handoff id 不得重复")
        for item in value:
            if not item.startswith("handoff://") or len(item) < len("handoff://x"):
                raise ValueError(f"handoff id 必须是 handoff://… 引用：{item}")
        return value

    @field_validator("artifact_ref")
    @classmethod
    def _valid_artifact_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith(("payload://", "lab-secret://", "secret://")):
            raise ValueError("artifact_ref 只允许 payload:// 或 lab-secret:// / secret://")
        return value

    @field_validator("param_domains")
    @classmethod
    def _non_empty_domains(cls, value: dict[str, tuple[Any, ...]]) -> dict[str, tuple[Any, ...]]:
        if any(not key.strip() or not domain for key, domain in value.items()):
            raise ValueError("param_domains 的键及每个取值域均不得为空")
        return value

    @field_validator("trigger_modes")
    @classmethod
    def _unique_triggers(cls, value: tuple[TriggerMode, ...]) -> tuple[TriggerMode, ...]:
        if len(value) != len(set(value)):
            raise ValueError("trigger_modes 不得重复")
        return value

    @field_validator("verification_profile")
    @classmethod
    def _verification_profile(cls, value: str) -> str:
        if value not in {"standard", "anti-analysis-ack"}:
            raise ValueError("verification_profile 仅允许 standard / anti-analysis-ack")
        return value

    @model_validator(mode="after")
    def _support_atom_consistency(self) -> AtomSpec:
        if not self.ph_ids:
            if self.attck_ids:
                raise ValueError("无 PH 的 handoff 支撑原子不得声明 attck_ids")
            if self.telemetry_contract_ref is not None:
                raise ValueError("无 PH 的 handoff 支撑原子不得声明遥测合同")
            if not self.produces_handoffs:
                raise ValueError("无 PH 原子必须至少 produces 一个 handoff")
        else:
            if not self.attck_ids:
                raise ValueError("有 PH 的原子必须声明 attck_ids")
        if self.materialize is HandoffMaterialize.EMBED_AT_BUILD and not self.artifact_ref:
            raise ValueError("embed_at_build 必须提供 artifact_ref")
        if self.materialize is HandoffMaterialize.NONE and self.artifact_ref is not None:
            raise ValueError("materialize=none 时不得携带 artifact_ref")
        return self


class PluginProvenance(_FrozenModel):
    """AtomSpec 外的供应链双闸；插件源码本身位于独立仓。"""

    repository_ref: str = Field(min_length=1)
    source_revision: str = Field(min_length=1)
    source_refs: tuple[str, ...] = Field(min_length=1)
    audit_passed: bool
    pinned: bool
    reviewed_by: str = Field(min_length=1)
    reviewed_at: datetime

    @field_validator("repository_ref")
    @classmethod
    def _external_repository(cls, value: str) -> str:
        if not value.startswith(("plugin://", "plugin-fixture://", "https://", "ssh://")):
            raise ValueError("插件仓必须是 plugin:// / plugin-fixture:// / https:// / ssh:// 外部引用")
        return value

    @field_validator("source_refs")
    @classmethod
    def _traceable_sources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.startswith(("https://", "http://", "doi:")) for item in value):
            raise ValueError("source_refs 只允许可追溯 URL/DOI")
        return value

    @model_validator(mode="after")
    def _pinned_review(self) -> PluginProvenance:
        if self.pinned and not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", self.source_revision):
            raise ValueError("pinned 插件 source_revision 必须是 40/64 位十六进制")
        if self.reviewed_at.tzinfo is None or self.reviewed_at.utcoffset() is None:
            raise ValueError("reviewed_at 必须带时区")
        return self


class SampleRecipe(_FrozenModel):
    recipe_id: str = Field(min_length=1)
    carrier: str | None = None
    loader_atoms: tuple[str, ...] = ()
    execution_atoms: tuple[str, ...] = ()
    implant_sha256: str | None = None
    implant_format: str | None = None
    delivery: DeliveryMode
    trigger_mode: TriggerMode
    ph_ids: tuple[str, ...] = Field(min_length=1)
    evasion_tier: str
    pointer_mode: PointerMode | None = None
    persona_ref: str | None = None
    execution_logging: bool = Field(default=False, strict=True)

    @field_validator("carrier")
    @classmethod
    def _carrier_id(cls, value: str | None) -> str | None:
        if value is not None and not _ATOM_ID_RE.fullmatch(value):
            raise ValueError("carrier 必须引用 atom.*")
        return value

    @field_validator("loader_atoms", "execution_atoms")
    @classmethod
    def _atom_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(not _ATOM_ID_RE.fullmatch(item) for item in value):
            raise ValueError("atom 序列必须是无重复 atom.* 引用")
        return value

    @field_validator("ph_ids")
    @classmethod
    def _recipe_ph_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(not _PH_ID_RE.fullmatch(item) for item in value):
            raise ValueError("ph_ids 必须是有序、无重复的 PH-XX00 标识")
        return value

    @field_validator("evasion_tier")
    @classmethod
    def _evasion_tier(cls, value: str) -> str:
        if value not in {"E0", "E1", "E2", "E3", "E4"}:
            raise ValueError("evasion_tier 仅允许 E0-E4")
        return value

    @model_validator(mode="after")
    def _recipe_consistency(self) -> SampleRecipe:
        if not (self.carrier or self.loader_atoms or self.execution_atoms):
            raise ValueError("SampleRecipe 至少引用一个样本原子")
        if (self.implant_sha256 is None) != (self.implant_format is None):
            raise ValueError("implant_sha256 与 implant_format 必须同时存在或同时为空")
        if self.implant_sha256 is not None and not _SHA256_RE.fullmatch(self.implant_sha256):
            raise ValueError("implant_sha256 必须是 64 位小写十六进制")
        if len(self.atom_ids) != len(set(self.atom_ids)):
            raise ValueError("同一 atom_id 不得跨角色重复")
        return self

    @property
    def atom_ids(self) -> tuple[str, ...]:
        carrier = (self.carrier,) if self.carrier is not None else ()
        return carrier + self.loader_atoms + self.execution_atoms


class ProductionProfile(_FrozenModel):
    profile_id: str = Field(min_length=1)
    env_detail: dict[str, Any] = Field(default_factory=dict)
    security_product_enabled: bool
    high_risk_enabled: bool = False
    isolated: bool = False
    rollback_capable: bool = False
    sensors_ready: bool = False
    no_edr_control: bool = False

    @model_validator(mode="after")
    def _profile_consistency(self) -> ProductionProfile:
        if self.no_edr_control and self.security_product_enabled:
            raise ValueError("no-edr 对照 profile 不得声明已启用商业安全产品")
        return self


class FailurePrior(_FrozenModel):
    atom_sequence: tuple[str, ...] = Field(min_length=1)
    taxonomy: FailureTaxonomy
    failures: int = Field(gt=0)
    attempts: int = Field(ge=1)

    @model_validator(mode="after")
    def _counts(self) -> FailurePrior:
        if self.failures > self.attempts:
            raise ValueError("failures 不得大于 attempts")
        return self


class FactoryPlanningContext(_FrozenModel):
    candidate_ph_ids: tuple[str, ...] = Field(min_length=1)
    required_ph_ids: tuple[str, ...] = ()
    production_policy: ProductionPolicy
    profile: ProductionProfile
    delivery: DeliveryMode
    trigger_mode: TriggerMode
    implant_sha256: str | None = None
    implant_format: str | None = None
    seed: int
    architecture: Literal["x86", "x64"] = "x64"
    failure_priors: tuple[FailurePrior, ...] = ()

    @field_validator("candidate_ph_ids", "required_ph_ids")
    @classmethod
    def _context_ph_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validate_ph_sequence(value)

    @model_validator(mode="after")
    def _planning_scope(self) -> FactoryPlanningContext:
        if not set(self.required_ph_ids).issubset(self.candidate_ph_ids):
            raise ValueError("required_ph_ids 必须属于 candidate_ph_ids")
        if (self.implant_sha256 is None) != (self.implant_format is None):
            raise ValueError("implant_sha256 与 implant_format 必须成对")
        if self.implant_sha256 is not None and not _SHA256_RE.fullmatch(self.implant_sha256):
            raise ValueError("implant_sha256 必须是 64 位小写十六进制")
        return self


class PlannedComposition(_FrozenModel):
    """工厂 LLM 唯一允许输出的组合 JSON；无命令/代码字段。"""

    ph_ids: tuple[str, ...] = Field(min_length=1)
    carrier: _PlannedAtomId | None = None
    loader_atoms: tuple[_PlannedAtomId, ...] = ()
    execution_atoms: tuple[_PlannedAtomId, ...] = ()
    atom_parameters: dict[str, dict[str, Any]] = Field(default_factory=dict)
    evasion_tier: str
    pointer_mode: PointerMode | None = None
    rationale: str = Field(min_length=1)

    @field_validator("evasion_tier")
    @classmethod
    def _plan_evasion_tier(cls, value: str) -> str:
        if value not in {"E0", "E1", "E2", "E3", "E4"}:
            raise ValueError("evasion_tier 仅允许 E0-E4")
        return value

    @model_validator(mode="after")
    def _selected_atoms_are_one_to_one(self) -> PlannedComposition:
        selected = (
            (() if self.carrier is None else (self.carrier,))
            + self.loader_atoms
            + self.execution_atoms
        )
        if len(selected) != len(set(selected)):
            raise ValueError("同一 atom_id 不得跨角色重复")
        if set(self.atom_parameters) != set(selected):
            raise ValueError(
                "atom_parameters 必须恰好为全部已选 atom_id 提供对象；无参数原子使用 {}"
            )
        return self


class GlueMaterializeItem(_FrozenModel):
    """Glue 工作区编译前确定性物化项（非 LLM 输出）。"""

    atom_id: str
    handoff_id: str
    artifact_ref: str
    strategy: HandoffMaterialize


class GlueInjectionContract(_FrozenModel):
    """注入类 glue 必须使用的独立牺牲进程。"""

    atom_id: str
    sacrificial_image: str = Field(min_length=5)

    @field_validator("sacrificial_image")
    @classmethod
    def _image(cls, value: str) -> str:
        name = value.replace("/", "\\").rsplit("\\", 1)[-1].strip()
        if not name.lower().endswith(".exe") or len(name) <= 4:
            raise ValueError("sacrificial_image 必须是可执行映像路径或文件名")
        return value


class GlueTask(_FrozenModel):
    """无头 coding agent 的受控任务合同。"""

    task_id: str = Field(min_length=1)
    recipe_id: str = Field(min_length=1)
    workspace_ref: str = Field(min_length=1)
    atom_ids: tuple[str, ...] = Field(min_length=1)
    ph_ids: tuple[str, ...] = Field(min_length=1)
    atom_ph_ids: tuple[tuple[str, ...], ...] = Field(min_length=1)
    trigger_mode: TriggerMode
    execution_logging: bool = Field(default=False, strict=True)
    pointer_mode: PointerMode | None = None
    atom_parameters: dict[str, dict[str, Any]]
    input_contracts: tuple[str, ...] = Field(min_length=1)
    output_contracts: tuple[str, ...] = Field(min_length=1)
    handoff_contracts: tuple[str | None, ...] = Field(min_length=1)
    produces_handoffs: tuple[tuple[str, ...], ...] = ()
    consumes_handoffs: tuple[tuple[str, ...], ...] = ()
    materialize_items: tuple[GlueMaterializeItem, ...] = ()
    injection_contracts: tuple[GlueInjectionContract, ...] = ()
    build_target_ref: str = Field(min_length=1)
    repair_of_session: str | None = None
    diagnostics_ref: str | None = None

    @field_validator("workspace_ref")
    @classmethod
    def _workspace_ref(cls, value: str) -> str:
        if not value.startswith("plugin-workspace://"):
            raise ValueError("workspace_ref 必须是外部 plugin-workspace:// 引用")
        return value

    @field_validator("build_target_ref")
    @classmethod
    def _build_target_ref(cls, value: str) -> str:
        if not value.startswith("build-target://"):
            raise ValueError("build_target_ref 必须是已登记 build-target:// 引用")
        return value

    @model_validator(mode="after")
    def _repair_fields(self) -> GlueTask:
        if (self.repair_of_session is None) != (self.diagnostics_ref is None):
            raise ValueError("repair_of_session 与 diagnostics_ref 必须同时存在或同时为空")
        length = len(self.atom_ids)
        if not (
            len(self.input_contracts) == length
            and len(self.output_contracts) == length
            and len(self.handoff_contracts) == length
            and len(self.atom_ph_ids) == length
        ):
            raise ValueError("GlueTask 的 atom 与 PH/输入/输出/交接合同必须逐项对齐")
        projected_ph_ids = {ph_id for values in self.atom_ph_ids for ph_id in values}
        if not set(self.ph_ids).issubset(projected_ph_ids):
            raise ValueError("GlueTask.atom_ph_ids 必须覆盖 Recipe.ph_ids")
        if self.produces_handoffs and len(self.produces_handoffs) != length:
            raise ValueError("GlueTask.produces_handoffs 必须与 atom_ids 对齐")
        if self.consumes_handoffs and len(self.consumes_handoffs) != length:
            raise ValueError("GlueTask.consumes_handoffs 必须与 atom_ids 对齐")
        if set(self.atom_parameters) != set(self.atom_ids):
            raise ValueError("GlueTask.atom_parameters 必须逐 atom 显式给出（无参数用空对象）")
        unknown_injection = [
            item.atom_id
            for item in self.injection_contracts
            if item.atom_id not in self.atom_ids
        ]
        if unknown_injection:
            raise ValueError(
                "GlueTask.injection_contracts 引用了任务外 atom："
                + ",".join(unknown_injection)
            )
        return self


class AgentWorkspaceResult(_FrozenModel):
    """Agent 改动后的来源证明；源码内容不进入控制面台账。"""

    session_ref: str = Field(min_length=1)
    workspace_ref: str = Field(min_length=1)
    changed_files: tuple[str, ...] = Field(min_length=1)
    source_digest: str

    @field_validator("source_digest")
    @classmethod
    def _source_digest(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("source_digest 必须是 sha256")
        return value


class GlueResolution(_FrozenModel):
    signature: str = Field(min_length=1)
    origin: GlueOrigin
    source_ref: str = Field(min_length=1)
    source_digest: str = Field(min_length=1)
    session_ref: str | None = None
    changed_files: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _resolution_shape(self) -> GlueResolution:
        if not _SHA256_RE.fullmatch(self.signature) or not _SHA256_RE.fullmatch(self.source_digest):
            raise ValueError("GlueResolution signature/source_digest 必须是 sha256")
        if self.origin is GlueOrigin.AGENT and (self.session_ref is None or not self.changed_files):
            raise ValueError("agent 胶水必须携带 session_ref 与 changed_files")
        if self.origin is GlueOrigin.TEMPLATE and (
            self.session_ref is not None or self.changed_files
        ):
            raise ValueError("template 胶水不得伪装 AgentSession 变更")
        return self


class TelemetryAssertion(_FrozenModel):
    assertion_id: str = Field(min_length=1)
    kind: SignalKind
    level: SignalLevel
    match_fields: dict[str, Any] = Field(min_length=1)
    description: str = Field(min_length=1)

    @model_validator(mode="after")
    def _required_cross_fields(self) -> TelemetryAssertion:
        if self.level is SignalLevel.REQUIRED and len(self.match_fields) < 2:
            raise ValueError("required 遥测断言必须至少交叉两个独立字段")
        return self


class TelemetryContract(_FrozenModel):
    contract_id: str = Field(min_length=1)
    atom_id: str
    profile_ids: tuple[str, ...] = Field(min_length=1)
    source_ref: str = Field(min_length=1)
    assertions: tuple[TelemetryAssertion, ...] = Field(min_length=1)

    @field_validator("atom_id")
    @classmethod
    def _contract_atom_id(cls, value: str) -> str:
        if not _ATOM_ID_RE.fullmatch(value):
            raise ValueError("TelemetryContract.atom_id 必须引用 atom.*")
        return value

    @model_validator(mode="after")
    def _unique_assertions(self) -> TelemetryContract:
        ids = [item.assertion_id for item in self.assertions]
        if len(ids) != len(set(ids)):
            raise ValueError("TelemetryContract.assertion_id 不得重复")
        if not any(item.level is SignalLevel.REQUIRED for item in self.assertions):
            raise ValueError("TelemetryContract 至少包含一条 required 断言")
        return self


class TelemetryEvent(_FrozenModel):
    run_id: str = Field(min_length=1)
    fields: dict[str, Any] = Field(min_length=1)


class TelemetryBundle(_FrozenModel):
    run_id: str = Field(min_length=1)
    profile_id: str = Field(min_length=1)
    source_ref: str = Field(min_length=1)
    baseline_collected: bool
    events: tuple[TelemetryEvent, ...] = ()


class EffectObservation(_FrozenModel):
    check_id: str = Field(min_length=1)
    passed: bool
    required: bool = True
    evidence_ref: str = Field(min_length=1)


class RawVerificationReport(_FrozenModel):
    run_id: str = Field(min_length=1)
    profile_id: str = Field(min_length=1)
    artifact_sha256: str
    process_created: bool
    exit_code: int | None = None
    timed_out: bool = False
    crashed: bool = False
    blocked: bool = False
    anti_analysis_skipped: bool = False
    telemetry: TelemetryBundle
    effects: tuple[EffectObservation, ...] = ()

    @field_validator("artifact_sha256")
    @classmethod
    def _report_sha256(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("artifact_sha256 必须是 64 位小写十六进制")
        return value


class BuiltSample(_FrozenModel):
    artifact_ref: str = Field(min_length=1, description="授权构建后端中的不透明引用")
    artifact_sha256: str
    source_digest: str
    toolchain_fp: str = Field(min_length=1)
    build_id: str = Field(min_length=1)
    factory_run_id: str | None = None
    factory_attempt_id: str | None = None

    @field_validator("artifact_sha256", "source_digest")
    @classmethod
    def _built_sha256(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("artifact_sha256 必须是 64 位小写十六进制")
        return value

    @model_validator(mode="after")
    def _factory_run_identity(self) -> BuiltSample:
        if (self.factory_run_id is None) != (self.factory_attempt_id is None):
            raise ValueError("BuiltSample 的 factory_run_id/factory_attempt_id 必须同时存在")
        if self.factory_run_id is not None and not self.factory_run_id.startswith("run-"):
            raise ValueError("BuiltSample factory_run_id 必须以 run- 开头")
        if self.factory_attempt_id is not None and not self.factory_attempt_id.startswith(
            "attempt-"
        ):
            raise ValueError("BuiltSample factory_attempt_id 必须以 attempt- 开头")
        return self


class DetectionOutcome(_FrozenModel):
    result_class: ResultClass
    edr_id: str = Field(min_length=1)
    observed_at: datetime
    alert_refs: tuple[str, ...] = ()
    misattribution: tuple[dict[str, Any], ...] = ()

    @field_validator("result_class")
    @classmethod
    def _pipeline_b_five_values(cls, value: ResultClass) -> ResultClass:
        if value is ResultClass.EXECUTION_FAILED:
            raise ValueError("execution_failed 属于流水线 A，不得写入 B detection_outcome")
        return value

    @field_validator("observed_at")
    @classmethod
    def _aware_observed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at 必须带时区")
        return value


class ComboIntent(_FrozenModel):
    combo_digest: str
    ph_sequence: tuple[str, ...] = Field(min_length=1)
    parameters_canonical: dict[str, Any]
    profile_id: str = Field(min_length=1)
    env_detail: dict[str, Any] = Field(default_factory=dict)
    parent_id: str | None = None
    seed: int | None = None

    @field_validator("combo_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("combo_digest 必须是 sha256")
        return value

    @field_validator("ph_sequence")
    @classmethod
    def _intent_ph_sequence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validate_ph_sequence(value)

    @field_validator("parameters_canonical")
    @classmethod
    def _intent_parameters(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_canonical_parameters(value)

    @model_validator(mode="after")
    def _identity_matches(self) -> ComboIntent:
        from packages.sample_factory.identity import combo_digest

        if self.combo_digest != combo_digest(self.ph_sequence, self.parameters_canonical):
            raise ValueError("combo_digest 与 ph_sequence/parameters_canonical 不一致")
        return self


class ComboRecord(_FrozenModel):
    record_id: str
    combo_digest: str
    ph_sequence: tuple[str, ...]
    parameters_canonical: dict[str, Any]
    profile_id: str
    env_detail: dict[str, Any]
    toolchain_fp: str | None = None
    artifact_sha256: str | None = None
    git_manifest_ref: str | None = None
    worker_id: str | None = None
    status: ComboStatus
    failure_taxonomy: FailureTaxonomy | None = None
    detection_outcome: DetectionOutcome | None = None
    parent_id: str | None = None
    seed: int | None = None
    created_at: datetime
    updated_at: datetime
    lease_expires_at: datetime | None = None

    @field_validator("combo_digest")
    @classmethod
    def _record_digest(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("combo_digest 必须是 sha256")
        return value

    @field_validator("ph_sequence")
    @classmethod
    def _record_ph_sequence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validate_ph_sequence(value)

    @field_validator("parameters_canonical")
    @classmethod
    def _record_parameters(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_canonical_parameters(value)

    @field_validator("artifact_sha256")
    @classmethod
    def _record_artifact_sha(cls, value: str | None) -> str | None:
        if value is not None and not _SHA256_RE.fullmatch(value):
            raise ValueError("artifact_sha256 必须是 sha256")
        return value

    @model_validator(mode="after")
    def _record_invariants(self) -> ComboRecord:
        from packages.sample_factory.identity import combo_digest

        if self.combo_digest != combo_digest(self.ph_sequence, self.parameters_canonical):
            raise ValueError("ComboRecord 身份字段与 combo_digest 不一致")
        if self.status is ComboStatus.IN_PROGRESS:
            if self.worker_id is None or self.lease_expires_at is None:
                raise ValueError("IN_PROGRESS 必须带 worker_id 与 lease_expires_at")
            if self.failure_taxonomy is not None:
                raise ValueError("IN_PROGRESS 不得带 failure_taxonomy")
        elif self.status is ComboStatus.FAILURE:
            if self.failure_taxonomy is None or self.lease_expires_at is not None:
                raise ValueError("FAILURE 必须带 taxonomy 且清空租约")
        elif self.status is ComboStatus.SUCCESS:
            if not (self.toolchain_fp and self.artifact_sha256 and self.git_manifest_ref):
                raise ValueError("SUCCESS 必须带 toolchain/artifact/manifest 三指纹")
            if self.failure_taxonomy is not None or self.lease_expires_at is not None:
                raise ValueError("SUCCESS 不得带 failure taxonomy/有效租约")
        if self.detection_outcome is not None and self.status is not ComboStatus.SUCCESS:
            raise ValueError("detection_outcome 只能挂在 SUCCESS 记录")
        return self


class LeaseClaim(_FrozenModel):
    record_id: str
    disposition: LeaseDisposition
    status: ComboStatus
    worker_id: str | None = None
    lease_expires_at: datetime | None = None


class DeploymentFingerprint(_FrozenModel):
    mode: PointerMode | None
    argv_env_snapshot: str | None = None
    note: str = Field(min_length=1)

    @model_validator(mode="after")
    def _secret_ref_only(self) -> DeploymentFingerprint:
        if self.mode is PointerMode.RUNTIME_PARAM:
            if self.argv_env_snapshot is None or not _SECRET_REF_RE.fullmatch(
                self.argv_env_snapshot
            ):
                raise ValueError("runtime-param 的 argv/env 快照必须使用 secret:// 引用")
        elif self.argv_env_snapshot is not None:
            raise ValueError("非 runtime-param 模式不得携带 argv/env 快照")
        return self


class RegressionManifestEntry(_FrozenModel):
    sample_id: str
    sample_sha256: str
    artifact_ref: str = Field(min_length=1)
    deployment_fp: DeploymentFingerprint
    ph_sequence: tuple[str, ...] = Field(min_length=1)
    attck_ids: tuple[str, ...] = Field(min_length=1)
    parameters_canonical: dict[str, Any]
    profile_id: str = Field(min_length=1)
    toolchain_fp: str = Field(min_length=1)
    telemetry_truth: dict[str, Any]
    expected_detection: dict[str, Any] = Field(min_length=1)
    lineage_parent: str | None = None
    regression_set_version: str = Field(min_length=1)
    retired_at: datetime | None = None

    @field_validator("ph_sequence")
    @classmethod
    def _manifest_ph_sequence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validate_ph_sequence(value)

    @field_validator("attck_ids")
    @classmethod
    def _manifest_attck_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(not _ATTCK_ID_RE.fullmatch(item) for item in value):
            raise ValueError("manifest attck_ids 非法")
        return value

    @field_validator("parameters_canonical")
    @classmethod
    def _manifest_parameters(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_canonical_parameters(value)

    @model_validator(mode="after")
    def _manifest_identity(self) -> RegressionManifestEntry:
        if not _SHA256_RE.fullmatch(self.sample_sha256):
            raise ValueError("sample_sha256 必须是 64 位小写十六进制")
        # 局部导入避免 models -> identity -> models 环；combo_digest 不作为 manifest
        # 冗余字段保存，它可由这两个冻结主键成分随时重算。
        from packages.sample_factory.identity import combo_digest

        digest = combo_digest(self.ph_sequence, self.parameters_canonical)
        expected = f"{digest[:8]}-{self.sample_sha256[:12]}"
        if self.sample_id != expected:
            raise ValueError("sample_id 必须是 <combo_digest8>-<sha256_12>")
        return self


__all__ = [
    "AgentWorkspaceResult",
    "AtomRole",
    "AtomSpec",
    "BuiltSample",
    "ComboIntent",
    "ComboRecord",
    "ComboStatus",
    "DeliveryMode",
    "DeploymentFingerprint",
    "DetectionOutcome",
    "EffectObservation",
    "FactoryPlanningContext",
    "FailurePrior",
    "FailureTaxonomy",
    "GlueInjectionContract",
    "GlueMaterializeItem",
    "GlueOrigin",
    "GlueResolution",
    "GlueTask",
    "HandoffMaterialize",
    "IntegrationState",
    "LeaseClaim",
    "LeaseDisposition",
    "PointerMode",
    "PlannedComposition",
    "PluginProvenance",
    "ProductionPolicy",
    "ProductionProfile",
    "RawVerificationReport",
    "RegressionManifestEntry",
    "SafetyProfile",
    "SampleRecipe",
    "SignalKind",
    "SignalLevel",
    "TelemetryAssertion",
    "TelemetryBundle",
    "TelemetryContract",
    "TelemetryEvent",
    "TemplateStatus",
    "TriggerMode",
]
