"""核心实体 pydantic 模型（B1 Schema 冻结基线）。

权威来源：主设计 v0.3.2 §2.1/§2.2；运行模式 v1.3 §1.2/§1.2.1。
约定：核心契约模型 `extra="forbid"`（未知字段即拒绝），防止 schema 漂移。
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import (
    Destructiveness,
    EscalationClass,
    ExecStatus,
    GateDecision,
    MatchAuthority,
    Mode,
    NoiseLevel,
    ObjectiveClass,
    OracleClass,
    OracleVerdict,
    PlanDecisionType,
    PolicyProfile,
    RejectCode,
    ResultClass,
    StopCondition,
)

_TC_ID_RE = re.compile(r"^tc\.[a-z0-9][a-z0-9.\-_]*$")
_CAMP_ID_RE = re.compile(r"^(camp|pb)\.[a-z0-9][a-z0-9.\-_]*$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Action(_Strict):
    """引用 Adapter 已注册动作名 + 参数模板（主设计 §2.2 actions[]）。

    注册表无上界（§0.5）；此处只承载引用与参数模板，不含可执行二进制。
    """

    name: str = Field(min_length=1, description="Adapter 已注册动作名")
    params: dict[str, object] = Field(default_factory=dict, description="参数模板")


class ActionSpec(_Strict):
    """已注册动作的风险元数据（运行模式 §1.3 R2 元数据治理门禁）。

    R2：destructiveness / noise / opsec_class / tactic 为必填——缺任一项即无法构造，
    注册门禁（ActionRegistry.register）据此拒绝注册，防止高危动作被错标 low 静默绕过 E2/E5。
    """

    name: str = Field(min_length=1)
    destructiveness: Destructiveness
    noise: NoiseLevel
    opsec_class: str = Field(min_length=1, description="OPSEC 层级，如 E0–E4")
    tactic: str = Field(min_length=1, description="ATT&CK 战术")
    required_caps: set[str] = Field(default_factory=set, description="REQUIRED_CAPS × Lab 前置")
    default_require_approval: bool = Field(
        default=False, description="横向/通道类默认 require_approval（§6.2）"
    )
    description: str | None = None
    output_encoding: str | None = Field(
        default=None,
        description="动作输出的声明文本编码（P7：证据归一化前置；None=UTF-8；"
        "封闭集 utf-8/utf-8-sig/utf-16/utf-16le/gb18030/latin-1，禁 chardet 探测）",
    )


class OracleSpec(_Strict):
    """独立于 EDR 遥测的断言（主设计 §2.2 oracle；运行模式 §4.2.2）。"""

    oracle_class: OracleClass
    assertion: str = Field(min_length=1, description="可判定断言的人类可读描述")


class Preconditions(_Strict):
    os: str | None = None
    privilege: str | None = None
    required_tools: list[str] = Field(default_factory=list)


class TestCase(_Strict):
    """测例定义（主设计 §2.2）。目录范围 = 覆盖矩阵 + 战役骨架（无上界，§0.5）。"""

    id: str
    attack_techniques: list[str] = Field(min_length=1, description="ATT&CK ID 列表")
    intent: str = Field(min_length=1)
    preconditions: Preconditions = Field(default_factory=Preconditions)
    actions: list[Action] = Field(min_length=1)
    expected_signals: list[str] = Field(default_factory=list)
    oracle: OracleSpec
    noise_level: NoiseLevel = NoiseLevel.LOW
    destructiveness: Destructiveness = Destructiveness.NONE
    timeout_sec: int = Field(default=300, gt=0)

    @field_validator("id")
    @classmethod
    def _id_pattern(cls, v: str) -> str:
        if not _TC_ID_RE.match(v):
            raise ValueError(f"TestCase.id 必须匹配 {_TC_ID_RE.pattern}，实为 {v!r}")
        return v


class Scope(_Strict):
    """Campaign 范围（主设计 §2.2；Policy Gate 第1项数据源）。"""

    hosts: list[str] = Field(default_factory=list)
    sessions: list[str] = Field(default_factory=list)
    network_labels: list[str] = Field(default_factory=list)


class Campaign(_Strict):
    """评估活动（主设计 §2.2）。"""

    id: str
    scope: Scope
    technique_targets: list[str] = Field(default_factory=list)
    policy_profile: PolicyProfile
    oracle: OracleSpec | None = Field(
        default=None, description="战役级目标断言；分解为 TestCase 级 oracle"
    )
    mode: Mode

    @field_validator("id")
    @classmethod
    def _id_pattern(cls, v: str) -> str:
        if not _CAMP_ID_RE.match(v):
            raise ValueError(f"Campaign.id 必须匹配 {_CAMP_ID_RE.pattern}，实为 {v!r}")
        return v


class ObjectiveConstraints(_Strict):
    """模式2 目标契约约束（运行模式 §1.2）。"""

    scope_hosts: list[str] = Field(default_factory=list)
    scope_sessions: list[str] = Field(default_factory=list)
    forbidden_tactics: list[str] = Field(default_factory=list)
    max_total_steps: int = Field(gt=0)
    noise_budget: NoiseLevel = NoiseLevel.MEDIUM
    time_budget_min: int = Field(gt=0)
    opsec_profile: str = Field(min_length=1)


class SubgoalCheckpoint(_Strict):
    """子目标检查点（运行模式 §1.2.1，oracle_stall 客观化前提）。

    每个检查点为可 Oracle 判定的布尔断言；oracle_stall = 连续 N 步无任一翻转。
    """

    id: str = Field(min_length=1)
    assertion: str = Field(min_length=1)
    oracle_class: OracleClass


class ObjectiveContract(_Strict):
    """模式2 目标契约（运行模式 §1.2 / §1.2.1）。

    校验（提交时）：
      - objective 必须可 Oracle 判定 → 至少一个 subgoal_checkpoint，否则拒绝
        （objective_not_verifiable / 无分解拒受理）；
      - stop_conditions 一律为可观测枚举（StopCondition 已排除 LLM 自评置信度）。
    """

    objective: str = Field(min_length=1)
    objective_class: ObjectiveClass
    constraints: ObjectiveConstraints
    stop_conditions: list[StopCondition] = Field(min_length=1)
    subgoal_checkpoints: list[SubgoalCheckpoint] = Field(
        min_length=1, description="§1.2.1：无分解拒受理"
    )
    fallback_depth: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _verifiable(self) -> ObjectiveContract:
        if not self.subgoal_checkpoints:
            raise ValueError("objective_not_verifiable：缺子目标检查点分解（§1.2.1）")
        return self


class ApprovalRecord(_Strict):
    """审批记录（主设计 §3.4）。审批必落 API 与审计库（运行模式 §7 硬约束）。"""

    approver: str = Field(min_length=1)
    decision: GateDecision
    timestamp: str
    reason: str | None = None


class GateResult(_Strict):
    """Policy Gate 裁决结果（主设计 §3.3 / 运行模式 §6）。"""

    policy_profile: PolicyProfile
    decision: GateDecision
    reject_code: RejectCode | None = None
    approver: str | None = None
    detail: str | None = Field(
        default=None, description="裁决补充说明（如 lab capability incompatible/inconclusive）"
    )
    escalations: list[EscalationClass] = Field(
        default_factory=list, description="触发的 E1–E7 请示类别（M1 EscalationEngine 接入）"
    )

    @model_validator(mode="after")
    def _deny_needs_code(self) -> GateResult:
        if self.decision == GateDecision.DENY and self.reject_code is None:
            raise ValueError("deny 裁决必须带 reject_code（运行模式 §6）")
        return self


class ExecutionRecord(_Strict):
    """Adapter 回执规范化（主设计 §2.1 / §6.1）。假 Adapter 回放器亦产出此结构。"""

    action_name: str = Field(min_length=1)
    host: str | None = None
    session_ref: str | None = None
    start_ts: str
    end_ts: str
    status: ExecStatus = ExecStatus.OK
    output_summary: str = ""
    params_hash: str | None = None
    # P7 证据归一化（i18n spec §4.5）：真实摄取记录 原始/归一 双 hash；None=未摄取（回放）
    evidence_sha256_raw: str | None = None
    evidence_sha256_normalized: str | None = None


class Playbook(_Strict):
    """Playbook 目录项（看板 PBS 块权威；board-implementation-spec §2.3 数据契约）。

    mode/policy 以冻结枚举校验（未知值即拒），tcs 以冻结 TestCase 文法校验——
    是 N5 四注册表对账的类型化载体。
    """

    id: str
    lifecycle: str = Field(min_length=1)
    tier: str | None = None
    lab: str = Field(min_length=1)
    mode: Mode
    policy: PolicyProfile
    hts: str = ""
    tcs: list[str] = Field(default_factory=list)
    purpose: str | None = None

    @field_validator("id")
    @classmethod
    def _id_pattern(cls, v: str) -> str:
        if not _CAMP_ID_RE.match(v):
            raise ValueError(f"Playbook.id 必须匹配 {_CAMP_ID_RE.pattern}，实为 {v!r}")
        return v

    @field_validator("tcs")
    @classmethod
    def _tcs_grammar(cls, v: list[str]) -> list[str]:
        bad = [t for t in v if not _TC_ID_RE.match(t)]
        if bad:
            raise ValueError(f"Playbook.tcs 含不合文法的 tc：{bad}")
        return v


class OracleResult(_Strict):
    """Oracle 判定结果（运行模式 §2.1 台账 oracle 字段）。"""

    verdict: OracleVerdict
    evidence_ref: str | None = None


class PlanDecision(_Strict):
    """LLM Planner 结构化决策（主设计 §5.3）。Planner 只产此结构，不执行命令。

    校验：`next_step` 必须带 `test_case_id`；`stop` 必须带 `stop_reason`。
    """

    decision: PlanDecisionType
    rationale: str = ""
    test_case_id: str | None = None
    target_session_ref: str | None = None
    param_overrides: dict[str, object] = Field(default_factory=dict)
    stop_reason: str | None = None

    @model_validator(mode="after")
    def _decision_consistency(self) -> PlanDecision:
        if self.decision is PlanDecisionType.NEXT_STEP and not self.test_case_id:
            raise ValueError("next_step 决策必须带 test_case_id（主设计 §5.3）")
        if self.decision is PlanDecisionType.STOP and not self.stop_reason:
            raise ValueError("stop 决策必须带 stop_reason")
        return self


class AlertEvent(_Strict):
    """规范化告警事件（主设计 §4.1 / §4.4）。Correlator 只依赖本 schema，不绑定单一 EDR。

    `ts` 为 epoch 毫秒（与归因数值时间窗对齐）；`rule_id` 是检测假设登记表的权威 join 键
    （S3：精确匹配优先，关键字弱匹配降级并单独标注）。`channel` 区分 sigma 轨 / edr 轨。
    """

    id: str = Field(min_length=1)
    ts: int = Field(description="epoch 毫秒（时钟校正后）")
    host: str = Field(min_length=1)
    severity: str = "unknown"
    channel: str = Field(default="sigma", description="sigma / edr 轨")
    rule_id: str | None = None
    rule_name: str | None = None
    raw_ref: str | None = None


class DetectionMatch(_Strict):
    """步骤 ↔ 检测的关联结果（主设计 §2.2 / §4.2 五值）。

    per-step 判定载体：result_class 为五值分类；alert_refs 为归因到该步的 AlertEvent.id；
    match_authority 记 join 权威性（registry 精确 / weak_match fallback，不混合统计）。
    """

    step_id: str = Field(min_length=1)
    result_class: ResultClass
    alert_refs: list[str] = Field(default_factory=list)
    match_authority: MatchAuthority = MatchAuthority.REGISTRY


class SessionRef(_Strict):
    """标签化会话引用（主设计 §5.2：available_sessions 非原始 implant 细节）。"""

    ref: str = Field(min_length=1)
    host: str | None = None
    os: str | None = None
    privilege: str | None = None


class BudgetState(_Strict):
    """运行时预算剩余（运行模式 §5.1 budget_state）。"""

    steps_remaining: int = Field(ge=0)
    time_remaining_min: int = Field(ge=0)
    noise_budget: NoiseLevel = NoiseLevel.MEDIUM


class OpsecState(_Strict):
    """OPSEC 剖面 + 累计 drift（运行模式 §5.1 opsec_profile_current / §3.2.4）。"""

    profile: str = Field(min_length=1)
    drift: float = Field(default=0.0, ge=0.0)


class PlannerContext(_Strict):
    """guided/hybrid Planner 输入上下文（主设计 §5.2 + 运行模式 §5.1 增量字段）。

    Planner 只消费结构化 Facts summary（控制 token 体积），不消费原始 BloodHound/扫描日志。
    模式2 携 objective_contract；模式3 fallback_registry 承载节点候选集与已试记录。
    """

    run_id: str = Field(min_length=1)
    campaign_goals: list[str] = Field(default_factory=list)
    policy_summary: str = ""
    environment_facts_summary: str = ""
    completed_steps: list[str] = Field(default_factory=list)
    open_techniques: list[str] = Field(default_factory=list)
    available_sessions: list[SessionRef] = Field(default_factory=list)
    last_correlation_summary: str | None = None
    # 运行模式 §5.1 增量字段
    objective_contract: ObjectiveContract | None = None  # 模式2；模式3 为矩阵约束摘要
    opsec: OpsecState | None = None
    budget: BudgetState | None = None
    fallback_registry: dict[str, list[str]] = Field(default_factory=dict)  # 模式3 节点候选集
    lab_capability_facts: dict[str, bool] = Field(default_factory=dict)  # 静态 capability Facts 初值
    run_manifest_digest: str | None = None


class DomainSpec(_Strict):
    """拓扑：域（拓扑输入契约 §1.2）。"""

    name: str = Field(min_length=1)
    role: str = Field(pattern="^(root|child|external)$")
    trust: list[str] = Field(default_factory=list)


class HostSpec(_Strict):
    """拓扑：主机（§1.2）。roles 含 dc/member/jumpbox/workstation/ca。"""

    hostname: str = Field(min_length=1)
    ip: str = Field(min_length=1)
    domain: str = Field(min_length=1)
    roles: list[str] = Field(min_length=1)
    services: list[str] = Field(default_factory=list)
    os: str = Field(default="windows")


class FootholdSpec(_Strict):
    """拓扑：落点声明（拓扑契约 §1.2 v1.1）。凭据只允许 lab-secret:// 引用。

    initial_access_mode 三模式（schema v0.10.0，lab-lifecycle 契约 §3.1）：
    - assumed_breach（默认）：既有语义，credential_ref 必填；
    - credential_access（场景A）：仅 A-IA 初始打点凭据，credential_ref 必填、
      session_ref 可空（立足点由 tc.ia.edge-cred-login 建立）；
    - preset_delivery（场景B）：预设投递，session_ref 必填、credential_ref
      必须为空（凭据最小化：不交接任何凭据）。
    """

    host: str = Field(min_length=1)
    session_ref: str = Field(default="")
    credential_ref: str = Field(default="")
    initial_access_mode: str = Field(
        default="assumed_breach",
        pattern="^(assumed_breach|credential_access|preset_delivery)$",
    )
    exemption_note: str = Field(default="")

    @field_validator("credential_ref")
    @classmethod
    def _cred_uri(cls, v: str) -> str:
        if v and not v.startswith("lab-secret://"):
            raise ValueError("credential_ref 必须是 lab-secret:// URI（禁明文凭据）")
        return v


class Topology(_Strict):
    """拓扑输入（模式1/模式3 用户输入；拓扑输入契约 §1）。

    校验：IP/主机名唯一；域必有 DC；host.domain 存在；foothold.host 存在；
    initial_access_mode 字段约束（v0.10.0）；jumpbox 双角色豁免强制登记。
    """

    topology_id: str = Field(min_length=1)
    domains: list[DomainSpec] = Field(min_length=1)
    hosts: list[HostSpec] = Field(min_length=1)
    foothold: FootholdSpec | None = None

    @model_validator(mode="after")
    def _validate(self) -> Topology:
        domain_names = {d.name for d in self.domains}
        ips = [h.ip for h in self.hosts]
        if len(ips) != len(set(ips)):
            raise ValueError("topology_invalid：hosts[].ip 重复")
        hostnames = [h.hostname for h in self.hosts]
        if len(hostnames) != len(set(hostnames)):
            raise ValueError("topology_invalid：hostname 重复")
        for d in self.domains:
            if not any(h.domain == d.name and "dc" in h.roles for h in self.hosts):
                raise ValueError(f"topology_invalid：域 {d.name} 无 DC 主机")
        for h in self.hosts:
            if h.domain not in domain_names:
                raise ValueError(f"topology_invalid：主机 {h.hostname} 的域 {h.domain} 不在 domains[]")
        if self.foothold is not None and self.foothold.host not in {h.hostname for h in self.hosts}:
            raise ValueError("topology_invalid：foothold.host 不在 hosts[]")
        if self.foothold is not None:
            f = self.foothold
            if f.initial_access_mode in ("assumed_breach", "credential_access") and not f.credential_ref:
                raise ValueError(
                    "topology_initial_access_invalid："
                    f"{f.initial_access_mode} 模式要求 foothold.credential_ref（lab-secret:// 引用）"
                )
            if f.initial_access_mode == "preset_delivery":
                if not f.session_ref:
                    raise ValueError(
                        "topology_initial_access_invalid："
                        "preset_delivery 模式要求 foothold.session_ref（指向植入会话）"
                    )
                if f.credential_ref:
                    raise ValueError(
                        "topology_initial_access_invalid："
                        "preset_delivery 模式不得交接凭据（credential_ref 必须为空）"
                    )
            if f.initial_access_mode == "credential_access":
                host = next((h for h in self.hosts if h.hostname == f.host), None)
                if host is not None and "jumpbox" in host.roles and not f.exemption_note:
                    raise ValueError(
                        "topology_management_conflict："
                        "管理面主机（jumpbox）作初始打点目标必须登记 exemption_note（双角色豁免理由）"
                    )
        return self


class FactItem(_Strict):
    """Facts 片段条目（拓扑输入与 Facts 解析契约 §2.2）。"""

    kind: str = Field(pattern="^(host|session|credential|path|object)$")
    key: str = Field(min_length=1)
    attrs: dict[str, object] = Field(default_factory=dict)
    confidence: str = Field(pattern="^(observed|inferred)$")


class FactsBatch(_Strict):
    """一次解析产生的 Facts 片段（§2.2）；epoch 单调由仓库维护。"""

    facts_version: int = 1
    epoch: int = Field(ge=0)
    source_step: str = Field(min_length=1)
    source_comp: str = Field(min_length=1)
    items: list[FactItem] = Field(min_length=1)


