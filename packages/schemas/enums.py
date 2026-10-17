"""冻结枚举集合（B1 Schema 冻结基线）。

权威来源：
  - 主设计 v0.3.2 §2.2（TestCase/Campaign/Run/Step 状态机、结果三值兼容层）
  - 运行模式 v1.3 §1（mode/license/E1–E7）、§4.2（五值分类学）、§6（拒绝码）

枚举取值为契约的一部分：任何取值增删须 bump packages/schemas/SCHEMA_VERSION.md。
"""

from __future__ import annotations

from enum import StrEnum


class Mode(StrEnum):
    """Planner 规划自由度（主设计 §2.2 Campaign.mode）。"""

    PLAYLIST = "playlist"
    HYBRID = "hybrid"
    GUIDED = "guided"


class LicenseTier(StrEnum):
    """产品分级（运行模式 §1.1），与 Mode 一一映射。"""

    ASSESS_DIRECTED = "assess-directed"  # -> playlist
    ASSIST_GUIDED = "assist-guided"  # -> hybrid
    EMULATE_AUTONOMOUS = "emulate-autonomous"  # -> guided


# License 档 -> 允许的 mode 全集（旗舰含全部；基础仅 playlist）
LICENSE_MODE_MAP: dict[LicenseTier, set[Mode]] = {
    LicenseTier.ASSESS_DIRECTED: {Mode.PLAYLIST},
    LicenseTier.ASSIST_GUIDED: {Mode.PLAYLIST, Mode.HYBRID},
    LicenseTier.EMULATE_AUTONOMOUS: {Mode.PLAYLIST, Mode.HYBRID, Mode.GUIDED},
}


class PolicyProfile(StrEnum):
    """策略档（主设计 §3.2）。"""

    LAB_SAFE = "lab-safe"
    BAS_STANDARD = "bas-standard"
    REDTEAM_AUDIT = "redteam-audit"
    OPERATOR_ASSISTED = "operator-assisted"


class NoiseLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Destructiveness(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RunState(StrEnum):
    """Run 生命周期（主设计 §2.2）。"""

    CREATED = "created"
    PLANNING = "planning"
    EXECUTING = "executing"
    CORRELATING = "correlating"
    COMPLETED = "completed"
    ABORTED = "aborted"
    FAILED = "failed"


class StepState(StrEnum):
    """Step 生命周期（主设计 §2.2）。"""

    PROPOSED = "proposed"
    GATED = "gated"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    DISPATCHED = "dispatched"
    FINISHED = "finished"
    CORRELATED = "correlated"


class ResultClass(StrEnum):
    """五值结果分类学（运行模式 §4.2）+ execution_failed。"""

    DETECTED = "detected"  # L1 L2 L3
    MISSED_DETECTION = "missed_detection"  # L1 L2 !L3 —— 最值钱：检测逻辑缺口
    TELEMETRY_GAP = "telemetry_gap"  # L1 !L2 —— 传感器配置缺口
    BLOCKED_BY_PRODUCT = "blocked_by_product"  # L1(被阻断) —— 控制有效
    INCONCLUSIVE = "inconclusive"  # 证据缺失/时钟漂移/Oracle 不可判定
    EXECUTION_FAILED = "execution_failed"  # L1 fail


class CompatResult(StrEnum):
    """主设计 §4.2 三值兼容层（由五值映射）。"""

    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    INCONCLUSIVE = "inconclusive"


# 五值 -> 三值兼容层映射（运行模式 §4.2）
RESULT_COMPAT_MAP: dict[ResultClass, CompatResult] = {
    ResultClass.DETECTED: CompatResult.DETECTED,
    ResultClass.MISSED_DETECTION: CompatResult.NOT_DETECTED,
    ResultClass.TELEMETRY_GAP: CompatResult.NOT_DETECTED,
    ResultClass.BLOCKED_BY_PRODUCT: CompatResult.DETECTED,
    ResultClass.INCONCLUSIVE: CompatResult.INCONCLUSIVE,
    ResultClass.EXECUTION_FAILED: CompatResult.INCONCLUSIVE,
}


class OracleVerdict(StrEnum):
    """双 Oracle 语义（主设计 §2.2 / 运行模式 §4.2）。"""

    PASS = "pass"
    FAIL = "fail"
    BLOCKED_BY_PRODUCT = "blocked_by_product"  # 控制有效，非 miss
    INCONCLUSIVE = "inconclusive"


class OracleClass(StrEnum):
    """Oracle 复用库断言类（运行模式 §4.2.2，C2 成本控制）。

    残差治理：无法映射到既有类的战役目标必须新写专用 Oracle 并登记，
    禁止“无断言即跳过”（运行模式 §4.2.2 C2-残留）。
    """

    ACCESS_CHECK = "access_check"  # dir 列表 / 资源访问
    ATTRIBUTE_READBACK = "attribute_readback"  # 写后回读
    TICKET_USE = "ticket_use"  # klist / 请求验证
    SESSION_ESTABLISHED = "session_established"  # 4624 断言
    CUSTOM = "custom"  # 专用 Oracle（须登记）


class EscalationClass(StrEnum):
    """模式2 请示触发分类学（运行模式 §1.3）。"""

    E1 = "E1"  # 敏感信息收集
    E2 = "E2"  # 破坏性风险动作（+快照前置）
    E3 = "E3"  # OPSEC 剖面偏离
    E4 = "E4"  # 持久化类动作（+cleanup 计划必填）
    E5 = "E5"  # Tier-0 对象写入
    E6 = "E6"  # 跨信任边界
    E7 = "E7"  # 预算逼近（<20% 通知；<5% require_approval）


class GateDecision(StrEnum):
    """Policy Gate 裁决（主设计 §3.3）。"""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class RejectCode(StrEnum):
    """拒绝原因码全集（运行模式 §6）。"""

    OUT_OF_SCOPE = "out_of_scope"
    UNREGISTERED_ACTION = "unregistered_action"
    MISSING_LAB_CAPABILITY = "missing_lab_capability"
    NOISE_OVER_BUDGET = "noise_over_budget"
    DESTRUCTIVE_OVER_PROFILE = "destructive_over_profile"
    LICENSE_DENIED = "license_denied"
    OPERATOR_REJECTED = "operator_rejected"
    APPROVAL_TIMEOUT = "approval_timeout"


class ObjectiveClass(StrEnum):
    """模式2 目标契约类（运行模式 §1.2）。"""

    DOMAIN_DOMINANCE = "domain_dominance"
    DATA_ACCESS = "data_access"
    PERSISTENCE = "persistence"
    DETECTION_PROBE = "detection_probe"


class StopCondition(StrEnum):
    """模式2 停机条件（运行模式 §1.2，R3 客观化）。

    显式不含 LLM 自述置信度：停机判据一律可观测（Facts 增量/预算/Oracle 检查点翻转）。
    """

    OBJECTIVE_MET_ORACLE_PASS = "objective_met_oracle_pass"
    BUDGET_EXHAUSTED = "budget_exhausted"
    NO_FACTS_PROGRESS = "no_facts_progress"  # 连续 N 步无 Facts 增量
    ORACLE_STALL = "oracle_stall"  # 连续 N 步无子目标检查点翻转（§1.2.1）
    OPERATOR_ABORT = "operator_abort"


class LedgerRole(StrEnum):
    """LedgerEntry 角色（N7 采集自污染防护：采集步归因排除）。"""

    ATTACK = "attack"
    EVIDENCE_COLLECTION = "evidence_collection"


class ExecStatus(StrEnum):
    """Adapter 执行回执状态（ExecutionRecord.status）。"""

    OK = "ok"
    ERROR = "error"
    BLOCKED = "blocked"  # 被产品阻断（配合 blocked_by_product 语义）
    TIMEOUT = "timeout"


class PlanDecisionType(StrEnum):
    """Planner 决策类型（主设计 §5.3 output schema）。"""

    NEXT_STEP = "next_step"
    STOP = "stop"
    ASK_HUMAN = "ask_human"


class MatchAuthority(StrEnum):
    """告警↔期望信号 join 键权威性（主设计 §4.2 规则3，S3 对齐）。"""

    REGISTRY = "registry"  # 检测假设登记表 rule_id 精确匹配（权威）
    WEAK_MATCH = "weak_match"  # 关键字/技术标签 fallback（单独标注，不混合统计）
