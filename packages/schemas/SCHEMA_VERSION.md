# SCHEMA_VERSION

**当前版本：** `0.10.0`

冻结基线（dev-acceptance-contract §1 / B1）。本文件是 schema 版本的权威登记处：
任何 `packages/schemas/` 下实体字段或枚举取值的变更，必须同步 bump 此版本并在下表登记；
破坏性变更（删字段/改类型/改枚举语义）须附迁移说明。

## 语义化版本约定

- **MAJOR**：破坏性变更（删除/重命名字段、收窄类型、删除枚举值）。
- **MINOR**：向后兼容新增（新增可选字段、新增枚举值）。
- **PATCH**：不改结构的修订（描述、校验消息、非语义约束微调）。

## 覆盖实体（v0.1.0）

| 实体 | 权威来源 |
|---|---|
| `TestCase` / `Campaign` / `Action` / `OracleSpec` / `Preconditions` / `Scope` | 主设计 v0.3.2 §2.2 |
| `ObjectiveContract` / `ObjectiveConstraints` / `SubgoalCheckpoint` | 运行模式 v1.3 §1.2 / §1.2.1 |
| `ApprovalRecord` / `GateResult` / `OracleResult` | 主设计 §3；运行模式 §6 / §4.2 |
| `LedgerEntry` 及子模型 / `RunManifest` | 运行模式 v1.3 §2.1 / §3.3 |
| Run/Step 状态机、五值/三值/E1–E7/拒绝码等枚举 | 主设计 §2.2；运行模式 §1/§4/§6 |

## 变更登记

| 版本 | 日期 | 变更 |
|---|---|---|
| 0.1.0 | 2026-08-22 | 初始冻结：实体模型 + 枚举 + Run/Step 状态机 + 台账/Manifest（M0 首个增量） |
| 0.2.0 | 2026-08-22 | MINOR 新增（向后兼容）：`ActionSpec`（R2 必填风险元数据）、`ExecutionRecord`、`ExecStatus` 枚举、`GateResult.detail` 可选字段（假 Adapter + Policy Gate 骨架增量） |
| 0.3.0 | 2026-08-22 | MINOR 新增（向后兼容）：`Playbook` 目录项模型（mode/policy 枚举校验、tcs 文法校验）——N5 对账的类型化载体 + 28 条结构回放 |
| 0.4.0 | 2026-08-22 | MINOR 新增（向后兼容）：`PlanDecision`(+`PlanDecisionType`)、`AlertEvent`、`DetectionMatch`——冻结 Planner/Correlator 载荷，使接线一致性套件强类型化（同步修正 header 与 __init__ 版本漂移） |
| 0.5.0 | 2026-08-22 | MINOR 新增（向后兼容）：`PlannerContext`(+子模型 `SessionRef`/`BudgetState`/`OpsecState`)——冻结 guided/hybrid Planner 输入（主设计 §5.2 + 运行模式 §5.1 增量字段），使 Planner 一致性套件覆盖模式2/3 |
| 0.6.0 | 2026-08-22 | MINOR 新增（向后兼容）：`PolicyContext.escalation` + `GateResult.escalations`——M1 EscalationEngine 接入 Policy Gate（handoff-prompt M1-1） |
| 0.7.0 | 2026-08-22 | MINOR 新增（向后兼容）：`ActionSpec.output_encoding` 可选字段——P7 证据编码归一化前置（声明式封闭集，禁 chardet 探测；None=UTF-8） |
| 0.8.0 | 2026-08-23 | MINOR 新增（向后兼容）：拓扑输入实体（`Topology`/`DomainSpec`/`HostSpec`/`FootholdSpec`，模式1 输入 schema 落地）与 Facts 片段实体（`FactItem`/`FactsBatch`，C3 拆解）——spec：2026-08-23-topology-and-facts-contract.md |
| 0.9.0 | 2026-08-23 | MINOR 新增（向后兼容）：`ExecutionRecord.evidence_sha256_raw/normalized` 可选字段——真实输出摄取双 hash 入账（P7 §4.5 接线） |
| 0.10.0 | 2026-08-24 | MINOR 新增（向后兼容）：`FootholdSpec.initial_access_mode`（三模式封闭集，默认 assumed_breach）与 `exemption_note` 可选字段；`credential_ref` 改可空（preset_delivery 模式必须为空）；新增校验错误 `topology_initial_access_invalid`/`topology_management_conflict`——初始打点两场景落地（spec：2026-08-24-lab-lifecycle-and-initial-access.md §3/§5；拓扑契约 v1.1）。同步修正 `__init__.SCHEMA_VERSION` 自 0.6.0 起的漂移 |
