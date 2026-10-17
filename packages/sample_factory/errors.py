"""样本工厂领域错误。"""

from __future__ import annotations


class SampleFactoryError(RuntimeError):
    """样本工厂错误基类。"""


class CatalogError(SampleFactoryError, ValueError):
    """原子目录或 Recipe 不满足冻结契约。"""


class FactoryDenied(SampleFactoryError, PermissionError):
    """生产未获审批或高危 profile 前置不完整。"""


class LeaseLostError(SampleFactoryError):
    """worker 已失去租约，结果必须丢弃。"""


class BuildError(SampleFactoryError):
    """受控构建后端报告编译或链接失败。"""


class PlanningError(SampleFactoryError):
    """工厂 LLM 多次返回非法组合计划。"""


class PlanningAuditError(SampleFactoryError):
    """已接受的规划选择无法持久化为审计 JSON。"""


class ProductionStopped(SampleFactoryError):
    """操作员请求在不破坏租约状态的安全检查点停止生产。"""

    def __init__(self, phase: str) -> None:
        super().__init__(f"生产已在安全检查点停止：{phase}")
        self.phase = phase


class CompilationFailure(BuildError):
    """编译失败，并携带外部诊断引用供 AgentSession 修复。"""

    def __init__(self, message: str, *, diagnostics_ref: str | None = None) -> None:
        super().__init__(message)
        self.diagnostics_ref = diagnostics_ref


class VerificationError(SampleFactoryError):
    """验证证据本身不完整或与本轮构建不一致。"""


class ManifestError(SampleFactoryError):
    """黄金回归集 manifest 冲突或损坏。"""
