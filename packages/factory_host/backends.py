"""本机 Windows 构建宿主的样本工厂部署后端。

- combo_state：默认 ``create_state_backend`` = 进程内 InMemory（单机无 PG）
- 共享生产：``create_postgres_state_backend``（DSN 见 postgres_state.py）
- verification：构建宿主不冒充沙箱遥测；collect 返回身份绑定的空报告，
  由 FunctionalTruthEvaluator 判 TELEMETRY_MISS / RUNTIME_CRASH，
  禁止伪造 Sysmon 事件或 SUCCESS
"""

from __future__ import annotations

from packages.factory_host.postgres_state import create_postgres_state_backend
from packages.sample_factory.models import (
    BuiltSample,
    FactoryPlanningContext,
    RawVerificationReport,
    SampleRecipe,
    TelemetryBundle,
)
from packages.sample_factory.state import InMemoryComboStateStore

_STATE: InMemoryComboStateStore | None = None


def create_state_backend() -> InMemoryComboStateStore:
    """单机内存租约；多机共享请改用 create_postgres_state_backend。"""
    global _STATE
    if _STATE is None:
        _STATE = InMemoryComboStateStore()
    return _STATE


class BuildHostVerificationBackend:
    """编译宿主验证接缝：明确声明本机未跑隔离沙箱，不伪造遥测。"""

    def collect(
        self,
        artifact: BuiltSample,
        recipe: SampleRecipe,
        context: FactoryPlanningContext,
    ) -> RawVerificationReport:
        del recipe
        run_id = f"build-host-unverified-{artifact.build_id}"
        return RawVerificationReport(
            run_id=run_id,
            profile_id=context.profile.profile_id,
            artifact_sha256=artifact.artifact_sha256,
            process_created=False,
            exit_code=None,
            telemetry=TelemetryBundle(
                run_id=run_id,
                profile_id=context.profile.profile_id,
                source_ref=f"build-host://unverified/{artifact.build_id}",
                baseline_collected=False,
                events=(),
            ),
            effects=(),
        )


def create_verification_backend() -> BuildHostVerificationBackend:
    return BuildHostVerificationBackend()


__all__ = [
    "BuildHostVerificationBackend",
    "create_postgres_state_backend",
    "create_state_backend",
    "create_verification_backend",
]
