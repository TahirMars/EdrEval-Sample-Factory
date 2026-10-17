"""Fail-closed one-plugin authoring and canonical-harness orchestration."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol
from uuid import uuid4

from packages.sample_factory.catalog import CoverageRegistry
from packages.sample_factory.errors import CompilationFailure, SampleFactoryError
from packages.sample_factory.plugin_models import (
    PluginAuthoringResult,
    PluginBuildResult,
    PluginLifecycleStatus,
    PluginRequest,
    PluginSourceCandidate,
    PluginValidationResult,
)

PluginEventSink = Callable[[tuple[str, dict[str, object]]], None]


class PluginAuthoringBackend(Protocol):
    def author(self, request: PluginRequest, *, plugin_run_id: str) -> PluginSourceCandidate: ...


class PluginCompilerBackend(Protocol):
    def compile(
        self,
        source: PluginSourceCandidate,
        request: PluginRequest,
        *,
        plugin_run_id: str,
    ) -> PluginBuildResult: ...


class PluginHarnessBackend(Protocol):
    """Validate behavior with an independent system-telemetry harness.

    Harness implementations may use Sysmon/CAPE evidence, but EDR/Sigma rule
    hits are intentionally outside this protocol and never gate behavior_valid.
    """

    def validate(
        self,
        source: PluginSourceCandidate,
        build: PluginBuildResult,
        request: PluginRequest,
        *,
        plugin_run_id: str,
    ) -> PluginValidationResult: ...


class PluginAuthoringPipeline:
    """Author, compile and validate one candidate without catalog promotion."""

    def __init__(
        self,
        *,
        author: PluginAuthoringBackend | None,
        compiler: PluginCompilerBackend,
        harness: PluginHarnessBackend | None,
        coverage: CoverageRegistry,
        sink: PluginEventSink | None = None,
        max_compile_attempts: int = 1,
    ) -> None:
        if max_compile_attempts < 1:
            raise ValueError("max_compile_attempts 必须至少为 1")
        self._author = author
        self._compiler = compiler
        self._harness = harness
        self._coverage = coverage
        self._sink = sink
        self._max_compile_attempts = max_compile_attempts

    def run(
        self,
        request: PluginRequest,
        *,
        approved: bool,
        plugin_run_id: str | None = None,
    ) -> PluginAuthoringResult:
        if not approved:
            raise PermissionError("单插件生成必须获得本轮人工审批")
        if self._author is None:
            raise ValueError("plugin authoring 模式缺少 Authoring backend")
        plugin_run_id = plugin_run_id or f"plugin-run-{uuid4().hex}"
        if not plugin_run_id.startswith("plugin-run-"):
            raise ValueError("plugin_run_id 非法")
        self._coverage.attack_ids_for(request.intent.ph_ids)
        self._emit(
            "sample_factory_plugin_authoring_started",
            {
                "plugin_run_id": plugin_run_id,
                "request_id": request.request_id,
                "operation": request.operation.value,
                "role": request.intent.role.value,
                "ph_ids": list(request.intent.ph_ids),
            },
        )
        stage = "authoring"
        try:
            source = self._author.author(request, plugin_run_id=plugin_run_id)
            self._validate_source(request, source)
            self._emit(
                "sample_factory_plugin_source_ready",
                {
                    "plugin_run_id": plugin_run_id,
                    "plugin_id": source.plugin_id,
                    "source_digest": source.source_digest,
                },
            )
            stage = "compile"
            source, build = self._compile_with_repairs(
                source,
                request,
                plugin_run_id=plugin_run_id,
            )
            self._validate_build(request, source, build)
            self._emit(
                "sample_factory_plugin_compile_valid",
                {
                    "plugin_run_id": plugin_run_id,
                    "plugin_id": source.plugin_id,
                    "build_ref": build.build_ref,
                },
            )
            if (
                self._harness is None
                or source.atom_spec is None
                or request.harness_ref is None
            ):
                compile_only_reason = (
                    "independent_harness_not_configured"
                    if self._harness is None or request.harness_ref is None
                    else "atom_spec_governance_pending"
                )
                result = PluginAuthoringResult(
                    plugin_run_id=plugin_run_id,
                    request_id=request.request_id,
                    status=PluginLifecycleStatus.COMPILE_VALID,
                    source=source,
                    build=build,
                    compile_only_reason=compile_only_reason,
                )
                self._emit(
                    "sample_factory_plugin_compile_only",
                    {
                        "plugin_run_id": plugin_run_id,
                        "plugin_id": source.plugin_id,
                        "behavior_valid": False,
                        "reason": compile_only_reason,
                    },
                )
                return result
            stage = "harness"
            validation = self._harness.validate(source, build, request, plugin_run_id=plugin_run_id)
            if request.harness_ref is not None and validation.harness_ref != request.harness_ref:
                raise ValueError("Harness 回执与 PluginRequest 不一致")
            if not validation.behavior_valid:
                raise ValueError("Canonical Harness 未证明插件行为有效")
            result = PluginAuthoringResult(
                plugin_run_id=plugin_run_id,
                request_id=request.request_id,
                status=PluginLifecycleStatus.BEHAVIOR_VALID,
                source=source,
                build=build,
                validation=validation,
            )
            self._emit(
                "sample_factory_plugin_behavior_valid",
                {
                    "plugin_run_id": plugin_run_id,
                    "plugin_id": source.plugin_id,
                    "evidence_ref": validation.evidence_ref,
                    "dispatchable": False,
                },
            )
            return result
        except Exception as exc:
            self._emit(
                "sample_factory_plugin_authoring_failed",
                {
                    "plugin_run_id": plugin_run_id,
                    "request_id": request.request_id,
                    "failure_stage": stage,
                    "error_type": type(exc).__name__,
                },
            )
            if isinstance(exc, (SampleFactoryError, ValueError)):
                raise
            raise SampleFactoryError(f"单插件 {stage} 阶段失败：{exc}") from exc

    def _compile_with_repairs(
        self,
        source: PluginSourceCandidate,
        request: PluginRequest,
        *,
        plugin_run_id: str,
    ) -> tuple[PluginSourceCandidate, PluginBuildResult]:
        current = source
        for attempt in range(1, self._max_compile_attempts + 1):
            self._emit(
                "sample_factory_plugin_compile_attempt",
                {
                    "plugin_run_id": plugin_run_id,
                    "plugin_id": current.plugin_id,
                    "attempt": attempt,
                    "max_attempts": self._max_compile_attempts,
                    "source_digest": current.source_digest,
                },
            )
            try:
                return current, self._compiler.compile(
                    current,
                    request,
                    plugin_run_id=plugin_run_id,
                )
            except CompilationFailure as exc:
                self._emit(
                    "sample_factory_plugin_compile_failed",
                    {
                        "plugin_run_id": plugin_run_id,
                        "plugin_id": current.plugin_id,
                        "attempt": attempt,
                        "max_attempts": self._max_compile_attempts,
                        "diagnostics_ref": exc.diagnostics_ref,
                    },
                )
                repair = getattr(self._author, "repair", None)
                if (
                    attempt >= self._max_compile_attempts
                    or exc.diagnostics_ref is None
                    or not callable(repair)
                ):
                    raise
                previous_digest = current.source_digest
                current = repair(
                    current,
                    request,
                    plugin_run_id=plugin_run_id,
                    diagnostics_ref=exc.diagnostics_ref,
                )
                self._validate_source(request, current)
                if current.source_digest == previous_digest:
                    raise ValueError("插件编译修复未改变源码摘要") from exc
                self._emit(
                    "sample_factory_plugin_source_repaired",
                    {
                        "plugin_run_id": plugin_run_id,
                        "plugin_id": current.plugin_id,
                        "attempt": attempt,
                        "previous_source_digest": previous_digest,
                        "source_digest": current.source_digest,
                        "diagnostics_ref": exc.diagnostics_ref,
                    },
                )
        raise AssertionError("plugin compile attempt loop exhausted")  # pragma: no cover

    def validate_existing(
        self,
        request: PluginRequest,
        source: PluginSourceCandidate,
        *,
        approved: bool,
        plugin_run_id: str | None = None,
    ) -> PluginAuthoringResult:
        if not approved:
            raise PermissionError("单插件验证必须获得本轮人工审批")
        plugin_run_id = plugin_run_id or f"plugin-run-{uuid4().hex}"
        self._coverage.attack_ids_for(request.intent.ph_ids)
        self._validate_source(request, source)
        if source.atom_spec is None:
            raise ValueError("已有插件验证必须携带治理流程确认的 AtomSpec")
        self._emit(
            "sample_factory_plugin_validation_started",
            {
                "plugin_run_id": plugin_run_id,
                "request_id": request.request_id,
                "plugin_id": source.plugin_id,
            },
        )
        if self._harness is None:
            raise ValueError("已有插件验证必须配置独立 Canonical Harness")
        stage = "compile"
        try:
            build = self._compiler.compile(source, request, plugin_run_id=plugin_run_id)
            self._validate_build(request, source, build)
            stage = "harness"
            validation = self._harness.validate(source, build, request, plugin_run_id=plugin_run_id)
            if request.harness_ref is not None and validation.harness_ref != request.harness_ref:
                raise ValueError("Harness 回执与 PluginRequest 不一致")
            if not validation.behavior_valid:
                raise ValueError("Canonical Harness 未证明插件行为有效")
            result = PluginAuthoringResult(
                plugin_run_id=plugin_run_id,
                request_id=request.request_id,
                status=PluginLifecycleStatus.BEHAVIOR_VALID,
                source=source,
                build=build,
                validation=validation,
            )
            self._emit(
                "sample_factory_plugin_validation_finished",
                {
                    "plugin_run_id": plugin_run_id,
                    "plugin_id": source.plugin_id,
                    "behavior_valid": True,
                    "dispatchable": False,
                },
            )
            return result
        except Exception as exc:
            self._emit(
                "sample_factory_plugin_validation_failed",
                {
                    "plugin_run_id": plugin_run_id,
                    "plugin_id": source.plugin_id,
                    "failure_stage": stage,
                    "error_type": type(exc).__name__,
                },
            )
            if isinstance(exc, (SampleFactoryError, ValueError)):
                raise
            raise SampleFactoryError(f"单插件验证 {stage} 阶段失败：{exc}") from exc

    @staticmethod
    def _validate_source(request: PluginRequest, source: PluginSourceCandidate) -> None:
        intent = request.intent
        spec = source.atom_spec
        if source.implementation_name != request.implementation_name:
            raise ValueError("候选 implementation_name 与 PluginRequest 不一致")
        if spec is not None:
            if source.plugin_id != spec.atom_id:
                raise ValueError("候选 plugin_id 与 AtomSpec.atom_id 不一致")
            if spec.role is not intent.role:
                raise ValueError("候选 AtomSpec.role 与 TechniqueIntent 不一致")
            if spec.ph_ids != intent.ph_ids:
                raise ValueError("候选 AtomSpec.ph_ids 与 TechniqueIntent 不一致")
            if spec.required_capabilities != intent.required_capabilities:
                raise ValueError("候选 AtomSpec.required_capabilities 与 TechniqueIntent 不一致")
            if spec.provided_capabilities != intent.provided_capabilities:
                raise ValueError("候选 AtomSpec.provided_capabilities 与 TechniqueIntent 不一致")
            if spec.param_domains != intent.parameter_domains:
                raise ValueError(
                    "候选 AtomSpec.param_domains 与 TechniqueIntent.parameter_domains 不一致"
                )
        if source.required_capabilities != intent.required_capabilities:
            raise ValueError("候选 required_capabilities 与 TechniqueIntent 不一致")
        if source.provided_capabilities != intent.provided_capabilities:
            raise ValueError("候选 provided_capabilities 与 TechniqueIntent 不一致")
        if source.input_ports != intent.input_ports or source.output_ports != intent.output_ports:
            raise ValueError("候选 Port 合同与 TechniqueIntent 不一致")

    @staticmethod
    def _validate_build(
        request: PluginRequest,
        source: PluginSourceCandidate,
        build: PluginBuildResult,
    ) -> None:
        if build.source_digest != source.source_digest:
            raise ValueError("插件编译回执 source_digest 与候选源码不一致")
        expected_filename = f"{request.implementation_name}.lib"
        if build.artifact_filename != expected_filename:
            raise ValueError(
                f"插件验证制品必须命名为 {expected_filename}，实际为 {build.artifact_filename}"
            )

    def _emit(self, kind: str, data: dict[str, object]) -> None:
        if self._sink is not None:
            self._sink((kind, data))


__all__ = [
    "PluginAuthoringBackend",
    "PluginAuthoringPipeline",
    "PluginCompilerBackend",
    "PluginHarnessBackend",
]
