"""VMware-backed Plugin Harness for generated TTP static libraries.

The plugin compiler deliberately emits a validation-only ``.lib``.  This
adapter performs the missing operator-owned link step, then sends the fixed
Harness EXE through :class:`VmwareVerificationBackend` for snapshot execution
and Sysmon collection.  A zero exit code alone is never treated as a TTP
oracle; assertions are explicit in the Harness contract and fail closed.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from packages.factory_host.vmware_verification import (
    GuestExecutionResult,
    VmwareVerificationBackend,
)
from packages.sample_factory.catalog import CoverageRegistry
from packages.sample_factory.errors import BuildError, VerificationError
from packages.sample_factory.models import (
    DeliveryMode,
    FactoryPlanningContext,
    ProductionPolicy,
    ProductionProfile,
    SampleRecipe,
    TriggerMode,
)
from packages.sample_factory.plugin_contract import (
    render_joint_validation_harness_main,
    render_logged_validation_harness_main,
    render_validation_harness_project,
)
from packages.sample_factory.runtime_logging import (
    configure_runtime_logging,
    validate_runtime_logging_build_inputs,
)
from packages.sample_factory.plugin_harness import (
    HarnessAssertion,
    HarnessTelemetrySource,
    PluginArtifactResolver,
    PluginHarnessExecutor,
    PluginHarnessObservation,
    PluginHarnessSpec,
    SystemTelemetryPluginHarness,
)
from packages.sample_factory.plugin_harness_oracles import (
    project_sysmon_event_for_oracle,
    required_sysmon_assertion_ids,
    resolve_harness_ph_ids,
    sysmon_event_matches,
    sysmon_image_by_process_id,
    variant_sysmon_matchers,
)
from packages.sample_factory.plugin_models import (
    PluginAuthoringResult,
    PluginBuildResult,
    PluginDecompositionPlan,
    PluginRequest,
    PluginSourceCandidate,
    PluginValidationResult,
)

_PROCESS_ASSERTIONS = ("process.created", "process.exit_code_zero")


def project_plugin_harness_assertions(
    ph_ids: tuple[str, ...],
    coverage: CoverageRegistry,
    atom_id: str | None = None,
) -> tuple[str, ...]:
    """Process/exit plus the variant Sysmon subset (matrix row is a ceiling)."""
    return _PROCESS_ASSERTIONS + required_sysmon_assertion_ids(ph_ids, coverage, atom_id)


class PluginSourceResolver(Protocol):
    def resolve(self, source_ref: str) -> Path: ...


class PluginHarnessProcessRunner(Protocol):
    def run(self, argv: list[str], *, timeout: float | None = None) -> tuple[int, str]: ...


class SubprocessPluginHarnessRunner:
    def run(self, argv: list[str], *, timeout: float | None = None) -> tuple[int, str]:
        process = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
        output = (process.stdout + b"\n" + process.stderr).decode("utf-8", errors="replace")
        return process.returncode, output


class VmwarePluginHarnessConfig(BaseModel):
    """Operator-owned wiring for one role/profile-specific Harness."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["factory-vmware-plugin-harness-v1"]
    spec: PluginHarnessSpec
    vmware_verification_config: Path
    profile: ProductionProfile
    msbuild_path: Path
    link_toolchain_fp: str = Field(min_length=1)
    link_timeout_s: float = Field(default=900, gt=0, le=3600)

    @model_validator(mode="after")
    def _profile_contract(self) -> VmwarePluginHarnessConfig:
        if self.spec.role.value != "execution_atom":
            raise ValueError("当前 VMware Plugin Harness 仅实现 execution_atom 角色")
        if not self.spec.ph_ids:
            raise ValueError("当前 VMware Plugin Harness 必须绑定至少一个 ph_id")
        if self.spec.input_contract_ref != "contract://plugin-harness/empty-json-smoke-v1":
            raise ValueError(
                "当前 VMware Plugin Harness 仅支持 empty-json-smoke 输入合同"
            )
        if self.profile.profile_id not in self.spec.profile_ids:
            raise ValueError("Harness profile_id 必须登记在 spec.profile_ids")
        network_mode = str(self.profile.env_detail.get("network_mode", "")).casefold()
        if network_mode not in {"nat", "isolated"}:
            raise ValueError("Harness profile.env_detail.network_mode 必须显式为 nat 或 isolated")
        if network_mode == "nat" and self.profile.isolated:
            raise ValueError(
                "NAT VMware Harness 必须如实声明 isolated=false"
            )
        if network_mode == "isolated" and not self.profile.isolated:
            raise ValueError("隔离网络 Harness 必须声明 isolated=true")
        if not self.profile.rollback_capable or not self.profile.sensors_ready:
            raise ValueError("Plugin Harness profile 必须可回滚且 sensors_ready")
        if self.profile.high_risk_enabled and not self.profile.isolated:
            raise ValueError("高风险 Plugin Harness 不得使用非隔离 NAT profile")
        if self.profile.security_product_enabled and self.profile.no_edr_control:
            raise ValueError("Harness profile 不得同时声明 EDR enabled 与 no_edr_control")
        required = set(self.spec.required_assertions)
        known = {"process.created", "process.exit_code_zero"}
        unknown = sorted(
            item
            for item in required
            if item not in known and re.fullmatch(r"sysmon\.event_id\.\d+", item) is None
        )
        if unknown:
            raise ValueError(f"Harness required_assertions 含未知 oracle：{unknown}")
        if not known.issubset(required) or not any(
            item.startswith("sysmon.event_id.") for item in required
        ):
            raise ValueError("VMware Plugin Harness 必须要求进程、退出码和 Sysmon oracle")
        if HarnessTelemetrySource.SYSMON not in self.spec.telemetry_sources:
            raise ValueError("VMware Plugin Harness 必须登记 sysmon telemetry source")
        return self

    def profile_context(
        self,
        profile_id: str,
        atom_spec: object,
        *,
        ph_ids: tuple[str, ...] = (),
    ) -> FactoryPlanningContext:
        resolved = tuple(getattr(atom_spec, "ph_ids", ()) or ()) or tuple(ph_ids)
        if not resolved:
            resolved = resolve_harness_ph_ids(None, atom_spec)
        if not resolved:
            plugin_id = getattr(atom_spec, "atom_id", None) or "unknown-plugin"
            raise VerificationError(f"Harness profile 缺少可验证的 PH ID：{plugin_id}")
        return FactoryPlanningContext(
            candidate_ph_ids=resolved,
            production_policy=ProductionPolicy.BASELINE,
            profile=self.profile.model_copy(update={"profile_id": profile_id}),
            delivery=DeliveryMode.PRESET_NO_MOTW,
            trigger_mode=TriggerMode.LAB_TRIGGER,
            seed=0,
        )

    def bind_spec(
        self,
        request: PluginRequest,
        atom_spec: object | None,
        *,
        coverage: CoverageRegistry | None,
    ) -> PluginHarnessSpec:
        """Narrow allowlisted HarnessSpec to this request's variant Sysmon oracles."""
        request_ph = resolve_harness_ph_ids(request, atom_spec)
        allowed = self.spec.ph_ids
        atom_id = getattr(atom_spec, "atom_id", None) or request.seed_plugin_id
        if not request_ph:
            plugin_id = atom_id or request.implementation_name
            raise VerificationError(f"Harness profile 缺少可验证的 PH ID：{plugin_id}")
        extra = [item for item in request_ph if item not in allowed]
        if extra:
            raise VerificationError(
                "PluginRequest ph_ids 不在 Harness 允许集："
                f"{list(request_ph)} extra={extra} allowed={list(allowed)}"
            )
        if coverage is None:
            if request_ph == allowed and variant_sysmon_matchers(atom_id) == ():
                return self.spec
            raise VerificationError("多 PH Harness 需要覆盖矩阵才能投影 Sysmon oracle")
        assertions = project_plugin_harness_assertions(
            request_ph, coverage, atom_id=atom_id
        )
        unsupported = [item for item in assertions if item not in self.spec.required_assertions]
        if unsupported:
            raise VerificationError(
                "Harness required_assertions 未覆盖矩阵投影："
                f"{unsupported} ph_ids={list(request_ph)}"
            )
        ph_token = "-".join(item.lower() for item in request_ph)
        atom_token = atom_id or "unknown-atom"
        return self.spec.model_copy(
            update={
                "ph_ids": request_ph,
                "required_assertions": assertions,
                "oracle_ref": f"oracle://{atom_token}/{ph_token}/variant-sysmon-v1",
            }
        )

    @classmethod
    def load(cls, path: str | Path) -> VmwarePluginHarnessConfig:
        source = Path(path).resolve()
        if not source.is_file():
            raise VerificationError(f"Plugin Harness 配置不存在：{source}")
        try:
            config = cls.model_validate_json(source.read_bytes().decode("utf-8-sig"))
        except Exception as exc:
            raise VerificationError(f"Plugin Harness 配置非法：{source}: {exc}") from exc
        base = source.parent
        updates = {
            field: (value if value.is_absolute() else base / value).resolve()
            for field in ("vmware_verification_config", "msbuild_path")
            if (value := getattr(config, field)) is not None
        }
        return config.model_copy(update=updates)


class PluginDependencyLinkResult(BaseModel):
    """Link-only evidence for one consumer and its declared upstream closure."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["sf-plugin-dependency-link-v1"] = "sf-plugin-dependency-link-v1"
    plan_id: str
    consumer_request_id: str
    dependency_request_ids: tuple[str, ...] = Field(min_length=1)
    artifact_sha256: str
    link_toolchain_fp: str
    evidence_ref: str
    behavior_valid: bool = False
    assertions: tuple[str, ...] = ()


class VmwarePluginHarnessBackend(PluginHarnessExecutor):
    """Link and execute a generated plugin through the existing VM backend."""

    def __init__(
        self,
        config: VmwarePluginHarnessConfig,
        *,
        vmware: VmwareVerificationBackend,
        source_resolver: PluginSourceResolver,
        artifact_resolver: PluginArtifactResolver,
        runner: PluginHarnessProcessRunner | None = None,
        coverage: CoverageRegistry | None = None,
    ) -> None:
        self._config = config
        self._vmware = vmware
        self._source_resolver = source_resolver
        self._artifact_resolver = artifact_resolver
        self._runner = runner or SubprocessPluginHarnessRunner()
        self._coverage = coverage

    def _bound_spec(
        self, request: PluginRequest, atom_spec: object | None
    ) -> PluginHarnessSpec:
        return self._config.bind_spec(request, atom_spec, coverage=self._coverage)

    def validate(
        self,
        source: PluginSourceCandidate,
        build: PluginBuildResult,
        request: PluginRequest,
        *,
        plugin_run_id: str,
    ) -> PluginValidationResult:
        contract = SystemTelemetryPluginHarness(
            self._bound_spec(request, source.atom_spec),
            self,
            artifact_resolver=self._artifact_resolver,
        )
        return contract.validate(source, build, request, plugin_run_id=plugin_run_id)

    def execute(
        self,
        spec: PluginHarnessSpec,
        source: PluginSourceCandidate,
        build: PluginBuildResult,
        request: PluginRequest,
        *,
        plugin_run_id: str,
    ) -> PluginHarnessObservation:
        if spec.harness_ref != self._config.spec.harness_ref:
            raise VerificationError("Plugin Harness spec 与部署配置不一致")
        if request.intent.required_capabilities:
            raise VerificationError(
                "单插件 Harness 不得猜测 required_capabilities；请使用依赖闭包链接验证"
            )
        if request.profile_id not in self._config.spec.profile_ids:
            raise VerificationError(
                "PluginRequest profile_id 不在 Harness 允许集："
                f"{request.profile_id} allowed={list(self._config.spec.profile_ids)}"
            )
        linked, linked_sha256, link_root = self._link(
            source,
            build,
            request,
            plugin_run_id=plugin_run_id,
            relative_output=Path("harness-build") / build.build_id,
        )
        recipe = _harness_recipe(source, plugin_run_id, request)
        context = self._config.profile_context(
            self._config.profile.profile_id,
            source.atom_spec,
            ph_ids=resolve_harness_ph_ids(request, source.atom_spec),
        )
        plugin_root = link_root.parents[1]
        evidence_dir = (plugin_root / "verification" / f"vmware-{uuid4().hex}").resolve()
        guest_name = linked.name
        result, evidence = self._vmware.execute_plugin_artifact(
            artifact_path=linked,
            artifact_sha256=linked_sha256,
            recipe=recipe,
            context=context,
            evidence_dir=evidence_dir,
            guest_artifact_name=guest_name,
        )
        observation = _observation(
            spec,
            request,
            source,
            build,
            plugin_run_id,
            result,
            evidence,
            profile_id=self._config.profile.profile_id,
        )
        (evidence / "plugin-harness-observation.json").write_text(
            json.dumps(observation.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return observation

    def validate_dependency_links(
        self,
        plan: PluginDecompositionPlan,
        results: tuple[PluginAuthoringResult, ...],
    ) -> tuple[PluginDependencyLinkResult, ...]:
        """Link each consumer against only its declared transitive producers."""
        if not plan.dependencies:
            return ()
        by_request = {item.request_id: item for item in plan.requests}
        by_result = {item.request_id: item for item in results}
        incoming: dict[str, list[str]] = {item.request_id: [] for item in plan.requests}
        for dependency in plan.dependencies:
            incoming[dependency.consumer_request_id].append(dependency.producer_request_id)
        topo_ids = [item.request_id for item in results]
        link_results: list[PluginDependencyLinkResult] = []
        for consumer_id, direct_dependencies in incoming.items():
            if not direct_dependencies:
                continue
            consumer_result = by_result.get(consumer_id)
            consumer_request = by_request[consumer_id]
            consumer_spec = (
                None
                if consumer_result is None or consumer_result.source is None
                else consumer_result.source.atom_spec
            )
            if not resolve_harness_ph_ids(consumer_request, consumer_spec):
                continue
            if consumer_request.profile_id not in self._config.spec.profile_ids:
                raise VerificationError(
                    "PluginRequest profile_id 不在 Harness 允许集："
                    f"{consumer_request.profile_id} allowed={list(self._config.spec.profile_ids)}"
                )
            closure = _upstream_closure(incoming, consumer_id)
            dependency_ids = _ordered_upstream_producers(incoming, consumer_id, topo_ids)
            if set(dependency_ids) != closure:
                raise VerificationError("依赖链接结果缺少计划节点")
            if (
                consumer_result is None
                or consumer_result.source is None
                or consumer_result.build is None
            ):
                raise VerificationError(f"依赖 consumer 尚未 compile_valid：{consumer_id}")
            dependency_builds: list[PluginBuildResult] = []
            dependency_include_paths: list[Path] = []
            dependency_names: list[str] = []
            for dependency_id in dependency_ids:
                item = by_result.get(dependency_id)
                if item is None or item.build is None or item.source is None:
                    raise VerificationError(f"依赖 producer 尚未 compile_valid：{dependency_id}")
                dependency_builds.append(item.build)
                dependency_names.append(item.source.implementation_name)
                dependency_include_paths.append(
                    self._source_resolver.resolve(item.source.source_ref).resolve() / "src"
                )
            linked, linked_sha256, link_root = self._link(
                consumer_result.source,
                consumer_result.build,
                consumer_request,
                plugin_run_id=consumer_result.plugin_run_id,
                relative_output=Path("dependency-links") / plan.plan_id,
                dependency_builds=tuple(dependency_builds),
                dependency_include_paths=tuple(dependency_include_paths),
                dependency_implementation_names=tuple(dependency_names),
                receipt_extra={
                    "plan_id": plan.plan_id,
                    "consumer_request_id": consumer_id,
                    "dependency_request_ids": list(dependency_ids),
                },
            )
            recipe = _harness_recipe(
                consumer_result.source,
                consumer_result.plugin_run_id,
                consumer_request,
            )
            context = self._config.profile_context(
                self._config.profile.profile_id,
                consumer_result.source.atom_spec,
                ph_ids=resolve_harness_ph_ids(
                    consumer_request, consumer_result.source.atom_spec
                ),
            )
            plugin_root = link_root.parents[1]
            evidence_dir = (plugin_root / "verification" / f"vmware-joint-{uuid4().hex}").resolve()
            result, vm_evidence = self._vmware.execute_plugin_artifact(
                artifact_path=linked,
                artifact_sha256=linked_sha256,
                recipe=recipe,
                context=context,
                evidence_dir=evidence_dir,
                guest_artifact_name=linked.name,
            )
            observation = _observation(
                self._bound_spec(consumer_request, consumer_result.source.atom_spec),
                consumer_request,
                consumer_result.source,
                consumer_result.build,
                consumer_result.plugin_run_id,
                result,
                vm_evidence,
                profile_id=self._config.profile.profile_id,
            )
            (vm_evidence / "plugin-harness-observation.json").write_text(
                json.dumps(observation.model_dump(mode="json"), ensure_ascii=False, indent=2)
                + "\n",
                encoding="utf-8",
            )
            assertions = tuple(
                f"{item.assertion_id}={'passed' if item.passed else 'failed'}:{item.evidence_ref}"
                for item in observation.assertions
            )
            if not observation.behavior_valid:
                raise VerificationError(
                    "联合 Harness 未证明 consumer 行为有效：" + ",".join(assertions)
                )
            link_results.append(
                PluginDependencyLinkResult(
                    plan_id=plan.plan_id,
                    consumer_request_id=consumer_id,
                    dependency_request_ids=dependency_ids,
                    artifact_sha256=linked_sha256,
                    link_toolchain_fp=self._config.link_toolchain_fp,
                    evidence_ref=(
                        f"plugin-dependency-link://{consumer_result.plugin_run_id}/"
                        f"{link_root.relative_to(link_root.parents[1]).as_posix()}"
                    ),
                    behavior_valid=True,
                    assertions=assertions,
                )
            )
            if not linked.is_file():  # pragma: no cover - _link enforces this
                raise AssertionError("dependency link artifact disappeared")
        return tuple(link_results)

    def _link(
        self,
        source: PluginSourceCandidate,
        build: PluginBuildResult,
        request: PluginRequest,
        *,
        plugin_run_id: str,
        relative_output: Path,
        dependency_builds: tuple[PluginBuildResult, ...] = (),
        dependency_include_paths: tuple[Path, ...] = (),
        dependency_implementation_names: tuple[str, ...] = (),
        receipt_extra: dict[str, object] | None = None,
    ) -> tuple[Path, str, Path]:
        source_root = self._source_resolver.resolve(source.source_ref).resolve()
        plugin_root = source_root.parent.parent.resolve()
        harness_root = (plugin_root / "harness").resolve()
        main_path = harness_root / "main.cpp"
        if not main_path.is_file():
            raise VerificationError("Canonical Harness main.cpp 不存在")
        if source.atom_spec is None:
            raise VerificationError("Plugin Harness 链接需要 AtomSpec")
        primary = self._verified_artifact(build)
        dependencies = tuple(self._verified_artifact(item) for item in dependency_builds)
        link_root = (plugin_root / relative_output).resolve()
        if not link_root.is_relative_to(plugin_root) or link_root == plugin_root:
            raise VerificationError("Plugin Harness link 输出路径越界")
        if link_root.exists():
            shutil.rmtree(link_root)
        link_root.mkdir(parents=True, mode=0o700, exist_ok=False)
        recipe = _harness_recipe(source, plugin_run_id, request)
        configure_runtime_logging(link_root, recipe)
        atom_id = source.atom_spec.atom_id
        ph_ids = resolve_harness_ph_ids(request, source.atom_spec)
        payload_handoff = any(
            capability.startswith("cap.payload.")
            for capability in request.intent.required_capabilities
        )
        if dependency_implementation_names:
            main_text = render_joint_validation_harness_main(
                request.implementation_name,
                dependency_implementation_names,
                consumer_atom_id=atom_id,
                consumer_ph_ids=ph_ids,
                payload_handoff=payload_handoff,
            )
        else:
            main_text = render_logged_validation_harness_main(
                request.implementation_name,
                atom_id=atom_id,
                ph_ids=ph_ids,
            )
        (link_root / "main.cpp").write_text(main_text, encoding="utf-8", newline="\n")
        project_path = link_root / "PluginValidationHarness.vcxproj"
        project_path.write_text(
            render_validation_harness_project(
                request.implementation_name,
                primary,
                source_root / "src",
                dependency_artifact_paths=dependencies,
                dependency_include_paths=dependency_include_paths,
                runtime_logging=True,
            ),
            encoding="utf-8",
            newline="\n",
        )
        output_name = f"{request.implementation_name}Harness.exe"
        argv = [
            str(self._config.msbuild_path),
            str(project_path),
            "/m:1",
            "/p:Configuration=Release",
            "/p:Platform=x64",
            f"/p:OutDir={link_root}\\",
            f"/p:TargetName={request.implementation_name}Harness",
        ]
        validate_runtime_logging_build_inputs(link_root, recipe, argv)
        rc, diagnostics = self._runner.run(argv, timeout=self._config.link_timeout_s)
        (link_root / "diagnostics.txt").write_text(diagnostics[-65536:], encoding="utf-8")
        linked = (link_root / output_name).resolve()
        if rc != 0 or not linked.is_relative_to(link_root) or not linked.is_file():
            raise BuildError(
                f"Plugin Harness 链接失败（rc={rc}, diagnostics=plugin-harness-link://{plugin_run_id}/{build.build_id}）"
            )
        linked_sha256 = _sha256_file(linked)
        receipt: dict[str, object] = {
            "schema_version": "sf-plugin-harness-link-v1",
            "plugin_run_id": plugin_run_id,
            "source_artifact_ref": build.artifact_ref,
            "source_artifact_sha256": build.artifact_sha256,
            "dependency_artifacts": [
                {
                    "artifact_ref": item.artifact_ref,
                    "artifact_sha256": item.artifact_sha256,
                }
                for item in dependency_builds
            ],
            "linked_artifact_sha256": linked_sha256,
            "toolchain_fp": self._config.link_toolchain_fp,
        }
        receipt.update(receipt_extra or {})
        (link_root / "link-receipt.json").write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return linked, linked_sha256, link_root

    def _verified_artifact(self, build: PluginBuildResult) -> Path:
        artifact = self._artifact_resolver.resolve_artifact(build.artifact_ref).resolve()
        if not artifact.is_file() or _sha256_file(artifact) != build.artifact_sha256:
            raise VerificationError("依赖链接前 .lib 身份与构建回执不一致")
        return artifact


def create_vmware_plugin_harness_backend(
    *,
    config_path: str | Path,
    vmware_config_path: str | Path,
    source_resolver: PluginSourceResolver,
    artifact_resolver: PluginArtifactResolver,
    secrets_env_path: str | Path,
    coverage: CoverageRegistry | None = None,
) -> VmwarePluginHarnessBackend:
    config = VmwarePluginHarnessConfig.load(config_path)
    configured_vmware = config.vmware_verification_config
    if configured_vmware != Path(vmware_config_path).resolve():
        raise VerificationError("Plugin Harness 与 factory-config 的 VMware 配置不一致")
    vmware = VmwareVerificationBackend.from_config(
        configured_vmware,
        secrets_env_path=secrets_env_path,
        artifact_resolver=artifact_resolver,
        telemetry_contracts_path=None,
    )
    if config.profile.profile_id != vmware._settings.profile_id:
        raise VerificationError("Plugin Harness profile_id 与 VMware 验证配置不一致")
    return VmwarePluginHarnessBackend(
        config,
        vmware=vmware,
        source_resolver=source_resolver,
        artifact_resolver=artifact_resolver,
        coverage=coverage,
    )


def _harness_recipe(
    source: PluginSourceCandidate,
    plugin_run_id: str,
    request: PluginRequest | None = None,
) -> SampleRecipe:
    spec_ph = () if source.atom_spec is None else tuple(source.atom_spec.ph_ids)
    intent_ph = () if request is None else tuple(request.intent.ph_ids)
    ph_ids = resolve_harness_ph_ids(request, source.atom_spec)
    if source.atom_spec is None or not ph_ids:
        plugin_id = "unknown-plugin" if source.atom_spec is None else source.atom_spec.atom_id
        raise VerificationError(
            "Plugin Harness 需要带 PH 的 AtomSpec 才能构造行为验证合同："
            f"{plugin_id} atom_spec.ph_ids={list(spec_ph)} intent.ph_ids={list(intent_ph)}"
        )
    return SampleRecipe(
        recipe_id=f"plugin-{plugin_run_id.removeprefix('plugin-run-')}",
        execution_atoms=(source.atom_spec.atom_id,),
        delivery=DeliveryMode.PRESET_NO_MOTW,
        trigger_mode=TriggerMode.LAB_TRIGGER,
        ph_ids=ph_ids,
        evasion_tier="E0",
        execution_logging=True,
    )


def _observation(
    spec: PluginHarnessSpec,
    _request: PluginRequest,
    source: PluginSourceCandidate,
    build: PluginBuildResult,
    plugin_run_id: str,
    result: GuestExecutionResult,
    evidence_dir: Path,
    *,
    profile_id: str,
) -> PluginHarnessObservation:
    event_ids: set[int] = set()
    for item in result.sysmon_events:
        event_id = item.get("event_id")
        if isinstance(event_id, int) and not isinstance(event_id, bool):
            event_ids.add(event_id)
    atom_id = None if source.atom_spec is None else source.atom_spec.atom_id
    matchers = variant_sysmon_matchers(atom_id)
    assertions = tuple(
        HarnessAssertion(
            assertion_id=assertion_id,
            passed=_assertion_passed(assertion_id, result, event_ids, matchers),
            evidence_ref=f"{evidence_dir.as_posix()}#assertion={assertion_id}",
        )
        for assertion_id in spec.required_assertions
    )
    finished = result.finished_at_utc
    from datetime import datetime

    started_at = datetime.fromisoformat(result.started_at_utc.replace("Z", "+00:00"))
    finished_at = datetime.fromisoformat(finished.replace("Z", "+00:00"))
    return PluginHarnessObservation(
        harness_ref=spec.harness_ref,
        plugin_run_id=plugin_run_id,
        profile_id=profile_id,
        host_id=f"vm://{profile_id}",
        process_identity=f"pid:{result.process_id or 0}/start:{result.started_at_utc}",
        isolation_profile_ref=spec.isolation_profile_ref,
        collector_config_ref=spec.collector_config_ref,
        artifact_sha256=build.artifact_sha256,
        source_digest=source.source_digest,
        telemetry_source=HarnessTelemetrySource.SYSMON,
        started_at=started_at,
        finished_at=finished_at,
        contract_valid=result.process_created and not result.timed_out and result.error is None,
        atom_valid=source.atom_spec is not None,
        assertions=assertions,
        evidence_ref=f"vmware-plugin-evidence://{plugin_run_id}/{evidence_dir.name}",
    )


def _assertion_passed(
    assertion_id: str,
    result: GuestExecutionResult,
    event_ids: set[int],
    matchers: tuple[Any, ...] = (),
) -> bool:
    if assertion_id == "process.created":
        return result.process_created
    if assertion_id == "process.exit_code_zero":
        return result.process_created and not result.timed_out and result.exit_code == 0
    match = re.fullmatch(r"sysmon\.event_id\.(\d+)", assertion_id)
    if match is None:
        return False
    event_id = int(match.group(1))
    relevant = tuple(item for item in matchers if getattr(item, "event_id", None) == event_id)
    if not relevant:
        return event_id in event_ids
    raw_events = tuple(event for event in result.sysmon_events if isinstance(event, dict))
    image_by_pid = sysmon_image_by_process_id(raw_events)
    return any(
        sysmon_event_matches(
            project_sysmon_event_for_oracle(event, image_by_pid=image_by_pid),
            matcher,
        )
        for event in raw_events
        for matcher in relevant
    )


def _upstream_closure(incoming: dict[str, list[str]], consumer_id: str) -> set[str]:
    closure: set[str] = set()

    def add_upstream(request_id: str) -> None:
        for producer_id in incoming[request_id]:
            if producer_id not in closure:
                closure.add(producer_id)
                add_upstream(producer_id)

    add_upstream(consumer_id)
    return closure


def _ordered_upstream_producers(
    incoming: dict[str, list[str]],
    consumer_id: str,
    topo_ids: list[str],
) -> tuple[str, ...]:
    """Return producers in dependency order so elevation runs before consumers."""
    remaining = set(_upstream_closure(incoming, consumer_id))
    ordered: list[str] = []
    while remaining:
        ready = [
            item
            for item in topo_ids
            if item in remaining
            and not any(dep in remaining for dep in incoming.get(item, ()))
        ]
        if not ready:
            ready = [item for item in topo_ids if item in remaining]
        if not ready:
            break
        pick = ready[0]
        ordered.append(pick)
        remaining.remove(pick)
    return tuple(ordered)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "PluginDependencyLinkResult",
    "SubprocessPluginHarnessRunner",
    "VmwarePluginHarnessBackend",
    "VmwarePluginHarnessConfig",
    "create_vmware_plugin_harness_backend",
    "project_plugin_harness_assertions",
]
