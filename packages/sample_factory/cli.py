"""Human-facing CLI for the AI-driven sample factory."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal, TextIO, cast
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from packages.config.runtime import RuntimeConfigError, load_runtime
from packages.config.secrets_env import SecretsEnv, SecretsEnvError
from packages.contract_gap import ContractGap, ContractGapError
from packages.factory_host.plugin_harness_vmware import (
    VmwarePluginHarnessConfig,
    create_vmware_plugin_harness_backend,
)
from packages.factory_host.vmware_verification import (
    ArtifactResolver,
    VmwareVerificationBackend,
)
from packages.llm.provider import LLMConfig, OpenAICompatClient
from packages.sample_factory.ai_planner import CompletionClient, FactoryPlanningAgent
from packages.sample_factory.artifacts import FilesystemArtifactPublisher
from packages.sample_factory.bundle_models import SampleBundle
from packages.sample_factory.cas import ContentAddressedStore
from packages.sample_factory.catalog import CoverageRegistry
from packages.sample_factory.technique_board import (
    collect_factory_plugin_board_rows,
    write_published_attck_board,
)
from packages.sample_factory.coding_agent import DeepSeekGlueAgent, LocalPluginWorkspace
from packages.sample_factory.compiler import (
    GuardedCompilerBackend,
    JsonBuildTargetCatalog,
)
from packages.sample_factory.errors import (
    FactoryDenied,
    SampleFactoryError,
    VerificationError,
)
from packages.sample_factory.experience import (
    ExperienceRecord,
    ExperienceSearchQuery,
    ExperienceSearchResult,
    FilesystemExperienceStore,
    HybridExperienceRetriever,
    KnowledgeMaturity,
    select_planning_strategy,
)
from packages.sample_factory.experience_extractor import ExperienceExtractor
from packages.sample_factory.export import (
    ArtifactExportService,
    ArtifactReplayService,
    BundleExportService,
    list_export_packages,
    locate_sample_telemetry_evidence,
    produced_sample_export_id,
)
from packages.sample_factory.factory_layout import initialize_factory_layout
from packages.sample_factory.glue import GlueCoordinator
from packages.sample_factory.handoff import HandoffError, resolve_payload_bytes
from packages.sample_factory.identity import canonical_json
from packages.sample_factory.manifest import ManifestRepository
from packages.sample_factory.metadata_backup import MetadataBackupService
from packages.sample_factory.models import (
    AtomSpec,
    FactoryPlanningContext,
    GlueResolution,
    HandoffMaterialize,
    PluginProvenance,
)
from packages.sample_factory.pipeline import (
    AIDrivenSampleFactory,
    ArtifactPublisher,
    BatchAttemptResult,
    BatchOptions,
    BuildRequest,
    CompilerBackend,
    ProductionBatchResult,
    ProductionRequest,
    ProductionResult,
    ProductionStopToken,
    VerificationBackend,
)
from packages.sample_factory.planning_audit import PlanningAuditRepository
from packages.sample_factory.plugin_authoring import (
    PluginAuthoringBackend,
    PluginAuthoringPipeline,
    PluginCompilerBackend,
    PluginHarnessBackend,
)
from packages.sample_factory.plugin_authoring_agent import LLMPluginAuthoringAgent
from packages.sample_factory.plugin_catalog import (
    PluginBuildArtifactResolver,
    PluginCatalogPromotionService,
    PluginRunSourceResolver,
)
from packages.sample_factory.plugin_compiler import GuardedPluginCompilerBackend
from packages.sample_factory.plugin_contract import materialize_validation_harness
from packages.sample_factory.plugin_harness import PluginArtifactResolver
from packages.sample_factory.plugin_harness_oracles import resolve_harness_ph_ids
from packages.sample_factory.plugin_intake import (
    PluginIntakeAgent,
    PluginIntakeCoordinator,
    PluginIntakeRepository,
    PluginIntakeSession,
    PluginSourceIntake,
)
from packages.sample_factory.plugin_models import (
    PluginAuthoringResult,
    PluginDecompositionPlan,
    PluginDependency,
    PluginLifecycleStatus,
    PluginRequest,
    PluginSourceCandidate,
    PluginValidationResult,
)
from packages.sample_factory.plugin_run_repository import PluginRunRepository
from packages.sample_factory.plugin_run_cleanup import (
    execute_plugin_run_cleanup,
    plan_plugin_run_cleanup,
)
from packages.sample_factory.plugin_run_select import plugin_run_identity, plugin_run_sort_key
from packages.sample_factory.plugin_seed import SeedPluginAuthoringBackend
from packages.sample_factory.run_index import RunIndex
from packages.sample_factory.run_models import (
    AttemptStatus,
    PlanningStrategy,
    RunEnvelope,
    RunKind,
    RunStatus,
    new_attempt_id,
    new_run_id,
    utc_now,
)
from packages.sample_factory.run_repository import (
    AttemptHandle,
    RecordingEventSink,
    RunHandle,
    RunRepository,
)
from packages.sample_factory.source_snapshot import (
    SourceReplayService,
    SourceSnapshotRepository,
)
from packages.sample_factory.sources import (
    DirectoryAtomCatalogLoader,
    JsonTelemetryContractSource,
    MatrixExpectedDetectionSource,
)
from packages.sample_factory.state import ComboStateStore
from packages.sample_factory.storage_management import StorageManager
from packages.sample_factory.telemetry import FunctionalTruthEvaluator
from packages.sample_factory.vector_index import (
    EmbeddingBackend,
    FilesystemSemanticExperienceIndex,
)
from packages.sample_factory.work_queue import FactoryWorkQueue, SampleDemand

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_PATH_FIELDS = (
    "catalog_root",
    "runtime_root",
    "manifest_root",
    "runtime_toml",
    "secrets_env",
    "coverage_matrix",
    "verification_config",
    "plugin_harness_config",
)
_STATE_METHODS = (
    "claim",
    "heartbeat",
    "complete_success",
    "complete_failure",
    "write_detection",
    "get",
)


class FactoryCliConfig(BaseModel):
    """Non-secret deployment wiring for one factory installation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["factory-config-v2"]
    coverage_matrix: Path
    catalog_root: Path
    runtime_root: Path
    manifest_root: Path
    verification_config: Path | None = None
    plugin_harness_config: Path | None = None
    runtime_toml: Path | None = None
    secrets_env: Path | None = None
    completion_backend_ref: str | None = None
    state_backend_ref: str | None = None
    verification_backend_ref: str | None = None
    compiler_backend_ref: str | None = None
    artifact_publisher_ref: str | None = None
    plugin_authoring_backend_ref: str | None = None
    plugin_compiler_backend_ref: str | None = None
    plugin_harness_backend_ref: str | None = None
    plugin_build_target_ref: str | None = Field(
        default=None, pattern=r"^build-target://.+"
    )
    embedding_backend_ref: str | None = None
    planner_retry_limit: int = Field(default=3, ge=1)
    glue_retry_limit: int = Field(default=2, ge=1)
    planner_max_tokens: int | None = Field(default=None, gt=0)
    glue_max_tokens: int | None = Field(default=None, gt=0)
    glue_agent_max_turns: int = Field(default=24, ge=2, le=64)
    max_compile_attempts: int = Field(default=3, ge=1)
    compiler_memory_limit_mb: int = Field(default=8192, gt=0)

    @property
    def plugin_root(self) -> Path:
        return self.catalog_root

    @property
    def telemetry_contracts(self) -> Path:
        return self.catalog_root / "telemetry" / "contracts.json"

    @property
    def build_targets(self) -> Path:
        return self.catalog_root / "build-targets" / "build-targets.json"

    @property
    def object_store_root(self) -> Path:
        return self.runtime_root / "store" / "artifacts" / "sha256"

    @property
    def payload_root(self) -> Path:
        return self.catalog_root / "payloads"

    @property
    def payload_search_roots(self) -> tuple[Path, ...]:
        return (
            self.catalog_root / "payloads",
            self.runtime_root / "store" / "inputs" / "payloads",
        )

    @property
    def manifest_path(self) -> Path:
        return self.manifest_root / "regression.jsonl"

    @property
    def experience_root(self) -> Path:
        return self.catalog_root / "experience" / "records"

    @property
    def experience_vector_index(self) -> Path:
        return self.runtime_root / "index" / "experience-vectors.json"

    @field_validator(
        "completion_backend_ref",
        "state_backend_ref",
        "verification_backend_ref",
        "compiler_backend_ref",
        "artifact_publisher_ref",
        "plugin_authoring_backend_ref",
        "plugin_compiler_backend_ref",
        "plugin_harness_backend_ref",
        "embedding_backend_ref",
    )
    @classmethod
    def _backend_ref(cls, value: str | None) -> str | None:
        if value is not None and not _valid_symbol_ref(value):
            raise ValueError("backend ref 必须是 module:attribute")
        return value

    @model_validator(mode="after")
    def _verification_source(self) -> FactoryCliConfig:
        if self.verification_config is not None and self.verification_backend_ref is not None:
            raise ValueError("verification_config 与 verification_backend_ref 只能配置一个")
        if self.plugin_harness_config is not None and self.plugin_harness_backend_ref is not None:
            raise ValueError("plugin_harness_config 与 plugin_harness_backend_ref 只能配置一个")
        return self


class FactoryBatchSpec(BaseModel):
    """Bounded multi-combination production request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sample_count: int = Field(default=1, ge=1, le=1000)
    max_attempts: int | None = Field(default=None, ge=1, le=3000)
    continue_on_failure: bool = Field(default=True, strict=True)

    @model_validator(mode="after")
    def _attempt_budget(self) -> FactoryBatchSpec:
        if self.max_attempts is not None and self.max_attempts < self.sample_count:
            raise ValueError("batch.max_attempts 不得小于 sample_count")
        return self

    @property
    def effective_max_attempts(self) -> int:
        return self.max_attempts or self.sample_count * 3


class FactoryRunSpec(BaseModel):
    """Per-production request; approval is intentionally not persisted here."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    context: FactoryPlanningContext
    run_kind: RunKind
    planning_strategy: PlanningStrategy
    worker_id: str = Field(min_length=1)
    workspace_ref: str = Field(min_length=1)
    build_target_ref: str = Field(min_length=1)
    regression_set_version: str = Field(min_length=1)
    runtime_param_snapshot_ref: str | None = None
    parent_id: str | None = None
    lease_ttl_seconds: float = Field(default=900, gt=3)
    compile_attempt_limit: int | None = Field(default=None, ge=1)
    execution_logging: bool = Field(default=False, strict=True)
    batch: FactoryBatchSpec | None = None

    @field_validator("workspace_ref")
    @classmethod
    def _workspace_ref(cls, value: str) -> str:
        if not value.startswith("plugin-workspace://"):
            raise ValueError("workspace_ref 必须是 plugin-workspace:// 引用")
        return value

    @field_validator("build_target_ref")
    @classmethod
    def _build_target_ref(cls, value: str) -> str:
        if not value.startswith("build-target://"):
            raise ValueError("build_target_ref 必须是 build-target:// 引用")
        return value


@dataclass(frozen=True)
class FactoryInputs:
    config: FactoryCliConfig
    run: FactoryRunSpec


def load_inputs(config_path: str | Path, run_path: str | Path) -> FactoryInputs:
    config_file = Path(config_path).resolve()
    config = _load_json_model(config_file, FactoryCliConfig)
    config = _resolve_config_paths(config, config_file.parent)
    run = _load_json_model(Path(run_path).resolve(), FactoryRunSpec)
    return FactoryInputs(config=config, run=run)


def start_plugin_intake(
    config_path: str | Path,
    run_path: str | Path,
    *,
    description: str,
    source_urls: tuple[str, ...],
    harness_ref: str | None = None,
) -> PluginIntakeSession:
    """Create a persisted conversational draft without starting plugin execution."""
    inputs = load_inputs(config_path, run_path)
    config, run = inputs.config, inputs.run
    _validate_layout_roots(config)
    if config.plugin_build_target_ref is None:
        raise ContractGapError(
            ContractGap(
                capability="创建只产出 .lib 的单插件请求",
                missing="FactoryCliConfig.plugin_build_target_ref",
                checked=(str(config_path), "catalog/build-targets/build-targets.json"),
                risk="复用样本 EXE/DLL build target 会把插件验证产物混入源码 Glue 路径",
                next_step="配置已登记的 StaticLibrary build target 后重试。",
            )
        )
    coordinator = _plugin_intake_coordinator(config)
    return coordinator.start(
        description=description,
        source_urls=source_urls,
        harness_ref=harness_ref,
        build_target_ref=config.plugin_build_target_ref,
        profile_id=run.context.profile.profile_id,
    )


def continue_plugin_intake(
    config_path: str | Path,
    *,
    session_id: str,
    user_message: str,
) -> PluginIntakeSession:
    """Refine a persisted intake session while preserving its frozen execution fields."""
    config_file = Path(config_path).resolve()
    config = _resolve_config_paths(
        _load_json_model(config_file, FactoryCliConfig), config_file.parent
    )
    _validate_layout_roots(config)
    return _plugin_intake_coordinator(config).continue_session(session_id, user_message)


def execute_plugin_authoring_request(
    config_path: str | Path,
    request: PluginRequest,
    *,
    approved: bool,
    sink: Callable[[tuple[str, dict[str, object]]], None] | None = None,
    run_harness: bool = True,
) -> PluginAuthoringResult:
    """Run one approved plugin request through the same pipeline used by the CLI."""
    if not approved:
        raise FactoryDenied("单插件生成需要本轮人工审批")
    config_file = Path(config_path).resolve()
    config = _resolve_config_paths(
        _load_json_model(config_file, FactoryCliConfig), config_file.parent
    )
    _validate_layout_roots(config)
    _plugin_authoring_preflight(config, request)
    coverage = CoverageRegistry.from_markdown(config.coverage_matrix)
    target = JsonBuildTargetCatalog(config.build_targets).load().get(request.build_target_ref)
    build_contract = (
        {}
        if target is None
        else {
            "target_ref": target.target_ref,
            "artifact_relative": target.artifact_relative.replace(
                "{implementation_name}", request.implementation_name
            ),
            "toolchain_fp": target.toolchain_fp,
        }
    )
    dispatchable_root = config.catalog_root / "plugins" / "dispatchable"
    if (
        dispatchable_root.is_dir()
        and next(dispatchable_root.glob("*/plugin.json"), None) is not None
    ):
        DirectoryAtomCatalogLoader(config.catalog_root, coverage).load()
        reference_roots = {
            path.parent.name: path.parent
            for path in sorted(dispatchable_root.glob("*/plugin.json"))
        }
    else:
        reference_roots = {}
    plugin_completion = (
        _plugin_completion_client(config) if config.plugin_authoring_backend_ref is None else None
    )
    external_author = (
        None
        if config.plugin_authoring_backend_ref is None
        else cast(
            PluginAuthoringBackend,
            _backend_instance(
                config.plugin_authoring_backend_ref,
                "Plugin Authoring 后端",
                ("author",),
            ),
        )
    )
    compiler = _plugin_compiler(config)
    harness = _plugin_harness(config, compiler) if run_harness else None
    plugin_run_id = f"plugin-run-{uuid4().hex}"
    plugin_repository = PluginRunRepository(config.runtime_root)
    plugin_root = plugin_repository.create(plugin_run_id, request)
    materialize_validation_harness(plugin_root, request.implementation_name)

    def plugin_sink(event: tuple[str, dict[str, object]]) -> None:
        plugin_repository.append_event(plugin_root, event)
        if sink is not None:
            sink(event)

    if request.seed_source_ref is not None:

        def resolve_seed_source(resolved_plugin_run_id: str) -> Path:
            if resolved_plugin_run_id != plugin_run_id:
                raise ValueError("Plugin Authoring run ID 与当前运行包不一致")
            return plugin_root / "authoring" / "final-source"

        author: PluginAuthoringBackend = SeedPluginAuthoringBackend(
            config.catalog_root,
            resolve_seed_source,
            coverage=coverage,
        )
    elif config.plugin_authoring_backend_ref is None:
        if plugin_completion is None:  # pragma: no cover - branch invariant
            raise AssertionError("builtin Plugin Authoring completion missing")

        def resolve_plugin_source(resolved_plugin_run_id: str) -> Path:
            if resolved_plugin_run_id != plugin_run_id:
                raise ValueError("Plugin Authoring run ID 与当前运行包不一致")
            return plugin_root / "authoring" / "final-source"

        author: PluginAuthoringBackend = LLMPluginAuthoringAgent(
            plugin_completion,
            resolve_plugin_source,
            retry_limit=config.glue_retry_limit,
            max_turns=config.glue_agent_max_turns,
            reference_roots=reference_roots,
            build_contract=build_contract,
            sink=plugin_sink,
        )
    else:
        if external_author is None:  # pragma: no cover - branch invariant
            raise AssertionError("external Plugin Authoring backend missing")
        author = external_author

    pipeline = PluginAuthoringPipeline(
        author=author,
        compiler=compiler,
        harness=harness,
        coverage=coverage,
        sink=plugin_sink,
        max_compile_attempts=config.max_compile_attempts,
    )
    try:
        result = pipeline.run(request, approved=True, plugin_run_id=plugin_run_id)
        plugin_repository.complete(plugin_root, result)
    except BaseException as exc:
        plugin_repository.fail(plugin_root, exc)
        raise
    return result


def execute_plugin_decomposition(
    config_path: str | Path,
    plan: PluginDecompositionPlan,
    *,
    approved: bool,
    sink: Callable[[tuple[str, dict[str, object]]], None] | None = None,
) -> tuple[PluginAuthoringResult, ...]:
    """Execute a model-produced plugin plan in validated dependency order."""
    if not approved:
        raise FactoryDenied("插件分解计划执行需要本轮人工审批")
    by_id = {item.request_id: item for item in plan.requests}
    dependents: dict[str, list[str]] = {item.request_id: [] for item in plan.requests}
    indegree = {item.request_id: 0 for item in plan.requests}
    for dependency in plan.dependencies:
        dependents[dependency.producer_request_id].append(dependency.consumer_request_id)
        indegree[dependency.consumer_request_id] += 1
    ready = [item.request_id for item in plan.requests if indegree[item.request_id] == 0]
    results: list[PluginAuthoringResult] = []
    defer_harness = bool(plan.dependencies)
    while ready:
        request_id = ready.pop(0)
        request = by_id[request_id]
        result = execute_plugin_authoring_request(
            config_path,
            request,
            approved=True,
            sink=sink,
            run_harness=not defer_harness,
        )
        results.append(result)
        if sink is not None:
            sink(
                (
                    "sample_factory_plugin_plan_node_finished",
                    {
                        "plan_id": plan.plan_id,
                        "request_id": request_id,
                        "plugin_run_id": result.plugin_run_id,
                        "status": result.status.value,
                    },
                )
            )
        for child in dependents[request_id]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if len(results) != len(plan.requests):  # pragma: no cover - model validates cycles
        raise ValueError("PluginDecompositionPlan 未能按依赖图完成拓扑排序")
    if defer_harness:
        config_file = Path(config_path).resolve()
        config = _resolve_config_paths(
            _load_json_model(config_file, FactoryCliConfig), config_file.parent
        )
        compiler = _plugin_compiler(config)
        harness = _plugin_harness(config, compiler)
        validate_links = getattr(harness, "validate_dependency_links", None)
        if not callable(validate_links):
            raise ContractGapError(
                ContractGap(
                    capability="多插件依赖闭包链接验证",
                    missing="Plugin Harness validate_dependency_links(plan, results)",
                    checked=(
                        "PluginDecompositionPlan.dependencies",
                        "FactoryCliConfig.plugin_harness_config",
                    ),
                    risk="逐个生成 .lib 不会解析跨插件外部符号；全量链接又会掩盖未声明依赖",
                )
            )
        link_results = validate_links(plan, tuple(results))
        if sink is not None:
            for item in link_results:
                sink(
                    (
                        "sample_factory_plugin_dependency_link_valid",
                        item.model_dump(mode="json"),
                    )
                )
    return tuple(results)


@dataclass(frozen=True)
class _PluginRunRecord:
    plugin_run_id: str
    root: Path
    request: PluginRequest
    result: PluginAuthoringResult


def plugin_run_short_id(plugin_run_id: str) -> str:
    """Stable 8-char suffix used in the verification TUI and operator errors."""
    return plugin_run_id.removeprefix("plugin-run-")[:8]


def describe_plugin_run_choice(
    plugin_run_id: str,
    *,
    implementation_name: str,
    plugin_id: str | None = None,
) -> str:
    short = plugin_run_short_id(plugin_run_id)
    name = implementation_name or "-"
    if plugin_id:
        return f"{name} [{short}] ({plugin_id})"
    return f"{name} [{short}]"


def _describe_plugin_record(record: _PluginRunRecord) -> str:
    plugin_id = None if record.result.source is None else record.result.source.plugin_id
    return describe_plugin_run_choice(
        record.plugin_run_id,
        implementation_name=record.request.implementation_name,
        plugin_id=plugin_id,
    )


def _resolved_plugin_ph_ids(record: _PluginRunRecord) -> tuple[str, ...]:
    source = record.result.source
    atom_spec = None if source is None else source.atom_spec
    return resolve_harness_ph_ids(record.request, atom_spec)


def _request_with_resolved_ph(
    record: _PluginRunRecord,
    config: FactoryCliConfig,
) -> PluginRequest:
    request = record.request
    resolved = _resolved_plugin_ph_ids(record)
    if resolved and not request.intent.ph_ids:
        request = request.model_copy(
            update={"intent": request.intent.model_copy(update={"ph_ids": resolved})}
        )
    if resolved:
        request = _bind_harness_ref(request, _harness_ref_for_request(config, request))
    return request


def _component_has_verifiable_ph(records: Sequence[_PluginRunRecord]) -> bool:
    return any(_resolved_plugin_ph_ids(item) for item in records)


def _partition_plugin_run_records(
    records: Sequence[_PluginRunRecord],
) -> tuple[tuple[_PluginRunRecord, ...], ...]:
    parent = {item.plugin_run_id: item.plugin_run_id for item in records}

    def find(node: str) -> str:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(left: str, right: str) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    providers: dict[str, list[str]] = {}
    for item in records:
        for capability in item.request.intent.provided_capabilities:
            providers.setdefault(capability, []).append(item.plugin_run_id)
    for item in records:
        for capability in item.request.intent.required_capabilities:
            for producer in providers.get(capability, ()):
                if producer != item.plugin_run_id:
                    union(producer, item.plugin_run_id)

    grouped: dict[str, list[_PluginRunRecord]] = {}
    order: list[str] = []
    for item in records:
        root = find(item.plugin_run_id)
        if root not in grouped:
            grouped[root] = []
            order.append(root)
        grouped[root].append(item)
    return tuple(tuple(grouped[root]) for root in order)


def _factory_cli_config(config_path: str | Path) -> FactoryCliConfig:
    config_file = Path(config_path).resolve()
    return _resolve_config_paths(
        _load_json_model(config_file, FactoryCliConfig), config_file.parent
    )


def list_plugin_inventory(config_path: str | Path) -> dict[str, object]:
    """List plugin runs plus catalog promotion status for the verification TUI."""
    config = _factory_cli_config(config_path)
    repository = PluginRunRepository(config.runtime_root)
    promotion = PluginCatalogPromotionService(
        config.catalog_root,
        PluginRunSourceResolver(config.runtime_root),
    )
    catalog = promotion.list_catalog()
    dispatchable = set(catalog.get("dispatchable", []))
    reviewed = set(catalog.get("reviewed", []))
    candidate = set(catalog.get("candidate", []))
    runs: list[dict[str, object]] = []
    for item in repository.list_runs():
        plugin_run_id = str(item["plugin_run_id"])
        payload = repository.payload(plugin_run_id)
        request = PluginRequest.model_validate(payload["request"])
        result = (
            None
            if payload["result"] is None
            else PluginAuthoringResult.model_validate(payload["result"])
        )
        plugin_id = None if result is None or result.source is None else result.source.plugin_id
        if plugin_id in dispatchable:
            catalog_status = "dispatchable"
        elif plugin_id in reviewed:
            catalog_status = "reviewed"
        elif plugin_id in candidate:
            catalog_status = "candidate"
        else:
            catalog_status = None
        runs.append(
            {
                **item,
                "implementation_name": request.implementation_name,
                "plugin_id": plugin_id,
                "ph_ids": list(request.intent.ph_ids),
                "required_capabilities": list(request.intent.required_capabilities),
                "provided_capabilities": list(request.intent.provided_capabilities),
                "lifecycle_status": (
                    item.get("lifecycle_status")
                    if result is None
                    else result.status.value
                ),
                "catalog_status": catalog_status,
                "source_digest": (
                    None
                    if result is None or result.source is None
                    else result.source.source_digest
                ),
            }
        )
    return {"runs": runs, "catalog": catalog}


def cleanup_plugin_runs(
    config_path: str | Path,
    *,
    approved: bool,
) -> dict[str, object]:
    """Preview or delete failed / superseded plugin-run packages."""
    config = _factory_cli_config(config_path)
    if not approved:
        return plan_plugin_run_cleanup(config.runtime_root)
    return execute_plugin_run_cleanup(config.runtime_root, approved=True)


def list_produced_samples(config_path: str | Path) -> dict[str, object]:
    """List SUCCESS regression samples and their export/published transfer status."""
    config = _factory_cli_config(config_path)
    entries = ManifestRepository(config.manifest_path).entries()
    packages = list_export_packages(config.runtime_root)
    by_sample_id: dict[str, dict[str, object]] = {}
    by_sha256: dict[str, dict[str, object]] = {}
    for stage in ("published", "approved"):
        for item in packages.get(stage, ()):
            sample_id = item.get("sample_id")
            sha256 = item.get("artifact_sha256")
            if isinstance(sample_id, str) and sample_id and sample_id not in by_sample_id:
                by_sample_id[sample_id] = item
            if isinstance(sha256, str) and sha256 and sha256 not in by_sha256:
                by_sha256[sha256] = item
    samples: list[dict[str, object]] = []
    for entry in entries:
        if entry.retired_at is not None:
            continue
        atoms = entry.parameters_canonical.get("atoms")
        atom_ids = (
            sorted(str(key) for key in atoms)
            if isinstance(atoms, dict)
            else []
        )
        matched = by_sample_id.get(entry.sample_id) or by_sha256.get(entry.sample_sha256)
        samples.append(
            {
                "sample_id": entry.sample_id,
                "sample_sha256": entry.sample_sha256,
                "artifact_ref": entry.artifact_ref,
                "ph_sequence": list(entry.ph_sequence),
                "attck_ids": list(entry.attck_ids),
                "atom_ids": atom_ids,
                "profile_id": entry.profile_id,
                "regression_set_version": entry.regression_set_version,
                "export_status": None if matched is None else matched.get("destination"),
                "export_ref": None if matched is None else matched.get("export_ref"),
                "export_id": None if matched is None else matched.get("export_id"),
            }
        )
    return {
        "samples": samples,
        "exports": {
            stage: list(items) for stage, items in packages.items()
        },
    }


def transfer_produced_samples(
    config_path: str | Path,
    sample_ids: Sequence[str],
    *,
    approved: bool,
) -> tuple[dict[str, object], ...]:
    """Copy selected SUCCESS samples into runtime/exports/published for handoff."""
    if not approved:
        raise FactoryDenied("样本发布转到必须获得本轮人工审批")
    selected = tuple(dict.fromkeys(sample_ids))
    if not selected:
        raise ValueError("请至少选择一个已生产样本")
    config = _factory_cli_config(config_path)
    entries = {item.sample_id: item for item in ManifestRepository(config.manifest_path).entries()}
    cas = ContentAddressedStore(config.runtime_root)
    exporter = ArtifactExportService(config.runtime_root, cas)
    transferred: list[dict[str, object]] = []
    for sample_id in selected:
        entry = entries.get(sample_id)
        if entry is None:
            raise ValueError(f"回归集中没有该样本：{sample_id}")
        if entry.retired_at is not None:
            raise ValueError(f"样本已退役，不能发布转到：{sample_id}")
        try:
            evidence_dir, evidence_ref = locate_sample_telemetry_evidence(
                config.runtime_root, entry.sample_sha256
            )
        except FileNotFoundError as exc:
            raise ValueError(f"样本缺少可发布遥测证据：{sample_id}") from exc
        result = exporter.export(
            export_id=produced_sample_export_id(entry.sample_id),
            artifact_ref=entry.artifact_ref,
            filename=f"{entry.sample_id}.exe",
            approved=True,
            destination="published",
            sample_record=entry.model_dump(mode="json"),
            telemetry_evidence_dir=evidence_dir,
            telemetry_evidence_ref=evidence_ref,
        )
        transferred.append(
            {
                "sample_id": entry.sample_id,
                "export_id": result.export_id,
                "export_ref": result.export_ref,
                "artifact_sha256": result.artifact_sha256,
                "artifact_path": result.artifact_path.as_posix(),
                "manifest_path": result.manifest_path.as_posix(),
            }
        )
    return tuple(transferred)


def export_published_attck_board(
    config_path: str | Path,
    *,
    open_browser: bool = False,
) -> dict[str, object]:
    """Write the published-sample ATT&CK HTML board under runtime/exports."""
    config = _factory_cli_config(config_path)
    coverage = CoverageRegistry.from_markdown(config.coverage_matrix)
    inventory = list_produced_samples(config_path)
    samples = [
        item
        for item in list(inventory.get("samples") or [])
        if isinstance(item, dict)
    ]
    try:
        plugin_inventory = list_plugin_inventory(config_path)
        plugin_runs = [
            item
            for item in list(plugin_inventory.get("runs") or [])
            if isinstance(item, dict)
        ]
    except Exception:
        plugin_runs = []
    plugins = collect_factory_plugin_board_rows(coverage, plugin_runs)
    path = write_published_attck_board(
        Path(config.runtime_root) / "exports" / "technique-board.html",
        coverage,
        samples,
        plugins,
    )
    if open_browser:
        import webbrowser

        webbrowser.open(path.as_uri())
    published = [
        item for item in samples if str(item.get("export_status") or "") == "published"
    ]
    return {
        "path": path.as_posix(),
        "published_count": len(published),
        "scope_ph": len(coverage.rows),
        "opened": open_browser,
    }


def execute_plugin_run_validation(
    config_path: str | Path,
    plugin_run_ids: Sequence[str],
    *,
    approved: bool,
    sink: Callable[[tuple[str, dict[str, object]]], None] | None = None,
) -> tuple[PluginAuthoringResult, ...]:
    """Run Plugin Harness against existing compile_valid plugin runs and persist behavior_valid."""
    if not approved:
        raise FactoryDenied("已有插件 Harness 验证需要本轮人工审批")
    selected = tuple(dict.fromkeys(plugin_run_ids))
    if not selected:
        raise ValueError("请至少选择一个插件运行")
    config = _factory_cli_config(config_path)
    repository = PluginRunRepository(config.runtime_root)
    compiler = _plugin_compiler(config)
    harness = _plugin_harness(config, compiler)
    if harness is None:
        raise ContractGapError(
            ContractGap(
                capability="已有插件 Canonical Harness 验证",
                missing="plugin_harness_config 或 plugin_harness_backend_ref",
                checked=("FactoryCliConfig",),
                risk="仅有 .lib 编译回执不能证明最终链接或 TTP 行为有效",
            )
        )
    available = _validatable_plugin_runs(repository)
    missing = [item for item in selected if item not in available]
    if missing:
        raise ValueError(f"所选 plugin run 不是可验证的 compile_valid/behavior_valid 候选：{missing}")
    closure_ids = _expand_validation_closure(selected, available)
    records = tuple(available[item] for item in closure_ids)
    roots = tuple(item.root for item in records)

    def validation_sink(event: tuple[str, dict[str, object]]) -> None:
        for root in roots:
            repository.append_event(root, event)
        if sink is not None:
            sink(event)

    updated: list[PluginAuthoringResult] = []
    skipped: list[str] = []
    try:
        for component in _partition_plugin_run_records(records):
            if not _component_has_verifiable_ph(component):
                names = "；".join(_describe_plugin_record(item) for item in component)
                skipped.append(names)
                validation_sink(
                    (
                        "sample_factory_plugin_validation_skipped",
                        {
                            "plugin_run_ids": [item.plugin_run_id for item in component],
                            "reason": f"无 PH，跳过 Harness：{names}",
                        },
                    )
                )
                continue
            plan = _validation_plan_for_records(component, config)
            if plan is None:
                updated.extend(
                    _validate_independent_plugin_run(
                        record,
                        harness=harness,
                        config=config,
                        sink=validation_sink,
                    )
                    for record in component
                )
            else:
                updated.extend(
                    _validate_plugin_run_closure(
                        component,
                        plan,
                        harness=harness,
                        sink=validation_sink,
                    )
                )
        if not updated:
            detail = "；".join(skipped) if skipped else "；".join(
                _describe_plugin_record(item) for item in records
            )
            raise ValueError(
                f"所选插件都没有可验证的 PH，不能走 Plugin Harness：{detail}。"
                "请勾选带 PH 的 TTP（例如 CallbackExec / ThreadHijack），"
                "payload 与 loader 只作为 producer 一起勾选。"
            )
    except Exception as exc:
        validation_sink(
            (
                "sample_factory_plugin_validation_failed",
                {
                    "plugin_run_ids": list(closure_ids),
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
        )
        raise
    completed = tuple(updated)
    by_id = {item.plugin_run_id: item for item in records}
    for result in completed:
        record = by_id[result.plugin_run_id]
        repository.complete(record.root, result)
    return completed


def review_plugin_run(
    config_path: str | Path,
    plugin_run_id: str,
    provenance: PluginProvenance,
    *,
    approved: bool,
) -> Path:
    if not approved:
        raise FactoryDenied("插件 review 需要本轮人工审批")
    config = _factory_cli_config(config_path)
    repository = PluginRunRepository(config.runtime_root)
    payload = repository.payload(plugin_run_id)
    if payload["result"] is None:
        raise ValueError("plugin run 尚无结果")
    result = PluginAuthoringResult.model_validate(payload["result"])
    if result.source is None:
        raise ValueError("behavior-valid plugin result 缺少 source")
    promotion = PluginCatalogPromotionService(
        config.catalog_root,
        PluginRunSourceResolver(config.runtime_root),
        artifact_resolver=_plugin_artifact_resolver(config),
        artifact_store=ContentAddressedStore(config.runtime_root),
        coverage=CoverageRegistry.from_markdown(config.coverage_matrix),
        profile_id=_lab_profile_id(config),
    )
    reviewed = promotion.review(result, provenance, approved=True)
    repository.append_event(
        repository.find(plugin_run_id),
        (
            "sample_factory_plugin_reviewed",
            {
                "plugin_run_id": plugin_run_id,
                "plugin_id": result.source.plugin_id,
                "reviewed_path": reviewed.as_posix(),
            },
        ),
    )
    return reviewed


def promote_plugin(
    config_path: str | Path,
    plugin_id: str,
    *,
    approved: bool,
) -> Path:
    if not approved:
        raise FactoryDenied("插件 promote 需要本轮人工审批")
    config = _factory_cli_config(config_path)
    promotion = PluginCatalogPromotionService(
        config.catalog_root,
        PluginRunSourceResolver(config.runtime_root),
    )
    return promotion.promote_dispatchable(plugin_id, approved=True)


def _validatable_plugin_runs(
    repository: PluginRunRepository,
) -> dict[str, _PluginRunRecord]:
    result: dict[str, _PluginRunRecord] = {}
    for item in repository.list_runs():
        plugin_run_id = str(item["plugin_run_id"])
        payload = repository.payload(plugin_run_id)
        if payload["result"] is None:
            continue
        request = PluginRequest.model_validate(payload["request"])
        authoring = PluginAuthoringResult.model_validate(payload["result"])
        if authoring.status not in {
            PluginLifecycleStatus.COMPILE_VALID,
            PluginLifecycleStatus.BEHAVIOR_VALID,
        }:
            continue
        if authoring.source is None or authoring.build is None:
            continue
        result[plugin_run_id] = _PluginRunRecord(
            plugin_run_id=plugin_run_id,
            root=repository.find(plugin_run_id),
            request=request,
            result=authoring,
        )
    return result


def _expand_validation_closure(
    selected: Sequence[str],
    available: Mapping[str, _PluginRunRecord],
) -> tuple[str, ...]:
    closure = list(selected)
    known = set(closure)
    while True:
        provided: set[str] = set()
        required: set[str] = set()
        for plugin_run_id in closure:
            intent = available[plugin_run_id].request.intent
            provided.update(intent.provided_capabilities)
            required.update(intent.required_capabilities)
        missing = required - provided
        if not missing:
            return tuple(closure)
        added = False
        for capability in sorted(missing):
            candidates = [
                plugin_run_id
                for plugin_run_id, record in available.items()
                if plugin_run_id not in known
                and capability in record.request.intent.provided_capabilities
            ]
            unique: dict[str, str] = {}
            for plugin_run_id in candidates:
                record = available[plugin_run_id]
                source = record.result.source
                identity = plugin_run_identity(
                    {
                        "plugin_id": None if source is None else source.plugin_id,
                        "implementation_name": record.request.implementation_name,
                        "plugin_run_id": plugin_run_id,
                    }
                )
                current = unique.get(identity)
                if current is None or plugin_run_sort_key(
                    {
                        "lifecycle_status": available[plugin_run_id].result.status.value,
                        "plugin_run_id": plugin_run_id,
                    }
                ) > plugin_run_sort_key(
                    {
                        "lifecycle_status": available[current].result.status.value,
                        "plugin_run_id": current,
                    }
                ):
                    unique[identity] = plugin_run_id
            candidates = list(unique.values())
            if len(candidates) == 0:
                raise ValueError(
                    f"缺少提供 {capability} 的 compile_valid 插件；请在验证页一并勾选 producer"
                )
            if len(candidates) > 1:
                choices = "；".join(
                    _describe_plugin_record(available[item]) for item in candidates
                )
                raise ValueError(
                    f"{capability} 有多个候选 producer，请按列表短 ID 只勾选其中一个：{choices}"
                )
            closure.append(candidates[0])
            known.add(candidates[0])
            added = True
        if not added:
            raise ValueError(f"无法闭合 required_capabilities：{sorted(missing)}")


def _bind_harness_ref(request: PluginRequest, harness_ref: str) -> PluginRequest:
    if request.harness_ref == harness_ref:
        return request
    if request.harness_ref is None:
        return request.model_copy(update={"harness_ref": harness_ref})
    raise ValueError(
        f"{request.request_id} harness_ref 与 Canonical Harness 不一致："
        f"{request.harness_ref} != {harness_ref}"
    )


def _harness_ref_for_request(config: FactoryCliConfig, request: PluginRequest) -> str:
    if request.harness_ref is not None:
        return request.harness_ref
    if config.plugin_harness_config is None:
        raise ValueError(
            f"{request.request_id} 未绑定 harness_ref，且 factory-config 未配置 Canonical Harness"
        )
    return VmwarePluginHarnessConfig.load(config.plugin_harness_config).spec.harness_ref


def _validation_plan_for_records(
    records: Sequence[_PluginRunRecord],
    config: FactoryCliConfig,
) -> PluginDecompositionPlan | None:
    bound: list[PluginRequest] = []
    for record in records:
        bound.append(_request_with_resolved_ph(record, config))
    by_run = {record.plugin_run_id: request for record, request in zip(records, bound, strict=True)}
    dependencies: list[PluginDependency] = []
    for record, request in zip(records, bound, strict=True):
        for capability in request.intent.required_capabilities:
            producers = [
                item
                for item in records
                if item.plugin_run_id != record.plugin_run_id
                and capability in by_run[item.plugin_run_id].intent.provided_capabilities
            ]
            if len(producers) != 1:
                choices = "；".join(_describe_plugin_record(item) for item in producers)
                raise ValueError(
                    f"{request.implementation_name} 的 {capability} 需要恰好一个已勾选 producer，"
                    f"实际 {len(producers)} 个：{choices or '无'}"
                )
            dependencies.append(
                PluginDependency(
                    producer_request_id=by_run[producers[0].plugin_run_id].request_id,
                    consumer_request_id=request.request_id,
                    capability=capability,
                )
            )
    if not dependencies:
        missing_ph = [
            record.plugin_run_id
            for record, request in zip(records, bound, strict=True)
            if not request.intent.ph_ids
        ]
        if missing_ph:
            choices = "；".join(
                _describe_plugin_record(record)
                for record, request in zip(records, bound, strict=True)
                if not request.intent.ph_ids
            )
            raise ValueError(
                "无 PH 的支撑插件不能单独走 Plugin Harness："
                f"{choices}。请改勾选带 PH 的 TTP，并只保留一个对应 producer。"
            )
        return None
    connected: set[str] = set()
    for item in dependencies:
        connected.add(item.producer_request_id)
        connected.add(item.consumer_request_id)
    stray = [
        record.plugin_run_id
        for record, request in zip(records, bound, strict=True)
        if request.request_id not in connected
    ]
    if stray:
        names = "；".join(
            _describe_plugin_record(record)
            for record in records
            if record.request.request_id
            not in {item.producer_request_id for item in dependencies}
            | {item.consumer_request_id for item in dependencies}
        )
        raise ValueError(f"勾选包含无法并入同一依赖闭包的插件：{names or stray}")
    return PluginDecompositionPlan(
        plan_id=f"plugin-plan-{uuid4().hex[:16]}",
        summary="existing plugin harness validation",
        requests=tuple(bound),
        dependencies=tuple(dependencies),
    )


def _validate_independent_plugin_run(
    record: _PluginRunRecord,
    *,
    harness: PluginHarnessBackend,
    config: FactoryCliConfig,
    sink: Callable[[tuple[str, dict[str, object]]], None],
) -> PluginAuthoringResult:
    request = _request_with_resolved_ph(record, config)
    source = record.result.source
    build = record.result.build
    if source is None or build is None or source.atom_spec is None:
        raise ValueError(f"{record.plugin_run_id} 缺少 source/build/AtomSpec，不能声明 behavior_valid")
    if request.intent.required_capabilities:
        raise ValueError(
            f"{record.plugin_run_id} 声明了 required_capabilities，必须与 producer 一起走依赖闭包 Harness"
        )
    sink(
        (
            "sample_factory_plugin_validation_started",
            {
                "plugin_run_id": record.plugin_run_id,
                "request_id": request.request_id,
                "plugin_id": source.plugin_id,
            },
        )
    )
    validation = harness.validate(
        source,
        build,
        request,
        plugin_run_id=record.plugin_run_id,
    )
    if validation.harness_ref != request.harness_ref:
        raise ValueError("Harness 回执与 PluginRequest 不一致")
    if not validation.behavior_valid:
        raise ValueError("Canonical Harness 未证明插件行为有效")
    updated = _with_behavior_validation(record.result, validation)
    sink(
        (
            "sample_factory_plugin_validation_finished",
            {
                "plugin_run_id": record.plugin_run_id,
                "plugin_id": source.plugin_id,
                "behavior_valid": True,
                "dispatchable": False,
            },
        )
    )
    return updated


def _validate_plugin_run_closure(
    records: Sequence[_PluginRunRecord],
    plan: PluginDecompositionPlan,
    *,
    harness: PluginHarnessBackend,
    sink: Callable[[tuple[str, dict[str, object]]], None],
) -> tuple[PluginAuthoringResult, ...]:
    validate_links = getattr(harness, "validate_dependency_links", None)
    if not callable(validate_links):
        raise ContractGapError(
            ContractGap(
                capability="已有插件依赖闭包链接验证",
                missing="Plugin Harness validate_dependency_links(plan, results)",
                checked=(
                    "PluginDecompositionPlan.dependencies",
                    "FactoryCliConfig.plugin_harness_config",
                ),
                risk="有 required_capabilities 的 TTP 不能用单插件 Harness 猜测输入",
            )
        )
    by_request = {item.request.request_id: item.result for item in records}
    ordered_results = _topo_authoring_results(plan, by_request)
    for record in records:
        source = record.result.source
        sink(
            (
                "sample_factory_plugin_validation_started",
                {
                    "plugin_run_id": record.plugin_run_id,
                    "request_id": record.request.request_id,
                    "plugin_id": None if source is None else source.plugin_id,
                    "plan_id": plan.plan_id,
                },
            )
        )
    link_results = validate_links(plan, ordered_results)
    for item in link_results:
        sink(("sample_factory_plugin_dependency_link_valid", item.model_dump(mode="json")))
        if not item.behavior_valid:
            raise ValueError(f"联合 Harness 未证明 {item.consumer_request_id} 行为有效")
    validation_by_request = _validations_from_link_results(plan, records, link_results)
    updated: list[PluginAuthoringResult] = []
    for record in records:
        validation = validation_by_request[record.request.request_id]
        result = _with_behavior_validation(record.result, validation)
        source = result.source
        sink(
            (
                "sample_factory_plugin_validation_finished",
                {
                    "plugin_run_id": record.plugin_run_id,
                    "plugin_id": None if source is None else source.plugin_id,
                    "behavior_valid": True,
                    "dispatchable": False,
                },
            )
        )
        updated.append(result)
    return tuple(updated)


def _validations_from_link_results(
    plan: PluginDecompositionPlan,
    records: Sequence[_PluginRunRecord],
    link_results: Sequence[Any],
) -> dict[str, PluginValidationResult]:
    by_request = {item.request.request_id: item for item in records}
    harness_ref_by_request = {
        item.request_id: item.harness_ref
        for item in plan.requests
        if item.harness_ref is not None
    }
    mapping: dict[str, PluginValidationResult] = {}
    for item in link_results:
        consumer = by_request[item.consumer_request_id]
        harness_ref = harness_ref_by_request.get(item.consumer_request_id)
        if harness_ref is None:
            raise ValueError(f"{item.consumer_request_id} 联合验证缺少 harness_ref")
        if (
            consumer.result.source is None
            or consumer.result.source.atom_spec is None
            or consumer.result.build is None
        ):
            raise ValueError(
                f"{item.consumer_request_id} 缺少 source/build/AtomSpec，不能声明 behavior_valid"
            )
        validation = PluginValidationResult(
            harness_ref=harness_ref,
            contract_valid=True,
            atom_valid=True,
            behavior_valid=True,
            evidence_ref=item.evidence_ref,
            assertions=tuple(item.assertions),
        )
        mapping[item.consumer_request_id] = validation
        for producer_id in item.dependency_request_ids:
            mapping.setdefault(producer_id, validation)
    missing = [item.request.request_id for item in records if item.request.request_id not in mapping]
    if missing:
        raise ValueError(f"联合 Harness 未覆盖闭包节点：{missing}")
    return mapping


def _topo_authoring_results(
    plan: PluginDecompositionPlan,
    by_request: Mapping[str, PluginAuthoringResult],
) -> tuple[PluginAuthoringResult, ...]:
    incoming = {item.request_id: 0 for item in plan.requests}
    edges: dict[str, list[str]] = {item.request_id: [] for item in plan.requests}
    for dependency in plan.dependencies:
        edges[dependency.producer_request_id].append(dependency.consumer_request_id)
        incoming[dependency.consumer_request_id] += 1
    ready = [request_id for request_id, count in incoming.items() if count == 0]
    ordered: list[PluginAuthoringResult] = []
    while ready:
        request_id = ready.pop(0)
        ordered.append(by_request[request_id])
        for child in edges[request_id]:
            incoming[child] -= 1
            if incoming[child] == 0:
                ready.append(child)
    if len(ordered) != len(plan.requests):
        raise ValueError("验证闭包无法拓扑排序")
    return tuple(ordered)


def _with_behavior_validation(
    result: PluginAuthoringResult,
    validation: PluginValidationResult,
) -> PluginAuthoringResult:
    if result.source is None or result.source.atom_spec is None or result.build is None:
        raise ValueError(f"{result.plugin_run_id} 缺少 source/build/AtomSpec，不能声明 behavior_valid")
    if not validation.behavior_valid:
        raise ValueError("Canonical Harness 未证明插件行为有效")
    return result.model_copy(
        update={
            "status": PluginLifecycleStatus.BEHAVIOR_VALID,
            "validation": validation,
            "compile_only_reason": None,
        }
    )


def _plugin_authoring_preflight(config: FactoryCliConfig, request: PluginRequest) -> None:
    """Fail before creating a plugin run when operator-owned authoring contracts are absent."""
    missing: list[str] = []
    if not config.build_targets.is_file():
        missing.append(f"build target catalog: {config.build_targets.as_posix()}")
    if missing:
        raise ContractGapError(
            ContractGap(
                capability="单插件生成与受控编译",
                missing="；".join(missing),
                checked=(
                    config.build_targets.as_posix(),
                    "FactoryCliConfig.plugin_harness_backend_ref",
                ),
                risk="没有 operator 固化的构建目标，不能进行确定性编译；独立 Harness 可在后续验证阶段接入",
                options=(
                    "补齐 catalog/build-targets/build-targets.json",
                    "后续配置已审计 plugin Harness 后端以取得 behavior_valid",
                ),
                next_step=(
                    f"确保 build target 包含 {request.build_target_ref}；生成可先得到 compile_valid，"
                    "配置独立 Harness 后再执行 plugin-validate 取得 behavior_valid。"
                ),
            )
        )
    targets = JsonBuildTargetCatalog(config.build_targets).load()
    if request.build_target_ref not in targets:
        raise ContractGapError(
            ContractGap(
                capability="解析单插件 build target",
                missing=request.build_target_ref,
                checked=(config.build_targets.as_posix(),),
                risk="请求引用未登记目标会绕过 operator 固化工具链",
                next_step="在 build-targets.json 登记完全相同的 target_ref 后重试。",
            )
        )
    target = targets[request.build_target_ref]
    artifact_relative = target.artifact_relative.replace(
        "{implementation_name}", request.implementation_name
    )
    if Path(artifact_relative).suffix.lower() != ".lib":
        raise ContractGapError(
            ContractGap(
                capability="单插件源码编译为独立验证静态库",
                missing=f"{request.build_target_ref} 的 .lib artifact_relative",
                checked=(config.build_targets.as_posix(), request.build_target_ref),
                risk="插件准入若产出 EXE/DLL，会与 Glue 生成最终样本的职责混淆",
                next_step="将插件 build target 配置为 StaticLibrary 和 .lib 产物。",
            )
        )
    if config.plugin_harness_config is not None and request.harness_ref is not None:
        harness_config = VmwarePluginHarnessConfig.load(config.plugin_harness_config)
        if request.harness_ref != harness_config.spec.harness_ref:
            raise ContractGapError(
                ContractGap(
                    capability="解析 Plugin Harness 合同",
                    missing=request.harness_ref,
                    checked=(config.plugin_harness_config.as_posix(),),
                    risk="使用不同 Harness 合同会把观测绑定到错误的 TTP oracle",
                )
            )
        if request.profile_id not in harness_config.spec.profile_ids:
            raise ContractGapError(
                ContractGap(
                    capability="在目标 VM profile 验证插件",
                    missing=request.profile_id,
                    checked=(config.plugin_harness_config.as_posix(),),
                    risk="跨 profile 复用行为结论会制造不可复现的 behavior_valid",
                )
            )
        if request.intent.role is not harness_config.spec.role:
            raise ContractGapError(
                ContractGap(
                    capability="匹配 Plugin Harness 角色",
                    missing=f"{request.intent.role.value} != {harness_config.spec.role.value}",
                    checked=(config.plugin_harness_config.as_posix(),),
                    risk="角色错误会把 carrier/loader 误送到 execution_atom Harness",
                )
            )
        if harness_config.spec.ph_ids and request.intent.ph_ids:
            extra = [
                item
                for item in request.intent.ph_ids
                if item not in harness_config.spec.ph_ids
            ]
            if extra:
                raise ContractGapError(
                    ContractGap(
                        capability="匹配 Plugin Harness PH 允许集",
                        missing=f"{request.intent.ph_ids} extra={tuple(extra)}",
                        checked=(config.plugin_harness_config.as_posix(),),
                        risk="跨 TTP 复用未授权 Sysmon oracle 会制造虚假 behavior_valid",
                    )
                )
        if not harness_config.msbuild_path.is_file():
            raise ContractGapError(
                ContractGap(
                    capability="链接 Plugin Harness EXE",
                    missing=harness_config.msbuild_path.as_posix(),
                    checked=(config.plugin_harness_config.as_posix(),),
                    risk="StaticLibrary 构建不会解析全部外部符号，必须执行最终 EXE 链接",
                )
            )
        if config.verification_config is None:
            raise ContractGapError(
                ContractGap(
                    capability="Plugin Harness VMware 接线",
                    missing="FactoryCliConfig.verification_config",
                    checked=(config.plugin_harness_config.as_posix(),),
                    risk="没有既有 VM 快照后端，不能执行链接后的 Harness EXE",
                )
            )
        if harness_config.vmware_verification_config != config.verification_config:
            raise ContractGapError(
                ContractGap(
                    capability="Plugin Harness VMware 配置一致性",
                    missing="vmware_verification_config 与 verification_config 不一致",
                    checked=(
                        harness_config.vmware_verification_config.as_posix(),
                        config.verification_config.as_posix(),
                    ),
                    risk="Harness 可能在不同快照或 profile 上执行，证据无法归属",
                )
            )
        if not config.verification_config.is_file():
            raise ContractGapError(
                ContractGap(
                    capability="读取 Plugin Harness VMware 配置",
                    missing=config.verification_config.as_posix(),
                    checked=(config.verification_config.as_posix(),),
                    risk="无法确认 NAT、快照和 WinRM 参数",
                )
            )


def preflight(inputs: FactoryInputs) -> dict[str, object]:
    config, run = inputs.config, inputs.run
    batch = run.batch
    _validate_layout_roots(config)
    if run.run_kind is not RunKind.SAMPLE_PRODUCTION:
        raise ContractGapError(
            ContractGap(
                capability=f"执行 run_kind={run.run_kind.value}",
                missing="EL-3 PluginAuthoringPipeline / PluginValidationPipeline",
                checked=("FactoryRunSpec.run_kind", run.run_kind.value),
                risk="把插件成形伪装成样本组合生产会混淆验证和晋升状态",
            )
        )
    _require_external(config.plugin_root, "plugin_root")
    _require_external(config.object_store_root, "object_store_root")
    _require_external(config.runtime_root, "runtime_root")

    coverage = CoverageRegistry.from_markdown(config.coverage_matrix)
    coverage.attack_ids_for(run.context.candidate_ph_ids)
    catalog = DirectoryAtomCatalogLoader(config.plugin_root, coverage).load()
    contracts = JsonTelemetryContractSource(config.telemetry_contracts)
    dispatchable = catalog.dispatchable_specs()
    if not dispatchable:
        raise ContractGapError(
            ContractGap(
                capability="CLI 选择可生产的样本原子",
                missing="至少一个已审计、已钉扎且可调度的 AtomSpec",
                checked=(config.plugin_root.as_posix(), "AtomCatalog.dispatchable_specs"),
                risk="用 reserved/planned 原子继续生产会绕过供应链与状态门禁",
            )
        )
    missing_sources = [
        spec.atom_id
        for spec in dispatchable
        if spec.atom_id not in catalog.source_roots and spec.materialize.value != "embed_at_build"
    ]
    if missing_sources:
        raise ContractGapError(
            ContractGap(
                capability="glue agent 读取已登记插件源码",
                missing=f"源码根目录映射：{missing_sources}",
                checked=(config.plugin_root.as_posix(), "plugin.json source manifest"),
                risk="从未登记路径猜测源码会破坏供应链钉扎",
            )
        )
    missing_capabilities = [spec.atom_id for spec in dispatchable if not spec.provided_capabilities]
    if missing_capabilities:
        raise ContractGapError(
            ContractGap(
                capability="CapabilityGraph 和成功经验提取",
                missing=f"provided_capabilities：{missing_capabilities}",
                checked=(config.plugin_root.as_posix(), "AtomSpec.provided_capabilities"),
                risk="缺少能力合同会迫使 Planner 从名称或 ATT&CK ID 猜测插件连接关系",
            )
        )
    for spec in dispatchable:
        contract_ref = spec.telemetry_contract_ref
        if contract_ref is not None:
            contracts.get(contract_ref)
    missing_payloads: list[str] = []
    for spec in dispatchable:
        if spec.materialize is not HandoffMaterialize.EMBED_AT_BUILD:
            continue
        if spec.artifact_ref is None:
            missing_payloads.append(f"{spec.atom_id} 缺 artifact_ref")
            continue
        try:
            resolve_payload_bytes(
                spec.artifact_ref, payload_root=config.payload_search_roots
            )
        except HandoffError as exc:
            missing_payloads.append(str(exc))
    if missing_payloads:
        raise ContractGapError(
            ContractGap(
                capability="embed_at_build 物化 operator-owned payload",
                missing="；".join(missing_payloads),
                checked=tuple(path.as_posix() for path in config.payload_search_roots),
                risk="规划成功后再找 payload 会把目录错误伪装成 RUNTIME_CRASH",
            )
        )

    targets = JsonBuildTargetCatalog(config.build_targets).load()
    if run.build_target_ref not in targets:
        raise ContractGapError(
            ContractGap(
                capability=f"编译 {run.build_target_ref}",
                missing="匹配的 operator-owned build target",
                checked=(config.build_targets.as_posix(), run.build_target_ref),
                risk="让模型或 CLI 临时拼编译命令会绕过固定工具链门禁",
            )
        )
    _preflight_completion(config, run)
    effective_strategy, experience_result = _preflight_experience(config, run)
    _require_backend(config.state_backend_ref, "生产共享 combo_state", _STATE_METHODS)
    if config.verification_config is not None:
        _vmware_verifier_preflight(config, run)
    else:
        _require_backend(config.verification_backend_ref, "隔离沙箱遥测采集", ("collect",))
    if config.compiler_backend_ref is not None:
        _require_backend(config.compiler_backend_ref, "外部受控编译", ("compile",))
        _require_backend(config.artifact_publisher_ref, "外部样本工件发布", ("publish",))
    elif config.artifact_publisher_ref is not None:
        _require_backend(config.artifact_publisher_ref, "外部样本工件发布", ("publish",))

    if not run.context.profile.sensors_ready:
        raise ContractGapError(
            ContractGap(
                capability="流水线 A V2/V3 功能真值验证",
                missing="profile.sensors_ready=true 的已就绪传感器环境",
                checked=(run.context.profile.profile_id, config.telemetry_contracts.as_posix()),
                risk="传感器未就绪时判 SUCCESS 会制造虚假遥测真值",
            )
        )
    return {
        "ready": True,
        "profile_id": run.context.profile.profile_id,
        "run_kind": run.run_kind.value,
        "planning_strategy": run.planning_strategy.value,
        "effective_planning_strategy": effective_strategy.value,
        "experience_set_version": (
            None if experience_result is None else experience_result.experience_set_version
        ),
        "experience_candidate_count": (
            0 if experience_result is None else len(experience_result.candidates)
        ),
        "candidate_ph_ids": list(run.context.candidate_ph_ids),
        "dispatchable_atoms": len(dispatchable),
        "build_target_ref": run.build_target_ref,
        "workspace_ref": run.workspace_ref,
        "state_backend_ref": config.state_backend_ref,
        "verification_backend_ref": config.verification_backend_ref,
        "verification_config": (
            None if config.verification_config is None else config.verification_config.as_posix()
        ),
        "execution_logging": run.execution_logging,
        "planning_audit_root": "run-scoped://attempt/planning",
        "runtime_root": config.runtime_root.as_posix(),
        "batch": {
            "sample_count": 1 if batch is None else batch.sample_count,
            "max_attempts": 1 if batch is None else batch.effective_max_attempts,
            "continue_on_failure": (False if batch is None else batch.continue_on_failure),
        },
    }


def execute_production(
    inputs: FactoryInputs,
    *,
    approved: bool,
    high_risk_approved: bool,
    execution_logging: bool | None = None,
    sink: Callable[[tuple[str, dict[str, object]]], None] | None = None,
    stop_token: ProductionStopToken | None = None,
) -> ProductionResult | ProductionBatchResult:
    if not approved:
        raise FactoryDenied("CLI 样本生产必须显式提供人工审批")
    preflight(inputs)
    config, run = inputs.config, inputs.run
    now = utc_now()
    run_id = new_run_id()
    attempt_id = None if run.batch is not None else new_attempt_id()
    config_fingerprint = hashlib.sha256(
        canonical_json(config.model_dump(mode="json")).encode("utf-8")
    ).hexdigest()
    repository = RunRepository(config.runtime_root)
    handle = repository.create(
        RunEnvelope(
            run_id=run_id,
            run_kind=run.run_kind,
            planning_strategy=run.planning_strategy,
            worker_id=run.worker_id,
            created_at=now,
            config_fingerprint=config_fingerprint,
            request_snapshot=run.model_dump(mode="json"),
        )
    )
    repository.mark_running(handle)
    single_attempt = None
    if attempt_id is not None:
        single_attempt = repository.start_attempt(
            handle,
            attempt_id=attempt_id,
            attempt_number=1,
            seed=run.context.seed,
            workspace_ref=run.workspace_ref,
        )
    recording_sink = RecordingEventSink(
        repository,
        handle,
        sink,
        initial_attempt_id=attempt_id,
    )

    def attempt_handle_for(resolved_attempt_id: str) -> AttemptHandle:
        if single_attempt is not None and single_attempt.record.attempt_id == resolved_attempt_id:
            return single_attempt
        return repository.find_attempt(handle, resolved_attempt_id)

    def resolve_attempt_workspace(workspace_ref: str) -> Path:
        del workspace_ref
        current_attempt_id = attempt_id or recording_sink.current_attempt_id
        if current_attempt_id is None:
            raise ValueError("解析工作区时缺少 attempt_id")
        return attempt_handle_for(current_attempt_id).root / "workspace"

    def resolve_attempt_build_root(request: BuildRequest) -> Path:
        if request.attempt_id is None:
            raise ValueError("解析构建目录时缺少 attempt_id")
        return attempt_handle_for(request.attempt_id).root / "build"

    def resolve_diagnostics(build_id: str) -> Path:
        current_attempt_id = attempt_id or recording_sink.current_attempt_id
        if current_attempt_id is None:
            raise ValueError("解析编译诊断时缺少 attempt_id")
        return attempt_handle_for(current_attempt_id).root / "build" / build_id / "diagnostics.txt"

    snapshots = SourceSnapshotRepository(cas=ContentAddressedStore(config.runtime_root))
    experience_extractor = ExperienceExtractor(config.runtime_root / "learning" / "proposals")

    def resolve_planning_root(resolved_run_id: str, resolved_attempt_id: str) -> Path:
        if resolved_run_id != run_id:
            raise ValueError("planning audit run_id 与当前运行包不一致")
        return attempt_handle_for(resolved_attempt_id).root / "planning"

    planning_audits = PlanningAuditRepository(root_resolver=resolve_planning_root)

    def persist_source_snapshot(
        source_root: Path,
        source_digest: str,
        compile_attempt: int,
        final_build_input: bool,
    ) -> str:
        current_attempt_id = attempt_id or recording_sink.current_attempt_id
        if current_attempt_id is None:
            raise ValueError("保存源码快照时缺少 attempt_id")
        attempt_handle = attempt_handle_for(current_attempt_id)
        snapshot = snapshots.capture(
            source_root,
            attempt_handle.root / "source",
            expected_digest=source_digest,
            compile_attempt=compile_attempt,
            final_build_input=final_build_input,
        )
        snapshot_ref = f"run-source://{run_id}/{current_attempt_id}/" + (
            "final-build-input" if final_build_input else f"compile-{compile_attempt:02d}"
        )
        recording_sink(
            (
                "sample_factory_source_snapshot_saved",
                {
                    "compile_attempt": compile_attempt,
                    "final_build_input": final_build_input,
                    "source_digest": source_digest,
                    "snapshot_ref": snapshot_ref,
                    "snapshot_path": snapshot.snapshot_root.relative_to(handle.root).as_posix(),
                },
            )
        )
        return snapshot_ref

    try:
        result = _execute_sample_production(
            inputs,
            high_risk_approved=high_risk_approved,
            execution_logging=execution_logging,
            sink=recording_sink,
            stop_token=stop_token,
            run_id=run_id,
            attempt_id=attempt_id,
            source_snapshot_sink=persist_source_snapshot,
            planning_audits=planning_audits,
            workspace_root=handle.root,
            workspace_resolver=resolve_attempt_workspace,
            build_root=handle.root,
            build_root_resolver=resolve_attempt_build_root,
            diagnostics_resolver=resolve_diagnostics,
            experience_extractor=experience_extractor,
        )
        payload = result_payload(result)
        if isinstance(result, ProductionBatchResult):
            for batch_attempt in result.attempts:
                if batch_attempt.attempt_id is None:
                    continue
                attempt_handle = repository.find_attempt(handle, batch_attempt.attempt_id)
                repository.write_attempt_result(
                    attempt_handle,
                    _batch_attempt_payload(batch_attempt),
                )
        elif single_attempt is not None:
            repository.write_attempt_result(single_attempt, payload)
            _complete_single_attempt(repository, handle, single_attempt, result)

        run_status, error_type = _run_status_for_result(result)
        repository.finish(
            handle,
            status=run_status,
            result_status=str(payload.get("status", "INCOMPLETE")),
            error_type=error_type,
            error=None if error_type is None else str(payload.get("failure_taxonomy") or ""),
        )
        return result
    except BaseException as exc:
        recording_sink.fail_current(exc)
        if single_attempt is not None:
            repository.complete_attempt(
                handle,
                single_attempt,
                status=(
                    AttemptStatus.STOPPED
                    if type(exc).__name__ in {"ProductionStopped", "KeyboardInterrupt"}
                    else AttemptStatus.FAILED
                ),
                error_type=type(exc).__name__,
                error=str(exc),
            )
        repository.finish(
            handle,
            status=(
                RunStatus.STOPPED
                if type(exc).__name__ in {"ProductionStopped", "KeyboardInterrupt"}
                else RunStatus.FAILED
            ),
            error_type=type(exc).__name__,
            error=str(exc),
        )
        raise


def _execute_sample_production(
    inputs: FactoryInputs,
    *,
    high_risk_approved: bool,
    execution_logging: bool | None,
    sink: Callable[[tuple[str, dict[str, object]]], None] | None,
    stop_token: ProductionStopToken | None,
    run_id: str | None,
    attempt_id: str | None,
    source_snapshot_sink: Callable[[Path, str, int, bool], str] | None,
    planning_audits: PlanningAuditRepository,
    workspace_root: Path,
    workspace_resolver: Callable[[str], Path],
    build_root: Path,
    build_root_resolver: Callable[[BuildRequest], Path],
    diagnostics_resolver: Callable[[str], Path],
    experience_extractor: ExperienceExtractor,
) -> ProductionResult | ProductionBatchResult:
    config, run = inputs.config, inputs.run
    coverage = CoverageRegistry.from_markdown(config.coverage_matrix)
    catalog = DirectoryAtomCatalogLoader(config.plugin_root, coverage).load()
    contracts = JsonTelemetryContractSource(config.telemetry_contracts)
    targets = JsonBuildTargetCatalog(config.build_targets).load()

    completion = _completion_client(config, run)
    workspace = LocalPluginWorkspace(
        catalog.source_roots,
        workspace_root=workspace_root,
        diagnostics_root=build_root,
        payload_root=config.payload_search_roots,
        root_resolver=workspace_resolver,
        diagnostics_resolver=diagnostics_resolver,
    )
    planner = FactoryPlanningAgent(
        completion,
        catalog,
        retry_limit=config.planner_retry_limit,
        max_tokens=config.planner_max_tokens,
        sink=sink,
        planning_strategy=run.planning_strategy,
        experience_retriever=_experience_retriever(config),
    )
    glue_client = _with_max_tokens(completion, config.glue_max_tokens)
    glue = GlueCoordinator(
        DeepSeekGlueAgent(
            glue_client,
            workspace,
            retry_limit=config.glue_retry_limit,
            max_turns=config.glue_agent_max_turns,
            sink=sink,
        )
    )

    def persist_glue_snapshot(
        resolution: GlueResolution, compile_attempt: int, final_build_input: bool
    ) -> str | None:
        if source_snapshot_sink is None:
            return None
        return source_snapshot_sink(
            workspace.resolve(resolution.source_ref),
            resolution.source_digest,
            compile_attempt,
            final_build_input,
        )

    def extract_experience(result: ProductionResult, specs: tuple[AtomSpec, ...]) -> str | None:
        if any(not spec.provided_capabilities for spec in specs):
            return None
        proposal = experience_extractor.extract_success(
            result,
            specs,
            capabilities_by_atom={spec.atom_id: spec.provided_capabilities for spec in specs},
            architecture=run.context.architecture,
        )
        return None if proposal is None else proposal.as_posix()

    if config.compiler_backend_ref is None:
        compiler: CompilerBackend = GuardedCompilerBackend(
            targets=targets,
            sources=workspace,
            artifact_root=build_root,
            memory_limit_mb=config.compiler_memory_limit_mb,
            artifact_root_resolver=build_root_resolver,
        )
    else:
        compiler = cast(
            CompilerBackend,
            _backend_instance(config.compiler_backend_ref, "编译后端", ("compile",)),
        )

    if config.artifact_publisher_ref is not None:
        publisher = cast(
            ArtifactPublisher,
            _backend_instance(config.artifact_publisher_ref, "工件发布后端", ("publish",)),
        )
    else:
        publisher = FilesystemArtifactPublisher(config.runtime_root, cast(Any, compiler))

    verifier: VerificationBackend
    if config.verification_config is not None:
        if config.secrets_env is None:
            raise ValueError("内置 VMware 验证需要 secrets_env")
        resolver = getattr(compiler, "resolve_artifact", None)
        if not callable(resolver):
            raise ContractGapError(
                ContractGap(
                    capability="向 VMware 验证 VM 投递本轮构建产物",
                    missing="CompilerBackend.resolve_artifact(artifact_ref)",
                    checked=("CompilerBackend", config.verification_config.as_posix()),
                    risk="从 build_id 猜测文件路径可能把上一轮或错误产物送入验证",
                )
            )
        verifier = VmwareVerificationBackend.from_config(
            config.verification_config,
            secrets_env_path=config.secrets_env,
            artifact_resolver=cast(ArtifactResolver, compiler),
            telemetry_contracts_path=config.telemetry_contracts,
        )
        if verifier.runtime_root != config.runtime_root:
            raise ValueError("VMware runtime_root 必须与 factory-config-v2 一致")
    else:
        verifier = cast(
            VerificationBackend,
            _backend_instance(config.verification_backend_ref, "验证后端", ("collect",)),
        )
    state = cast(
        ComboStateStore,
        _backend_instance(config.state_backend_ref, "状态后端", _STATE_METHODS),
    )
    initialize = getattr(state, "initialize", None)
    if callable(initialize):
        initialize()

    factory = AIDrivenSampleFactory(
        planner=planner,
        catalog=catalog,
        glue=glue,
        compiler=compiler,
        verifier=verifier,
        truth_evaluator=FunctionalTruthEvaluator(),
        contracts=contracts,
        expected_detection=MatrixExpectedDetectionSource(coverage),
        publisher=publisher,
        state=state,
        manifests=ManifestRepository(config.manifest_path),
        planning_audits=planning_audits,
        sink=sink,
        max_compile_attempts=config.max_compile_attempts,
    )
    request = ProductionRequest(
        context=run.context,
        worker_id=run.worker_id,
        approved=True,
        high_risk_approved=high_risk_approved,
        workspace_ref=run.workspace_ref,
        build_target_ref=run.build_target_ref,
        regression_set_version=run.regression_set_version,
        runtime_param_snapshot_ref=run.runtime_param_snapshot_ref,
        parent_id=run.parent_id,
        lease_ttl=timedelta(seconds=run.lease_ttl_seconds),
        compile_attempt_limit=run.compile_attempt_limit,
        execution_logging=(
            run.execution_logging if execution_logging is None else execution_logging
        ),
        stop_token=stop_token,
        run_id=run_id,
        attempt_id=attempt_id,
        source_snapshot_sink=(None if source_snapshot_sink is None else persist_glue_snapshot),
        experience_sink=extract_experience,
    )
    batch = run.batch
    if batch is not None:
        return factory.produce_batch(
            request,
            BatchOptions(
                sample_count=batch.sample_count,
                max_attempts=batch.effective_max_attempts,
                continue_on_failure=batch.continue_on_failure,
            ),
        )
    return factory.produce(request)


def result_payload(
    result: ProductionResult | ProductionBatchResult,
) -> dict[str, object]:
    if isinstance(result, ProductionBatchResult):
        return _batch_result_payload(result)
    return _single_result_payload(result)


def _single_result_payload(result: ProductionResult) -> dict[str, object]:
    recipe = None if result.plan is None else result.plan.recipe
    record = result.record
    return {
        "run_id": result.run_id,
        "attempt_id": result.attempt_id,
        "source_snapshot_ref": result.source_snapshot_ref,
        "build_id": result.build_id,
        "artifact_sha256": result.artifact_sha256,
        "source_digest": result.source_digest,
        "toolchain_fp": result.toolchain_fp,
        "verification_run_id": result.verification_run_id,
        "verification_ref": result.verification_ref,
        "experience_proposal_ref": result.experience_proposal_ref,
        "produced": result.produced,
        "record_id": None if record is None else record.record_id,
        "status": None if record is None else record.status.value,
        "failure_taxonomy": (
            None
            if record is None or record.failure_taxonomy is None
            else record.failure_taxonomy.value
        ),
        "claim_disposition": (None if result.claim is None else result.claim.disposition.value),
        "recipe_id": None if recipe is None else recipe.recipe_id,
        "ph_ids": [] if recipe is None else list(recipe.ph_ids),
        "atom_ids": [] if recipe is None else list(recipe.atom_ids),
        "artifact_ref": result.artifact_ref,
        "manifest_ref": None if record is None else record.git_manifest_ref,
        "functional_truth": None if result.truth is None else result.truth.telemetry_summary(),
        "execution_logging": False if recipe is None else recipe.execution_logging,
        "planning_audit_ref": None if result.plan is None else result.plan.audit_ref,
        "planning_strategy": (None if result.plan is None else result.plan.planning_strategy.value),
        "experience_refs": [] if result.plan is None else list(result.plan.experience_refs),
        "experience_set_version": (
            None if result.plan is None else result.plan.experience_set_version
        ),
        "learning_snapshot_ref": (
            None if result.plan is None else result.plan.learning_snapshot_ref
        ),
    }


def _batch_result_payload(result: ProductionBatchResult) -> dict[str, object]:
    completed_results = [
        attempt.result for attempt in result.attempts if attempt.result is not None
    ]
    last = completed_results[-1] if completed_results else None
    last_payload = _single_result_payload(last) if last is not None else {}
    artifact_refs = [
        attempt.result.artifact_ref
        for attempt in result.attempts
        if attempt.result is not None and attempt.result.artifact_ref is not None
    ]
    audit_refs = [
        attempt.result.plan.audit_ref
        for attempt in result.attempts
        if attempt.result is not None
        and attempt.result.plan is not None
        and attempt.result.plan.audit_ref is not None
    ]
    if result.produced:
        status = "SUCCESS"
    elif result.stopped:
        status = "STOPPED"
    elif result.produced_count:
        status = "PARTIAL"
    elif result.exhausted:
        status = "EXHAUSTED"
    else:
        status = "INCOMPLETE"
    return {
        "batch": True,
        "run_id": result.run_id,
        "batch_id": result.batch_id,
        "produced": result.produced,
        "status": status,
        "requested_count": result.requested_count,
        "produced_count": result.produced_count,
        "attempt_count": len(result.attempts),
        "max_attempts": result.max_attempts,
        "exhausted": result.exhausted,
        "stopped": result.stopped,
        "artifact_ref": artifact_refs[-1] if artifact_refs else None,
        "artifact_refs": artifact_refs,
        "planning_audit_ref": audit_refs[-1] if audit_refs else None,
        "planning_audit_refs": audit_refs,
        "failure_taxonomy": last_payload.get("failure_taxonomy"),
        "recipe_id": last_payload.get("recipe_id"),
        "ph_ids": last_payload.get("ph_ids", []),
        "atom_ids": last_payload.get("atom_ids", []),
        "functional_truth": last_payload.get("functional_truth"),
        "attempts": [_batch_attempt_payload(attempt) for attempt in result.attempts],
    }


def _batch_attempt_payload(attempt: BatchAttemptResult) -> dict[str, object]:
    return {
        "attempt": attempt.attempt_number,
        "attempt_id": attempt.attempt_id,
        "seed": attempt.seed,
        "workspace_ref": attempt.workspace_ref,
        "newly_produced": attempt.newly_produced,
        "error_type": attempt.error_type,
        "error": attempt.error,
        "status": (
            None
            if attempt.result is None or attempt.result.record is None
            else attempt.result.record.status.value
        ),
        "recipe_id": (
            None
            if attempt.result is None or attempt.result.plan is None
            else attempt.result.plan.recipe.recipe_id
        ),
        "plan_fingerprint": (
            None
            if attempt.result is None or attempt.result.plan is None
            else attempt.result.plan.plan_fingerprint
        ),
        "combination_fingerprint": (
            None
            if attempt.result is None or attempt.result.plan is None
            else attempt.result.plan.combination_fingerprint
        ),
        "planning_audit_ref": (
            None
            if attempt.result is None or attempt.result.plan is None
            else attempt.result.plan.audit_ref
        ),
        "artifact_ref": None if attempt.result is None else attempt.result.artifact_ref,
        "source_snapshot_ref": (
            None if attempt.result is None else attempt.result.source_snapshot_ref
        ),
        "build_id": None if attempt.result is None else attempt.result.build_id,
        "artifact_sha256": (None if attempt.result is None else attempt.result.artifact_sha256),
        "source_digest": None if attempt.result is None else attempt.result.source_digest,
        "verification_run_id": (
            None if attempt.result is None else attempt.result.verification_run_id
        ),
        "verification_ref": (None if attempt.result is None else attempt.result.verification_ref),
        "experience_proposal_ref": (
            None if attempt.result is None else attempt.result.experience_proposal_ref
        ),
    }


def _complete_single_attempt(
    repository: RunRepository,
    handle: RunHandle,
    attempt: AttemptHandle,
    result: ProductionResult,
) -> None:
    record = result.record
    result_status = None if record is None else record.status.value
    taxonomy = None if record is None else record.failure_taxonomy
    repository.complete_attempt(
        handle,
        attempt,
        status=(AttemptStatus.SUCCEEDED if result.produced else AttemptStatus.FAILED),
        result_status=result_status,
        error_type=None if result.produced else "ProductionFailed",
        error=None if taxonomy is None else taxonomy.value,
    )


def _run_status_for_result(
    result: ProductionResult | ProductionBatchResult,
) -> tuple[RunStatus, str | None]:
    if isinstance(result, ProductionBatchResult):
        if result.produced:
            return RunStatus.SUCCEEDED, None
        if result.stopped:
            return RunStatus.STOPPED, None
        if result.produced_count:
            return RunStatus.PARTIAL, None
        return RunStatus.FAILED, "ProductionFailed"
    if result.produced:
        return RunStatus.SUCCEEDED, None
    return RunStatus.FAILED, "ProductionFailed"


def schema_payload() -> dict[str, object]:
    return {
        "config": FactoryCliConfig.model_json_schema(),
        "run": FactoryRunSpec.model_json_schema(),
        "backend_contracts": {
            "completion_backend_ref": ["complete_tool_with_metadata(messages, tools, tool_choice=...)"],
            "state_backend_ref": [f"{name}(...)" for name in _STATE_METHODS],
            "verification_backend_ref": ["collect(artifact, recipe, context)"],
            "verification_config": [
                "built-in VMware Workstation snapshot + WinRM HTTPS backend",
                "mutually exclusive with verification_backend_ref",
            ],
            "compiler_backend_ref": [
                "compile(request)",
                "must enforce request.recipe.execution_logging source inclusion/exclusion",
            ],
            "artifact_publisher_ref": ["publish(artifact)"],
            "plugin_authoring_backend_ref": ["author(request, plugin_run_id=...)"],
            "plugin_compiler_backend_ref": [
                "compile(source, request, plugin_run_id=...)",
                "resolve_artifact(artifact_ref) required for review promotion",
                "must emit validation-only <implementation_name>.lib",
            ],
            "plugin_harness_backend_ref": [
                "validate(source, build, request, plugin_run_id=...)",
                "must use independent system telemetry (sysmon/cape); EDR/Sigma hits are not required",
            ],
            "plugin_harness_config": [
                "built-in VMware static-library link + snapshot + Sysmon Harness",
                "dependency plans use validate_dependency_links(plan, results) with minimal closure",
                "mutually exclusive with plugin_harness_backend_ref",
            ],
            "embedding_backend_ref": ["model_fingerprint", "embed(text)"],
            "factory_reference": "module:attribute; attribute may be an instance or zero-argument factory",
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="edreval-sample-factory")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("schema", help="输出 CLI 配置与运行请求 JSON Schema")
    init_layout = commands.add_parser("init-layout", help="初始化外部工厂 v2 目录骨架")
    init_layout.add_argument("--root", required=True, type=Path)
    run_list = commands.add_parser("run-list", help="列出 v2 运行包")
    run_list.add_argument("--config", required=True, type=Path)
    run_show = commands.add_parser("run-show", help="查看一个 v2 运行包")
    run_show.add_argument("--config", required=True, type=Path)
    run_show.add_argument("--run-id", required=True)
    run_index = commands.add_parser("run-index-rebuild", help="从运行包重建 SQLite 查询索引")
    run_index.add_argument("--config", required=True, type=Path)
    artifact_verify = commands.add_parser("artifact-verify", help="校验一个 CAS artifact")
    artifact_verify.add_argument("--config", required=True, type=Path)
    artifact_verify.add_argument("--artifact-ref", required=True)
    artifact_export = commands.add_parser("artifact-export", help="审批后导出一个 CAS artifact")
    artifact_export.add_argument("--config", required=True, type=Path)
    artifact_export.add_argument("--artifact-ref", required=True)
    artifact_export.add_argument("--export-id", required=True)
    artifact_export.add_argument("--filename", required=True)
    artifact_export.add_argument("--approve", action="store_true")
    sample_list = commands.add_parser("sample-list", help="列出已生产 SUCCESS 样本及其发布状态")
    sample_list.add_argument("--config", required=True, type=Path)
    sample_transfer = commands.add_parser(
        "sample-transfer", help="审批后将 SUCCESS 样本转到 runtime/exports/published"
    )
    sample_transfer.add_argument("--config", required=True, type=Path)
    sample_transfer.add_argument(
        "--sample-id",
        action="append",
        required=True,
        dest="sample_ids",
    )
    sample_transfer.add_argument("--approve", action="store_true")
    sample_board = commands.add_parser(
        "sample-board-export",
        help="导出已发布样本 ATT&CK HTML 看板（AEL 热力图/Gap/攻击链/靶场/适合覆盖 + 明细表 + 插件状态）",
    )
    sample_board.add_argument("--config", required=True, type=Path)
    sample_board.add_argument(
        "--open",
        action="store_true",
        dest="open_browser",
        help="导出后用系统浏览器打开",
    )
    source_restore = commands.add_parser("source-restore", help="审批后从 source CAS 恢复构建输入")
    source_restore.add_argument("--config", required=True, type=Path)
    source_restore.add_argument("--manifest", required=True, type=Path)
    source_restore.add_argument("--destination", required=True, type=Path)
    source_restore.add_argument("--approve", action="store_true")
    bundle_export = commands.add_parser("bundle-export", help="审批后原子导出多阶段 Bundle")
    bundle_export.add_argument("--config", required=True, type=Path)
    bundle_export.add_argument("--bundle", required=True, type=Path)
    bundle_export.add_argument("--export-id", required=True)
    bundle_export.add_argument("--approve", action="store_true")
    experience_list = commands.add_parser("experience-list", help="列出持久化经验版本")
    experience_list.add_argument("--config", required=True, type=Path)
    experience_import = commands.add_parser("experience-import", help="审批后导入经验版本")
    experience_import.add_argument("--config", required=True, type=Path)
    experience_import.add_argument("--record", required=True, type=Path)
    experience_import.add_argument("--approve", action="store_true")
    experience_search = commands.add_parser("experience-search", help="执行结构化经验检索")
    experience_search.add_argument("--config", required=True, type=Path)
    experience_search.add_argument("--query", required=True, type=Path)
    experience_promote = commands.add_parser("experience-promote", help="审批后推进经验成熟度")
    experience_promote.add_argument("--config", required=True, type=Path)
    experience_promote.add_argument("--experience-id", required=True)
    experience_promote.add_argument(
        "--maturity", required=True, choices=[item.value for item in KnowledgeMaturity]
    )
    experience_promote.add_argument("--approve", action="store_true")
    experience_index = commands.add_parser("experience-index-build", help="审批后重建经验向量索引")
    experience_index.add_argument("--config", required=True, type=Path)
    experience_index.add_argument("--approve", action="store_true")
    reconcile = commands.add_parser("run-reconcile", help="只读检查运行包一致性")
    reconcile.add_argument("--config", required=True, type=Path)
    storage_report = commands.add_parser("storage-report", help="统计 CAS 对象数量和容量")
    storage_report.add_argument("--config", required=True, type=Path)
    gc_plan = commands.add_parser("gc-plan", help="生成引用感知的 CAS GC 计划")
    gc_plan.add_argument("--config", required=True, type=Path)
    gc_plan.add_argument("--grace-days", type=int, default=30)
    gc_apply = commands.add_parser("gc-apply", help="审批后执行引用感知 CAS GC")
    gc_apply.add_argument("--config", required=True, type=Path)
    gc_apply.add_argument("--grace-days", type=int, default=30)
    gc_apply.add_argument("--approve", action="store_true")
    metadata_backup = commands.add_parser("metadata-backup", help="审批后创建工厂元数据备份")
    metadata_backup.add_argument("--config", required=True, type=Path)
    metadata_backup.add_argument("--destination", required=True, type=Path)
    metadata_backup.add_argument("--approve", action="store_true")
    metadata_restore = commands.add_parser("metadata-restore", help="审批后恢复元数据到空目录")
    metadata_restore.add_argument("--backup", required=True, type=Path)
    metadata_restore.add_argument("--destination", required=True, type=Path)
    metadata_restore.add_argument("--approve", action="store_true")
    plugin_author = commands.add_parser("plugin-author", help="生成并独立验证一个候选插件")
    plugin_author.add_argument("--config", required=True, type=Path)
    plugin_author.add_argument("--request", required=True, type=Path)
    plugin_author.add_argument("--approve", action="store_true")
    for command_name, help_text in (
        ("plugin-validate", "编译并验证已有候选插件"),
        ("plugin-regression", "回归验证一个钉扎插件候选"),
    ):
        plugin_validation = commands.add_parser(command_name, help=help_text)
        plugin_validation.add_argument("--config", required=True, type=Path)
        plugin_validation.add_argument("--request", required=True, type=Path)
        plugin_validation.add_argument("--candidate", required=True, type=Path)
        plugin_validation.add_argument("--approve", action="store_true")
    plugin_list = commands.add_parser("plugin-list", help="列出插件运行和 catalog 状态")
    plugin_list.add_argument("--config", required=True, type=Path)
    plugin_cleanup = commands.add_parser(
        "plugin-cleanup",
        help="预览或审批后清理失败/重复的 plugin-run 包（不加 --approve 只输出计划）",
    )
    plugin_cleanup.add_argument("--config", required=True, type=Path)
    plugin_cleanup.add_argument(
        "--approve",
        action="store_true",
        help="删除计划中的失败终态与已被更新 behavior_valid 取代的旧包",
    )
    plugin_show = commands.add_parser("plugin-show", help="查看一个插件运行包")
    plugin_show.add_argument("--config", required=True, type=Path)
    plugin_show.add_argument("--plugin-run-id", required=True)
    plugin_review = commands.add_parser(
        "plugin-review", help="审批 behavior-valid 插件进入 reviewed"
    )
    plugin_review.add_argument("--config", required=True, type=Path)
    plugin_review.add_argument("--plugin-run-id", required=True)
    plugin_review.add_argument("--provenance", required=True, type=Path)
    plugin_review.add_argument("--approve", action="store_true")
    plugin_promote = commands.add_parser(
        "plugin-promote", help="独立审批 reviewed 插件进入 dispatchable"
    )
    plugin_promote.add_argument("--config", required=True, type=Path)
    plugin_promote.add_argument("--plugin-id", required=True)
    plugin_promote.add_argument("--approve", action="store_true")
    demand_submit = commands.add_parser("demand-submit", help="审批后提交在线 Planner 动态样本工单")
    demand_submit.add_argument("--config", required=True, type=Path)
    demand_submit.add_argument("--demand", required=True, type=Path)
    demand_submit.add_argument("--approve", action="store_true")
    demand_list = commands.add_parser("demand-list", help="列出动态样本工单")
    demand_list.add_argument("--config", required=True, type=Path)
    for name, help_text in (
        ("preflight", "校验权威来源、路径、模型和部署后端"),
        ("produce", "启动一次经人工审批的样本生产"),
        ("tui", "打开样本工厂 TUI（插件生成 / 插件验证 / 样本生产 / 样本发布 / 技术看板）"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--config", required=True, type=Path)
        command.add_argument("--run", required=True, type=Path)
        if name == "produce":
            command.add_argument("--approve", action="store_true")
            command.add_argument("--approve-high-risk", action="store_true")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "schema":
            _write_json(schema_payload(), stdout)
            return 0
        if args.command == "init-layout":
            _write_json(initialize_factory_layout(args.root), stdout)
            return 0
        if args.command == "metadata-restore":
            if not args.approve:
                raise FactoryDenied("元数据恢复需要本轮 --approve")
            _write_json(
                MetadataBackupService.restore(args.backup, args.destination, approved=True),
                stdout,
            )
            return 0
        if args.command == "metadata-backup":
            if not args.approve:
                raise FactoryDenied("元数据备份需要本轮 --approve")
            config_file = Path(args.config).resolve()
            config = _resolve_config_paths(
                _load_json_model(config_file, FactoryCliConfig), config_file.parent
            )
            _validate_layout_roots(config)
            _write_json(
                MetadataBackupService(config.catalog_root.parent).create(
                    args.destination, approved=True
                ),
                stdout,
            )
            return 0
        if args.command == "plugin-author" and not args.approve:
            raise FactoryDenied("缺少 --approve；单插件生成需要本轮人工审批")
        if args.command == "plugin-author":
            request_path = Path(args.request).resolve()
            raw_request = json.loads(request_path.read_text(encoding="utf-8-sig"))

            def cli_plugin_sink(event: tuple[str, dict[str, object]]) -> None:
                kind, data = event
                _write_json({"event": kind, "data": data}, stderr)

            if isinstance(raw_request, dict) and "plan_id" in raw_request:
                plan = PluginDecompositionPlan.model_validate(raw_request)
                plugin_results = execute_plugin_decomposition(
                    args.config,
                    plan,
                    approved=True,
                    sink=cli_plugin_sink,
                )
                _write_json(
                    {
                        "plan_id": plan.plan_id,
                        "results": [item.model_dump(mode="json") for item in plugin_results],
                    },
                    stdout,
                )
                return 0
            request = PluginRequest.model_validate(raw_request)
            plugin_result = execute_plugin_authoring_request(
                args.config,
                request,
                approved=True,
                sink=cli_plugin_sink,
            )
            _write_json(plugin_result.model_dump(mode="json"), stdout)
            return 0
        if args.command in {"plugin-validate", "plugin-regression"}:
            if not args.approve:
                raise FactoryDenied("单插件验证需要本轮 --approve")
            config_file = Path(args.config).resolve()
            config = _resolve_config_paths(
                _load_json_model(config_file, FactoryCliConfig), config_file.parent
            )
            request = _load_json_model(Path(args.request).resolve(), PluginRequest)
            source = _load_json_model(Path(args.candidate).resolve(), PluginSourceCandidate)
            compiler = _plugin_compiler(config)
            harness = _plugin_harness(config, compiler)
            if harness is None:
                raise ContractGapError(
                    ContractGap(
                        capability="单插件 Canonical Harness 验证",
                        missing="plugin_harness_config 或 plugin_harness_backend_ref",
                        checked=("FactoryCliConfig",),
                        risk="仅有 .lib 编译回执不能证明最终链接或 TTP 行为有效",
                    )
                )
            plugin_run_id = f"plugin-run-{uuid4().hex}"
            repository = PluginRunRepository(config.runtime_root)
            root = repository.create(plugin_run_id, request)
            materialize_validation_harness(root, request.implementation_name)

            def validation_sink(event: tuple[str, dict[str, object]]) -> None:
                repository.append_event(root, event)
                kind, data = event
                _write_json({"event": kind, "data": data}, stderr)

            pipeline = PluginAuthoringPipeline(
                author=None,
                compiler=compiler,
                harness=harness,
                coverage=CoverageRegistry.from_markdown(config.coverage_matrix),
                sink=validation_sink,
            )
            try:
                validation_result = pipeline.validate_existing(
                    request,
                    source,
                    approved=True,
                    plugin_run_id=plugin_run_id,
                )
                repository.complete(root, validation_result)
            except BaseException as exc:
                repository.fail(root, exc)
                raise
            _write_json(validation_result.model_dump(mode="json"), stdout)
            return 0
        if args.command in {
            "plugin-list",
            "plugin-show",
            "plugin-review",
            "plugin-promote",
            "plugin-cleanup",
        }:
            if args.command == "plugin-list":
                _write_json(list_plugin_inventory(args.config), stdout)
            elif args.command == "plugin-cleanup":
                _write_json(
                    cleanup_plugin_runs(args.config, approved=bool(args.approve)),
                    stdout,
                )
            elif args.command == "plugin-show":
                config = _factory_cli_config(args.config)
                _write_json(
                    PluginRunRepository(config.runtime_root).payload(args.plugin_run_id),
                    stdout,
                )
            elif args.command == "plugin-review":
                provenance = _load_json_model(
                    Path(args.provenance).resolve(), PluginProvenance
                )
                reviewed = review_plugin_run(
                    args.config,
                    args.plugin_run_id,
                    provenance,
                    approved=args.approve,
                )
                payload = PluginRunRepository(
                    _factory_cli_config(args.config).runtime_root
                ).payload(args.plugin_run_id)
                review_result = PluginAuthoringResult.model_validate(payload["result"])
                _write_json(
                    {
                        "plugin_id": None
                        if review_result.source is None
                        else review_result.source.plugin_id,
                        "reviewed_path": reviewed.as_posix(),
                    },
                    stdout,
                )
            else:
                dispatched = promote_plugin(
                    args.config, args.plugin_id, approved=args.approve
                )
                _write_json(
                    {
                        "plugin_id": args.plugin_id,
                        "dispatchable_path": dispatched.as_posix(),
                    },
                    stdout,
                )
            return 0
        if args.command in {"demand-submit", "demand-list"}:
            config_file = Path(args.config).resolve()
            config = _resolve_config_paths(
                _load_json_model(config_file, FactoryCliConfig), config_file.parent
            )
            queue = FactoryWorkQueue(config.runtime_root)
            if args.command == "demand-submit":
                if not args.approve:
                    raise FactoryDenied("动态样本工单提交需要本轮 --approve")
                demand = _load_json_model(Path(args.demand).resolve(), SampleDemand)
                _write_json({"demand_ref": queue.submit(demand, approved=True)}, stdout)
            else:
                _write_json({"demands": queue.list()}, stdout)
            return 0
        if args.command in {"run-list", "run-show"}:
            config_file = Path(args.config).resolve()
            config = _resolve_config_paths(
                _load_json_model(config_file, FactoryCliConfig), config_file.parent
            )
            run_query_repository = RunRepository(config.runtime_root)
            if args.command == "run-show":
                _write_json(run_query_repository.run_payload(args.run_id), stdout)
            else:
                _write_json(
                    {
                        "runs": [
                            {
                                "run_id": envelope.run_id,
                                "run_kind": envelope.run_kind.value,
                                "planning_strategy": envelope.planning_strategy.value,
                                "created_at": envelope.created_at.isoformat(),
                                "status": state.status.value,
                                "attempt_count": state.attempt_count,
                                "completed_attempt_count": state.completed_attempt_count,
                                "result_status": state.result_status,
                                "run_path": path.as_posix(),
                            }
                            for envelope, state, path in run_query_repository.list_runs()
                        ]
                    },
                    stdout,
                )
            return 0
        if args.command == "run-index-rebuild":
            config_file = Path(args.config).resolve()
            config = _resolve_config_paths(
                _load_json_model(config_file, FactoryCliConfig), config_file.parent
            )
            run_index_repository = RunRepository(config.runtime_root)
            _write_json(RunIndex(config.runtime_root).rebuild(run_index_repository), stdout)
            return 0
        if args.command in {"run-reconcile", "storage-report"}:
            config_file = Path(args.config).resolve()
            config = _resolve_config_paths(
                _load_json_model(config_file, FactoryCliConfig), config_file.parent
            )
            if args.command == "run-reconcile":
                _write_json(RunRepository(config.runtime_root).reconcile_report(), stdout)
            else:
                _write_json(ContentAddressedStore(config.runtime_root).storage_report(), stdout)
            return 0
        if args.command in {"gc-plan", "gc-apply"}:
            config_file = Path(args.config).resolve()
            config = _resolve_config_paths(
                _load_json_model(config_file, FactoryCliConfig), config_file.parent
            )
            manager = StorageManager(
                factory_root=config.catalog_root.parent,
                runtime_root=config.runtime_root,
                catalog_root=config.catalog_root,
                manifest_root=config.manifest_root,
            )
            if args.command == "gc-plan":
                _write_json(manager.gc_plan(grace_days=args.grace_days), stdout)
            else:
                if not args.approve:
                    raise FactoryDenied("GC 删除需要本轮 --approve")
                _write_json(manager.collect(grace_days=args.grace_days, approved=True), stdout)
            return 0
        if args.command in {"artifact-verify", "artifact-export"}:
            config_file = Path(args.config).resolve()
            config = _resolve_config_paths(
                _load_json_model(config_file, FactoryCliConfig), config_file.parent
            )
            cas = ContentAddressedStore(config.runtime_root)
            if args.command == "artifact-verify":
                _write_json(ArtifactReplayService(cas).replay(args.artifact_ref), stdout)
            else:
                export_result = ArtifactExportService(config.runtime_root, cas).export(
                    export_id=args.export_id,
                    artifact_ref=args.artifact_ref,
                    filename=args.filename,
                    approved=bool(args.approve),
                )
                _write_json(
                    {
                        "export_id": export_result.export_id,
                        "export_ref": export_result.export_ref,
                        "artifact_sha256": export_result.artifact_sha256,
                        "artifact_path": export_result.artifact_path.as_posix(),
                        "manifest_path": export_result.manifest_path.as_posix(),
                    },
                    stdout,
                )
            return 0
        if args.command == "sample-list":
            _write_json(list_produced_samples(args.config), stdout)
            return 0
        if args.command == "sample-transfer":
            transferred = transfer_produced_samples(
                args.config,
                args.sample_ids,
                approved=bool(args.approve),
            )
            _write_json({"transferred": list(transferred)}, stdout)
            return 0
        if args.command == "sample-board-export":
            _write_json(
                export_published_attck_board(
                    args.config,
                    open_browser=bool(args.open_browser),
                ),
                stdout,
            )
            return 0
        if args.command == "source-restore":
            if not args.approve:
                raise FactoryDenied("源码恢复需要本轮 --approve")
            config_file = Path(args.config).resolve()
            config = _resolve_config_paths(
                _load_json_model(config_file, FactoryCliConfig), config_file.parent
            )
            destination = Path(args.destination).resolve()
            if destination.is_relative_to(_REPO_ROOT):
                raise ValueError("源码恢复目标不得位于 EdrEvalAgent 代码仓")
            digest = SourceReplayService(ContentAddressedStore(config.runtime_root)).restore(
                Path(args.manifest).resolve(), destination
            )
            _write_json(
                {
                    "source_digest": digest,
                    "destination": destination.as_posix(),
                    "restored": True,
                },
                stdout,
            )
            return 0
        if args.command == "bundle-export":
            if not args.approve:
                raise FactoryDenied("Bundle 导出需要本轮 --approve")
            config_file = Path(args.config).resolve()
            config = _resolve_config_paths(
                _load_json_model(config_file, FactoryCliConfig), config_file.parent
            )
            bundle = _load_json_model(Path(args.bundle).resolve(), SampleBundle)
            bundle_result = BundleExportService(
                config.runtime_root, ContentAddressedStore(config.runtime_root)
            ).export(bundle, export_id=args.export_id, approved=True)
            _write_json(
                {
                    "export_id": bundle_result.export_id,
                    "export_ref": bundle_result.export_ref,
                    "bundle_digest": bundle_result.artifact_sha256,
                    "export_path": bundle_result.artifact_path.as_posix(),
                    "bundle_manifest": bundle_result.manifest_path.as_posix(),
                },
                stdout,
            )
            return 0
        if args.command in {
            "experience-list",
            "experience-import",
            "experience-search",
            "experience-promote",
            "experience-index-build",
        }:
            config_file = Path(args.config).resolve()
            config = _resolve_config_paths(
                _load_json_model(config_file, FactoryCliConfig), config_file.parent
            )
            store = FilesystemExperienceStore(config.experience_root)
            if args.command == "experience-index-build":
                if not args.approve:
                    raise FactoryDenied("经验向量索引构建需要本轮 --approve")
                backend = cast(
                    EmbeddingBackend,
                    _backend_instance(
                        config.embedding_backend_ref,
                        "Embedding 后端",
                        ("embed",),
                    ),
                )
                if not isinstance(getattr(backend, "model_fingerprint", None), str):
                    raise TypeError("Embedding 后端缺少 model_fingerprint")
                index = FilesystemSemanticExperienceIndex(config.experience_vector_index, backend)
                index.build(store.records(), approved=True)
                _write_json(
                    {
                        "index_path": config.experience_vector_index.as_posix(),
                        "record_count": len(store.records()),
                        "model_fingerprint": backend.model_fingerprint,
                    },
                    stdout,
                )
            elif args.command == "experience-list":
                _write_json(
                    {"records": [item.model_dump(mode="json") for item in store.records()]},
                    stdout,
                )
            elif args.command == "experience-import":
                if not args.approve:
                    raise FactoryDenied("经验导入需要本轮 --approve")
                record = _load_json_model(Path(args.record).resolve(), ExperienceRecord)
                _write_json({"experience_ref": store.put(record, approved=True)}, stdout)
            elif args.command == "experience-search":
                query = _load_json_model(Path(args.query).resolve(), ExperienceSearchQuery)
                _write_json(
                    HybridExperienceRetriever(store).search(query).model_dump(mode="json"),
                    stdout,
                )
            else:
                if not args.approve:
                    raise FactoryDenied("经验成熟度推进需要本轮 --approve")
                _write_json(
                    {
                        "experience_ref": store.advance(
                            args.experience_id,
                            KnowledgeMaturity(args.maturity),
                            approved=True,
                        )
                    },
                    stdout,
                )
            return 0
        if args.command == "produce" and not args.approve:
            raise FactoryDenied("缺少 --approve；CLI 不接受配置文件代替本轮人工审批")
        if args.command == "tui":
            from packages.sample_factory.tui import run_tui

            return run_tui(args.config, args.run)

        inputs = load_inputs(args.config, args.run)
        if args.command == "preflight":
            _write_json(preflight(inputs), stdout)
            return 0

        def event_sink(event: tuple[str, dict[str, object]]) -> None:
            kind, data = event
            _write_json({"event": kind, "data": data}, stderr)

        result = execute_production(
            inputs,
            approved=True,
            high_risk_approved=bool(args.approve_high_risk),
            sink=event_sink,
        )
        _write_json(result_payload(result), stdout)
        return 0 if result.produced else 2
    except ContractGapError as exc:
        _write_line(str(exc), stderr)
        return 3
    except FactoryDenied as exc:
        _write_line(f"审批拒绝：{exc}", stderr)
        return 4
    except (
        ValidationError,
        RuntimeConfigError,
        SecretsEnvError,
        SampleFactoryError,
        ValueError,
    ) as exc:
        _write_line(f"样本工厂失败：{exc}", stderr)
        return 2
    except KeyboardInterrupt:
        _write_line("样本工厂已由操作员中断", stderr)
        return 130
    except Exception as exc:
        _write_line(f"样本工厂未预期错误：{type(exc).__name__}: {exc}", stderr)
        return 1


def _load_json_model[ModelT: BaseModel](path: Path, model: type[ModelT]) -> ModelT:
    if not path.is_file():
        raise ValueError(f"JSON 配置不存在：{path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON 配置非法：{path}: {exc.msg}") from exc
    return model.model_validate(raw)


def _resolve_config_paths(config: FactoryCliConfig, base: Path) -> FactoryCliConfig:
    updates: dict[str, Path | None] = {}
    for field_name in _CONFIG_PATH_FIELDS:
        value = cast(Path | None, getattr(config, field_name))
        if value is not None:
            updates[field_name] = (value if value.is_absolute() else base / value).resolve()
    return config.model_copy(update=updates)


def _preflight_completion(config: FactoryCliConfig, run: FactoryRunSpec) -> None:
    if config.completion_backend_ref is not None:
        _require_backend(
            config.completion_backend_ref,
            "工厂 LLM completion",
            ("complete_tool_with_metadata",),
        )
        return
    _standard_completion_config(config, run)


def _experience_retriever(config: FactoryCliConfig) -> HybridExperienceRetriever:
    semantic_index = None
    if config.embedding_backend_ref is not None:
        backend = cast(
            EmbeddingBackend,
            _backend_instance(config.embedding_backend_ref, "Embedding 后端", ("embed",)),
        )
        if not isinstance(getattr(backend, "model_fingerprint", None), str):
            raise TypeError("Embedding 后端缺少 model_fingerprint")
        semantic_index = FilesystemSemanticExperienceIndex(config.experience_vector_index, backend)
    return HybridExperienceRetriever(
        FilesystemExperienceStore(config.experience_root), semantic_index
    )


def _preflight_experience(
    config: FactoryCliConfig, run: FactoryRunSpec
) -> tuple[PlanningStrategy, ExperienceSearchResult]:
    retriever = _experience_retriever(config)
    strategy = run.planning_strategy
    if strategy is PlanningStrategy.AUTO:
        strategy = select_planning_strategy(
            retriever,
            seed=run.context.seed,
            ph_ids=run.context.required_ph_ids,
            profile_id=run.context.profile.profile_id,
            architecture=run.context.architecture,
        )
    minimum = {
        PlanningStrategy.EXPLOIT: KnowledgeMaturity.REPLAY_STABLE,
        PlanningStrategy.MUTATE: KnowledgeMaturity.BEHAVIOR_VALID,
        PlanningStrategy.EXPLORE: KnowledgeMaturity.HYPOTHESIS,
    }[strategy]
    result = retriever.search(
        ExperienceSearchQuery(
            strategy=strategy,
            ph_ids=run.context.required_ph_ids,
            profile_id=run.context.profile.profile_id,
            architecture=run.context.architecture,
            minimum_maturity=minimum,
            semantic_query=(
                "TTP composition "
                + " ".join(run.context.required_ph_ids or run.context.candidate_ph_ids)
            ),
        )
    )
    if strategy is not PlanningStrategy.EXPLORE and not result.candidates:
        raise ContractGapError(
            ContractGap(
                capability=f"执行 planning_strategy={strategy.value}",
                missing=f"至少一条 {minimum.value} 及以上、符合 profile/架构/PH 的经验",
                checked=(config.experience_root.as_posix(), result.experience_set_version),
                risk="没有经验基线时伪装 exploit/mutate 会造成不可解释的自由规划",
            )
        )
    return strategy, result


def _completion_client(config: FactoryCliConfig, run: FactoryRunSpec) -> CompletionClient:
    if config.completion_backend_ref is not None:
        return cast(
            CompletionClient,
            _backend_instance(
                config.completion_backend_ref,
                "LLM completion",
                ("complete_tool_with_metadata",),
            ),
        )
    return OpenAICompatClient(_standard_completion_config(config, run))


def _plugin_completion_client(config: FactoryCliConfig) -> CompletionClient:
    if config.completion_backend_ref is not None:
        return cast(
            CompletionClient,
            _backend_instance(
                config.completion_backend_ref,
                "工厂 LLM completion",
                ("complete_tool_with_metadata",),
            ),
        )
    if config.runtime_toml is None or config.secrets_env is None:
        raise ContractGapError(
            ContractGap(
                capability="Plugin Authoring LLM",
                missing="runtime_toml + secrets_env 或 completion_backend_ref",
                checked=("FactoryCliConfig",),
                risk="缺少受控模型配置时不能生成插件源码",
            )
        )
    runtime = load_runtime(config.runtime_toml)
    secrets = SecretsEnv.load(config.secrets_env)
    if runtime.model is None or not secrets.llm_api_key:
        raise ContractGapError(
            ContractGap(
                capability="Plugin Authoring LLM",
                missing="model 配置或 LLM API key",
                checked=(config.runtime_toml.as_posix(), config.secrets_env.as_posix()),
                risk="不能用占位凭据或默认模型生成插件源码",
            )
        )
    return OpenAICompatClient(
        LLMConfig(
            base_url=runtime.model.base_url,
            model=runtime.model.name,
            api_key=secrets.llm_api_key,
            output_locale=runtime.model.output_locale,
            timeout_sec=runtime.model.timeout_sec,
            max_tokens=config.glue_max_tokens or 16384,
        )
    )


def _plugin_intake_coordinator(config: FactoryCliConfig) -> PluginIntakeCoordinator:
    coverage = CoverageRegistry.from_markdown(config.coverage_matrix)
    return PluginIntakeCoordinator(
        agent=PluginIntakeAgent(
            _plugin_completion_client(config),
            coverage,
            retry_limit=config.planner_retry_limit,
        ),
        sources=PluginSourceIntake(config.runtime_root),
        repository=PluginIntakeRepository(config.runtime_root),
    )


def _plugin_compiler(config: FactoryCliConfig) -> PluginCompilerBackend:
    if config.plugin_compiler_backend_ref is not None:
        return cast(
            PluginCompilerBackend,
            _backend_instance(
                config.plugin_compiler_backend_ref,
                "Plugin Compiler 后端",
                ("compile",),
            ),
        )
    return GuardedPluginCompilerBackend(
        targets=JsonBuildTargetCatalog(config.build_targets).load(),
        sources=PluginRunSourceResolver(config.runtime_root),
        runtime_root=config.runtime_root,
        memory_limit_mb=config.compiler_memory_limit_mb,
        payload_root=config.payload_search_roots,
    )


def _plugin_harness(
    config: FactoryCliConfig,
    compiler: PluginCompilerBackend,
) -> PluginHarnessBackend | None:
    if config.plugin_harness_config is not None:
        if config.verification_config is None or config.secrets_env is None:
            raise ContractGapError(
                ContractGap(
                    capability="内置 VMware Plugin Harness",
                    missing="verification_config + secrets_env",
                    checked=(config.plugin_harness_config.as_posix(), "FactoryCliConfig"),
                    risk="缺少 VM 配置或 secret store 时无法安全控制快照与 WinRM",
                )
            )
        if not callable(getattr(compiler, "resolve_artifact", None)):
            raise ContractGapError(
                ContractGap(
                    capability="解析 Plugin Harness 静态库",
                    missing="PluginCompilerBackend.resolve_artifact",
                    checked=("FactoryCliConfig.plugin_compiler_backend_ref",),
                    risk="无法验证实际投递的 .lib 是否等于本轮构建回执",
                )
            )
        return create_vmware_plugin_harness_backend(
            config_path=config.plugin_harness_config,
            vmware_config_path=config.verification_config,
            source_resolver=PluginRunSourceResolver(config.runtime_root),
            artifact_resolver=cast(PluginArtifactResolver, compiler),
            secrets_env_path=config.secrets_env,
            coverage=CoverageRegistry.from_markdown(config.coverage_matrix),
        )
    if config.plugin_harness_backend_ref is None:
        return None
    return cast(
        PluginHarnessBackend,
        _backend_instance(
            config.plugin_harness_backend_ref,
            "Plugin Harness 后端",
            ("validate",),
        ),
    )


def _plugin_artifact_resolver(config: FactoryCliConfig) -> PluginBuildArtifactResolver:
    compiler = _plugin_compiler(config)
    if not callable(getattr(compiler, "resolve_artifact", None)):
        raise ValueError(
            "Plugin Compiler 后端必须实现 resolve_artifact 后才能晋升验证静态库"
        )
    return cast(PluginBuildArtifactResolver, compiler)


def _standard_completion_config(config: FactoryCliConfig, run: FactoryRunSpec) -> LLMConfig:
    if config.runtime_toml is None or config.secrets_env is None:
        raise ContractGapError(
            ContractGap(
                capability="工厂 AI 规划与 glue 生成",
                missing="runtime_toml + secrets_env，或 completion_backend_ref",
                checked=("FactoryCliConfig", "packages/config runtime + secrets contract"),
                risk="从环境或命令行猜模型凭据会绕过最小权限投影",
            )
        )
    runtime = load_runtime(config.runtime_toml)
    if runtime.model is None:
        raise ContractGapError(
            ContractGap(
                capability="工厂 AI 规划与 glue 生成",
                missing="runtime.toml [model]",
                checked=(config.runtime_toml.as_posix(),),
                risk="没有明确模型指纹时生产结果不可复现",
            )
        )
    secrets = SecretsEnv.load(config.secrets_env)
    if not secrets.llm_api_key:
        raise ContractGapError(
            ContractGap(
                capability="调用已配置的工厂 LLM",
                missing="secrets.env LLM_API_KEY",
                checked=(config.secrets_env.as_posix(),),
                risk="凭据不得从参数、日志或占位值伪造",
            )
        )
    if runtime.model.seed is not None and runtime.model.seed != run.context.seed:
        raise ValueError("runtime.toml model.seed 必须与 run.context.seed 一致")
    return LLMConfig(
        base_url=runtime.model.base_url,
        model=runtime.model.name,
        api_key=secrets.llm_api_key,
        output_locale=runtime.model.output_locale,
        timeout_sec=runtime.model.timeout_sec,
    )


def _with_max_tokens(client: CompletionClient, max_tokens: int | None) -> CompletionClient:
    if max_tokens is None:
        return client
    copier = getattr(client, "with_max_tokens", None)
    if not callable(copier):
        raise ValueError("自定义 completion backend 不支持 with_max_tokens")
    return cast(CompletionClient, copier(max_tokens))


class _PreflightArtifactResolver:
    def resolve_artifact(self, artifact_ref: str) -> Path:
        raise VerificationError(f"preflight 不得解析构建产物：{artifact_ref}")


def _lab_profile_id(config: FactoryCliConfig) -> str:
    for path in (config.plugin_harness_config, config.verification_config):
        if path is None or not path.is_file():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            continue
        profile = payload.get("profile")
        if isinstance(profile, dict) and profile.get("profile_id"):
            return str(profile["profile_id"])
        if payload.get("profile_id"):
            return str(payload["profile_id"])
    raise ValueError("无法从 plugin_harness_config / verification_config 解析 lab profile_id")


def _vmware_verifier_preflight(config: FactoryCliConfig, run: FactoryRunSpec) -> dict[str, object]:
    if config.verification_config is None or config.secrets_env is None:
        raise ContractGapError(
            ContractGap(
                capability="内置 VMware Workstation 验证",
                missing="verification_config + secrets_env",
                checked=("FactoryCliConfig",),
                risk="缺少 VM 配置或 secret store 时无法安全控制快照与 WinRM",
            )
        )
    verifier = VmwareVerificationBackend.from_config(
        config.verification_config,
        secrets_env_path=config.secrets_env,
        artifact_resolver=_PreflightArtifactResolver(),
        telemetry_contracts_path=config.telemetry_contracts,
    )
    if verifier.runtime_root != config.runtime_root:
        raise ValueError("VMware runtime_root 必须与 factory-config-v2 一致")
    return verifier.preflight(run.context)


def _require_backend(ref: str | None, capability: str, methods: tuple[str, ...]) -> None:
    if ref is None:
        raise ContractGapError(
            ContractGap(
                capability=capability,
                missing=f"部署后端引用（需要方法：{', '.join(methods)}）",
                checked=("FactoryCliConfig", "docs/dev/design-and-progress-registry.md §2"),
                risk="用测试桩伪装真实后端会制造虚假生产与验证结论",
                options=("配置已审计 module:attribute 后端", "补齐对应 SF 实现", "仅运行 schema"),
                next_step="由部署层提供真实后端后执行 preflight。",
            )
        )
    _import_symbol(ref)


def _backend_instance(ref: str | None, label: str, methods: tuple[str, ...]) -> object:
    if ref is None:
        raise ValueError(f"{label} backend ref 缺失")
    value = _import_symbol(ref)
    if inspect.isclass(value) or (
        callable(value) and not all(callable(getattr(value, name, None)) for name in methods)
    ):
        value = value()
    missing = [name for name in methods if not callable(getattr(value, name, None))]
    if missing:
        raise TypeError(f"{label} 缺少方法：{missing}")
    return value


def _import_symbol(ref: str) -> object:
    module_name, _, attribute_path = ref.partition(":")
    if not module_name or not attribute_path:
        raise ValueError(f"backend ref 非法：{ref}")
    value: object = importlib.import_module(module_name)
    for part in attribute_path.split("."):
        try:
            value = getattr(value, part)
        except AttributeError as exc:
            raise ValueError(f"backend ref 不存在：{ref}") from exc
    return value


def _valid_symbol_ref(value: str) -> bool:
    module_name, separator, attribute = value.partition(":")
    return bool(separator and module_name.strip() and attribute.strip())


def _require_external(path: Path, label: str) -> None:
    resolved = path.resolve()
    if resolved.is_relative_to(_REPO_ROOT):
        raise ValueError(f"{label} 必须位于 EdrEvalAgent 代码仓外：{resolved}")


def _validate_layout_roots(config: FactoryCliConfig) -> None:
    roots = {
        "catalog_root": config.catalog_root.resolve(),
        "runtime_root": config.runtime_root.resolve(),
        "manifest_root": config.manifest_root.resolve(),
    }
    for name, path in roots.items():
        _require_external(path, name)
    for left_name, left in roots.items():
        for right_name, right in roots.items():
            if left_name >= right_name:
                continue
            if left == right or left.is_relative_to(right) or right.is_relative_to(left):
                raise ValueError(f"{left_name} 与 {right_name} 不得相同或相互嵌套")
    if len({path.parent for path in roots.values()}) != 1:
        raise ValueError("catalog_root/runtime_root/manifest_root 必须是同一工厂根目录的兄弟目录")


def _write_json(value: object, stream: TextIO) -> None:
    _write_line(json.dumps(value, ensure_ascii=False, sort_keys=True), stream)


def _write_line(value: str, stream: TextIO) -> None:
    stream.write(value + "\n")
    stream.flush()


__all__ = [
    "FactoryBatchSpec",
    "FactoryCliConfig",
    "FactoryInputs",
    "FactoryRunSpec",
    "build_parser",
    "execute_production",
    "load_inputs",
    "main",
    "preflight",
    "result_payload",
    "schema_payload",
]
