"""AI 驱动的样本生产流水线 A 控制面编排。"""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import timedelta
from typing import Protocol
from uuid import uuid4

from packages.sample_factory.ai_planner import FactoryPlanningAgent, PlannedRecipe
from packages.sample_factory.catalog import AtomCatalog
from packages.sample_factory.errors import (
    BuildError,
    CompilationFailure,
    FactoryDenied,
    LeaseLostError,
    PlanningAuditError,
    ProductionStopped,
    SampleFactoryError,
    VerificationError,
)
from packages.sample_factory.glue import GlueCoordinator
from packages.sample_factory.handoff import materialize_items_for
from packages.sample_factory.identity import canonical_parameters, combo_digest
from packages.sample_factory.manifest import ManifestRepository
from packages.sample_factory.models import (
    AtomSpec,
    BuiltSample,
    ComboIntent,
    ComboRecord,
    ComboStatus,
    DeploymentFingerprint,
    FactoryPlanningContext,
    FailureTaxonomy,
    GlueMaterializeItem,
    GlueOrigin,
    GlueResolution,
    LeaseClaim,
    LeaseDisposition,
    PlannedComposition,
    PointerMode,
    ProductionPolicy,
    RawVerificationReport,
    RegressionManifestEntry,
    SampleRecipe,
    TelemetryContract,
)
from packages.sample_factory.planning_audit import PlanningAuditRepository
from packages.sample_factory.run_models import new_attempt_id, new_run_id
from packages.sample_factory.state import ComboStateStore
from packages.sample_factory.telemetry import FunctionalTruth, FunctionalTruthEvaluator

EventSink = Callable[[tuple[str, dict[str, object]]], None]


class ProductionStopToken:
    """跨 TUI/生产 worker 传递的线程安全协作式停止信号。"""

    def __init__(self) -> None:
        self._requested = threading.Event()

    @property
    def is_stop_requested(self) -> bool:
        return self._requested.is_set()

    def request_stop(self) -> None:
        self._requested.set()

    def raise_if_requested(self, phase: str) -> None:
        if self.is_stop_requested:
            raise ProductionStopped(phase)


@dataclass(frozen=True)
class BuildRequest:
    recipe: SampleRecipe
    atom_parameters: Mapping[str, Mapping[str, object]]
    glue: GlueResolution
    build_target_ref: str
    materialize_items: tuple[GlueMaterializeItem, ...]
    run_id: str | None = None
    attempt_id: str | None = None


class CompilerBackend(Protocol):
    """授权构建主机端口；build target 已注册，模型不提供命令。"""

    def compile(self, request: BuildRequest) -> BuiltSample: ...


class VerificationBackend(Protocol):
    """隔离沙箱/CAPE 等原始证据采集端口；不得由 coding agent 实现裁判。"""

    def collect(
        self,
        artifact: BuiltSample,
        recipe: SampleRecipe,
        context: FactoryPlanningContext,
    ) -> RawVerificationReport: ...


@dataclass(frozen=True)
class PublishedArtifact:
    artifact_ref: str
    artifact_sha256: str

    def __post_init__(self) -> None:
        if not self.artifact_ref.startswith(("artifact://", "object://", "s3://")):
            raise ValueError("发布产物必须返回 artifact:// / object:// / s3:// 不透明引用")
        if len(self.artifact_sha256) != 64 or any(
            ch not in "0123456789abcdef" for ch in self.artifact_sha256
        ):
            raise ValueError("发布产物 artifact_sha256 必须是 sha256")


class ArtifactPublisher(Protocol):
    def publish(self, artifact: BuiltSample) -> PublishedArtifact: ...


class TelemetryContractSource(Protocol):
    def get(self, contract_ref: str) -> TelemetryContract: ...


class ExpectedDetectionSource(Protocol):
    """覆盖矩阵期望标注端口；实现必须保留权威 source_ref。"""

    def get(self, ph_ids: tuple[str, ...], *, evasion_tier: str) -> dict[str, object]: ...


@dataclass(frozen=True)
class ProductionRequest:
    context: FactoryPlanningContext
    worker_id: str
    approved: bool
    high_risk_approved: bool
    workspace_ref: str
    build_target_ref: str
    regression_set_version: str
    runtime_param_snapshot_ref: str | None = None
    parent_id: str | None = None
    lease_ttl: timedelta = timedelta(minutes=15)
    compile_attempt_limit: int | None = None
    execution_logging: bool = False
    excluded_compositions: tuple[PlannedComposition, ...] = ()
    batch_id: str | None = None
    batch_attempt: int | None = None
    accepted_plan_sink: Callable[[PlannedRecipe], None] | None = None
    source_snapshot_sink: Callable[[GlueResolution, int, bool], str | None] | None = None
    experience_sink: Callable[[ProductionResult, tuple[AtomSpec, ...]], str | None] | None = None
    stop_token: ProductionStopToken | None = None
    run_id: str | None = None
    attempt_id: str | None = None


@dataclass(frozen=True)
class ProductionResult:
    plan: PlannedRecipe | None
    claim: LeaseClaim | None
    record: ComboRecord | None
    truth: FunctionalTruth | None
    artifact_ref: str | None = None
    run_id: str | None = None
    attempt_id: str | None = None
    source_snapshot_ref: str | None = None
    build_id: str | None = None
    artifact_sha256: str | None = None
    source_digest: str | None = None
    toolchain_fp: str | None = None
    verification_run_id: str | None = None
    verification_ref: str | None = None
    experience_proposal_ref: str | None = None

    @property
    def produced(self) -> bool:
        return self.record is not None and self.record.status is ComboStatus.SUCCESS

    @property
    def newly_produced(self) -> bool:
        return self.produced and self.artifact_ref is not None


@dataclass(frozen=True)
class BatchOptions:
    sample_count: int
    max_attempts: int
    continue_on_failure: bool = True

    def __post_init__(self) -> None:
        if self.sample_count < 1:
            raise ValueError("batch sample_count 必须至少为 1")
        if self.max_attempts < self.sample_count:
            raise ValueError("batch max_attempts 不得小于 sample_count")


@dataclass(frozen=True)
class BatchAttemptResult:
    attempt_number: int
    seed: int
    workspace_ref: str
    result: ProductionResult | None = None
    error_type: str | None = None
    error: str | None = None
    attempt_id: str | None = None

    @property
    def newly_produced(self) -> bool:
        return self.result is not None and self.result.newly_produced


@dataclass(frozen=True)
class ProductionBatchResult:
    batch_id: str
    requested_count: int
    max_attempts: int
    attempts: tuple[BatchAttemptResult, ...]
    stopped: bool = False
    run_id: str | None = None

    @property
    def produced_count(self) -> int:
        return sum(attempt.newly_produced for attempt in self.attempts)

    @property
    def produced(self) -> bool:
        return self.produced_count >= self.requested_count

    @property
    def exhausted(self) -> bool:
        return (
            not self.produced
            and not self.stopped
            and len(self.attempts) >= self.max_attempts
        )


class _LeaseHeartbeat:
    """长 Agent/编译/验证阶段的后台续租；丢租约后主线程在提交前失败。"""

    def __init__(
        self,
        store: ComboStateStore,
        record_id: str,
        worker_id: str,
        ttl: timedelta,
    ) -> None:
        if ttl <= timedelta(seconds=3):
            raise ValueError("lease_ttl 必须大于 3 秒")
        self._store = store
        self._record_id = record_id
        self._worker_id = worker_id
        self._ttl = ttl
        self._stop = threading.Event()
        self._error: Exception | None = None
        self._thread = threading.Thread(
            target=self._run, name=f"sf-lease-{record_id[:8]}", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop_and_check(self) -> None:
        self._stop.set()
        self._thread.join()
        if self._error is not None:
            raise LeaseLostError(f"后台心跳失败：{self._error}") from self._error

    def cancel(self) -> None:
        self._stop.set()
        self._thread.join()

    def _run(self) -> None:
        interval = self._ttl.total_seconds() / 3
        while not self._stop.wait(interval):
            try:
                self._store.heartbeat(
                    self._record_id,
                    worker_id=self._worker_id,
                    ttl=self._ttl,
                )
            except Exception as exc:
                self._error = exc
                self._stop.set()


class AIDrivenSampleFactory:
    """审批 → AI 选件 → 抢租约 → 胶水 Agent → 编译 → V1/V2/V3 → 发布。"""

    def __init__(
        self,
        *,
        planner: FactoryPlanningAgent,
        catalog: AtomCatalog,
        glue: GlueCoordinator,
        compiler: CompilerBackend,
        verifier: VerificationBackend,
        truth_evaluator: FunctionalTruthEvaluator,
        contracts: TelemetryContractSource,
        expected_detection: ExpectedDetectionSource,
        publisher: ArtifactPublisher,
        state: ComboStateStore,
        manifests: ManifestRepository,
        planning_audits: PlanningAuditRepository | None = None,
        sink: EventSink | None = None,
        repair_limit: int = 2,
        max_compile_attempts: int | None = None,
    ) -> None:
        if repair_limit < 0:
            raise ValueError("repair_limit 不得小于 0")
        if max_compile_attempts is not None and max_compile_attempts < 1:
            raise ValueError("max_compile_attempts 必须至少为 1")
        self._planner = planner
        self._catalog = catalog
        self._glue = glue
        self._compiler = compiler
        self._verifier = verifier
        self._truth = truth_evaluator
        self._contracts = contracts
        self._expected_detection = expected_detection
        self._publisher = publisher
        self._state = state
        self._manifests = manifests
        self._planning_audits = planning_audits
        self._sink = sink
        self._max_compile_attempts = (
            max_compile_attempts if max_compile_attempts is not None else repair_limit + 1
        )
        # An explicit attempt cap supersedes the legacy repair_limit, so each
        # failed clang build can receive a diagnostics-driven repair until cap.
        self._repair_limit = (
            self._max_compile_attempts - 1
            if max_compile_attempts is not None
            else repair_limit
        )

    def produce(self, request: ProductionRequest) -> ProductionResult:
        request = replace(
            request,
            run_id=request.run_id or new_run_id(),
            attempt_id=request.attempt_id or new_attempt_id(),
        )
        self._preflight(request)
        self._stop_if_requested(request, "规划前")
        self._emit(
            "sample_factory_planning_started",
            {
                "profile_id": request.context.profile.profile_id,
                "production_policy": request.context.production_policy.value,
                "candidate_ph_ids": list(request.context.candidate_ph_ids),
            },
        )
        plan = self._planner.plan(
            request.context,
            high_risk_approved=request.high_risk_approved,
            excluded_compositions=request.excluded_compositions,
        )
        recipe = plan.recipe.model_copy(
            update={"execution_logging": request.execution_logging}
        )
        parameters = canonical_parameters(
            plan.atom_parameters,
            evasion_tier=recipe.evasion_tier,
            pointer_mode=None if recipe.pointer_mode is None else recipe.pointer_mode.value,
            execution_logging=recipe.execution_logging,
        )
        digest = combo_digest(recipe.ph_ids, parameters)
        recipe = recipe.model_copy(update={"recipe_id": f"sf-{digest[:16]}"})
        plan = replace(plan, recipe=recipe)
        if self._planning_audits is not None:
            audit_ref = self._planning_audits.record(
                plan,
                request.context,
                worker_id=request.worker_id,
                approved=request.approved,
                high_risk_approved=request.high_risk_approved,
                workspace_ref=request.workspace_ref,
                build_target_ref=request.build_target_ref,
                regression_set_version=request.regression_set_version,
                run_id=request.run_id,
                attempt_id=request.attempt_id,
                batch_id=request.batch_id,
                batch_attempt=request.batch_attempt,
                excluded_compositions=request.excluded_compositions,
            )
            plan = replace(plan, audit_ref=audit_ref)
        if request.accepted_plan_sink is not None:
            request.accepted_plan_sink(plan)
        self._emit(
            "sample_factory_plan_ready",
            {
                "recipe_id": recipe.recipe_id,
                "atom_ids": list(recipe.atom_ids),
                "ph_ids": list(recipe.ph_ids),
                "evasion_tier": recipe.evasion_tier,
                "execution_logging": recipe.execution_logging,
                "plan_fingerprint": plan.plan_fingerprint,
                "combination_fingerprint": plan.combination_fingerprint,
                "planning_audit_ref": plan.audit_ref,
                "planning_strategy": plan.planning_strategy.value,
                "experience_refs": list(plan.experience_refs),
                "experience_set_version": plan.experience_set_version,
                "learning_snapshot_ref": plan.learning_snapshot_ref,
            },
        )
        specs = self._catalog.validate_recipe(
            recipe,
            plan.atom_parameters,
            request.context.profile,
            high_risk_approved=request.high_risk_approved,
        )
        telemetry_contracts_list: list[TelemetryContract] = []
        for spec in specs:
            contract_ref = spec.telemetry_contract_ref
            if contract_ref is not None:
                telemetry_contracts_list.append(self._contracts.get(contract_ref))
        telemetry_contracts = tuple(telemetry_contracts_list)
        self._truth.validate_contract_bindings(recipe, specs, telemetry_contracts)
        annotation = self._expected_detection.get(
            recipe.ph_ids,
            evasion_tier=recipe.evasion_tier,
        )
        self._validate_expected_detection(annotation, recipe)
        if recipe.pointer_mode is PointerMode.RUNTIME_PARAM and not request.runtime_param_snapshot_ref:
            raise ValueError("runtime-param Recipe 必须在生产请求中提供 secret:// 快照引用")
        if recipe.pointer_mode is not PointerMode.RUNTIME_PARAM and request.runtime_param_snapshot_ref:
            raise ValueError("非 runtime-param Recipe 不得携带 argv/env 快照引用")
        self._stop_if_requested(request, "组合租约前")
        intent = ComboIntent(
            combo_digest=digest,
            ph_sequence=recipe.ph_ids,
            parameters_canonical=parameters,
            profile_id=request.context.profile.profile_id,
            env_detail=request.context.profile.env_detail,
            parent_id=request.parent_id,
            seed=request.context.seed,
        )
        claim = self._state.claim(
            intent,
            worker_id=request.worker_id,
            ttl=request.lease_ttl,
        )
        self._emit(
            "sample_factory_claim",
            {
                "record_id": claim.record_id,
                "combo_digest": digest,
                "profile_id": intent.profile_id,
                "disposition": claim.disposition.value,
                "production_policy": request.context.production_policy.value,
                "execution_logging": recipe.execution_logging,
            },
        )
        if claim.disposition not in {LeaseDisposition.ACQUIRED, LeaseDisposition.TAKEN_OVER}:
            return ProductionResult(
                plan=plan,
                claim=claim,
                record=self._state.get(claim.record_id),
                truth=None,
                run_id=request.run_id,
                attempt_id=request.attempt_id,
            )

        keeper = _LeaseHeartbeat(
            self._state,
            claim.record_id,
            request.worker_id,
            request.lease_ttl,
        )
        keeper.start()
        try:
            self._emit(
                "sample_factory_glue_started",
                {"recipe_id": recipe.recipe_id, "atom_ids": list(recipe.atom_ids)},
            )
            glue = self._glue.resolve(
                recipe,
                specs,
                plan.atom_parameters,
                workspace_ref=request.workspace_ref,
                build_target_ref=request.build_target_ref,
            )
            self._emit(
                "sample_factory_glue_ready",
                {
                    "recipe_id": recipe.recipe_id,
                    "glue_origin": glue.origin.value,
                    "execution_logging": recipe.execution_logging,
                    "changed_file_count": len(glue.changed_files),
                },
            )
            try:
                artifact, glue, source_snapshot_ref = self._compile_with_repairs(
                    recipe,
                    plan,
                    specs,
                    glue,
                    request,
                    max_attempts=request.compile_attempt_limit,
                )
            except BuildError:
                keeper.stop_and_check()
                record = self._state.complete_failure(
                    claim.record_id,
                    worker_id=request.worker_id,
                    taxonomy=FailureTaxonomy.COMPILE_FAIL,
                )
                self._emit_failure(record)
                return ProductionResult(
                    plan,
                    claim,
                    record,
                    None,
                    run_id=request.run_id,
                    attempt_id=request.attempt_id,
                )

            if artifact.source_digest != glue.source_digest:
                raise ValueError("编译回执 source_digest 与胶水工作区源码摘要不一致")
            self._emit(
                "sample_factory_verification_started",
                {
                    "recipe_id": recipe.recipe_id,
                    "artifact_sha256": artifact.artifact_sha256,
                    "profile_id": request.context.profile.profile_id,
                },
            )
            report = self._verifier.collect(artifact, recipe, request.context)
            truth = self._truth.evaluate(
                recipe,
                specs,
                telemetry_contracts,
                request.context.profile,
                report,
                built_sha256=artifact.artifact_sha256,
            )
            self._glue.record_functional_truth(
                glue,
                v2_passed=truth.v2_passed,
                v3_passed=truth.v3_passed,
            )
            self._emit(
                "sample_factory_verification_finished",
                {
                    "recipe_id": recipe.recipe_id,
                    "v1_passed": truth.v1_passed,
                    "v2_passed": truth.v2_passed,
                    "v3_passed": truth.v3_passed,
                    "failure_taxonomy": (
                        None if truth.taxonomy is None else truth.taxonomy.value
                    ),
                },
            )
            if not truth.success:
                if truth.taxonomy is None:  # pragma: no cover - FunctionalTruth 不变量
                    raise AssertionError("失败真值必须带 taxonomy")
                keeper.stop_and_check()
                record = self._state.complete_failure(
                    claim.record_id,
                    worker_id=request.worker_id,
                    taxonomy=truth.taxonomy,
                )
                self._emit_failure(record)
                return ProductionResult(
                    plan,
                    claim,
                    record,
                    truth,
                    run_id=request.run_id,
                    attempt_id=request.attempt_id,
                    source_snapshot_ref=source_snapshot_ref,
                    build_id=artifact.build_id,
                    artifact_sha256=artifact.artifact_sha256,
                    source_digest=artifact.source_digest,
                    toolchain_fp=artifact.toolchain_fp,
                    verification_run_id=report.run_id,
                    verification_ref=report.telemetry.source_ref,
                )

            self._emit(
                "sample_factory_publish_started",
                {"recipe_id": recipe.recipe_id, "artifact_sha256": artifact.artifact_sha256},
            )
            published = self._publisher.publish(artifact)
            if published.artifact_sha256 != artifact.artifact_sha256:
                raise ValueError("对象存储发布回执 sha256 与本轮构建不一致")
            manifest_entry = self._manifest_entry(
                request,
                recipe,
                parameters,
                digest,
                artifact,
                published,
                truth,
                annotation,
            )
            manifest_ref = self._manifests.append(manifest_entry)
            keeper.stop_and_check()
            record = self._state.complete_success(
                claim.record_id,
                worker_id=request.worker_id,
                toolchain_fp=artifact.toolchain_fp,
                artifact_sha256=artifact.artifact_sha256,
                git_manifest_ref=manifest_ref,
            )
            result = ProductionResult(
                plan,
                claim,
                record,
                truth,
                published.artifact_ref,
                run_id=request.run_id,
                attempt_id=request.attempt_id,
                source_snapshot_ref=source_snapshot_ref,
                build_id=artifact.build_id,
                artifact_sha256=artifact.artifact_sha256,
                source_digest=artifact.source_digest,
                toolchain_fp=artifact.toolchain_fp,
                verification_run_id=report.run_id,
                verification_ref=report.telemetry.source_ref,
            )
            if request.experience_sink is not None:
                try:
                    proposal_ref = request.experience_sink(result, specs)
                    result = replace(result, experience_proposal_ref=proposal_ref)
                    self._emit(
                        "sample_factory_experience_proposed",
                        {
                            "recipe_id": recipe.recipe_id,
                            "proposal_ref": proposal_ref,
                        },
                    )
                except Exception as exc:
                    self._emit(
                        "sample_factory_experience_extraction_failed",
                        {
                            "recipe_id": recipe.recipe_id,
                            "error_type": type(exc).__name__,
                        },
                    )
            self._emit(
                "sample_factory_success",
                {
                    "record_id": record.record_id,
                    "recipe_id": recipe.recipe_id,
                    "atom_ids": list(recipe.atom_ids),
                    "ph_ids": list(recipe.ph_ids),
                    "trigger_mode": recipe.trigger_mode.value,
                    "artifact_sha256": artifact.artifact_sha256,
                    "manifest_ref": manifest_ref,
                    "glue_origin": glue.origin.value,
                    "execution_logging": recipe.execution_logging,
                    "plan_fingerprint": plan.plan_fingerprint,
                    "planning_audit_ref": plan.audit_ref,
                    "planning_strategy": plan.planning_strategy.value,
                    "experience_refs": list(plan.experience_refs),
                    "experience_set_version": plan.experience_set_version,
                    "learning_snapshot_ref": plan.learning_snapshot_ref,
                    "experience_proposal_ref": result.experience_proposal_ref,
                    "build_id": artifact.build_id,
                    "source_digest": artifact.source_digest,
                    "verification_run_id": report.run_id,
                    "verification_ref": report.telemetry.source_ref,
                },
            )
            return result
        except LeaseLostError:
            raise
        except Exception as exc:
            # claim 之后的任何未预期错误都必须留下可学习的终态，避免永久
            # IN_PROGRESS；fencing/租约丢失本身仍向上抛出，不允许僵尸提交。
            taxonomy = self._taxonomy_for_exception(exc)
            keeper.stop_and_check()
            record = self._state.complete_failure(
                claim.record_id,
                worker_id=request.worker_id,
                taxonomy=taxonomy,
            )
            self._emit_failure(record)
            raise
        finally:
            if keeper._thread.is_alive():
                keeper.cancel()

    def produce_batch(
        self,
        request: ProductionRequest,
        options: BatchOptions,
    ) -> ProductionBatchResult:
        request = replace(request, run_id=request.run_id or new_run_id())
        batch_id = uuid4().hex
        attempts: list[BatchAttemptResult] = []
        excluded: list[PlannedComposition] = []
        stopped = False
        self._emit(
            "sample_factory_batch_started",
            {
                "batch_id": batch_id,
                "requested_count": options.sample_count,
                "max_attempts": options.max_attempts,
            },
        )
        for attempt_number in range(1, options.max_attempts + 1):
            if sum(item.newly_produced for item in attempts) >= options.sample_count:
                break
            if self._stop_requested(request):
                stopped = True
                self._emit_stop_acknowledged("批量尝试间", batch_id=batch_id)
                break
            seed = request.context.seed + attempt_number - 1
            workspace_ref = self._batch_workspace_ref(
                request.workspace_ref, batch_id, attempt_number
            )
            attempt_id = new_attempt_id()
            attempt_request = replace(
                request,
                context=request.context.model_copy(update={"seed": seed}),
                workspace_ref=workspace_ref,
                excluded_compositions=tuple(excluded),
                batch_id=batch_id,
                batch_attempt=attempt_number,
                attempt_id=attempt_id,
                accepted_plan_sink=lambda plan: excluded.append(plan.composition),
            )
            self._emit(
                "sample_factory_batch_attempt_started",
                {
                    "batch_id": batch_id,
                    "attempt": attempt_number,
                    "attempt_id": attempt_id,
                    "seed": seed,
                    "workspace_ref": workspace_ref,
                },
            )
            try:
                result = self.produce(attempt_request)
            except ProductionStopped as exc:
                stopped = True
                attempt = BatchAttemptResult(
                    attempt_number=attempt_number,
                    seed=seed,
                    workspace_ref=workspace_ref,
                    error_type=type(exc).__name__,
                    error=str(exc),
                    attempt_id=attempt_id,
                )
                attempts.append(attempt)
                self._emit(
                    "sample_factory_batch_attempt_finished",
                    {
                        "batch_id": batch_id,
                        "attempt": attempt_number,
                        "attempt_id": attempt_id,
                        "newly_produced": False,
                        "error_type": attempt.error_type,
                        "error": attempt.error,
                        "stopped": True,
                    },
                )
                break
            except (PlanningAuditError, LeaseLostError):
                raise
            except SampleFactoryError as exc:
                attempt = BatchAttemptResult(
                    attempt_number=attempt_number,
                    seed=seed,
                    workspace_ref=workspace_ref,
                    error_type=type(exc).__name__,
                    error=str(exc),
                    attempt_id=attempt_id,
                )
                attempts.append(attempt)
                self._emit(
                    "sample_factory_batch_attempt_finished",
                    {
                        "batch_id": batch_id,
                        "attempt": attempt_number,
                        "attempt_id": attempt_id,
                        "newly_produced": False,
                        "error_type": attempt.error_type,
                        "error": attempt.error,
                    },
                )
                if not options.continue_on_failure:
                    break
                continue

            attempt = BatchAttemptResult(
                attempt_number=attempt_number,
                seed=seed,
                workspace_ref=workspace_ref,
                result=result,
                attempt_id=attempt_id,
            )
            attempts.append(attempt)
            self._emit(
                "sample_factory_batch_attempt_finished",
                {
                    "batch_id": batch_id,
                    "attempt": attempt_number,
                    "attempt_id": attempt_id,
                    "newly_produced": attempt.newly_produced,
                    "status": (
                        None if result.record is None else result.record.status.value
                    ),
                    "produced_count": sum(item.newly_produced for item in attempts),
                    "plan_fingerprint": (
                        None if result.plan is None else result.plan.plan_fingerprint
                    ),
                    "combination_fingerprint": (
                        None
                        if result.plan is None
                        else result.plan.combination_fingerprint
                    ),
                },
            )
            if not attempt.newly_produced and not options.continue_on_failure:
                break

        batch_result = ProductionBatchResult(
            batch_id=batch_id,
            requested_count=options.sample_count,
            max_attempts=options.max_attempts,
            attempts=tuple(attempts),
            stopped=stopped,
            run_id=request.run_id,
        )
        self._emit(
            "sample_factory_batch_finished",
            {
                "batch_id": batch_id,
                "requested_count": options.sample_count,
                "produced_count": batch_result.produced_count,
                "attempt_count": len(batch_result.attempts),
                "exhausted": batch_result.exhausted,
                "stopped": batch_result.stopped,
            },
        )
        return batch_result

    @staticmethod
    def _stop_requested(request: ProductionRequest) -> bool:
        return request.stop_token is not None and request.stop_token.is_stop_requested

    def _stop_if_requested(self, request: ProductionRequest, phase: str) -> None:
        if not self._stop_requested(request):
            return
        self._emit_stop_acknowledged(phase, batch_id=request.batch_id)
        assert request.stop_token is not None
        request.stop_token.raise_if_requested(phase)

    def _emit_stop_acknowledged(self, phase: str, *, batch_id: str | None) -> None:
        self._emit(
            "sample_factory_stop_acknowledged",
            {"phase": phase, "batch_id": batch_id},
        )

    @staticmethod
    def _batch_workspace_ref(base_ref: str, batch_id: str, attempt: int) -> str:
        suffix = base_ref.removeprefix("plugin-workspace://").strip("/")
        return (
            f"plugin-workspace://{suffix}/batch-{batch_id[:12]}-"
            f"{attempt:04d}"
        )

    def _compile_with_repairs(
        self,
        recipe: SampleRecipe,
        plan: PlannedRecipe,
        specs: tuple[AtomSpec, ...],
        glue: GlueResolution,
        request: ProductionRequest,
        *,
        max_attempts: int | None = None,
    ) -> tuple[BuiltSample, GlueResolution, str | None]:
        current = glue
        repairs = 0
        attempts = 0
        attempt_limit = max_attempts or self._max_compile_attempts
        repair_limit = attempt_limit - 1 if max_attempts is not None else self._repair_limit
        while attempts < attempt_limit:
            attempts += 1
            self._emit(
                "sample_factory_compile_attempt",
                {
                    "recipe_id": recipe.recipe_id,
                    "attempt": attempts,
                    "max_attempts": attempt_limit,
                    "glue_origin": current.origin.value,
                },
            )
            if request.source_snapshot_sink is not None:
                request.source_snapshot_sink(current, attempts, False)
            try:
                artifact = self._compiler.compile(
                    BuildRequest(
                        recipe=recipe,
                        atom_parameters=plan.atom_parameters,
                        glue=current,
                        build_target_ref=request.build_target_ref,
                        materialize_items=materialize_items_for(specs),
                        run_id=request.run_id,
                        attempt_id=request.attempt_id,
                    )
                )
                artifact = BuiltSample.model_validate(
                    artifact.model_copy(
                        update={
                            "factory_run_id": request.run_id,
                            "factory_attempt_id": request.attempt_id,
                        }
                    ).model_dump(mode="python")
                )
                source_snapshot_ref = None
                if request.source_snapshot_sink is not None:
                    source_snapshot_ref = request.source_snapshot_sink(
                        current, attempts, True
                    )
                return artifact, current, source_snapshot_ref
            except CompilationFailure as exc:
                self._emit(
                    "sample_factory_compile_failed",
                    {
                        "recipe_id": recipe.recipe_id,
                        "attempt": attempts,
                        "max_attempts": attempt_limit,
                        "diagnostics_ref": exc.diagnostics_ref,
                    },
                )
                if (
                    attempts >= attempt_limit
                    or repairs >= repair_limit
                    or exc.diagnostics_ref is None
                ):
                    raise
                if current.origin is GlueOrigin.TEMPLATE:
                    current = self._glue.resolve(
                        recipe,
                        specs,
                        plan.atom_parameters,
                        workspace_ref=request.workspace_ref,
                        build_target_ref=request.build_target_ref,
                        force_agent=True,
                    )
                else:
                    current = self._glue.repair(
                        current,
                        recipe,
                        specs,
                        plan.atom_parameters,
                        workspace_ref=request.workspace_ref,
                        build_target_ref=request.build_target_ref,
                        diagnostics_ref=exc.diagnostics_ref,
                    )
                self._emit(
                    "sample_factory_glue_repair",
                    {
                        "recipe_id": recipe.recipe_id,
                        "attempt": attempts,
                        "next_attempt": attempts + 1,
                        "diagnostics_ref": exc.diagnostics_ref,
                    },
                )
                repairs += 1
        raise CompilationFailure(
            f"编译尝试达到上限（{attempt_limit}）",
            diagnostics_ref=None,
        )

    def _manifest_entry(
        self,
        request: ProductionRequest,
        recipe: SampleRecipe,
        parameters: dict[str, object],
        digest: str,
        artifact: BuiltSample,
        published: PublishedArtifact,
        truth: FunctionalTruth,
        annotation: dict[str, object],
    ) -> RegressionManifestEntry:
        mode = recipe.pointer_mode
        deployment = DeploymentFingerprint(
            mode=mode,
            argv_env_snapshot=request.runtime_param_snapshot_ref,
            note=(
                "runtime-param deployment snapshot is secret-referenced"
                if mode is PointerMode.RUNTIME_PARAM
                else "sample and deployment fingerprint are identical"
            ),
        )
        return RegressionManifestEntry(
            sample_id=f"{digest[:8]}-{artifact.artifact_sha256[:12]}",
            sample_sha256=artifact.artifact_sha256,
            artifact_ref=published.artifact_ref,
            deployment_fp=deployment,
            ph_sequence=recipe.ph_ids,
            attck_ids=self._catalog.coverage.attack_ids_for(recipe.ph_ids),
            parameters_canonical=parameters,
            profile_id=request.context.profile.profile_id,
            toolchain_fp=artifact.toolchain_fp,
            telemetry_truth=truth.telemetry_summary(),
            expected_detection=annotation,
            lineage_parent=request.parent_id,
            regression_set_version=request.regression_set_version,
        )

    @staticmethod
    def _preflight(request: ProductionRequest) -> None:
        if not isinstance(request.execution_logging, bool):
            raise ValueError("execution_logging 必须是布尔值")
        if not request.approved:
            raise FactoryDenied("样本生产必须先获人工审批")
        if not request.worker_id.strip() or not request.regression_set_version.strip():
            raise ValueError("worker_id / regression_set_version 不得为空")
        if not request.workspace_ref.startswith("plugin-workspace://"):
            raise ValueError("workspace_ref 必须是 plugin-workspace:// 引用")
        if not request.build_target_ref.startswith("build-target://"):
            raise ValueError("build_target_ref 必须是已登记 build-target:// 引用")
        if request.lease_ttl <= timedelta(seconds=3):
            raise ValueError("lease_ttl 必须大于 3 秒")
        if request.compile_attempt_limit is not None and request.compile_attempt_limit < 1:
            raise ValueError("compile_attempt_limit 必须至少为 1")
        if request.context.production_policy not in {
            ProductionPolicy.BASELINE,
            ProductionPolicy.EVASION_FRONTIER,
        }:
            raise ValueError("未知 production_policy")

    @staticmethod
    def _validate_expected_detection(annotation: dict[str, object], recipe: SampleRecipe) -> None:
        if not str(annotation.get("source_ref", "")).strip():
            raise ValueError("expected_detection 必须带覆盖矩阵 source_ref")
        annotated = annotation.get("ph_ids")
        if not isinstance(annotated, list) or tuple(annotated) != recipe.ph_ids:
            raise ValueError("expected_detection.ph_ids 必须与 Recipe 有序 PH 序列一致")

    def _emit_failure(self, record: ComboRecord) -> None:
        self._emit(
            "sample_factory_failure",
            {
                "record_id": record.record_id,
                "failure_taxonomy": (
                    None if record.failure_taxonomy is None else record.failure_taxonomy.value
                ),
            },
        )

    @staticmethod
    def _taxonomy_for_exception(exc: Exception) -> FailureTaxonomy:
        if isinstance(exc, VerificationError):
            message = str(exc)
            if "退出码" in message or "崩溃" in message or "crash" in message.casefold():
                return FailureTaxonomy.RUNTIME_CRASH
            return FailureTaxonomy.TELEMETRY_MISS
        if isinstance(exc, BuildError):
            return FailureTaxonomy.COMPILE_FAIL
        return FailureTaxonomy.RUNTIME_CRASH

    def _emit(self, kind: str, data: dict[str, object]) -> None:
        if self._sink is not None:
            self._sink((kind, data))


__all__ = [
    "AIDrivenSampleFactory",
    "BatchAttemptResult",
    "BatchOptions",
    "ArtifactPublisher",
    "BuildRequest",
    "CompilerBackend",
    "ExpectedDetectionSource",
    "ProductionRequest",
    "ProductionBatchResult",
    "ProductionResult",
    "ProductionStopToken",
    "PublishedArtifact",
    "TelemetryContractSource",
    "VerificationBackend",
]
