from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from packages.llm.provider import LLMCompletion, LLMTool
from packages.sample_factory.ai_planner import FactoryPlanningAgent
from packages.sample_factory.catalog import AtomCatalog, CoverageRegistry
from packages.sample_factory.errors import (
    CompilationFailure,
    PlanningAuditError,
    PlanningError,
    ProductionStopped,
    VerificationError,
)
from packages.sample_factory.frontier import select_urgent_findings
from packages.sample_factory.glue import GlueCoordinator, GlueError
from packages.sample_factory.identity import canonical_parameters, combo_digest
from packages.sample_factory.manifest import ManifestRepository
from packages.sample_factory.models import (
    AgentWorkspaceResult,
    BuiltSample,
    ComboIntent,
    DeliveryMode,
    DetectionOutcome,
    EffectObservation,
    FactoryPlanningContext,
    GlueOrigin,
    HandoffMaterialize,
    PlannedComposition,
    ProductionPolicy,
    ProductionProfile,
    RawVerificationReport,
    TelemetryBundle,
    TelemetryEvent,
    TemplateStatus,
    TriggerMode,
)
from packages.sample_factory.pipeline import (
    AIDrivenSampleFactory,
    BatchOptions,
    ProductionRequest,
    ProductionStopToken,
    PublishedArtifact,
)
from packages.sample_factory.planning_audit import PlanningAuditRepository
from packages.sample_factory.postgres import POSTGRES_DDL
from packages.sample_factory.state import InMemoryComboStateStore
from packages.sample_factory.telemetry import FunctionalTruthEvaluator
from packages.schemas.enums import ResultClass

from tests.llm_tool_fakes import as_tool_completion
from tests.sample_factory_fixtures import (
    ARTIFACT_SHA,
    IMPLANT_SHA,
    PROFILE_ID,
    atom_specs,
    catalog,
    provenance,
    telemetry_contracts,
)


def _composition(*, extra: dict[str, object] | None = None) -> str:
    value: dict[str, object] = {
        "ph_ids": ["PH-IA01", "PH-OB05", "PH-IN04"],
        "carrier": "atom.ia.document",
        "loader_atoms": ["atom.ob.decode"],
        "execution_atoms": ["atom.in.apc"],
        "atom_parameters": {
            "atom.ia.document": {"container": "docm"},
            "atom.ob.decode": {"codec": "rc4"},
            "atom.in.apc": {"target": "notepad.exe"},
        },
        "evasion_tier": "E2",
        "pointer_mode": None,
        "rationale": "cover required rows with compatible handoffs",
    }
    value.update(extra or {})
    return json.dumps(value)


class FakeCompletionClient:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.calls: list[list[dict[str, object]]] = []
        self.tool_requests: list[list[LLMTool]] = []

    def complete_tool_with_metadata(self, messages, tools: list[LLMTool], **kwargs) -> LLMCompletion:
        del kwargs
        self.calls.append(messages)
        self.tool_requests.append(tools)
        return as_tool_completion(self.responses.pop(0), tools, call_index=len(self.calls))


def _context(*, policy: ProductionPolicy = ProductionPolicy.BASELINE) -> FactoryPlanningContext:
    return FactoryPlanningContext(
        candidate_ph_ids=("PH-IA01", "PH-OB05", "PH-IN04"),
        required_ph_ids=("PH-IA01", "PH-IN04"),
        production_policy=policy,
        profile=ProductionProfile(
            profile_id=PROFILE_ID,
            env_detail={"os_build": "22631", "sysmon": "15"},
            security_product_enabled=False,
            no_edr_control=True,
            sensors_ready=True,
        ),
        delivery=DeliveryMode.MOTW_STAMPED,
        trigger_mode=TriggerMode.LAB_TRIGGER,
        implant_sha256=IMPLANT_SHA,
        implant_format="shellcode",
        seed=42,
    )


def _handoff_only_catalog() -> AtomCatalog:
    execution = atom_specs()[2].model_copy(
        update={"atom_id": "atom.in.apc_early_bird"}
    )
    payload = atom_specs()[1].model_copy(
        update={
            "atom_id": "atom.payload.msf_calc_x64",
            "ph_ids": (),
            "attck_ids": (),
            "param_domains": {},
            "required_capabilities": (),
            "provided_capabilities": ("cap.payload.shellcode",),
            "telemetry_contract_ref": None,
            "requires_implant": False,
            "materialize": HandoffMaterialize.EMBED_AT_BUILD,
            "artifact_ref": "payload://x64/msf_calc_x64",
        }
    )
    result = AtomCatalog(CoverageRegistry({"PH-IN04": ("T1055.004",)}))
    # Register in filesystem-like lexical order to prove the prompt reorders by stage.
    result.register(execution, provenance())
    result.register(payload, provenance())
    return result


def _handoff_context() -> FactoryPlanningContext:
    return FactoryPlanningContext(
        candidate_ph_ids=("PH-IN04",),
        required_ph_ids=("PH-IN04",),
        production_policy=ProductionPolicy.BASELINE,
        profile=ProductionProfile(
            profile_id=PROFILE_ID,
            security_product_enabled=False,
            no_edr_control=True,
            sensors_ready=True,
        ),
        delivery=DeliveryMode.MOTW_STAMPED,
        trigger_mode=TriggerMode.LAB_TRIGGER,
        seed=42,
    )


def _handoff_composition(**updates: object) -> str:
    value: dict[str, object] = {
        "ph_ids": ["PH-IN04"],
        "carrier": None,
        "loader_atoms": ["atom.payload.msf_calc_x64"],
        "execution_atoms": ["atom.in.apc_early_bird"],
        "atom_parameters": {
            "atom.payload.msf_calc_x64": {},
            "atom.in.apc_early_bird": {"target": "notepad.exe"},
        },
        "evasion_tier": "E1",
        "pointer_mode": None,
        "rationale": "close shellcode handoff before the execution atom",
    }
    value.update(updates)
    return json.dumps(value)


class FactoryPlanningAgentTest(unittest.TestCase):
    def test_planner_retries_empty_model_content_with_specific_feedback(self) -> None:
        client = FakeCompletionClient(["", _composition()])

        result = FactoryPlanningAgent(client, catalog(), retry_limit=2).plan(_context())

        self.assertEqual("E2", result.recipe.evasion_tier)
        self.assertIn("submit_planned_composition", client.calls[1][-1]["content"])
        self.assertIn("submit_planned_composition", client.calls[0][0]["content"])
        self.assertEqual(
            ["system", "user", "user"],
            [message["role"] for message in client.calls[1]],
        )

    def test_planner_surfaces_safe_empty_response_diagnostics(self) -> None:
        class MetadataThenSuccess:
            def __init__(self) -> None:
                self.calls: list[list[dict[str, object]]] = []

            def complete_tool_with_metadata(
                self, messages, tools: list[LLMTool], **kwargs
            ) -> LLMCompletion:
                del kwargs
                self.calls.append([dict(message) for message in messages])
                if len(self.calls) == 1:
                    return LLMCompletion(
                        content="",
                        finish_reason="length",
                        prompt_tokens=1800,
                        completion_tokens=4096,
                        reasoning_tokens=4096,
                        reasoning_content_chars=12000,
                    )
                return as_tool_completion(
                    LLMCompletion(content=_composition(), finish_reason="tool_calls"),
                    tools,
                    call_index=len(self.calls),
                )

        client = MetadataThenSuccess()
        events: list[tuple[str, dict[str, object]]] = []

        result = FactoryPlanningAgent(
            client, catalog(), retry_limit=2, sink=events.append
        ).plan(_context())

        self.assertEqual("E2", result.recipe.evasion_tier)
        first_output = next(
            data
            for kind, data in events
            if kind == "sample_factory_planner_model_output" and data["turn"] == 1
        )
        self.assertIn("finish_reason=length", first_output["content"])
        self.assertIn("reasoning_tokens=4096", first_output["content"])
        first_feedback = next(
            data
            for kind, data in events
            if kind == "sample_factory_planner_feedback" and data["turn"] == 1
        )
        self.assertIn("reasoning_chars=12000", first_feedback["content"])
        self.assertEqual(
            ["system", "user", "user"],
            [message["role"] for message in client.calls[1]],
        )

    def test_planner_retries_transient_llm_timeout(self) -> None:
        class TimeoutThenSuccess:
            def __init__(self) -> None:
                self.calls = 0

            def complete_tool_with_metadata(self, messages, tools: list[LLMTool], **kwargs):
                del messages, kwargs
                self.calls += 1
                if self.calls == 1:
                    raise TimeoutError("simulated read timeout")
                return as_tool_completion(_composition(), tools, call_index=self.calls)

        client = TimeoutThenSuccess()
        events: list[tuple[str, dict[str, object]]] = []
        result = FactoryPlanningAgent(
            client,
            catalog(),
            retry_limit=2,
            sink=events.append,
        ).plan(_context())

        self.assertEqual(2, client.calls)
        self.assertEqual("E2", result.recipe.evasion_tier)
        timeout_feedback = [
            data
            for kind, data in events
            if kind == "sample_factory_planner_feedback"
        ]
        self.assertEqual("timeout", timeout_feedback[0]["reason"])
        self.assertIn("simulated read timeout", timeout_feedback[0]["content"])

    def test_strict_plan_is_projected_to_valid_recipe(self) -> None:
        client = FakeCompletionClient([_composition()])
        events: list[tuple[str, dict[str, object]]] = []
        result = FactoryPlanningAgent(client, catalog(), sink=events.append).plan(_context())
        self.assertEqual("sf-", result.recipe.recipe_id[:3])
        self.assertEqual(
            ("atom.ia.document", "atom.ob.decode", "atom.in.apc"),
            result.recipe.atom_ids,
        )
        prompt_payload = json.loads(client.calls[0][1]["content"])
        self.assertNotIn("command", prompt_payload)
        self.assertNotIn("args", prompt_payload)
        schema = client.tool_requests[0][0].parameters
        carrier_schema = schema["properties"]["carrier"]
        self.assertIn("^atom", json.dumps(carrier_schema))
        model_event = next(
            data
            for kind, data in events
            if kind == "sample_factory_planner_model_output"
        )
        self.assertEqual(1, model_event["turn"])
        self.assertIn("carrier=atom.ia.document", model_event["content"])
        self.assertNotIn("notepad.exe", model_event["content"])

    def test_unknown_command_field_is_rejected_then_retried(self) -> None:
        bad = _composition(extra={"shell_command": "not-allowed"})
        client = FakeCompletionClient([bad, _composition()])
        result = FactoryPlanningAgent(client, catalog()).plan(_context())
        self.assertEqual(2, len(client.calls))
        self.assertEqual("E2", result.recipe.evasion_tier)
        self.assertIn("未通过控制面门禁", client.calls[1][-1]["content"])

    def test_frontier_policy_rejects_low_tier_plan(self) -> None:
        client = FakeCompletionClient([_composition(), _composition()])
        with self.assertRaises(PlanningError):
            FactoryPlanningAgent(client, catalog()).plan(
                _context(policy=ProductionPolicy.EVASION_FRONTIER)
            )

    def test_role_contract_corrects_output_contract_used_as_carrier(self) -> None:
        client = FakeCompletionClient(
            [_handoff_composition(carrier="exe"), _handoff_composition()]
        )

        result = FactoryPlanningAgent(client, _handoff_only_catalog()).plan(
            _handoff_context()
        )

        self.assertIsNone(result.recipe.carrier)
        self.assertEqual(
            ("atom.payload.msf_calc_x64", "atom.in.apc_early_bird"),
            result.recipe.atom_ids,
        )
        payload = json.loads(client.calls[0][1]["content"])
        self.assertEqual([], payload["selection_contract"]["carrier_atom_ids"])
        self.assertEqual(
            ["atom.payload.msf_calc_x64"],
            payload["selection_contract"]["loader_atom_ids"],
        )
        self.assertEqual(
            ["loader_atom", "execution_atom"],
            [plugin["role"] for plugin in payload["plugins"]],
        )
        self.assertIn("output_contract", client.calls[1][-1]["content"])

    def test_role_contract_corrects_atom_reused_across_slots(self) -> None:
        duplicate = _handoff_composition(
            loader_atoms=["atom.in.apc_early_bird"],
            execution_atoms=["atom.in.apc_early_bird"],
            atom_parameters={
                "atom.in.apc_early_bird": {"target": "notepad.exe"}
            },
        )
        client = FakeCompletionClient([duplicate, _handoff_composition()])

        result = FactoryPlanningAgent(client, _handoff_only_catalog()).plan(
            _handoff_context()
        )

        self.assertEqual(2, len(client.calls))
        self.assertEqual(
            ("atom.payload.msf_calc_x64",), result.recipe.loader_atoms
        )
        self.assertIn("跨角色重复", client.calls[1][-1]["content"])

    def test_system_prompt_requires_param_domain_values(self) -> None:
        client = FakeCompletionClient([_composition()])

        FactoryPlanningAgent(client, catalog()).plan(_context())

        prompt = client.calls[0][0]["content"]
        self.assertEqual("system", client.calls[0][0]["role"])
        self.assertIn("只能从 plugins[].param_domains 同名枚举取", prompt)
        self.assertIn("换合法 atom_parameters 即新组合", prompt)
        self.assertIn("prefer_unused_values", prompt)
        self.assertIn("attack_chain_templates", prompt)
        self.assertIn("IT→OB→EX→IN", prompt)
        self.assertIn("轮换不同 PH 族前缀", prompt)
        payload = json.loads(client.calls[0][1]["content"])
        contract = payload["selection_contract"]
        self.assertTrue(contract["atom_parameters_values_must_be_in_param_domains"])
        self.assertTrue(contract["changing_atom_parameters_creates_new_combination"])
        self.assertTrue(contract["prefer_unused_param_values_before_changing_atom_graph"])
        self.assertTrue(contract["prefer_attack_chain_templates_when_capability_closes"])
        self.assertTrue(contract["diversify_across_ph_families"])
        self.assertTrue(contract["single_atom_only_when_no_multi_atom_path"])
        templates = payload["attack_chain_templates"]
        self.assertTrue(templates)
        self.assertIn("template_id", templates[0])
        self.assertIn("family_sequence", templates[0])
        self.assertGreaterEqual(len(payload["capability_paths"]), 1)

    def test_parameter_diversity_drops_used_enum_values(self) -> None:
        excluded = PlannedComposition.model_validate(json.loads(_composition()))
        client = FakeCompletionClient(
            [
                _composition(
                    extra={
                        "atom_parameters": {
                            "atom.ia.document": {"container": "lnk"},
                            "atom.ob.decode": {"codec": "xor"},
                            "atom.in.apc": {"target": "werfault.exe"},
                        }
                    }
                )
            ]
        )

        FactoryPlanningAgent(client, catalog()).plan(
            _context(), excluded_compositions=(excluded,)
        )

        payload = json.loads(client.calls[0][1]["content"])
        by_id = {item["atom_id"]: item for item in payload["parameter_diversity"]}
        self.assertEqual(["lnk"], by_id["atom.ia.document"]["prefer_unused_values"]["container"])
        self.assertEqual(["xor"], by_id["atom.ob.decode"]["prefer_unused_values"]["codec"])
        self.assertEqual(
            ["werfault.exe"], by_id["atom.in.apc"]["prefer_unused_values"]["target"]
        )
        self.assertEqual([], by_id["atom.in.apc"]["exhausted_keys"])


class FakeCodingAgent:
    def __init__(self) -> None:
        self.tasks = []

    def run(self, task):
        self.tasks.append(task)
        return AgentWorkspaceResult(
            session_ref=f"agent-session://{len(self.tasks)}",
            workspace_ref=task.workspace_ref,
            changed_files=("generated/glue.cpp",),
            source_digest=f"{len(self.tasks):064x}",
        )


class GlueCoordinatorTest(unittest.TestCase):
    def test_agent_fallback_repair_and_template_promotion_use_function_truth(self) -> None:
        agent = FakeCodingAgent()
        glue = GlueCoordinator(agent)
        planned = FactoryPlanningAgent(FakeCompletionClient([_composition()]), catalog()).plan(
            _context()
        )
        recipe = planned.recipe
        resolved = glue.resolve(
            recipe,
            atom_specs(),
            planned.atom_parameters,
            workspace_ref="plugin-workspace://run-1",
            build_target_ref="build-target://windows-x64",
        )
        self.assertEqual(GlueOrigin.AGENT, resolved.origin)
        repaired = glue.repair(
            resolved,
            recipe,
            atom_specs(),
            planned.atom_parameters,
            workspace_ref="plugin-workspace://run-1",
            build_target_ref="build-target://windows-x64",
            diagnostics_ref="build-diagnostics://run-1/1",
        )
        self.assertEqual(resolved.session_ref, agent.tasks[-1].repair_of_session)
        for _ in range(10):
            stats = glue.record_functional_truth(repaired, v2_passed=True, v3_passed=True)
        self.assertEqual(TemplateStatus.VERIFIED, stats.status)
        glue.promote(
            repaired.signature,
            template_ref="glue-template://approved/signature-1",
            source_digest="d" * 64,
        )
        cached = glue.resolve(
            recipe,
            atom_specs(),
            planned.atom_parameters,
            workspace_ref="plugin-workspace://run-2",
            build_target_ref="build-target://windows-x64",
        )
        self.assertEqual(GlueOrigin.TEMPLATE, cached.origin)
        self.assertEqual(2, len(agent.tasks))

    def test_agent_cannot_report_build_output_as_source_change(self) -> None:
        class BadAgent:
            def run(self, task):
                return AgentWorkspaceResult(
                    session_ref="agent-session://bad",
                    workspace_ref=task.workspace_ref,
                    changed_files=("x64/Release/sample.exe",),
                    source_digest="d" * 64,
                )

        planned = FactoryPlanningAgent(FakeCompletionClient([_composition()]), catalog()).plan(
            _context()
        )
        recipe = planned.recipe
        with self.assertRaises(GlueError):
            GlueCoordinator(BadAgent()).resolve(
                recipe,
                atom_specs(),
                planned.atom_parameters,
                workspace_ref="plugin-workspace://run-bad",
                build_target_ref="build-target://windows-x64",
            )


class FakeCompiler:
    def __init__(self, *, fail_once: bool = False, always_fail: bool = False) -> None:
        self.fail_once = fail_once
        self.always_fail = always_fail
        self.calls = []

    def compile(self, request):
        self.calls.append(request)
        if self.always_fail or (self.fail_once and len(self.calls) == 1):
            raise CompilationFailure(
                "compile failed",
                diagnostics_ref=f"build-diagnostics://run/{len(self.calls)}",
            )
        return BuiltSample(
            artifact_ref="build-artifact://run/sample",
            artifact_sha256=ARTIFACT_SHA,
            source_digest=request.glue.source_digest,
            toolchain_fp="clang-cl-17@pinned",
            build_id=f"build-{len(self.calls)}",
        )


class FakeVerifier:
    def collect(self, artifact, recipe, context):
        events = tuple(
            TelemetryEvent(
                run_id="sandbox-run-1",
                fields={"event_id": event_id, "atom_id": spec.atom_id},
            )
            for spec, event_id in zip(atom_specs(), (11, 7, 10), strict=True)
        )
        return RawVerificationReport(
            run_id="sandbox-run-1",
            profile_id=context.profile.profile_id,
            artifact_sha256=artifact.artifact_sha256,
            process_created=True,
            exit_code=0,
            telemetry=TelemetryBundle(
                run_id="sandbox-run-1",
                profile_id=context.profile.profile_id,
                source_ref="sandbox-report://sandbox-run-1",
                baseline_collected=True,
                events=events,
            ),
            effects=(
                EffectObservation(
                    check_id="loader-and-injector-health",
                    passed=True,
                    evidence_ref="sandbox-report://sandbox-run-1#effects",
                ),
            ),
        )


class ContractSource:
    def __init__(self) -> None:
        self.by_id = {item.contract_id: item for item in telemetry_contracts()}

    def get(self, contract_ref):
        return self.by_id[contract_ref]


class NoContractSource:
    def get(self, contract_ref):
        raise AssertionError(f"optional telemetry contract must not be loaded: {contract_ref}")


class ExpectedSource:
    def get(self, ph_ids, *, evasion_tier):
        return {
            "source_ref": "docs/coverage/procedure-host-ttp-coverage-matrix.md",
            "ph_ids": list(ph_ids),
            "evasion_tier": evasion_tier,
        }


class Publisher:
    def publish(self, artifact):
        return PublishedArtifact(
            artifact_ref="artifact://sample-store/" + artifact.artifact_sha256,
            artifact_sha256=artifact.artifact_sha256,
        )


class AIDrivenPipelineTest(unittest.TestCase):
    def _factory(
        self,
        tmp: str,
        compiler: FakeCompiler,
        *,
        max_compile_attempts: int | None = None,
        planning_audits: PlanningAuditRepository | None = None,
        catalog_override: AtomCatalog | None = None,
        contracts_override=None,
        planner_responses: list[str] | None = None,
    ):
        cat = catalog_override or catalog()
        agent = FakeCodingAgent()
        events = []
        state = InMemoryComboStateStore()
        factory = AIDrivenSampleFactory(
            planner=FactoryPlanningAgent(
                FakeCompletionClient(planner_responses or [_composition()]), cat
            ),
            catalog=cat,
            glue=GlueCoordinator(agent),
            compiler=compiler,
            verifier=FakeVerifier(),
            truth_evaluator=FunctionalTruthEvaluator(),
            contracts=contracts_override or ContractSource(),
            expected_detection=ExpectedSource(),
            publisher=Publisher(),
            state=state,
            manifests=ManifestRepository(Path(tmp) / "regression.jsonl"),
            planning_audits=planning_audits,
            sink=events.append,
            repair_limit=2,
            max_compile_attempts=max_compile_attempts,
        )
        return factory, state, agent, events

    def _request(
        self,
        *,
        execution_logging: bool = False,
        stop_token: ProductionStopToken | None = None,
    ) -> ProductionRequest:
        return ProductionRequest(
            context=_context(),
            worker_id="factory-worker-1",
            approved=True,
            high_risk_approved=False,
            workspace_ref="plugin-workspace://production-1",
            build_target_ref="build-target://windows-x64",
            regression_set_version="v1",
            lease_ttl=timedelta(minutes=5),
            execution_logging=execution_logging,
            stop_token=stop_token,
        )

    def test_ai_select_glue_repair_compile_verify_publish_manifest_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            compiler = FakeCompiler(fail_once=True)
            factory, state, agent, events = self._factory(tmp, compiler)
            result = factory.produce(self._request())

            self.assertTrue(result.produced)
            self.assertEqual(2, len(compiler.calls))
            self.assertEqual(2, len(agent.tasks))
            self.assertEqual("agent-session://1", agent.tasks[1].repair_of_session)
            self.assertEqual(1, len(ManifestRepository(Path(tmp) / "regression.jsonl").entries()))
            self.assertEqual(1, len(state.records()))
            self.assertEqual("sample_factory_success", events[-1][0])
            event_names = [event[0] for event in events]
            expected_order = [
                "sample_factory_planning_started",
                "sample_factory_plan_ready",
                "sample_factory_claim",
                "sample_factory_glue_started",
                "sample_factory_glue_ready",
                "sample_factory_compile_attempt",
                "sample_factory_verification_started",
                "sample_factory_verification_finished",
                "sample_factory_publish_started",
                "sample_factory_success",
            ]
            positions = [event_names.index(name) for name in expected_order]
            self.assertEqual(sorted(positions), positions)
            event_blob = json.dumps(events, ensure_ascii=False)
            self.assertNotIn("artifact_content", event_blob)
            self.assertNotIn("rationale", event_blob)

    def test_experience_extraction_failure_does_not_rollback_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            factory, state, _, events = self._factory(tmp, FakeCompiler())

            def fail_extraction(result, specs):
                del result, specs
                raise ValueError("synthetic extraction failure")

            result = factory.produce(
                replace(self._request(), experience_sink=fail_extraction)
            )

            self.assertTrue(result.produced)
            self.assertEqual("SUCCESS", state.records()[0].status.value)
            self.assertIn(
                "sample_factory_experience_extraction_failed",
                [name for name, _ in events],
            )
            self.assertEqual("sample_factory_success", events[-1][0])

    def test_execution_logging_reaches_glue_compiler_and_manifest_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            compiler = FakeCompiler()
            factory, state, agent, events = self._factory(tmp, compiler)

            result = factory.produce(self._request(execution_logging=True))

            self.assertTrue(result.produced)
            self.assertTrue(agent.tasks[0].execution_logging)
            self.assertTrue(compiler.calls[0].recipe.execution_logging)
            self.assertTrue(state.records()[0].parameters_canonical["execution_logging"])
            manifest = ManifestRepository(Path(tmp) / "regression.jsonl").entries()[0]
            self.assertTrue(manifest.parameters_canonical["execution_logging"])
            ready = next(data for name, data in events if name == "sample_factory_glue_ready")
            self.assertTrue(ready["execution_logging"])

    def test_planning_audit_failure_stops_before_claim_glue_and_compile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "planning-audits"
            blocker.write_text("not a directory", encoding="utf-8")
            compiler = FakeCompiler()
            factory, state, agent, _ = self._factory(
                tmp,
                compiler,
                planning_audits=PlanningAuditRepository(blocker),
            )

            with self.assertRaises(PlanningAuditError):
                factory.produce(self._request())

            self.assertEqual((), state.records())
            self.assertEqual([], agent.tasks)
            self.assertEqual([], compiler.calls)

    def test_reviewed_plugins_without_telemetry_contract_complete_v1_v3(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cat = AtomCatalog(
                CoverageRegistry(
                    {
                        "PH-IA01": ("T1566.001",),
                        "PH-OB05": ("T1027.013",),
                        "PH-IN04": ("T1055.004",),
                    }
                )
            )
            for spec in atom_specs():
                cat.register(
                    spec.model_copy(update={"telemetry_contract_ref": None}),
                    provenance(),
                )
            compiler = FakeCompiler()
            factory, state, _, _ = self._factory(
                tmp,
                compiler,
                catalog_override=cat,
                contracts_override=NoContractSource(),
            )

            result = factory.produce(self._request())

            self.assertTrue(result.produced)
            self.assertIsNotNone(result.run_id)
            self.assertTrue(result.run_id.startswith("run-"))
            self.assertIsNotNone(result.attempt_id)
            self.assertTrue(result.attempt_id.startswith("attempt-"))
            self.assertIsNotNone(result.truth)
            assert result.truth is not None
            self.assertFalse(result.truth.v2_applicable)
            self.assertFalse(result.truth.v2_passed)
            self.assertTrue(result.truth.v1_passed)
            self.assertTrue(result.truth.v3_passed)
            self.assertEqual(1, len(compiler.calls))
            self.assertEqual("SUCCESS", state.records()[0].status.value)

    def test_batch_produces_distinct_combinations_with_isolated_workspaces(self) -> None:
        alternate = _composition(
            extra={
                "atom_parameters": {
                    "atom.ia.document": {"container": "lnk"},
                    "atom.ob.decode": {"codec": "xor"},
                    "atom.in.apc": {"target": "werfault.exe"},
                },
                "evasion_tier": "E1",
                "rationale": "second legal parameter combination",
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            compiler = FakeCompiler()
            audits = PlanningAuditRepository(Path(tmp) / "planning-audits")
            factory, state, agent, events = self._factory(
                tmp,
                compiler,
                planning_audits=audits,
                planner_responses=[_composition(), alternate],
            )

            result = factory.produce_batch(
                self._request(),
                BatchOptions(sample_count=2, max_attempts=4),
            )

            self.assertTrue(result.produced)
            self.assertEqual(2, result.produced_count)
            self.assertEqual(2, len(result.attempts))
            self.assertIsNotNone(result.run_id)
            self.assertEqual(2, len({item.attempt_id for item in result.attempts}))
            self.assertTrue(
                all(
                    item.result is not None and item.result.run_id == result.run_id
                    for item in result.attempts
                )
            )
            self.assertEqual(2, len(state.records()))
            self.assertEqual(2, len(compiler.calls))
            combo_digests = [record.combo_digest for record in state.records()]
            self.assertEqual(2, len(set(combo_digests)))
            self.assertEqual(2, len(list(audits.root.glob("*.json"))))
            self.assertEqual(2, len({task.workspace_ref for task in agent.tasks}))
            self.assertEqual(
                [42, 43], [attempt.seed for attempt in result.attempts]
            )
            fingerprints = {
                attempt.result.plan.plan_fingerprint
                for attempt in result.attempts
                if attempt.result is not None and attempt.result.plan is not None
            }
            self.assertEqual(2, len(fingerprints))
            self.assertEqual("sample_factory_batch_finished", events[-1][0])

    def test_stop_after_current_sample_prevents_next_batch_attempt(self) -> None:
        alternate = _composition(
            extra={
                "atom_parameters": {
                    "atom.ia.document": {"container": "lnk"},
                    "atom.ob.decode": {"codec": "xor"},
                    "atom.in.apc": {"target": "werfault.exe"},
                },
                "rationale": "must not be planned after operator stop",
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            token = ProductionStopToken()
            compiler = FakeCompiler()
            factory, state, _, events = self._factory(
                tmp,
                compiler,
                planner_responses=[_composition(), alternate],
            )

            def stop_after_success(event: tuple[str, dict[str, object]]) -> None:
                events.append(event)
                if event[0] == "sample_factory_success":
                    token.request_stop()

            factory._sink = stop_after_success
            result = factory.produce_batch(
                self._request(stop_token=token),
                BatchOptions(sample_count=2, max_attempts=4),
            )

            self.assertTrue(result.stopped)
            self.assertFalse(result.produced)
            self.assertFalse(result.exhausted)
            self.assertEqual(1, result.produced_count)
            self.assertEqual(1, len(result.attempts))
            self.assertEqual(1, len(state.records()))
            self.assertEqual(1, len(compiler.calls))
            acknowledged = [
                data
                for name, data in events
                if name == "sample_factory_stop_acknowledged"
            ]
            self.assertEqual("批量尝试间", acknowledged[-1]["phase"])
            self.assertTrue(events[-1][1]["stopped"])

    def test_stop_after_planning_does_not_create_a_lease(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            token = ProductionStopToken()
            compiler = FakeCompiler()
            factory, state, agent, events = self._factory(tmp, compiler)

            def stop_when_plan_is_ready(event: tuple[str, dict[str, object]]) -> None:
                events.append(event)
                if event[0] == "sample_factory_plan_ready":
                    token.request_stop()

            factory._sink = stop_when_plan_is_ready

            with self.assertRaises(ProductionStopped) as raised:
                factory.produce(self._request(stop_token=token))

            self.assertEqual("组合租约前", raised.exception.phase)
            self.assertEqual((), state.records())
            self.assertEqual([], agent.tasks)
            self.assertEqual([], compiler.calls)
            self.assertEqual("sample_factory_stop_acknowledged", events[-1][0])

    def test_batch_exhausts_instead_of_counting_duplicate_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            compiler = FakeCompiler()
            factory, state, _, _ = self._factory(
                tmp,
                compiler,
                planner_responses=[
                    _composition(),
                    _composition(extra={"rationale": "same combination, new words"}),
                    _composition(extra={"rationale": "same combination again"}),
                ],
            )

            result = factory.produce_batch(
                self._request(),
                BatchOptions(sample_count=2, max_attempts=2),
            )

            self.assertFalse(result.produced)
            self.assertTrue(result.exhausted)
            self.assertEqual(1, result.produced_count)
            self.assertEqual(2, len(result.attempts))
            self.assertEqual("PlanningError", result.attempts[-1].error_type)
            self.assertEqual(1, len(state.records()))
            self.assertEqual(1, len(compiler.calls))

    def test_batch_continues_after_recoverable_verification_errors(self) -> None:
        alternate = _composition(
            extra={
                "atom_parameters": {
                    "atom.ia.document": {"container": "lnk"},
                    "atom.ob.decode": {"codec": "xor"},
                    "atom.in.apc": {"target": "werfault.exe"},
                },
                "rationale": "alternate after verifier failure",
            }
        )

        class BadVerifier:
            def collect(self, artifact, recipe, context):
                raise VerificationError("report has no marker")

        with tempfile.TemporaryDirectory() as tmp:
            compiler = FakeCompiler()
            factory, state, _, _ = self._factory(
                tmp,
                compiler,
                planner_responses=[_composition(), alternate],
            )
            factory._verifier = BadVerifier()

            result = factory.produce_batch(
                self._request(),
                BatchOptions(sample_count=1, max_attempts=2),
            )

            self.assertFalse(result.produced)
            self.assertTrue(result.exhausted)
            self.assertEqual(2, len(result.attempts))
            self.assertTrue(
                all(
                    attempt.error_type == "VerificationError"
                    for attempt in result.attempts
                )
            )
            self.assertEqual(2, len(state.records()))
            self.assertEqual(2, len(compiler.calls))
            self.assertEqual(
                2,
                len({record.combo_digest for record in state.records()}),
            )

    def test_compile_exhaustion_is_compile_fail_not_fake_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            factory, state, _, _ = self._factory(tmp, FakeCompiler(always_fail=True))
            result = factory.produce(self._request())
            self.assertFalse(result.produced)
            self.assertEqual("COMPILE_FAIL", result.record.failure_taxonomy.value)
            self.assertEqual(0, len(ManifestRepository(Path(tmp) / "regression.jsonl").entries()))
            self.assertEqual(1, len(state.records()))

    def test_explicit_compile_attempt_cap_controls_diagnostics_repairs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            compiler = FakeCompiler(always_fail=True)
            factory, state, agent, _ = self._factory(
                tmp, compiler, max_compile_attempts=4
            )
            result = factory.produce(self._request())
            self.assertFalse(result.produced)
            self.assertEqual(4, len(compiler.calls))
            self.assertEqual(4, len(agent.tasks))
            self.assertEqual("COMPILE_FAIL", result.record.failure_taxonomy.value)

    def test_publisher_integrity_error_closes_claim_as_compile_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:

            class BadPublisher:
                def publish(self, artifact):
                    return PublishedArtifact(
                        artifact_ref="artifact://sample-store/bad",
                        artifact_sha256="c" * 64,
                    )

            factory, state, _, _ = self._factory(tmp, FakeCompiler())
            factory._publisher = BadPublisher()
            with self.assertRaises(ValueError):
                factory.produce(self._request())
            self.assertEqual(1, len(state.records()))
            self.assertEqual("RUNTIME_CRASH", state.records()[0].failure_taxonomy.value)

    def test_verifier_contract_error_closes_claim_as_telemetry_miss(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:

            class BadVerifier:
                def collect(self, artifact, recipe, context):
                    raise VerificationError("report has no marker")

            factory, state, _, _ = self._factory(tmp, FakeCompiler())
            factory._verifier = BadVerifier()
            with self.assertRaises(VerificationError):
                factory.produce(self._request())
            self.assertEqual(1, len(state.records()))
            self.assertEqual("TELEMETRY_MISS", state.records()[0].failure_taxonomy.value)


class FrontierAndPostgresContractTest(unittest.TestCase):
    def _success_record(self, tier: str, result_class: ResultClass, *, profile_id: str):
        params = canonical_parameters({}, evasion_tier=tier, pointer_mode=None)
        ph_ids = ("PH-IN04",)
        state = InMemoryComboStateStore()
        claim = state.claim(
            ComboIntent(
                combo_digest=combo_digest(ph_ids, params),
                ph_sequence=ph_ids,
                parameters_canonical=params,
                profile_id=profile_id,
            ),
            worker_id="w",
            ttl=timedelta(minutes=5),
        )
        state.complete_success(
            claim.record_id,
            worker_id="w",
            toolchain_fp="tc",
            artifact_sha256=ARTIFACT_SHA,
            git_manifest_ref="m#s",
        )
        return state.write_detection(
            claim.record_id,
            DetectionOutcome(
                result_class=result_class,
                edr_id="edr-1",
                observed_at="2026-08-31T12:00:00Z",
            ),
        )

    def test_urgent_finding_needs_high_tier_miss_and_excludes_no_edr(self) -> None:
        baseline = self._success_record("E1", ResultClass.DETECTED, profile_id="edr-profile")
        frontier = self._success_record(
            "E4", ResultClass.MISSED_DETECTION, profile_id="edr-profile"
        )
        control = self._success_record("E4", ResultClass.MISSED_DETECTION, profile_id="no-edr")
        findings = select_urgent_findings(
            (baseline, frontier, control), no_edr_profile_ids=frozenset({"no-edr"})
        )
        self.assertEqual(1, len(findings))
        self.assertEqual(baseline.record_id, findings[0].baseline_record_id)

    def test_postgres_schema_contains_unique_lease_and_exact_taxonomy(self) -> None:
        self.assertIn("UNIQUE (combo_digest, profile_id)", POSTGRES_DDL)
        self.assertIn("lease_expires_at TIMESTAMPTZ", POSTGRES_DDL)
        for name in (
            "COMPILE_FAIL",
            "RUNTIME_CRASH",
            "TELEMETRY_MISS",
            "LOADER_FAIL",
            "SANDBOX_BLOCKED",
            "TIMEOUT",
            "ANTI_ANALYSIS_SKIP",
        ):
            self.assertIn(name, POSTGRES_DDL)


if __name__ == "__main__":
    unittest.main()
