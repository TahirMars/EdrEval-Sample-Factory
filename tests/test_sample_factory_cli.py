from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from packages.llm.provider import LLMTool
from packages.sample_factory.cas import ContentAddressedStore, ObjectNamespace
from packages.sample_factory.catalog import PH_MATRIX_ROW_COUNT
from packages.sample_factory.cli import (
    FactoryCliConfig,
    _backend_instance,
    load_inputs,
    main,
    preflight,
    start_plugin_intake,
    transfer_produced_samples,
)
from packages.sample_factory.errors import FactoryDenied
from packages.sample_factory.experience import ExperienceRecord, KnowledgeMaturity
from packages.sample_factory.identity import canonical_parameters, combo_digest
from packages.sample_factory.manifest import ManifestRepository
from packages.sample_factory.models import (
    BuiltSample,
    DeliveryMode,
    DeploymentFingerprint,
    EffectObservation,
    FactoryPlanningContext,
    ProductionPolicy,
    ProductionProfile,
    RawVerificationReport,
    RegressionManifestEntry,
    TelemetryBundle,
    TelemetryEvent,
    TriggerMode,
)
from packages.sample_factory.pipeline import PublishedArtifact
from packages.sample_factory.plugin_intake import (
    PluginIntakeDecision,
    PluginIntakeSession,
    PluginIntakeSource,
    PluginIntakeStatus,
)
from packages.sample_factory.plugin_models import (
    PluginBuildResult,
    PluginDecompositionPlan,
    PluginDependency,
    PluginOperation,
    PluginRequest,
    PluginSourceCandidate,
    PluginValidationResult,
    PortContract,
    TechniqueIntent,
)
from packages.sample_factory.state import InMemoryComboStateStore
from packages.sample_factory.tui import (
    CoverageCountBar,
    SampleFactoryTui,
    _display_width,
    plugin_run_matches_filter,
    plugin_verify_catalog_summary,
    plugin_verify_matches_queue,
    plugin_verify_option_prompt,
    plugin_verify_queue,
    plugin_verify_queue_label,
    produced_sample_matches_filter,
    produced_sample_matches_scope,
    produced_sample_option_prompt,
    produced_sample_status_label,
    published_attck_coverage,
    published_coverage_summary,
    published_ph_coverage,
    render_coverage_bars,
    render_coverage_detail,
)
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    ProgressBar,
    Select,
    SelectionList,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from tests.llm_tool_fakes import as_tool_completion
from tests.sample_factory_fixtures import (
    ARTIFACT_SHA,
    IMPLANT_SHA,
    PROFILE_ID,
    atom_specs,
    provenance,
    telemetry_contracts,
)
from tests.test_sample_factory_cas_export import _seed_telemetry_evidence


class _Verifier:
    def collect(self, artifact, recipe, context):
        events = tuple(
            TelemetryEvent(
                run_id="cli-sandbox-run",
                fields={"event_id": event_id, "atom_id": spec.atom_id},
            )
            for spec, event_id in zip(atom_specs(), (11, 7, 10), strict=True)
        )
        return RawVerificationReport(
            run_id="cli-sandbox-run",
            profile_id=context.profile.profile_id,
            artifact_sha256=artifact.artifact_sha256,
            process_created=True,
            exit_code=0,
            telemetry=TelemetryBundle(
                run_id="cli-sandbox-run",
                profile_id=context.profile.profile_id,
                source_ref="sandbox-report://cli-sandbox-run",
                baseline_collected=True,
                events=events,
            ),
            effects=(
                EffectObservation(
                    check_id="loader-and-injector-health",
                    passed=True,
                    evidence_ref="sandbox-report://cli-sandbox-run#effects",
                ),
            ),
        )


class _Completion:
    def __init__(self) -> None:
        self.calls = 0

    def complete_tool_with_metadata(self, messages, tools: list[LLMTool], **kwargs):
        del kwargs
        self.calls += 1
        system = messages[0]["content"]
        if "组合规划器" in system:
            planning_input = json.loads(messages[1]["content"])
            alternate = bool(planning_input.get("excluded_combinations"))
            return as_tool_completion({
                    "ph_ids": ["PH-IA01", "PH-OB05", "PH-IN04"],
                    "carrier": "atom.ia.document",
                    "loader_atoms": ["atom.ob.decode"],
                    "execution_atoms": ["atom.in.apc"],
                    "atom_parameters": {
                        "atom.ia.document": {"container": "lnk" if alternate else "docm"},
                        "atom.ob.decode": {"codec": "xor" if alternate else "rc4"},
                        "atom.in.apc": {"target": "werfault.exe" if alternate else "notepad.exe"},
                    },
                    "evasion_tier": "E1" if alternate else "E2",
                    "pointer_mode": None,
                    "rationale": "CLI integration fixture",
            }, tools, call_index=self.calls)
        if not any(message.get("role") == "tool" for message in messages):
            return as_tool_completion({
                "action": "write_files",
                "files": [
                    {
                        "path": "generated/main.cpp",
                        "content": (
                            "int main() { /* CreateProcessW: notepad.exe or "
                            "werfault.exe; WaitForSingleObject */ return 0; }\n"
                        ),
                    }
                ],
                "rationale": "deterministic fixture glue",
            }, tools, call_index=self.calls)
        return as_tool_completion(
            {"action": "finish", "rationale": "fixture complete"},
            tools,
            call_index=self.calls,
        )


class _Compiler:
    def compile(self, request):
        return BuiltSample(
            artifact_ref="build-artifact://cli-test",
            artifact_sha256=ARTIFACT_SHA,
            source_digest=request.glue.source_digest,
            toolchain_fp="cli-test-compiler@pinned",
            build_id="cli-test-build",
        )


class _Publisher:
    def publish(self, artifact):
        return PublishedArtifact(
            artifact_ref=f"artifact://cli-test/{artifact.artifact_sha256}",
            artifact_sha256=artifact.artifact_sha256,
        )


def make_verifier() -> _Verifier:
    return _Verifier()


def make_completion() -> _Completion:
    return _Completion()


def make_state() -> InMemoryComboStateStore:
    return InMemoryComboStateStore()


def make_compiler() -> _Compiler:
    return _Compiler()


def make_publisher() -> _Publisher:
    return _Publisher()


class _PluginAuthor:
    def author(self, request, *, plugin_run_id):
        del plugin_run_id
        spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
        return PluginSourceCandidate(
            plugin_id=spec.atom_id,
            implementation_name=request.implementation_name,
            source_ref="plugin-source://cli-candidate",
            source_digest="d" * 64,
            changed_files=(
                f"src/{request.implementation_name}.h",
                f"src/{request.implementation_name}.cpp",
            ),
            atom_spec=spec,
            required_capabilities=request.intent.required_capabilities,
            provided_capabilities=request.intent.provided_capabilities,
            input_ports=request.intent.input_ports,
            output_ports=request.intent.output_ports,
        )


class _PluginCompiler:
    def compile(self, source, request, *, plugin_run_id):
        del request
        return PluginBuildResult(
            build_ref=f"plugin-build://{plugin_run_id}",
            artifact_ref=f"plugin-build-artifact://{plugin_run_id}/build1",
            artifact_sha256="e" * 64,
            source_digest=source.source_digest,
            implementation_source_digest="f" * 64,
            artifact_filename=f"{source.implementation_name}.lib",
            toolchain_fp="cli-plugin-compiler@pinned",
            build_id="build1",
        )


class _PluginHarness:
    def validate(self, source, build, request, *, plugin_run_id):
        del source, build
        return PluginValidationResult(
            harness_ref=request.harness_ref,
            contract_valid=True,
            atom_valid=True,
            behavior_valid=True,
            evidence_ref=f"plugin-evidence://{plugin_run_id}",
        )


def make_plugin_author() -> _PluginAuthor:
    return _PluginAuthor()


def make_plugin_compiler() -> _PluginCompiler:
    return _PluginCompiler()


def make_plugin_harness() -> _PluginHarness:
    return _PluginHarness()


class SampleFactoryCliTest(unittest.TestCase):
    def test_plugin_intake_uses_configured_target_and_run_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path, run_path, _ = self._factory_files(Path(tmp))
            coordinator = Mock()
            coordinator.start.return_value = "plugin-intake-session"

            with patch(
                "packages.sample_factory.cli._plugin_intake_coordinator",
                return_value=coordinator,
            ):
                result = start_plugin_intake(
                    config_path,
                    run_path,
                    description="Generate one authorized test plugin",
                    source_urls=(),
                )

            self.assertEqual("plugin-intake-session", result)
            kwargs = coordinator.start.call_args.kwargs
            self.assertEqual("build-target://plugin-cli-test", kwargs["build_target_ref"])
            self.assertEqual(PROFILE_ID, kwargs["profile_id"])

    def test_schema_is_machine_readable_and_does_not_persist_approval(self) -> None:
        stdout, stderr = StringIO(), StringIO()
        rc = main(["schema"], stdout=stdout, stderr=stderr)
        self.assertEqual(0, rc)
        self.assertEqual("", stderr.getvalue())
        payload = json.loads(stdout.getvalue())
        self.assertIn("backend_contracts", payload)
        self.assertNotIn("approved", payload["run"]["properties"])
        self.assertNotIn("high_risk_approved", payload["run"]["properties"])
        self.assertFalse(payload["run"]["properties"]["execution_logging"]["default"])
        self.assertIn("run_kind", payload["run"]["required"])
        self.assertIn("planning_strategy", payload["run"]["required"])
        self.assertIn("verification_config", payload["config"]["properties"])
        self.assertIn("runtime_root", payload["config"]["properties"])
        self.assertEqual(3, payload["config"]["properties"]["planner_retry_limit"]["default"])
        deployment_config = json.loads(
            Path("deployment/factory-config.json").read_text(encoding="utf-8")
        )
        self.assertEqual(16384, deployment_config["planner_max_tokens"])
        self.assertEqual(16384, deployment_config["glue_max_tokens"])
        self.assertEqual(64, deployment_config["glue_agent_max_turns"])
        batch_schema = payload["run"]["properties"]["batch"]
        self.assertIn("FactoryBatchSpec", json.dumps(batch_schema))

    def test_produce_requires_live_approval_before_reading_files(self) -> None:
        stdout, stderr = StringIO(), StringIO()
        rc = main(
            ["produce", "--config", "missing.json", "--run", "missing-run.json"],
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(4, rc)
        self.assertEqual("", stdout.getvalue())
        self.assertIn("--approve", stderr.getvalue())

    def test_init_layout_command_creates_v2_skeleton(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "factory"
            stdout, stderr = StringIO(), StringIO()

            rc = main(
                ["init-layout", "--root", str(root)],
                stdout=stdout,
                stderr=stderr,
            )

            self.assertEqual(0, rc, stderr.getvalue())
            result = json.loads(stdout.getvalue())
            self.assertEqual("sample-factory-layout-v2", result["schema_version"])
            self.assertFalse(result["catalog_ready"])
            self.assertTrue((root / "runtime" / "runs").is_dir())

    def test_artifact_verify_and_approved_export_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, _, _ = self._factory_files(root)
            source = root / "sample.bin"
            source.write_bytes(b"synthetic artifact")
            stored = ContentAddressedStore(root / "runtime").put_file(
                ObjectNamespace.ARTIFACTS, source
            )

            verify_out, verify_err = StringIO(), StringIO()
            verify_rc = main(
                [
                    "artifact-verify",
                    "--config",
                    str(config_path),
                    "--artifact-ref",
                    stored.object_ref,
                ],
                stdout=verify_out,
                stderr=verify_err,
            )
            self.assertEqual(0, verify_rc, verify_err.getvalue())
            self.assertTrue(json.loads(verify_out.getvalue())["verified"])

            export_out, export_err = StringIO(), StringIO()
            export_rc = main(
                [
                    "artifact-export",
                    "--config",
                    str(config_path),
                    "--artifact-ref",
                    stored.object_ref,
                    "--export-id",
                    "export-12345678",
                    "--filename",
                    "sample.exe",
                    "--approve",
                ],
                stdout=export_out,
                stderr=export_err,
            )
            self.assertEqual(0, export_rc, export_err.getvalue())
            exported = json.loads(export_out.getvalue())
            self.assertTrue(Path(exported["artifact_path"]).is_file())

    def test_sample_list_and_approved_transfer_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, _, _ = self._factory_files(root)
            sample_id = self._seed_produced_sample(root)

            listed_out, listed_err = StringIO(), StringIO()
            listed_rc = main(
                ["sample-list", "--config", str(config_path)],
                stdout=listed_out,
                stderr=listed_err,
            )
            self.assertEqual(0, listed_rc, listed_err.getvalue())
            listed = json.loads(listed_out.getvalue())
            self.assertEqual(1, len(listed["samples"]))
            self.assertEqual(sample_id, listed["samples"][0]["sample_id"])
            self.assertIsNone(listed["samples"][0]["export_status"])

            denied_out, denied_err = StringIO(), StringIO()
            denied_rc = main(
                [
                    "sample-transfer",
                    "--config",
                    str(config_path),
                    "--sample-id",
                    sample_id,
                ],
                stdout=denied_out,
                stderr=denied_err,
            )
            self.assertEqual(4, denied_rc)
            self.assertIn("审批", denied_err.getvalue())
            with self.assertRaises(FactoryDenied):
                transfer_produced_samples(config_path, [sample_id], approved=False)

            transfer_out, transfer_err = StringIO(), StringIO()
            transfer_rc = main(
                [
                    "sample-transfer",
                    "--config",
                    str(config_path),
                    "--sample-id",
                    sample_id,
                    "--approve",
                ],
                stdout=transfer_out,
                stderr=transfer_err,
            )
            self.assertEqual(0, transfer_rc, transfer_err.getvalue())
            transferred = json.loads(transfer_out.getvalue())["transferred"][0]
            artifact_path = Path(transferred["artifact_path"])
            self.assertTrue(artifact_path.is_file())
            self.assertEqual("published", artifact_path.parent.parent.name)
            sample_json = json.loads(
                (artifact_path.parent / "sample.json").read_text(encoding="utf-8")
            )
            self.assertEqual(sample_id, sample_json["sample_id"])
            checksums = json.loads(
                (artifact_path.parent / "checksums.json").read_text(encoding="utf-8")
            )
            self.assertTrue(
                (artifact_path.parent / "telemetry" / "telemetry-projection.json").is_file()
            )
            self.assertIn("telemetry/telemetry-projection.json", checksums)
            self.assertIn("telemetry/sample-logs/sample.jsonl", checksums)

            listed_again_out, listed_again_err = StringIO(), StringIO()
            listed_again_rc = main(
                ["sample-list", "--config", str(config_path)],
                stdout=listed_again_out,
                stderr=listed_again_err,
            )
            self.assertEqual(0, listed_again_rc, listed_again_err.getvalue())
            self.assertEqual(
                "published",
                json.loads(listed_again_out.getvalue())["samples"][0]["export_status"],
            )

    def test_sample_transfer_requires_telemetry_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, _, _ = self._factory_files(root)
            sample_id = self._seed_produced_sample(root, with_telemetry=False)
            stdout, stderr = StringIO(), StringIO()
            rc = main(
                [
                    "sample-transfer",
                    "--config",
                    str(config_path),
                    "--sample-id",
                    sample_id,
                    "--approve",
                ],
                stdout=stdout,
                stderr=stderr,
            )
            self.assertEqual(2, rc)
            self.assertIn("遥测证据", stderr.getvalue())

    def test_plugin_author_command_persists_behavior_valid_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, _, _ = self._factory_files(root)
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config.update(
                {
                    "plugin_authoring_backend_ref": "tests.test_sample_factory_cli:make_plugin_author",
                    "plugin_compiler_backend_ref": "tests.test_sample_factory_cli:make_plugin_compiler",
                    "plugin_harness_backend_ref": "tests.test_sample_factory_cli:make_plugin_harness",
                }
            )
            config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
            request_path = root / "plugin-request.json"
            request = PluginRequest(
                request_id="plugin-request-12345678",
                operation=PluginOperation.CREATE,
                implementation_name="EarlyApcInjection",
                intent=TechniqueIntent(
                    intent_id="intent-12345678",
                    ph_ids=("PH-IN04",),
                    role=atom_specs()[2].role,
                    required_capabilities=atom_specs()[2].required_capabilities,
                    provided_capabilities=atom_specs()[2].provided_capabilities,
                    input_ports=(
                        PortContract(
                            port_id="port.payload.input",
                            value_type="ByteBuffer",
                            semantic="ExecutablePayload",
                            architecture="x64",
                        ),
                    ),
                    parameter_domains=atom_specs()[2].param_domains,
                    architecture="x64",
                    safety_profile=atom_specs()[2].safety_profile,
                    source_refs=("https://example.invalid/reference",),
                ),
                build_target_ref="build-target://cli-test",
                harness_ref="plugin-harness://execution/windows-x64/v1",
                profile_id=PROFILE_ID,
            )
            request = request.model_copy(
                update={"build_target_ref": "build-target://plugin-cli-test"}
            )
            request_path.write_text(
                json.dumps(request.model_dump(mode="json"), ensure_ascii=False),
                encoding="utf-8",
            )
            stdout, stderr = StringIO(), StringIO()

            rc = main(
                [
                    "plugin-author",
                    "--config",
                    str(config_path),
                    "--request",
                    str(request_path),
                    "--approve",
                ],
                stdout=stdout,
                stderr=stderr,
            )

            self.assertEqual(0, rc, stderr.getvalue())
            result = json.loads(stdout.getvalue())
            self.assertEqual("behavior_valid", result["status"])
            roots = list((root / "runtime" / "plugin-runs").glob("*/*/*/plugin-run-*"))
            self.assertEqual(1, len(roots))
            state = json.loads((roots[0] / "state.json").read_text(encoding="utf-8"))
            self.assertEqual("SUCCEEDED", state["status"])

    def test_experience_import_list_and_search_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, _, _ = self._factory_files(root)
            record_path = root / "experience.json"
            record = ExperienceRecord(
                experience_id="experience-cli00001",
                version=1,
                maturity=KnowledgeMaturity.REPLAY_STABLE,
                ph_sequence=("PH-IN04",),
                atom_ids=("atom.in.apc",),
                capabilities=("cap.process.injection",),
                profile_ids=(PROFILE_ID,),
                architecture="x64",
                evidence_refs=("factory-run://run-12345678",),
                success_count=3,
                semantic_summary="CLI experience fixture",
            )
            record_path.write_text(
                json.dumps(record.model_dump(mode="json"), ensure_ascii=False),
                encoding="utf-8",
            )
            imported, errors = StringIO(), StringIO()
            rc = main(
                [
                    "experience-import",
                    "--config",
                    str(config_path),
                    "--record",
                    str(record_path),
                    "--approve",
                ],
                stdout=imported,
                stderr=errors,
            )
            self.assertEqual(0, rc, errors.getvalue())

            query_path = root / "query.json"
            query_path.write_text(
                json.dumps(
                    {
                        "strategy": "exploit",
                        "ph_ids": ["PH-IN04"],
                        "profile_id": PROFILE_ID,
                        "architecture": "x64",
                        "minimum_maturity": "replay_stable",
                    }
                ),
                encoding="utf-8",
            )
            searched, search_errors = StringIO(), StringIO()
            search_rc = main(
                [
                    "experience-search",
                    "--config",
                    str(config_path),
                    "--query",
                    str(query_path),
                ],
                stdout=searched,
                stderr=search_errors,
            )
            self.assertEqual(0, search_rc, search_errors.getvalue())
            payload = json.loads(searched.getvalue())
            self.assertEqual(
                "experience-cli00001", payload["candidates"][0]["experience"]["experience_id"]
            )

    def test_zero_argument_backend_factory_is_resolved_and_checked(self) -> None:
        backend = _backend_instance(
            "tests.test_sample_factory_cli:make_verifier",
            "test verifier",
            ("collect",),
        )
        self.assertTrue(callable(getattr(backend, "collect", None)))

    def test_builtin_and_custom_verification_backends_are_mutually_exclusive(self) -> None:
        required_paths = {
            name: Path("fixture")
            for name in (
                "coverage_matrix",
                "catalog_root",
                "runtime_root",
                "manifest_root",
            )
        }
        with self.assertRaises(ValueError):
            FactoryCliConfig(
                schema_version="factory-config-v2",
                **required_paths,
                verification_config=Path("vmware.json"),
                verification_backend_ref="tests.test_sample_factory_cli:make_verifier",
            )

    def test_v1_scattered_path_config_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FactoryCliConfig.model_validate(
                {
                    "coverage_matrix": "coverage.md",
                    "plugin_root": "factory",
                    "telemetry_contracts": "telemetry.json",
                    "build_targets": "build-targets.json",
                    "workspace_root": "workspaces",
                    "build_artifact_root": "build-artifacts",
                    "object_store_root": "object-store",
                    "manifest_path": "manifests/regression.jsonl",
                    "planning_audit_root": "planning-audits",
                }
            )

    def test_v2_layout_roots_must_not_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, run_path, _ = self._factory_files(root)
            payload = json.loads(config_path.read_text(encoding="utf-8"))
            payload["manifest_root"] = str(root / "runtime" / "manifests")
            config_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "不得相同或相互嵌套"):
                preflight(load_inputs(config_path, run_path))

    def test_payload_root_prefers_catalog_payloads(self) -> None:
        config = FactoryCliConfig(
            schema_version="factory-config-v2",
            coverage_matrix=Path("coverage.md"),
            catalog_root=Path("catalog"),
            runtime_root=Path("runtime"),
            manifest_root=Path("manifests"),
        )
        self.assertEqual(Path("catalog") / "payloads", config.payload_root)
        self.assertEqual(
            (
                Path("catalog") / "payloads",
                Path("runtime") / "store" / "inputs" / "payloads",
            ),
            config.payload_search_roots,
        )

    def test_explore_allows_cold_start_without_experience(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, run_path, _ = self._factory_files(root)
            payload = json.loads(run_path.read_text(encoding="utf-8"))
            payload["planning_strategy"] = "explore"
            run_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

            result = preflight(load_inputs(config_path, run_path))
            self.assertEqual("explore", result["planning_strategy"])
            self.assertEqual(0, result["experience_candidate_count"])

    def test_produce_command_runs_factory_pipeline_and_writes_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, run_path, manifest_path = self._factory_files(root)
            stdout, stderr = StringIO(), StringIO()
            rc = main(
                [
                    "produce",
                    "--config",
                    str(config_path),
                    "--run",
                    str(run_path),
                    "--approve",
                ],
                stdout=stdout,
                stderr=stderr,
            )
            self.assertEqual(0, rc, stderr.getvalue())
            result = json.loads(stdout.getvalue())
            self.assertTrue(result["produced"])
            self.assertEqual("SUCCESS", result["status"])
            self.assertTrue(result["run_id"].startswith("run-"))
            self.assertTrue(result["attempt_id"].startswith("attempt-"))
            self.assertIsNotNone(result["experience_proposal_ref"])
            self.assertTrue(Path(result["experience_proposal_ref"]).is_file())
            self.assertTrue(manifest_path.is_file())
            run_dirs = list((root / "runtime" / "runs").glob("*/*/*/run-*"))
            self.assertEqual(1, len(run_dirs))
            attempt_dirs = list((run_dirs[0] / "attempts").glob("0001-attempt-*"))
            self.assertEqual(1, len(attempt_dirs))
            audit_files = list((attempt_dirs[0] / "planning").glob("*.json"))
            self.assertEqual(1, len(audit_files))
            audit = json.loads(audit_files[0].read_text(encoding="utf-8"))
            self.assertEqual("sample-factory-planning-audit-v1", audit["schema_version"])
            self.assertEqual(
                result["planning_audit_ref"],
                f"planning-audit://{result['run_id']}/{result['attempt_id']}/{audit_files[0].name}",
            )
            self.assertEqual(result["run_id"], audit["run_id"])
            self.assertEqual(result["attempt_id"], audit["attempt_id"])
            events = [json.loads(line)["event"] for line in stderr.getvalue().splitlines()]
            self.assertIn("sample_factory_planning_started", events)
            self.assertEqual("sample_factory_success", events[-1])
            run_state = json.loads((run_dirs[0] / "state.json").read_text(encoding="utf-8"))
            self.assertEqual("SUCCEEDED", run_state["status"])
            self.assertTrue((attempt_dirs[0] / "result" / "result.json").is_file())
            self.assertTrue((attempt_dirs[0] / "source" / "generated-attempt-01").is_dir())
            self.assertTrue((attempt_dirs[0] / "source" / "final-build-input").is_dir())

            listed_out, listed_err = StringIO(), StringIO()
            listed_rc = main(
                ["run-list", "--config", str(config_path)],
                stdout=listed_out,
                stderr=listed_err,
            )
            self.assertEqual(0, listed_rc, listed_err.getvalue())
            self.assertEqual(
                result["run_id"], json.loads(listed_out.getvalue())["runs"][0]["run_id"]
            )

            shown_out, shown_err = StringIO(), StringIO()
            shown_rc = main(
                [
                    "run-show",
                    "--config",
                    str(config_path),
                    "--run-id",
                    result["run_id"],
                ],
                stdout=shown_out,
                stderr=shown_err,
            )
            self.assertEqual(0, shown_rc, shown_err.getvalue())
            shown = json.loads(shown_out.getvalue())
            self.assertEqual("SUCCEEDED", shown["state"]["status"])
            self.assertEqual(result["attempt_id"], shown["attempts"][0]["attempt_id"])

    def test_produce_command_runs_distinct_combination_batch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, run_path, _ = self._factory_files(root)
            run_data = json.loads(run_path.read_text(encoding="utf-8"))
            run_data["batch"] = {
                "sample_count": 2,
                "max_attempts": 3,
                "continue_on_failure": True,
            }
            run_path.write_text(json.dumps(run_data, ensure_ascii=False), encoding="utf-8")
            stdout, stderr = StringIO(), StringIO()

            rc = main(
                [
                    "produce",
                    "--config",
                    str(config_path),
                    "--run",
                    str(run_path),
                    "--approve",
                ],
                stdout=stdout,
                stderr=stderr,
            )

            self.assertEqual(0, rc, stderr.getvalue())
            result = json.loads(stdout.getvalue())
            self.assertTrue(result["batch"])
            self.assertEqual(2, result["requested_count"])
            self.assertEqual(2, result["produced_count"])
            self.assertEqual(2, len(result["attempts"]))
            self.assertTrue(result["run_id"].startswith("run-"))
            self.assertEqual(
                2,
                len({attempt["attempt_id"] for attempt in result["attempts"]}),
            )
            self.assertEqual(2, len(set(result["planning_audit_refs"])))
            run_dirs = list((root / "runtime" / "runs").glob("*/*/*/run-*"))
            self.assertEqual(1, len(run_dirs))
            self.assertEqual(
                2,
                len(list((run_dirs[0] / "attempts").glob("*/planning/*.json"))),
            )
            events = [json.loads(line)["event"] for line in stderr.getvalue().splitlines()]
            self.assertEqual("sample_factory_batch_started", events[0])
            self.assertEqual("sample_factory_batch_finished", events[-1])
            attempt_dirs = list((run_dirs[0] / "attempts").glob("*-attempt-*"))
            self.assertEqual(2, len(attempt_dirs))
            self.assertTrue(
                all((path / "source" / "final-build-input").is_dir() for path in attempt_dirs)
            )

    def _factory_files(self, root: Path) -> tuple[Path, Path, Path]:
        plugin_root = root / "catalog"
        for index, spec in enumerate(atom_specs()):
            plugin_dir = plugin_root / "plugins" / "dispatchable" / spec.atom_id
            source_dir = plugin_dir / "src"
            source_dir.mkdir(parents=True)
            source_name = f"atom-{index}.cpp"
            (source_dir / source_name).write_text(
                f"int atom_{index}() {{ return {index}; }}\n", encoding="utf-8"
            )
            (plugin_dir / "plugin.json").write_text(
                json.dumps(
                    {
                        "format_version": "sf-plugin-v1",
                        "spec": spec.model_dump(mode="json"),
                        "provenance": provenance().model_dump(mode="json"),
                        "source": {
                            "root": "src",
                            "files": [source_name],
                            "entry_point": "generated/main.cpp",
                            "lineage": "cli-integration-fixture",
                        },
                    }
                ),
                encoding="utf-8",
            )

        contracts_path = plugin_root / "telemetry" / "contracts.json"
        contracts_path.parent.mkdir(parents=True)
        contracts_path.write_text(
            json.dumps(
                {"contracts": [item.model_dump(mode="json") for item in telemetry_contracts()]}
            ),
            encoding="utf-8",
        )
        targets_path = plugin_root / "build-targets" / "build-targets.json"
        targets_path.parent.mkdir(parents=True)
        targets_path.write_text(
            json.dumps(
                {
                    "targets": [
                        {
                            "target_ref": "build-target://cli-test",
                            "argv_template": ["fakecc", "{source_root}", "{output_dir}"],
                            "artifact_relative": "sample.bin",
                            "toolchain_fp": "cli-test-compiler@pinned",
                        },
                        {
                            "target_ref": "build-target://plugin-cli-test",
                            "argv_template": ["fakecc", "{source_root}", "{output_dir}"],
                            "artifact_relative": "{implementation_name}.lib",
                            "toolchain_fp": "cli-plugin-test-compiler@pinned",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        manifest_path = root / "manifests" / "regression.jsonl"
        config_path = root / "factory-config.json"
        config_path.write_text(
            json.dumps(
                {
                    "schema_version": "factory-config-v2",
                    "coverage_matrix": str(
                        Path("docs/coverage/procedure-host-ttp-coverage-matrix.md").resolve()
                    ),
                    "catalog_root": str(plugin_root),
                    "runtime_root": str(root / "runtime"),
                    "manifest_root": str(manifest_path.parent),
                    "plugin_build_target_ref": "build-target://plugin-cli-test",
                    "completion_backend_ref": "tests.test_sample_factory_cli:make_completion",
                    "state_backend_ref": "tests.test_sample_factory_cli:make_state",
                    "verification_backend_ref": "tests.test_sample_factory_cli:make_verifier",
                    "compiler_backend_ref": "tests.test_sample_factory_cli:make_compiler",
                    "artifact_publisher_ref": "tests.test_sample_factory_cli:make_publisher",
                }
            ),
            encoding="utf-8",
        )
        run_path = root / "factory-run.json"
        context = FactoryPlanningContext(
            candidate_ph_ids=("PH-IA01", "PH-OB05", "PH-IN04"),
            required_ph_ids=("PH-IA01", "PH-IN04"),
            production_policy=ProductionPolicy.BASELINE,
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
        run_path.write_text(
            json.dumps(
                {
                    "run_kind": "sample_production",
                    "planning_strategy": "auto",
                    "context": context.model_dump(mode="json"),
                    "worker_id": "cli-worker-1",
                    "workspace_ref": "plugin-workspace://cli-run-1",
                    "build_target_ref": "build-target://cli-test",
                    "regression_set_version": "cli-v1",
                    "lease_ttl_seconds": timedelta(minutes=5).total_seconds(),
                }
            ),
            encoding="utf-8",
        )
        return config_path, run_path, manifest_path

    def _seed_produced_sample(self, root: Path, *, with_telemetry: bool = True) -> str:
        source = root / "produced.bin"
        source.write_bytes(b"produced sample artifact")
        stored = ContentAddressedStore(root / "runtime").put_file(
            ObjectNamespace.ARTIFACTS, source
        )
        params = canonical_parameters(
            {
                "atom.ia.document": {"container": "docm"},
                "atom.ob.decode": {"codec": "rc4"},
                "atom.in.apc": {"target": "notepad.exe"},
            },
            evasion_tier="E2",
            pointer_mode=None,
        )
        ph_ids = ("PH-IA01", "PH-OB05", "PH-IN04")
        digest = combo_digest(ph_ids, params)
        sample_id = f"{digest[:8]}-{stored.sha256[:12]}"
        ManifestRepository(root / "manifests" / "regression.jsonl").append(
            RegressionManifestEntry(
                sample_id=sample_id,
                sample_sha256=stored.sha256,
                artifact_ref=stored.object_ref,
                deployment_fp=DeploymentFingerprint(mode=None, note="no pointer"),
                ph_sequence=ph_ids,
                attck_ids=("T1566.001", "T1027.013", "T1055.004"),
                parameters_canonical=params,
                profile_id=PROFILE_ID,
                toolchain_fp="clang-cl-pinned",
                telemetry_truth={"v1_passed": True, "v2_passed": True, "v3_passed": True},
                expected_detection={
                    "source_ref": "docs/coverage/procedure-host-ttp-coverage-matrix.md",
                    "ph_ids": list(ph_ids),
                },
                regression_set_version="v1",
            )
        )
        if with_telemetry:
            _seed_telemetry_evidence(root / "runtime", stored.sha256)
        return sample_id


class PluginVerifySelectionLabelTest(unittest.TestCase):
    def test_option_prompt_leads_with_short_id_and_capabilities(self) -> None:
        item = {
            "plugin_run_id": "plugin-run-ea649a26ee24464bb9e311e98abf1c18",
            "implementation_name": "MsfCalcX64",
            "plugin_id": "atom.payload.msf_calc_x64",
            "lifecycle_status": "compile_valid",
            "ph_ids": [],
            "required_capabilities": [],
            "provided_capabilities": ["cap.payload.shellcode"],
        }
        prompt = plugin_verify_option_prompt(item)
        self.assertTrue(prompt.startswith("待验证 [ea649a26] MsfCalcX64"))
        self.assertIn("compile_valid", prompt)
        self.assertIn("provide=cap.payload.shellcode", prompt)
        self.assertEqual("validate", plugin_verify_queue(item))
        self.assertEqual("待验证", plugin_verify_queue_label(item))
        self.assertTrue(plugin_run_matches_filter(item, "ea649a26"))
        self.assertTrue(plugin_run_matches_filter(item, "shellcode"))
        self.assertTrue(plugin_run_matches_filter(item, "MsfCalc"))
        self.assertTrue(plugin_run_matches_filter(item, "待验证"))
        self.assertFalse(plugin_run_matches_filter(item, "PH-IN04"))

    def test_option_prompt_includes_superseded_history_count(self) -> None:
        item = {
            "plugin_run_id": "plugin-run-ea649a26ee24464bb9e311e98abf1c18",
            "implementation_name": "MsfCalcX64",
            "plugin_id": "atom.payload.msf_calc_x64",
            "lifecycle_status": "behavior_valid",
            "superseded_runs": 8,
            "ph_ids": [],
            "required_capabilities": [],
            "provided_capabilities": ["cap.payload.shellcode"],
        }
        self.assertIn("历史 8", plugin_verify_option_prompt(item))
        self.assertTrue(plugin_verify_option_prompt(item).startswith("待review "))
        self.assertEqual("review", plugin_verify_queue(item))
        self.assertTrue(plugin_verify_matches_queue(item, "work"))
        self.assertFalse(plugin_verify_matches_queue(item, "validate"))


class PluginVerifyQueueSummaryTest(unittest.TestCase):
    def test_catalog_summary_uses_counts_not_plugin_id_lists(self) -> None:
        runs = [
            {
                "plugin_id": "atom.ex.powershell",
                "lifecycle_status": "compile_valid",
                "catalog_status": None,
            },
            {
                "plugin_id": "atom.di.whoami",
                "lifecycle_status": "behavior_valid",
                "catalog_status": None,
            },
            {
                "plugin_id": "atom.in.apc_early_bird",
                "lifecycle_status": "behavior_valid",
                "catalog_status": "reviewed",
            },
            {
                "plugin_id": "atom.payload.msf_calc_x64",
                "lifecycle_status": "behavior_valid",
                "catalog_status": "dispatchable",
            },
        ]
        catalog = {
            "candidate": [],
            "reviewed": ["atom.in.apc_early_bird", "atom.di.dir"],
            "dispatchable": ["atom.payload.msf_calc_x64"],
        }
        summary = plugin_verify_catalog_summary(runs, catalog, hidden=8)
        self.assertEqual(
            "待验证 1 · 待review 1 · 待promote 1 · 已入库 1 · 隐藏历史 8 · "
            "catalog reviewed=2 dispatchable=1",
            summary,
        )
        self.assertNotIn("atom.ex.powershell", summary)
        self.assertNotIn("atom.in.apc_early_bird", summary)

    def test_queue_hides_cataloged_plugins_from_work_scope(self) -> None:
        reviewed = {
            "lifecycle_status": "behavior_valid",
            "catalog_status": "reviewed",
        }
        self.assertFalse(plugin_verify_matches_queue(reviewed, "work"))
        self.assertTrue(plugin_verify_matches_queue(reviewed, "promote"))
        self.assertTrue(plugin_verify_matches_queue(reviewed, "all"))


class CanonicalPluginRunSelectTest(unittest.TestCase):
    def test_keeps_highest_lifecycle_per_plugin_id(self) -> None:
        from packages.sample_factory.plugin_run_select import select_canonical_plugin_runs

        rows = select_canonical_plugin_runs(
            [
                {
                    "plugin_run_id": "plugin-run-old00001",
                    "plugin_id": "atom.payload.msf_calc_x64",
                    "implementation_name": "MsfCalcX64",
                    "lifecycle_status": "compile_valid",
                    "updated_at": "2026-09-01T00:00:00+00:00",
                },
                {
                    "plugin_run_id": "plugin-run-new00001",
                    "plugin_id": "atom.payload.msf_calc_x64",
                    "implementation_name": "MsfCalcX64",
                    "lifecycle_status": "behavior_valid",
                    "updated_at": "2026-09-10T00:00:00+00:00",
                },
                {
                    "plugin_run_id": "plugin-run-sf033001",
                    "plugin_id": "atom.payload.msf_calc_x64_sf033",
                    "implementation_name": "MsfCalcX64Sf033",
                    "lifecycle_status": "compile_valid",
                },
            ]
        )
        by_id = {item["plugin_id"]: item for item in rows}
        self.assertEqual(2, len(rows))
        self.assertEqual("plugin-run-new00001", by_id["atom.payload.msf_calc_x64"]["plugin_run_id"])
        self.assertEqual(1, by_id["atom.payload.msf_calc_x64"]["superseded_runs"])
        self.assertEqual(0, by_id["atom.payload.msf_calc_x64_sf033"]["superseded_runs"])


class ProducedSampleSelectionLabelTest(unittest.TestCase):
    def test_option_prompt_includes_ph_atoms_and_status(self) -> None:
        item = {
            "sample_id": "abcd1234-bbbbccccdddd",
            "sample_sha256": "b" * 64,
            "ph_sequence": ["PH-IN04", "PH-IN08"],
            "atom_ids": ["atom.in.apc", "atom.in.pool_party"],
            "profile_id": PROFILE_ID,
            "export_status": None,
            "export_ref": None,
        }
        prompt = produced_sample_option_prompt(item)
        self.assertTrue(prompt.startswith("未发布"))
        self.assertIn("abcd1234-bbbbccccdddd", prompt)
        self.assertIn("PH-IN08", prompt)
        self.assertIn("atom.in.pool_party", prompt)
        self.assertEqual("未发布", produced_sample_status_label(item))
        self.assertTrue(produced_sample_matches_scope(item, "unpublished"))
        self.assertFalse(produced_sample_matches_scope(item, "published"))
        self.assertTrue(produced_sample_matches_filter(item, "PH-IN08"))
        self.assertTrue(produced_sample_matches_filter(item, "pool_party"))
        self.assertTrue(produced_sample_matches_filter(item, "未发布"))
        self.assertFalse(produced_sample_matches_filter(item, "published"))
        published = {**item, "export_status": "published"}
        self.assertEqual("已发布", produced_sample_status_label(published))
        self.assertTrue(produced_sample_matches_scope(published, "published"))
        self.assertFalse(produced_sample_matches_scope(published, "unpublished"))
        self.assertTrue(produced_sample_matches_filter(published, "已发布"))


class PublishedTechniqueCoverageTest(unittest.TestCase):
    def test_aggregates_unique_published_samples_and_ignores_unpublished(self) -> None:
        samples = [
            {
                "sample_id": "pub-1",
                "attck_ids": ["T1055.004", "T1055"],
                "ph_sequence": ["PH-IN04", "PH-IN08"],
                "export_status": "published",
            },
            {
                "sample_id": "pub-2",
                "attck_ids": ["T1055.004"],
                "ph_sequence": ["PH-IN04"],
                "export_status": "published",
            },
            {
                "sample_id": "draft-1",
                "attck_ids": ["T1059.001"],
                "ph_sequence": ["PH-EX01"],
                "export_status": None,
            },
        ]
        attck = published_attck_coverage(
            samples,
            labels={"T1055.004": "Process Injection", "T1055": "Process Injection"},
        )
        self.assertEqual(("T1055.004", "T1055"), tuple(item.key for item in attck))
        self.assertEqual(2, attck[0].sample_count)
        self.assertEqual(("pub-1", "pub-2"), attck[0].sample_ids)
        self.assertEqual(("PH-IN04", "PH-IN08"), attck[0].extra)
        self.assertEqual("Process Injection", attck[0].label)
        self.assertEqual(1, attck[1].sample_count)
        ph = published_ph_coverage(samples)
        self.assertEqual(("PH-IN04", "PH-IN08"), tuple(item.key for item in ph))
        self.assertEqual(2, ph[0].sample_count)
        self.assertEqual(1, ph[1].sample_count)
        self.assertEqual((2, 2, 2), published_coverage_summary(samples))
        chart = render_coverage_bars(attck)
        self.assertIn("T1055.004", chart)
        self.assertIn("Process Injection", chart)
        self.assertIn("  2", chart)
        self.assertNotIn("T1059.001", chart)
        self.assertIn("尚无已发布样本", render_coverage_bars(()))
        self.assertIn("pub-1", render_coverage_detail(attck))
        self.assertNotIn("draft-1", render_coverage_detail(attck))

    def test_cjk_labels_do_not_shift_bar_column(self) -> None:
        rows = (
            CoverageCountBar(
                key="T1055",
                label="命名变体组：映射注入（NtMapViewOfSection）",
                sample_count=1,
                sample_ids=("pub-1",),
            ),
            CoverageCountBar(
                key="T1055.004",
                label="APC Injection",
                sample_count=1,
                sample_ids=("pub-1",),
            ),
        )
        chart = render_coverage_bars(rows, bar_width=4, key_width=11, label_width=16)
        lines = chart.splitlines()
        prefixes = [line[: line.index("█")] for line in lines]
        self.assertEqual(_display_width(prefixes[0]), _display_width(prefixes[1]))
        self.assertEqual(11 + 1 + 16 + 1, _display_width(prefixes[0]))


class SampleFactoryTuiTest(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _plugin_intake_session(request: PluginRequest) -> PluginIntakeSession:
        source = PluginIntakeSource(
            source_ref="operator-source://sha256/" + "a" * 64,
            kind="operator",
            sha256="a" * 64,
            locator="operator-input",
            captured_at=datetime.now(UTC),
            media_type="text/plain",
            text_excerpt="Generate one authorized test plugin",
        )
        return PluginIntakeSession(
            session_id="plugin-intake-12345678",
            description="Generate one authorized test plugin",
            harness_ref=request.harness_ref,
            build_target_ref=request.build_target_ref,
            profile_id=request.profile_id,
            sources=(source,),
            messages=(),
            decision=PluginIntakeDecision(
                status=PluginIntakeStatus.READY,
                message="合同已闭合，请审核",
                request=request.model_copy(
                    update={
                        "intent": request.intent.model_copy(
                            update={"source_refs": (source.source_ref,)}
                        )
                    }
                ),
            ),
        )

    async def test_tui_starts_and_surfaces_preflight_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing_config = Path(tmp) / "missing-config.json"
            missing_run = Path(tmp) / "missing-run.json"
            app = SampleFactoryTui(missing_config, missing_run)
            async with app.run_test(size=(120, 40)) as pilot:
                for _ in range(3):
                    await pilot.pause()
                status = app.query_one("#status", Static)
                self.assertIn("预检失败", str(status.render()))

    async def test_tui_start_without_approve_explains_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path, run_path, _ = SampleFactoryCliTest()._factory_files(Path(tmp))
            app = SampleFactoryTui(config_path, run_path)
            async with app.run_test(size=(120, 40)) as pilot:
                for _ in range(8):
                    await pilot.pause()
                    if "等待人工审批" in str(app.query_one("#status", Static).render()):
                        break
                self.assertIn("等待人工审批", str(app.query_one("#status", Static).render()))
                app.query_one("#factory-tabs", TabbedContent).active = "production-tab"
                await pilot.pause()
                self.assertTrue(app.query_one("#start", Button).disabled)
                self.assertTrue(app.query_one("#stop", Button).disabled)
                logging = app.query_one("#execution-logging", Checkbox)
                self.assertFalse(logging.value)
                await pilot.click("#execution-logging")
                await pilot.pause()
                self.assertTrue(logging.value)
                app._try_start_production()
                await pilot.pause()
                self.assertIn("请先勾选人工审批", str(app.query_one("#status", Static).render()))
                await pilot.click("#approve")
                await pilot.pause()
                self.assertFalse(app.query_one("#start", Button).disabled)
                with patch.object(app, "_run_production") as run_production:
                    app._try_start_production()
                    run_production.assert_called_once_with(False, True)
                stop = app.query_one("#stop", Button)
                self.assertFalse(stop.disabled)
                await pilot.click("#stop")
                await pilot.pause()
                self.assertTrue(stop.disabled)
                self.assertIsNotNone(app._stop_token)
                assert app._stop_token is not None
                self.assertTrue(app._stop_token.is_stop_requested)
                self.assertIn(
                    "正在停止生产",
                    str(app.query_one("#status", Static).render()),
                )
                app._production_stopped(
                    {
                        "batch": True,
                        "produced": False,
                        "produced_count": 1,
                        "requested_count": 2,
                    }
                )
                self.assertIn(
                    "生产已停止 1/2",
                    str(app.query_one("#status", Static).render()),
                )
                self.assertTrue(stop.disabled)

    async def test_tui_plugin_intake_preview_dialogue_and_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing_config = Path(tmp) / "missing-config.json"
            missing_run = Path(tmp) / "missing-run.json"
            request = PluginRequest(
                request_id="plugin-request-tui00001",
                operation=PluginOperation.CREATE,
                implementation_name="EarlyApcInjection",
                intent=TechniqueIntent(
                    intent_id="intent-tui00001",
                    ph_ids=("PH-IN04",),
                    role=atom_specs()[2].role,
                    required_capabilities=atom_specs()[2].required_capabilities,
                    provided_capabilities=atom_specs()[2].provided_capabilities,
                    input_ports=(
                        PortContract(
                            port_id="port.payload.input",
                            value_type="ByteBuffer",
                            semantic="ExecutablePayload",
                            architecture="x64",
                        ),
                    ),
                    parameter_domains=atom_specs()[2].param_domains,
                    architecture="x64",
                    safety_profile=atom_specs()[2].safety_profile,
                    source_refs=("operator-source://sha256/" + "a" * 64,),
                ),
                build_target_ref="build-target://cli-test",
                harness_ref="plugin-harness://execution/windows-x64/v1",
                profile_id=PROFILE_ID,
            )
            session = self._plugin_intake_session(request)
            app = SampleFactoryTui(missing_config, missing_run)
            with patch(
                "packages.sample_factory.tui.start_plugin_intake",
                return_value=session,
            ) as start_intake:
                async with app.run_test(size=(150, 52)) as pilot:
                    await pilot.pause()
                    app.query_one("#factory-tabs", TabbedContent).active = "plugin-tab"
                    app.query_one("#plugin-description", TextArea).load_text(
                        "Generate one authorized test plugin"
                    )
                    app.query_one("#plugin-urls", TextArea).load_text(
                        "https://example.test/reference"
                    )
                    app._try_start_plugin_intake()
                    for _ in range(10):
                        await pilot.pause()
                        if app._plugin_intake is not None:
                            break

                    start_intake.assert_called_once()
                    self.assertIsNotNone(app._plugin_intake)
                    preview = app.query_one("#plugin-request-preview", TextArea).text
                    self.assertIn("plugin-request-tui00001", preview)
                    conversation = app.query_one("#plugin-conversation", TextArea).text
                    self.assertIn("Intake Agent: 合同已闭合", conversation)
                    self.assertFalse(app.query_one("#plugin-message-send", Button).disabled)
                    self.assertFalse(app.query_one("#plugin-approve", Checkbox).disabled)
                    self.assertTrue(app.query_one("#plugin-author-start", Button).disabled)

                    app.query_one("#plugin-message", Input).value = "Use a fixed test target"
                    with patch.object(app, "_run_plugin_intake_continue") as continue_intake:
                        await pilot.click("#plugin-message-send")
                        await pilot.pause()
                        continue_intake.assert_called_once_with(
                            "plugin-intake-12345678", "Use a fixed test target"
                        )
                    app._plugin_active = False
                    app._update_plugin_buttons()
                    await pilot.click("#plugin-approve")
                    await pilot.pause()
                    self.assertFalse(app.query_one("#plugin-author-start", Button).disabled)
                    with patch.object(app, "_run_plugin_authoring") as run_authoring:
                        await pilot.click("#plugin-author-start")
                        await pilot.pause()
                        assert session.decision.request is not None
                        run_authoring.assert_called_once_with(session.decision.request)
                    app._plugin_active = False

    async def test_tui_prefills_operator_configured_plugin_harness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            harness_path = root / "plugin-harness.json"
            harness_path.write_text(
                json.dumps(
                    {
                        "schema_version": "factory-vmware-plugin-harness-v1",
                        "spec": {
                            "schema_version": "sf-plugin-harness-v1",
                            "harness_ref": "plugin-harness://execution/windows-x64/v1",
                            "role": "execution_atom",
                            "ph_ids": ["PH-IN04"],
                            "profile_ids": [PROFILE_ID],
                            "architectures": ["x64"],
                            "telemetry_sources": ["sysmon"],
                            "input_contract_ref": "contract://plugin-harness/empty-json-smoke-v1",
                            "oracle_ref": "oracle://ph-in04/sysmon-v1",
                            "collector_config_ref": "collector://sysmon/v1",
                            "isolation_profile_ref": "vm-profile://windows/nat/test",
                            "required_assertions": [
                                "process.created",
                                "process.exit_code_zero",
                                "sysmon.event_id.1",
                            ],
                        },
                        "vmware_verification_config": "vmware.json",
                        "profile": {
                            "profile_id": PROFILE_ID,
                            "env_detail": {"network_mode": "nat"},
                            "security_product_enabled": False,
                            "isolated": False,
                            "rollback_capable": True,
                            "sensors_ready": True,
                            "no_edr_control": True,
                        },
                        "msbuild_path": "MSBuild.exe",
                        "link_toolchain_fp": "msvc-test+harness-v1",
                    }
                ),
                encoding="utf-8",
            )
            inputs = SimpleNamespace(
                config=SimpleNamespace(plugin_harness_config=harness_path),
                run=SimpleNamespace(execution_logging=False),
            )
            app = SampleFactoryTui(root / "config.json", root / "run.json")
            with (
                patch("packages.sample_factory.tui.load_inputs", return_value=inputs),
                patch.object(app, "_run_preflight"),
            ):
                async with app.run_test(size=(150, 52)) as pilot:
                    await pilot.pause()
                    harness = app.query_one("#plugin-harness", Input)
                    self.assertEqual(
                        "plugin-harness://execution/windows-x64/v1",
                        harness.value,
                    )
                    self.assertTrue(harness.read_only)
                    self.assertIn(
                        "Harness 已配置",
                        app.query_one("#plugin-events", TextArea).text,
                    )

    async def test_tui_reports_atom_spec_pending_without_claiming_harness_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = SampleFactoryTui(root / "missing-config.json", root / "missing-run.json")
            with patch.object(app, "_run_preflight"):
                async with app.run_test(size=(150, 52)) as pilot:
                    await pilot.pause()
                    app.query_one("#plugin-harness", Input).value = (
                        "plugin-harness://execution/windows-x64/v1"
                    )

                    app._plugin_authoring_finished([
                        {
                            "status": "compile_valid",
                            "compile_only_reason": "atom_spec_governance_pending",
                        }
                    ])

                    output = app.query_one("#plugin-events", TextArea).text
                    self.assertIn("Harness 已配置", output)
                    self.assertIn("AtomSpec 治理尚未完成", output)
                    self.assertNotIn("未配置独立 Harness", output)
                    self.assertEqual(3, app.query_one("#plugin-progress", ProgressBar).progress)

    async def test_tui_reports_harness_missing_only_for_matching_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = SampleFactoryTui(root / "missing-config.json", root / "missing-run.json")
            with patch.object(app, "_run_preflight"):
                async with app.run_test(size=(150, 52)) as pilot:
                    await pilot.pause()

                    app._plugin_authoring_finished([
                        {
                            "status": "compile_valid",
                            "compile_only_reason": "independent_harness_not_configured",
                        }
                    ])

                    output = app.query_one("#plugin-events", TextArea).text
                    self.assertIn("未配置独立 Harness", output)

    async def test_tui_previews_and_executes_full_plugin_decomposition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            request = self._plugin_intake_session(
                PluginRequest(
                    request_id="plugin-request-consumer99",
                    operation=PluginOperation.CREATE,
                    implementation_name="EarlyApcInjection",
                    intent=TechniqueIntent(
                        intent_id="intent-consumer99",
                        ph_ids=("PH-IN04",),
                        role=atom_specs()[2].role,
                        required_capabilities=("cap.payload.shellcode",),
                        provided_capabilities=("cap.process.injection",),
                        input_ports=(
                            PortContract(
                                port_id="port.payload.input",
                                value_type="ByteBuffer",
                                semantic="ExecutablePayload",
                                architecture="x64",
                            ),
                        ),
                        parameter_domains=atom_specs()[2].param_domains,
                        architecture="x64",
                        safety_profile=atom_specs()[2].safety_profile,
                        source_refs=("operator-source://sha256/" + "a" * 64,),
                    ),
                    build_target_ref="build-target://cli-test",
                    profile_id=PROFILE_ID,
                )
            )
            consumer = request.decision.request
            assert consumer is not None
            producer = consumer.model_copy(
                update={
                    "request_id": "plugin-request-producer99",
                    "implementation_name": "ShellcodeProducer",
                    "intent": consumer.intent.model_copy(
                        update={
                            "intent_id": "intent-producer99",
                            "required_capabilities": (),
                            "provided_capabilities": ("cap.payload.shellcode",),
                            "input_ports": (),
                        }
                    ),
                }
            )
            plan = PluginDecompositionPlan(
                plan_id="plugin-plan-tui00001",
                summary="two plugin chain",
                requests=(producer, consumer),
                dependencies=(
                    PluginDependency(
                        producer_request_id=producer.request_id,
                        consumer_request_id=consumer.request_id,
                        capability="cap.payload.shellcode",
                    ),
                ),
            )
            session = request.model_copy(
                update={
                    "decision": PluginIntakeDecision(
                        status=PluginIntakeStatus.READY,
                        message="已拆分为两个插件",
                        request=producer,
                        decomposition=plan,
                    )
                }
            )
            app = SampleFactoryTui(Path(tmp) / "missing.json", Path(tmp) / "run.json")
            async with app.run_test(size=(150, 52)) as pilot:
                await pilot.pause()
                app.query_one("#factory-tabs", TabbedContent).active = "plugin-tab"
                app._plugin_intake_ready(session)
                preview = app.query_one("#plugin-request-preview", TextArea).text
                self.assertIn("plugin-plan-tui00001", preview)
                self.assertIn("plugin-request-producer99", preview)
                self.assertIn("plugin-request-consumer99", preview)
                app.query_one("#plugin-approve", Checkbox).value = True
                app._update_plugin_buttons()
                with patch.object(app, "_run_plugin_authoring") as run_authoring:
                    app._try_start_plugin_authoring()
                    await pilot.pause()
                    run_authoring.assert_called_once_with(plan)
                app._plugin_active = False

    async def test_tui_clicks_do_not_change_theme(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing_config = Path(tmp) / "missing-config.json"
            missing_run = Path(tmp) / "missing-run.json"
            app = SampleFactoryTui(missing_config, missing_run)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                self.assertEqual(app.theme, "textual-dark")
                app.query_one("#factory-tabs", TabbedContent).active = "production-tab"
                await pilot.pause()
                footer = app.query_one(Footer)
                self.assertTrue(footer.show_command_palette)
                icon = app.query_one("HeaderIcon")
                self.assertFalse(icon.disabled)
                # 避开标题栏左侧命令面板图标；点标题/正文/页脚空白不应改主题
                for target in (
                    "HeaderTitle",
                    "#events",
                    "#approve",
                    "#execution-logging",
                    "#body",
                    "#run-info",
                ):
                    await pilot.click(target)
                    await pilot.pause()
                    self.assertEqual(app.theme, "textual-dark")
                    self.assertTrue(app.has_class("-dark-mode"))
                    self.assertFalse(app.has_class("-light-mode"))
                    self.assertFalse(app.query_one(Header).has_class("-tall"))

    async def test_tui_renders_agent_activity_as_conversation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = SampleFactoryTui(Path(tmp) / "missing.json", Path(tmp) / "run.json")
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                app._render_event(
                    (
                        "sample_factory_planner_model_output",
                        {"turn": 1, "content": "选择 PH=['PH-IN04']; carrier=None"},
                    )
                )
                app._render_event(
                    (
                        "sample_factory_coding_model_output",
                        {
                            "turn": 2,
                            "session_ref": "coding-session://test",
                            "action": "read_file",
                            "content": "read_file src/atom.cpp lines=1-80",
                        },
                    )
                )
                await pilot.pause()

                text = app.query_one("#events", TextArea).text
                self.assertIn("[Planner 模型输出 · 回合 1]", text)
                self.assertIn("选择 PH=['PH-IN04']", text)
                self.assertIn("[Coding Agent 模型输出 · 回合 2]", text)
                self.assertIn("read_file src/atom.cpp lines=1-80", text)

    async def test_copy_events_uses_active_factory_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = SampleFactoryTui(Path(tmp) / "missing.json", Path(tmp) / "run.json")
            async with app.run_test(size=(150, 52)) as pilot:
                await pilot.pause()
                app._event_lines[:] = ["sample event"]
                app._plugin_event_lines[:] = ["plugin event"]
                app._plugin_verify_event_lines[:] = ["verify event"]
                app._publish_event_lines[:] = ["publish event"]
                with patch.object(app, "copy_to_clipboard") as copy:
                    app._copy_events_to_clipboard()
                    copy.assert_called_once_with("plugin event")
                    copy.reset_mock()
                    app.query_one("#factory-tabs", TabbedContent).active = "plugin-verify-tab"
                    app._copy_events_to_clipboard()
                    copy.assert_called_once_with("verify event")
                    copy.reset_mock()
                    app.query_one("#factory-tabs", TabbedContent).active = "production-tab"
                    app._copy_events_to_clipboard()
                    copy.assert_called_once_with("sample event")
                    copy.reset_mock()
                    app.query_one("#factory-tabs", TabbedContent).active = "sample-publish-tab"
                    app._copy_events_to_clipboard()
                    copy.assert_called_once_with("publish event")
                    copy.reset_mock()
                    app._technique_board_copy_lines[:] = ["board chart"]
                    app.query_one("#factory-tabs", TabbedContent).active = "technique-board-tab"
                    app._copy_events_to_clipboard()
                    copy.assert_called_once_with("board chart")

    async def test_tui_tabs_are_generate_verify_then_production(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = SampleFactoryTui(Path(tmp) / "missing.json", Path(tmp) / "run.json")
            async with app.run_test(size=(160, 60)) as pilot:
                await pilot.pause()
                self.assertEqual(
                    [
                        "plugin-tab",
                        "plugin-verify-tab",
                        "production-tab",
                        "sample-publish-tab",
                        "technique-board-tab",
                    ],
                    [pane.id for pane in app.query(TabPane)],
                )

    async def test_tui_sample_publish_requires_approval_before_transfer(self) -> None:
        inventory = {
            "samples": [
                {
                    "sample_id": "abcd1234-bbbbccccdddd",
                    "sample_sha256": "b" * 64,
                    "artifact_ref": "object://artifacts/sha256/" + "b" * 64,
                    "ph_sequence": ["PH-IN04", "PH-IN08"],
                    "attck_ids": ["T1055"],
                    "atom_ids": ["atom.in.apc", "atom.in.pool_party"],
                    "profile_id": PROFILE_ID,
                    "regression_set_version": "v1",
                    "export_status": None,
                    "export_ref": None,
                    "export_id": None,
                }
            ],
            "exports": {"approved": [], "published": [], "revoked": []},
        }
        with tempfile.TemporaryDirectory() as tmp:
            app = SampleFactoryTui(Path(tmp) / "missing.json", Path(tmp) / "run.json")
            with (
                patch("packages.sample_factory.tui.list_produced_samples", return_value=inventory),
                patch.object(app, "_run_preflight"),
            ):
                async with app.run_test(size=(160, 60)) as pilot:
                    await pilot.pause()
                    app.query_one("#factory-tabs", TabbedContent).active = "sample-publish-tab"
                    app._refresh_publish_list()
                    widget = app.query_one("#sample-publish-list", SelectionList)
                    widget.select("abcd1234-bbbbccccdddd")
                    await pilot.pause()
                    self.assertTrue(app.query_one("#sample-publish-transfer", Button).disabled)
                    app.query_one("#sample-publish-approve", Checkbox).value = True
                    app._update_publish_buttons()
                    self.assertFalse(app.query_one("#sample-publish-transfer", Button).disabled)
                    with patch.object(app, "_run_sample_transfer") as run_transfer:
                        app._try_start_sample_transfer()
                        run_transfer.assert_called_once_with(("abcd1234-bbbbccccdddd",))
                    self.assertTrue(app._publish_active)
                    detail = app.query_one("#sample-publish-detail", TextArea).text
                    self.assertIn("abcd1234-bbbbccccdddd", detail)
                    self.assertIn("PH-IN08", detail)

    async def test_tui_sample_publish_scope_hides_published_and_selects_visible(self) -> None:
        inventory = {
            "samples": [
                {
                    "sample_id": "aaaa1111-bbbbccccdddd",
                    "sample_sha256": "a" * 64,
                    "ph_sequence": ["PH-IN04"],
                    "atom_ids": ["atom.in.apc"],
                    "profile_id": PROFILE_ID,
                    "export_status": None,
                },
                {
                    "sample_id": "zzzz9999-bbbbccccdddd",
                    "sample_sha256": "c" * 64,
                    "ph_sequence": ["PH-IN08"],
                    "atom_ids": ["atom.in.pool_party"],
                    "profile_id": PROFILE_ID,
                    "export_status": "published",
                    "export_ref": "export://published/export-zzzz9999-bbbbccccdddd",
                },
            ],
            "exports": {"approved": [], "published": [{}], "revoked": []},
        }
        with tempfile.TemporaryDirectory() as tmp:
            app = SampleFactoryTui(Path(tmp) / "missing.json", Path(tmp) / "run.json")
            with (
                patch("packages.sample_factory.tui.list_produced_samples", return_value=inventory),
                patch.object(app, "_run_preflight"),
            ):
                async with app.run_test(size=(160, 60)) as pilot:
                    await pilot.pause()
                    app.query_one("#factory-tabs", TabbedContent).active = "sample-publish-tab"
                    app._refresh_publish_list()
                    widget = app.query_one("#sample-publish-list", SelectionList)
                    self.assertEqual(1, widget.option_count)
                    unpublished = str(widget.get_option_at_index(0).prompt)
                    self.assertIn("未发布", unpublished)
                    self.assertIn("aaaa1111-bbbbccccdddd", unpublished)
                    catalog = str(app.query_one("#sample-publish-catalog", Static).content)
                    self.assertIn("未发布=1", catalog)
                    self.assertIn("已发布=1", catalog)
                    app.query_one("#sample-publish-scope", Select).value = "published"
                    app._sample_publish_scope_changed()
                    self.assertEqual(1, widget.option_count)
                    published = str(widget.get_option_at_index(0).prompt)
                    self.assertIn("已发布", published)
                    self.assertIn("zzzz9999-bbbbccccdddd", published)
                    app.query_one("#sample-publish-scope", Select).value = "all"
                    app._sample_publish_scope_changed()
                    self.assertEqual(2, widget.option_count)
                    app.query_one("#sample-publish-scope", Select).value = "unpublished"
                    app._sample_publish_scope_changed()
                    app._select_visible_unpublished()
                    self.assertEqual(("aaaa1111-bbbbccccdddd",), app._publish_selected_ids())

    async def test_tui_technique_board_charts_published_attck(self) -> None:
        inventory = {
            "samples": [
                {
                    "sample_id": "pub-1",
                    "sample_sha256": "a" * 64,
                    "ph_sequence": ["PH-IN04", "PH-IN08"],
                    "attck_ids": ["T1055.004", "T1055"],
                    "atom_ids": ["atom.in.apc", "atom.in.pool_party"],
                    "profile_id": PROFILE_ID,
                    "export_status": "published",
                    "export_ref": "export://published/export-pub-1",
                    "export_id": "export-pub-1",
                },
                {
                    "sample_id": "pub-2",
                    "sample_sha256": "b" * 64,
                    "ph_sequence": ["PH-IN04"],
                    "attck_ids": ["T1055.004"],
                    "atom_ids": ["atom.in.apc"],
                    "profile_id": PROFILE_ID,
                    "export_status": "published",
                    "export_ref": "export://published/export-pub-2",
                    "export_id": "export-pub-2",
                },
                {
                    "sample_id": "draft-1",
                    "sample_sha256": "c" * 64,
                    "ph_sequence": ["PH-EX01"],
                    "attck_ids": ["T1059.001"],
                    "atom_ids": ["atom.ex.cmd"],
                    "profile_id": PROFILE_ID,
                    "export_status": None,
                    "export_ref": None,
                    "export_id": None,
                },
            ],
            "exports": {"approved": [], "published": [], "revoked": []},
        }
        with tempfile.TemporaryDirectory() as tmp:
            app = SampleFactoryTui(Path(tmp) / "missing.json", Path(tmp) / "run.json")
            with (
                patch("packages.sample_factory.tui.list_produced_samples", return_value=inventory),
                patch.object(app, "_run_preflight"),
            ):
                async with app.run_test(size=(160, 60)) as pilot:
                    await pilot.pause()
                    app.query_one("#factory-tabs", TabbedContent).active = "technique-board-tab"
                    app._refresh_publish_list()
                    await pilot.pause()
                    summary = str(app.query_one("#technique-board-summary", Static).content)
                    self.assertIn("已发布样本=2", summary)
                    self.assertIn("覆盖 ATT&CK=2", summary)
                    self.assertIn("覆盖 PH=2", summary)
                    detail = app.query_one("#technique-board-detail", TextArea).text
                    self.assertIn("PH-IN04", detail)
                    self.assertIn("PH-IN08", detail)
                    self.assertIn("pub-1", detail)
                    self.assertIn("pub-2", detail)
                    self.assertNotIn("PH-EX01", detail)
                    self.assertNotIn("draft-1", detail)
                    self.assertTrue(app.query_one("#technique-board-export", Button).disabled)

    async def test_tui_technique_board_exports_green_html(self) -> None:
        inventory = {
            "samples": [
                {
                    "sample_id": "pub-1",
                    "ph_sequence": ["PH-IN04", "PH-IN08"],
                    "attck_ids": ["T1055.004", "T1055"],
                    "export_status": "published",
                }
            ],
            "exports": {"approved": [], "published": [], "revoked": []},
        }
        matrix = Path("docs/coverage/procedure-host-ttp-coverage-matrix.md").resolve()
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            runtime.mkdir()
            app = SampleFactoryTui(Path(tmp) / "missing.json", Path(tmp) / "run.json")
            app._inputs = SimpleNamespace(
                config=SimpleNamespace(coverage_matrix=matrix, runtime_root=runtime),
            )
            with (
                patch("packages.sample_factory.tui.list_produced_samples", return_value=inventory),
                patch.object(app, "_run_preflight"),
            ):
                async with app.run_test(size=(160, 60)) as pilot:
                    await pilot.pause()
                    app._refresh_publish_list()
                    app.query_one("#factory-tabs", TabbedContent).active = "technique-board-tab"
                    app._update_technique_board_buttons()
                    self.assertFalse(app.query_one("#technique-board-export", Button).disabled)
                    with patch("packages.sample_factory.tui.webbrowser.open", return_value=True) as opened:
                        app._export_technique_board(open_browser=True)
                        path = runtime / "exports" / "technique-board.html"
                        opened.assert_called_once_with(path.as_uri())
                    html = path.read_text(encoding="utf-8")
                    self.assertIn('data-row-ph="PH-IN04"', html)
                    self.assertIn("cov-now", html)
                    self.assertIn(f"明细表（{PH_MATRIX_ROW_COUNT} 行）", html)
                    self.assertIn("适合覆盖/转换", html)
                    self.assertIn("热力图（AEL T 号）", html)
                    self.assertIn("攻击链（16 案例）", html)
                    self.assertIn('data-row-ph="PH-EX01"', html)
                    self.assertEqual(PH_MATRIX_ROW_COUNT, html.count('data-row-ph="PH-'))
                    self.assertIn("插件状态", html)
                    self.assertIn("CreateScheduledTaskCom", html)
                    self.assertIn("plugin-only", html)

    async def test_tui_plugin_verify_cleanup_requires_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = SampleFactoryTui(Path(tmp) / "missing.json", Path(tmp) / "run.json")
            async with app.run_test(size=(120, 32)) as pilot:
                await pilot.pause()
                app.query_one("#factory-tabs", TabbedContent).active = "plugin-verify-tab"
                await pilot.pause()
                cleanup = app.query_one("#plugin-verify-cleanup", Button)
                approve = app.query_one("#plugin-verify-cleanup-approve", Checkbox)
                self.assertTrue(cleanup.disabled)
                approve.value = True
                app._update_verify_buttons()
                self.assertFalse(cleanup.disabled)
                approve.value = False
                app._update_verify_buttons()
                self.assertTrue(cleanup.disabled)

    async def test_tui_plugin_verify_review_actions_stay_visible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = SampleFactoryTui(Path(tmp) / "missing.json", Path(tmp) / "run.json")
            async with app.run_test(size=(120, 32)) as pilot:
                await pilot.pause()
                app.query_one("#factory-tabs", TabbedContent).active = "plugin-verify-tab"
                await pilot.pause()
                review = app.query_one("#plugin-verify-review", Button)
                approve = app.query_one("#plugin-verify-review-approve", Checkbox)
                promote = app.query_one("#plugin-verify-promote", Button)
                screen_height = app.size.height
                for widget in (review, approve, promote):
                    self.assertGreater(widget.region.height, 0)
                    self.assertLessEqual(widget.region.bottom, screen_height)

    async def test_tui_plugin_verify_validate_review_promote_gates(self) -> None:
        inventory = {
            "runs": [
                {
                    "plugin_run_id": "plugin-run-verify0001",
                    "implementation_name": "EarlyApcInjection",
                    "plugin_id": "atom.in.apc",
                    "lifecycle_status": "compile_valid",
                    "catalog_status": None,
                    "ph_ids": ["PH-IN04"],
                    "required_capabilities": ["cap.payload.shellcode"],
                    "source_digest": "a" * 64,
                }
            ],
            "catalog": {"candidate": [], "reviewed": [], "dispatchable": []},
        }
        with tempfile.TemporaryDirectory() as tmp:
            app = SampleFactoryTui(Path(tmp) / "missing.json", Path(tmp) / "run.json")
            with (
                patch("packages.sample_factory.tui.list_plugin_inventory", return_value=inventory),
                patch.object(app, "_run_preflight"),
            ):
                async with app.run_test(size=(160, 60)) as pilot:
                    await pilot.pause()
                    app.query_one("#factory-tabs", TabbedContent).active = "plugin-verify-tab"
                    app._refresh_plugin_verify_list()
                    widget = app.query_one("#plugin-verify-list", SelectionList)
                    widget.select("plugin-run-verify0001")
                    await pilot.pause()
                    self.assertTrue(app.query_one("#plugin-verify-validate", Button).disabled)
                    self.assertTrue(app.query_one("#plugin-verify-review", Button).disabled)
                    app.query_one("#plugin-verify-validate-approve", Checkbox).value = True
                    app._update_verify_buttons()
                    self.assertFalse(app.query_one("#plugin-verify-validate", Button).disabled)
                    with patch.object(app, "_run_plugin_validation") as run_validation:
                        app._try_start_plugin_validation()
                        run_validation.assert_called_once_with(("plugin-run-verify0001",))
                    app._plugin_active = False
                    inventory["runs"][0]["lifecycle_status"] = "behavior_valid"
                    app._refresh_plugin_verify_list()
                    widget.select("plugin-run-verify0001")
                    app.query_one("#plugin-verify-reviewed-by", Input).value = "reviewer-1"
                    app.query_one("#plugin-verify-source-refs", TextArea).load_text(
                        "https://example.invalid/reference"
                    )
                    app.query_one("#plugin-verify-audit", Checkbox).value = True
                    app.query_one("#plugin-verify-pinned", Checkbox).value = True
                    app.query_one("#plugin-verify-review-approve", Checkbox).value = True
                    app._update_verify_buttons()
                    self.assertFalse(app.query_one("#plugin-verify-review", Button).disabled)
                    self.assertTrue(app.query_one("#plugin-verify-promote", Button).disabled)
                    with patch.object(app, "_run_plugin_review") as run_review:
                        app._try_start_plugin_review()
                        self.assertEqual(1, run_review.call_count)
                        reviewed_ids = [item[0] for item in run_review.call_args.args[0]]
                        self.assertEqual(["plugin-run-verify0001"], reviewed_ids)
                    app._plugin_active = False
                    inventory["runs"][0]["catalog_status"] = "reviewed"
                    app._refresh_plugin_verify_list()
                    app.query_one("#plugin-verify-queue", Select).value = "promote"
                    app._render_plugin_verify_options()
                    widget.select("plugin-run-verify0001")
                    app.query_one("#plugin-verify-promote-approve", Checkbox).value = True
                    app._update_verify_buttons()
                    self.assertFalse(app.query_one("#plugin-verify-promote", Button).disabled)
                    with patch.object(app, "_run_plugin_promote") as run_promote:
                        app._try_start_plugin_promote()
                        run_promote.assert_called_once_with(("atom.in.apc",))

    async def test_tui_plugin_verify_filter_and_selected_summary(self) -> None:
        inventory = {
            "runs": [
                {
                    "plugin_run_id": "plugin-run-e4ff6ed6b8ff442d",
                    "implementation_name": "EarlyApcInjection",
                    "plugin_id": "atom.in.apc",
                    "lifecycle_status": "compile_valid",
                    "catalog_status": None,
                    "ph_ids": ["PH-IN04"],
                    "required_capabilities": ["cap.payload.shellcode"],
                    "provided_capabilities": ["cap.process.injection"],
                },
                {
                    "plugin_run_id": "plugin-run-ea649a26ee24464b",
                    "implementation_name": "MsfCalcX64",
                    "plugin_id": "atom.payload.msf_calc_x64",
                    "lifecycle_status": "compile_valid",
                    "catalog_status": None,
                    "ph_ids": [],
                    "required_capabilities": [],
                    "provided_capabilities": ["cap.payload.shellcode"],
                },
                {
                    "plugin_run_id": "plugin-run-a8a3aca19458402a",
                    "implementation_name": "MsfCalcX64Sf033",
                    "plugin_id": "atom.payload.msf_calc_x64_sf033",
                    "lifecycle_status": "compile_valid",
                    "catalog_status": None,
                    "ph_ids": [],
                    "required_capabilities": [],
                    "provided_capabilities": ["cap.payload.shellcode"],
                },
            ],
            "catalog": {"candidate": [], "reviewed": [], "dispatchable": []},
        }
        with tempfile.TemporaryDirectory() as tmp:
            app = SampleFactoryTui(Path(tmp) / "missing.json", Path(tmp) / "run.json")
            with (
                patch("packages.sample_factory.tui.list_plugin_inventory", return_value=inventory),
                patch.object(app, "_run_preflight"),
            ):
                async with app.run_test(size=(160, 60)) as pilot:
                    await pilot.pause()
                    app.query_one("#factory-tabs", TabbedContent).active = "plugin-verify-tab"
                    app._refresh_plugin_verify_list()
                    widget = app.query_one("#plugin-verify-list", SelectionList)
                    prompts = [
                        str(widget.get_option_at_index(index).prompt)
                        for index in range(widget.option_count)
                    ]
                    self.assertEqual(3, len(prompts))
                    self.assertIn("[ea649a26] MsfCalcX64", prompts[1])
                    self.assertTrue(any("待验证" in prompt for prompt in prompts))
                    widget.select("plugin-run-e4ff6ed6b8ff442d")
                    await pilot.pause()
                    detail = app.query_one("#plugin-verify-detail", TextArea).text
                    self.assertIn("EarlyApcInjection [e4ff6ed6]", detail)
                    self.assertIn("need=cap.payload.shellcode", detail)
                    app.query_one("#plugin-verify-filter", Input).value = "sf033"
                    app._render_plugin_verify_options()
                    visible = [
                        str(widget.get_option_at_index(index).prompt)
                        for index in range(widget.option_count)
                    ]
                    self.assertEqual(2, len(visible))
                    self.assertTrue(any("[e4ff6ed6]" in prompt for prompt in visible))
                    self.assertTrue(any("[a8a3aca1]" in prompt for prompt in visible))
                    self.assertFalse(any("[ea649a26]" in prompt for prompt in visible))

    async def test_tui_plugin_verify_collapses_duplicate_plugin_runs(self) -> None:
        inventory = {
            "runs": [
                {
                    "plugin_run_id": "plugin-run-oldcalc01",
                    "implementation_name": "MsfCalcX64",
                    "plugin_id": "atom.payload.msf_calc_x64",
                    "lifecycle_status": "compile_valid",
                    "updated_at": "2026-09-01T00:00:00+00:00",
                    "ph_ids": [],
                    "required_capabilities": [],
                    "provided_capabilities": ["cap.payload.shellcode"],
                },
                {
                    "plugin_run_id": "plugin-run-newcalc01",
                    "implementation_name": "MsfCalcX64",
                    "plugin_id": "atom.payload.msf_calc_x64",
                    "lifecycle_status": "behavior_valid",
                    "updated_at": "2026-09-10T00:00:00+00:00",
                    "ph_ids": [],
                    "required_capabilities": [],
                    "provided_capabilities": ["cap.payload.shellcode"],
                },
                {
                    "plugin_run_id": "plugin-run-e4ff6ed6b8ff442d",
                    "implementation_name": "EarlyApcInjection",
                    "plugin_id": "atom.in.apc",
                    "lifecycle_status": "compile_valid",
                    "ph_ids": ["PH-IN04"],
                    "required_capabilities": ["cap.payload.shellcode"],
                    "provided_capabilities": ["cap.process.injection"],
                },
            ],
            "catalog": {"candidate": [], "reviewed": [], "dispatchable": []},
        }
        with tempfile.TemporaryDirectory() as tmp:
            app = SampleFactoryTui(Path(tmp) / "missing.json", Path(tmp) / "run.json")
            with (
                patch("packages.sample_factory.tui.list_plugin_inventory", return_value=inventory),
                patch.object(app, "_run_preflight"),
            ):
                async with app.run_test(size=(160, 60)) as pilot:
                    await pilot.pause()
                    app.query_one("#factory-tabs", TabbedContent).active = "plugin-verify-tab"
                    app._refresh_plugin_verify_list()
                    widget = app.query_one("#plugin-verify-list", SelectionList)
                    prompts = [
                        str(widget.get_option_at_index(index).prompt)
                        for index in range(widget.option_count)
                    ]
                    self.assertEqual(2, len(prompts))
                    self.assertTrue(any("[newcalc0] MsfCalcX64" in prompt for prompt in prompts))
                    self.assertTrue(any("待review" in prompt and "behavior_valid" in prompt and "历史 1" in prompt for prompt in prompts))
                    self.assertTrue(any("待验证" in prompt for prompt in prompts))
                    self.assertFalse(any("[oldcalc0]" in prompt for prompt in prompts))
                    catalog = str(app.query_one("#plugin-verify-catalog", Static).content)
                    self.assertIn("待验证 1", catalog)
                    self.assertIn("待review 1", catalog)
                    self.assertIn("隐藏历史 1", catalog)
                    self.assertNotIn("atom.payload.msf_calc_x64", catalog)

    async def test_tui_plugin_verify_queue_separates_validate_and_review(self) -> None:
        inventory = {
            "runs": [
                {
                    "plugin_run_id": "plugin-run-compile01",
                    "implementation_name": "CreateProcessCmd",
                    "plugin_id": "atom.ex.create_process_cmd",
                    "lifecycle_status": "compile_valid",
                    "catalog_status": None,
                    "ph_ids": ["PH-EX01"],
                    "required_capabilities": [],
                    "provided_capabilities": [],
                },
                {
                    "plugin_run_id": "plugin-run-review01",
                    "implementation_name": "PowershellCommand",
                    "plugin_id": "atom.ex.powershell",
                    "lifecycle_status": "behavior_valid",
                    "catalog_status": None,
                    "ph_ids": ["PH-EX11"],
                    "required_capabilities": [],
                    "provided_capabilities": [],
                },
                {
                    "plugin_run_id": "plugin-run-reviewed01",
                    "implementation_name": "Whoami",
                    "plugin_id": "atom.di.whoami",
                    "lifecycle_status": "behavior_valid",
                    "catalog_status": "reviewed",
                    "ph_ids": ["PH-DI01"],
                    "required_capabilities": [],
                    "provided_capabilities": [],
                },
                {
                    "plugin_run_id": "plugin-run-dispatch01",
                    "implementation_name": "MsfCalcX64",
                    "plugin_id": "atom.payload.msf_calc_x64",
                    "lifecycle_status": "behavior_valid",
                    "catalog_status": "dispatchable",
                    "ph_ids": [],
                    "required_capabilities": [],
                    "provided_capabilities": ["cap.payload.shellcode"],
                },
            ],
            "catalog": {
                "candidate": [],
                "reviewed": ["atom.di.whoami"],
                "dispatchable": ["atom.payload.msf_calc_x64"],
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            app = SampleFactoryTui(Path(tmp) / "missing.json", Path(tmp) / "run.json")
            with (
                patch("packages.sample_factory.tui.list_plugin_inventory", return_value=inventory),
                patch.object(app, "_run_preflight"),
            ):
                async with app.run_test(size=(160, 60)) as pilot:
                    await pilot.pause()
                    app.query_one("#factory-tabs", TabbedContent).active = "plugin-verify-tab"
                    app._refresh_plugin_verify_list()
                    widget = app.query_one("#plugin-verify-list", SelectionList)

                    def prompts() -> list[str]:
                        return [
                            str(widget.get_option_at_index(index).prompt)
                            for index in range(widget.option_count)
                        ]

                    work = prompts()
                    self.assertEqual(2, len(work))
                    self.assertTrue(any("待验证" in prompt and "CreateProcessCmd" in prompt for prompt in work))
                    self.assertTrue(any("待review" in prompt and "PowershellCommand" in prompt for prompt in work))
                    self.assertFalse(any("Whoami" in prompt for prompt in work))
                    self.assertFalse(any("MsfCalcX64" in prompt for prompt in work))
                    catalog = str(app.query_one("#plugin-verify-catalog", Static).content)
                    self.assertIn("待验证 1", catalog)
                    self.assertIn("待review 1", catalog)
                    self.assertIn("待promote 1", catalog)
                    self.assertIn("已入库 1", catalog)
                    self.assertNotIn("atom.di.whoami", catalog)

                    app.query_one("#plugin-verify-queue", Select).value = "validate"
                    app._render_plugin_verify_options()
                    only_validate = prompts()
                    self.assertEqual(1, len(only_validate))
                    self.assertTrue(any("CreateProcessCmd" in prompt for prompt in only_validate))

                    app.query_one("#plugin-verify-queue", Select).value = "review"
                    app._render_plugin_verify_options()
                    only_review = prompts()
                    self.assertEqual(1, len(only_review))
                    self.assertTrue(any("PowershellCommand" in prompt for prompt in only_review))

                    app.query_one("#plugin-verify-queue", Select).value = "promote"
                    app._render_plugin_verify_options()
                    only_promote = prompts()
                    self.assertEqual(1, len(only_promote))
                    self.assertTrue(any("Whoami" in prompt for prompt in only_promote))


if __name__ == "__main__":
    unittest.main()
