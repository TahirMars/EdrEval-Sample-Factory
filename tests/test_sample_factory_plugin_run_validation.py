from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.factory_host.plugin_harness_vmware import PluginDependencyLinkResult
from packages.sample_factory.cli import (
    execute_plugin_run_validation,
    list_plugin_inventory,
)
from packages.sample_factory.compiler import source_tree_digest
from packages.sample_factory.errors import FactoryDenied
from packages.sample_factory.models import (
    AtomRole,
    AtomSpec,
    HandoffMaterialize,
    IntegrationState,
    SafetyProfile,
    TriggerMode,
)
from packages.sample_factory.plugin_models import (
    PluginAuthoringResult,
    PluginBuildResult,
    PluginLifecycleStatus,
    PluginOperation,
    PluginRequest,
    PluginSourceCandidate,
    PluginValidationResult,
    PortContract,
    TechniqueIntent,
)
from packages.sample_factory.plugin_run_repository import PluginRunRepository

from tests.sample_factory_fixtures import atom_specs
from tests.test_sample_factory_plugin_authoring import _request


def _coverage_matrix() -> Path:
    return Path("docs/coverage/procedure-host-ttp-coverage-matrix.md").resolve()


def _factory_config(root: Path) -> Path:
    catalog = root / "catalog"
    catalog.mkdir()
    (catalog / "telemetry").mkdir()
    (catalog / "telemetry" / "contracts.json").write_text("{\"contracts\": []}\n", encoding="utf-8")
    targets = catalog / "build-targets"
    targets.mkdir()
    (targets / "build-targets.json").write_text(
        json.dumps({"targets": []}),
        encoding="utf-8",
    )
    config_path = root / "factory-config.json"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": "factory-config-v2",
                "coverage_matrix": str(_coverage_matrix()),
                "catalog_root": str(catalog),
                "runtime_root": str(root / "runtime"),
                "manifest_root": str(root / "manifests"),
            }
        ),
        encoding="utf-8",
    )
    (root / "manifests").mkdir()
    (root / "runtime").mkdir()
    return config_path


def _payload_spec() -> AtomSpec:
    return AtomSpec(
        atom_id="atom.payload.msf_calc_x64",
        role=AtomRole.LOADER_ATOM,
        integration_state=IntegrationState.IMPLEMENTED,
        variant_family="payload",
        provided_capabilities=("cap.payload.shellcode",),
        inputs_schema_ref="schema://payload",
        output_contract="shellcode",
        produces_handoffs=("handoff://shellcode/v1",),
        materialize=HandoffMaterialize.EMBED_AT_BUILD,
        artifact_ref="payload://x64/msf_calc_x64",
        verification_profile="standard",
        safety_profile=SafetyProfile.LOW,
        trigger_modes=(TriggerMode.LAB_TRIGGER,),
        requires_implant=False,
        env_prerequisites=("windows-11",),
        toolchain_ref="toolchain://msvc-pinned",
        tool_ref="plugin://payload/msf-calc",
    )


def _payload_request() -> PluginRequest:
    return PluginRequest(
        request_id="plugin-request-payload01",
        operation=PluginOperation.CREATE,
        implementation_name="MsfCalcX64",
        intent=TechniqueIntent(
            intent_id="intent-payload01",
            ph_ids=(),
            role=AtomRole.LOADER_ATOM,
            required_capabilities=(),
            provided_capabilities=("cap.payload.shellcode",),
            input_ports=(
                PortContract(
                    port_id="port.request",
                    value_type="json",
                    semantic="empty",
                    architecture="any",
                    required=False,
                ),
            ),
            produces_handoffs=("handoff://shellcode/v1",),
            artifact_ref="payload://x64/msf_calc_x64",
            architecture="x64",
            safety_profile=SafetyProfile.LOW,
            source_refs=("https://example.invalid/payload",),
        ),
        build_target_ref="build-target://windows-x64",
        profile_id="win11-sysmon15-no-edr",
    )


def _write_compile_valid_run(
    runtime: Path,
    *,
    plugin_run_id: str,
    request: PluginRequest,
    spec: AtomSpec,
) -> None:
    repository = PluginRunRepository(runtime)
    root = repository.create(plugin_run_id, request)
    source_root = root / "authoring" / "final-source"
    src = source_root / "src"
    src.mkdir(parents=True)
    header = src / f"{request.implementation_name}.h"
    impl = src / f"{request.implementation_name}.cpp"
    header.write_text(
        f'#pragma once\nextern "C" int EdrEvalTtp_{request.implementation_name}_Execute();\n',
        encoding="utf-8",
    )
    impl.write_text(
        f'#include "{request.implementation_name}.h"\nint '
        f"EdrEvalTtp_{request.implementation_name}_Execute() {{ return 0; }}\n",
        encoding="utf-8",
    )
    (source_root / "generated").mkdir()
    (source_root / "generated" / "sample.vcxproj").write_text("<Project />\n", encoding="utf-8")
    digest = source_tree_digest(source_root)
    implementation_digest = source_tree_digest(src)
    build_dir = root / "build" / "build1"
    build_dir.mkdir(parents=True)
    artifact = build_dir / f"{request.implementation_name}.lib"
    artifact.write_bytes(b"validation-library")
    artifact_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    result = PluginAuthoringResult(
        plugin_run_id=plugin_run_id,
        request_id=request.request_id,
        status=PluginLifecycleStatus.COMPILE_VALID,
        source=PluginSourceCandidate(
            plugin_id=spec.atom_id,
            implementation_name=request.implementation_name,
            source_ref=f"plugin-source://{plugin_run_id}/final-source",
            source_digest=digest,
            changed_files=(
                f"src/{request.implementation_name}.cpp",
                f"src/{request.implementation_name}.h",
                "generated/sample.vcxproj",
            ),
            atom_spec=spec,
            required_capabilities=request.intent.required_capabilities,
            provided_capabilities=request.intent.provided_capabilities,
            input_ports=request.intent.input_ports,
            output_ports=request.intent.output_ports,
        ),
        build=PluginBuildResult(
            build_ref=f"plugin-build://{plugin_run_id}",
            artifact_ref=f"plugin-build-artifact://{plugin_run_id}/build1",
            artifact_sha256=artifact_digest,
            source_digest=digest,
            implementation_source_digest=implementation_digest,
            artifact_filename=f"{request.implementation_name}.lib",
            toolchain_fp="msvc-test@pinned",
            build_id="build1",
        ),
        compile_only_reason="independent_harness_not_configured",
    )
    repository.complete(root, result)


class _IndependentHarness:
    def validate(self, source, build, request, *, plugin_run_id):
        del source, build
        assert request.harness_ref is not None
        return PluginValidationResult(
            harness_ref=request.harness_ref,
            contract_valid=True,
            atom_valid=True,
            behavior_valid=True,
            evidence_ref=f"plugin-evidence://{plugin_run_id}",
            assertions=("process.created=passed:evidence",),
        )


class _JointHarness:
    def validate_dependency_links(self, plan, results):
        consumer_id = plan.dependencies[0].consumer_request_id
        producer_id = plan.dependencies[0].producer_request_id
        self.seen_request_ids = [item.request_id for item in results]
        return (
            PluginDependencyLinkResult(
                plan_id=plan.plan_id,
                consumer_request_id=consumer_id,
                dependency_request_ids=(producer_id,),
                artifact_sha256="a" * 64,
                link_toolchain_fp="msvc-test+harness-v1",
                evidence_ref="plugin-dependency-link://consumer/joint",
                behavior_valid=True,
                assertions=("sysmon.event_id.1=passed:evidence",),
            ),
        )


class PluginRunValidationTest(unittest.TestCase):
    def test_independent_harness_persists_behavior_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = _factory_config(root)
            spec = atom_specs()[2].model_copy(update={"required_capabilities": ()})
            request = _request().model_copy(
                update={
                    "intent": _request().intent.model_copy(update={"required_capabilities": ()})
                }
            )
            _write_compile_valid_run(
                root / "runtime",
                plugin_run_id="plugin-run-independent1",
                request=request,
                spec=spec,
            )
            with patch(
                "packages.sample_factory.cli._plugin_harness",
                return_value=_IndependentHarness(),
            ):
                results = execute_plugin_run_validation(
                    config_path,
                    ("plugin-run-independent1",),
                    approved=True,
                )

            self.assertEqual(1, len(results))
            self.assertEqual(PluginLifecycleStatus.BEHAVIOR_VALID, results[0].status)
            self.assertIsNotNone(results[0].validation)
            payload = PluginRunRepository(root / "runtime").payload("plugin-run-independent1")
            stored = PluginAuthoringResult.model_validate(payload["result"])
            self.assertEqual(PluginLifecycleStatus.BEHAVIOR_VALID, stored.status)
            self.assertIsNone(stored.compile_only_reason)

    def test_joint_harness_auto_includes_producer_and_folds_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = _factory_config(root)
            runtime = root / "runtime"
            consumer_request = _request()
            _write_compile_valid_run(
                runtime,
                plugin_run_id="plugin-run-consumer01",
                request=consumer_request,
                spec=atom_specs()[2],
            )
            _write_compile_valid_run(
                runtime,
                plugin_run_id="plugin-run-producer01",
                request=_payload_request(),
                spec=_payload_spec(),
            )
            harness = _JointHarness()
            with patch("packages.sample_factory.cli._plugin_harness", return_value=harness):
                results = execute_plugin_run_validation(
                    config_path,
                    ("plugin-run-consumer01",),
                    approved=True,
                )

            statuses = {item.request_id: item.status for item in results}
            self.assertEqual(PluginLifecycleStatus.BEHAVIOR_VALID, statuses[consumer_request.request_id])
            self.assertEqual(
                PluginLifecycleStatus.BEHAVIOR_VALID,
                statuses[_payload_request().request_id],
            )
            self.assertEqual(
                ["plugin-request-payload01", "plugin-request-12345678"],
                harness.seen_request_ids,
            )
            inventory = list_plugin_inventory(config_path)
            by_id = {item["plugin_run_id"]: item for item in inventory["runs"]}
            self.assertEqual("behavior_valid", by_id["plugin-run-consumer01"]["lifecycle_status"])
            self.assertEqual("behavior_valid", by_id["plugin-run-producer01"]["lifecycle_status"])

    def test_joint_harness_collapses_duplicate_producer_runs_of_same_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = _factory_config(root)
            runtime = root / "runtime"
            consumer_request = _request()
            _write_compile_valid_run(
                runtime,
                plugin_run_id="plugin-run-consumer01",
                request=consumer_request,
                spec=atom_specs()[2],
            )
            _write_compile_valid_run(
                runtime,
                plugin_run_id="plugin-run-producer01",
                request=_payload_request(),
                spec=_payload_spec(),
            )
            _write_compile_valid_run(
                runtime,
                plugin_run_id="plugin-run-producer02",
                request=_payload_request(),
                spec=_payload_spec(),
            )
            harness = _JointHarness()
            with patch("packages.sample_factory.cli._plugin_harness", return_value=harness):
                results = execute_plugin_run_validation(
                    config_path,
                    ("plugin-run-consumer01",),
                    approved=True,
                )

            statuses = {item.request_id: item.status for item in results}
            self.assertEqual(PluginLifecycleStatus.BEHAVIOR_VALID, statuses[consumer_request.request_id])
            self.assertEqual(
                PluginLifecycleStatus.BEHAVIOR_VALID,
                statuses[_payload_request().request_id],
            )
            self.assertEqual(
                ["plugin-request-payload01", "plugin-request-12345678"],
                harness.seen_request_ids,
            )

    def test_mixed_unrelated_chains_validate_only_ph_component(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = _factory_config(root)
            runtime = root / "runtime"
            consumer_request = _request()
            _write_compile_valid_run(
                runtime,
                plugin_run_id="plugin-run-consumer01",
                request=consumer_request,
                spec=atom_specs()[2],
            )
            _write_compile_valid_run(
                runtime,
                plugin_run_id="plugin-run-producer01",
                request=_payload_request(),
                spec=_payload_spec(),
            )
            token_request = _payload_request().model_copy(
                update={
                    "request_id": "plugin-request-token0001",
                    "implementation_name": "EnableTokenPrivilege",
                    "intent": _payload_request().intent.model_copy(
                        update={
                            "intent_id": "intent-token0001",
                            "required_capabilities": ("cap.process.elevated",),
                            "provided_capabilities": ("cap.token.privilege",),
                        }
                    ),
                }
            )
            uac_request = _payload_request().model_copy(
                update={
                    "request_id": "plugin-request-uac00001",
                    "implementation_name": "RequestElevationByUacPrompt",
                    "intent": _payload_request().intent.model_copy(
                        update={
                            "intent_id": "intent-uac00001",
                            "provided_capabilities": ("cap.process.elevated",),
                        }
                    ),
                }
            )
            _write_compile_valid_run(
                runtime,
                plugin_run_id="plugin-run-token0001",
                request=token_request,
                spec=_payload_spec().model_copy(
                    update={
                        "atom_id": "atom.pe.enable_token_privilege",
                        "provided_capabilities": ("cap.token.privilege",),
                    }
                ),
            )
            _write_compile_valid_run(
                runtime,
                plugin_run_id="plugin-run-uac000001",
                request=uac_request,
                spec=_payload_spec().model_copy(
                    update={
                        "atom_id": "atom.pe.request_elevation_uac",
                        "provided_capabilities": ("cap.process.elevated",),
                    }
                ),
            )
            harness = _JointHarness()
            with patch("packages.sample_factory.cli._plugin_harness", return_value=harness):
                results = execute_plugin_run_validation(
                    config_path,
                    ("plugin-run-consumer01", "plugin-run-token0001"),
                    approved=True,
                )

            statuses = {item.request_id: item.status for item in results}
            self.assertEqual(
                PluginLifecycleStatus.BEHAVIOR_VALID, statuses[consumer_request.request_id]
            )
            self.assertNotIn(token_request.request_id, statuses)
            self.assertEqual(
                ["plugin-request-payload01", "plugin-request-12345678"],
                harness.seen_request_ids,
            )

    def test_multiple_producers_error_names_short_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = _factory_config(root)
            runtime = root / "runtime"
            _write_compile_valid_run(
                runtime,
                plugin_run_id="plugin-run-consumer01",
                request=_request(),
                spec=atom_specs()[2],
            )
            _write_compile_valid_run(
                runtime,
                plugin_run_id="plugin-run-ea649a26ee24464b",
                request=_payload_request(),
                spec=_payload_spec(),
            )
            other = _payload_request().model_copy(
                update={
                    "request_id": "plugin-request-payload02",
                    "implementation_name": "MsfCalcX64Sf033",
                    "intent": _payload_request().intent.model_copy(
                        update={"intent_id": "intent-payload02"}
                    ),
                }
            )
            _write_compile_valid_run(
                runtime,
                plugin_run_id="plugin-run-a8a3aca19458402a",
                request=other,
                spec=_payload_spec().model_copy(
                    update={"atom_id": "atom.payload.msf_calc_x64_sf033"}
                ),
            )
            with (
                patch("packages.sample_factory.cli._plugin_harness", return_value=_IndependentHarness()),
                self.assertRaises(ValueError) as ctx,
            ):
                execute_plugin_run_validation(
                    config_path,
                    ("plugin-run-consumer01",),
                    approved=True,
                )
            message = str(ctx.exception)
            self.assertIn("cap.payload.shellcode", message)
            self.assertIn("MsfCalcX64 [ea649a26]", message)
            self.assertIn("MsfCalcX64Sf033 [a8a3aca1]", message)
            self.assertNotIn("plugin-run-ea649a26ee24464b", message)

    def test_support_plugins_without_ph_error_names_short_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = _factory_config(root)
            runtime = root / "runtime"
            _write_compile_valid_run(
                runtime,
                plugin_run_id="plugin-run-ea649a26ee24464b",
                request=_payload_request(),
                spec=_payload_spec(),
            )
            other = _payload_request().model_copy(
                update={
                    "request_id": "plugin-request-payload02",
                    "implementation_name": "MsfCalcX64Sf033",
                    "intent": _payload_request().intent.model_copy(
                        update={"intent_id": "intent-payload02"}
                    ),
                }
            )
            _write_compile_valid_run(
                runtime,
                plugin_run_id="plugin-run-da062067da1e41b1",
                request=other,
                spec=_payload_spec(),
            )
            with (
                patch("packages.sample_factory.cli._plugin_harness", return_value=_IndependentHarness()),
                self.assertRaises(ValueError) as ctx,
            ):
                execute_plugin_run_validation(
                    config_path,
                    ("plugin-run-ea649a26ee24464b", "plugin-run-da062067da1e41b1"),
                    approved=True,
                )
            message = str(ctx.exception)
            self.assertIn("所选插件都没有可验证的 PH", message)
            self.assertIn("MsfCalcX64 [ea649a26]", message)
            self.assertIn("MsfCalcX64Sf033 [da062067]", message)

    def test_validation_requires_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(FactoryDenied):
            execute_plugin_run_validation(
                _factory_config(Path(tmp)),
                ("plugin-run-missing1",),
                approved=False,
            )


if __name__ == "__main__":
    unittest.main()
