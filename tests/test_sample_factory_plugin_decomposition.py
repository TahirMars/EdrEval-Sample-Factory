from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.contract_gap import ContractGapError
from packages.sample_factory.cli import (
    FactoryCliConfig,
    _plugin_authoring_preflight,
    execute_plugin_decomposition,
)
from packages.sample_factory.models import AtomRole, SafetyProfile
from packages.sample_factory.plugin_models import (
    PluginAuthoringResult,
    PluginDecompositionPlan,
    PluginDependency,
    PluginLifecycleStatus,
    PluginOperation,
    PluginRequest,
    PortContract,
    TechniqueIntent,
)

from tests.test_sample_factory_plugin_authoring import _request


def _plan() -> PluginDecompositionPlan:
    producer = _request().model_copy(
        update={
            "request_id": "plugin-request-producer01",
            "implementation_name": "PayloadProducer",
            "intent": _request().intent.model_copy(
                update={
                    "required_capabilities": (),
                    "provided_capabilities": ("cap.payload.shellcode",),
                }
            ),
        }
    )
    consumer = _request().model_copy(
        update={
            "request_id": "plugin-request-consumer01",
            "intent": _request().intent.model_copy(
                update={
                    "required_capabilities": ("cap.payload.shellcode",),
                    "provided_capabilities": ("cap.process.injection",),
                }
            ),
        }
    )
    return PluginDecompositionPlan(
        plan_id="plugin-plan-12345678",
        summary="payload provider followed by execution consumer",
        requests=(consumer, producer),
        external_capabilities=(),
        dependencies=(
            PluginDependency(
                producer_request_id=producer.request_id,
                consumer_request_id=consumer.request_id,
                capability="cap.payload.shellcode",
            ),
        ),
    )


class PluginDecompositionTest(unittest.TestCase):
    def test_executes_producer_before_consumer(self) -> None:
        calls: list[str] = []

        class DependencyHarness:
            def validate_dependency_links(self, plan, results):
                del plan, results
                return ()

        def execute(config_path, request, *, approved, sink, run_harness):
            del config_path, approved, sink, run_harness
            calls.append(request.request_id)
            return PluginAuthoringResult(
                plugin_run_id=f"plugin-run-{request.request_id.removeprefix('plugin-request-')}",
                request_id=request.request_id,
                status=PluginLifecycleStatus.COMPILE_VALID,
            )

        with patch(
            "packages.sample_factory.cli.execute_plugin_authoring_request",
            side_effect=execute,
        ), patch(
            "packages.sample_factory.cli._load_json_model",
            return_value=object(),
        ), patch(
            "packages.sample_factory.cli._resolve_config_paths",
            return_value=object(),
        ), patch(
            "packages.sample_factory.cli._plugin_compiler",
            return_value=object(),
        ), patch(
            "packages.sample_factory.cli._plugin_harness",
            return_value=DependencyHarness(),
        ):
            results = execute_plugin_decomposition("factory-config.json", _plan(), approved=True)

        self.assertEqual(["plugin-request-producer01", "plugin-request-consumer01"], calls)
        self.assertEqual(tuple(calls), tuple(item.request_id for item in results))

    def test_stops_before_dependent_node_when_producer_fails(self) -> None:
        calls: list[str] = []

        def execute(config_path, request, *, approved, sink, run_harness):
            del config_path, approved, sink, run_harness
            calls.append(request.request_id)
            raise RuntimeError("producer failed")

        with (
            patch(
                "packages.sample_factory.cli.execute_plugin_authoring_request",
                side_effect=execute,
            ),
            self.assertRaisesRegex(RuntimeError, "producer failed"),
        ):
            execute_plugin_decomposition("factory-config.json", _plan(), approved=True)

        self.assertEqual(["plugin-request-producer01"], calls)

    def test_rejects_dependency_without_matching_capability(self) -> None:
        plan = _plan()
        payload = plan.model_dump(mode="json")
        payload["dependencies"] = [
            {
                "producer_request_id": "plugin-request-producer01",
                "consumer_request_id": "plugin-request-consumer01",
                "capability": "cap.unknown",
            }
        ]
        with self.assertRaisesRegex(ValueError, "producer"):
            PluginDecompositionPlan.model_validate(payload)

    def test_rejects_cycle(self) -> None:
        plan = _plan()
        payload = plan.model_dump(mode="json")
        payload["requests"][0]["intent"]["provided_capabilities"] = ["cap.process.injection"]
        payload["requests"][1]["intent"]["required_capabilities"] = ["cap.process.injection"]
        payload["dependencies"].append(
            {
                "producer_request_id": "plugin-request-consumer01",
                "consumer_request_id": "plugin-request-producer01",
                "capability": "cap.process.injection",
            }
        )
        with self.assertRaisesRegex(ValueError, "存在环"):
            PluginDecompositionPlan.model_validate(payload)

    def test_requires_explicit_external_capability_for_unbound_input(self) -> None:
        request = _request()
        with self.assertRaisesRegex(ValueError, "external_capabilities"):
            PluginDecompositionPlan(
                plan_id="plugin-plan-unbound01",
                summary="unbound input",
                requests=(request,),
            )

        plan = PluginDecompositionPlan(
            plan_id="plugin-plan-external01",
            summary="input supplied by approved fixture",
            requests=(request,),
            external_capabilities=("cap.payload.shellcode",),
        )
        self.assertEqual(("cap.payload.shellcode",), plan.external_capabilities)

    def test_preflight_does_not_bind_loader_atom_to_execution_harness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            catalog = root / "catalog"
            targets = catalog / "build-targets" / "build-targets.json"
            targets.parent.mkdir(parents=True)
            targets.write_text(
                json.dumps(
                    {
                        "targets": [
                            {
                                "target_ref": "build-target://windows-x64",
                                "argv_template": ["fakecc", "{source_root}", "{output_dir}"],
                                "artifact_relative": "{implementation_name}.lib",
                                "toolchain_fp": "test@pinned",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            harness_path = root / "factory-plugin-harness.json"
            msbuild = root / "MSBuild.exe"
            msbuild.write_bytes(b"fake")
            vmware = root / "vmware.json"
            vmware.write_text("{}", encoding="utf-8")
            harness_path.write_text(
                json.dumps(
                    {
                        "schema_version": "factory-vmware-plugin-harness-v1",
                        "spec": {
                            "schema_version": "sf-plugin-harness-v1",
                            "harness_ref": "plugin-harness://execution/windows-x64/v1",
                            "role": "execution_atom",
                            "ph_ids": ["PH-IN04"],
                            "profile_ids": ["win11-sysmon15-no-edr"],
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
                        "vmware_verification_config": str(vmware),
                        "profile": {
                            "profile_id": "win11-sysmon15-no-edr",
                            "env_detail": {"network_mode": "nat"},
                            "security_product_enabled": False,
                            "isolated": False,
                            "rollback_capable": True,
                            "sensors_ready": True,
                            "no_edr_control": True,
                        },
                        "msbuild_path": str(msbuild),
                        "link_toolchain_fp": "msvc-test+harness-v1",
                    }
                ),
                encoding="utf-8",
            )
            config = FactoryCliConfig(
                schema_version="factory-config-v2",
                coverage_matrix=root / "coverage.md",
                catalog_root=catalog,
                runtime_root=root / "runtime",
                manifest_root=root / "manifests",
                plugin_harness_config=harness_path,
                verification_config=vmware,
            )
            loader = PluginRequest(
                request_id="plugin-request-msf-calc-x64-0001",
                operation=PluginOperation.CREATE,
                implementation_name="MsfCalcX64",
                intent=TechniqueIntent(
                    intent_id="intent-msf-calc-x64-0001",
                    ph_ids=(),
                    role=AtomRole.LOADER_ATOM,
                    required_capabilities=(),
                    provided_capabilities=("cap.payload.shellcode",),
                    input_ports=(
                        PortContract(
                            port_id="port.request",
                            value_type="json",
                            semantic="empty json smoke",
                            required=False,
                        ),
                    ),
                    output_ports=(
                        PortContract(
                            port_id="port.payload",
                            value_type="byte[]",
                            semantic="shellcode",
                            architecture="x64",
                        ),
                    ),
                    architecture="x64",
                    safety_profile=SafetyProfile.LOW,
                    source_refs=("plugin-seed://atom.payload.msf_calc_x64",),
                ),
                build_target_ref="build-target://windows-x64",
                profile_id="win11-sysmon15-no-edr",
            )

            _plugin_authoring_preflight(config, loader)

            misbound = loader.model_copy(
                update={"harness_ref": "plugin-harness://execution/windows-x64/v1"}
            )
            with self.assertRaises(ContractGapError) as raised:
                _plugin_authoring_preflight(config, misbound)
            self.assertIn("loader_atom != execution_atom", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
