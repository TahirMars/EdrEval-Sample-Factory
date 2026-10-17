from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from packages.factory_host.plugin_harness_vmware import (
    VmwarePluginHarnessBackend,
    VmwarePluginHarnessConfig,
)
from packages.factory_host.vmware_verification import GuestExecutionResult
from packages.sample_factory.compiler import source_tree_digest
from packages.sample_factory.errors import VerificationError
from packages.sample_factory.models import ProductionProfile
from packages.sample_factory.plugin_contract import materialize_validation_harness
from packages.sample_factory.plugin_harness import PluginHarnessSpec
from packages.sample_factory.plugin_models import (
    PluginAuthoringResult,
    PluginBuildResult,
    PluginDecompositionPlan,
    PluginDependency,
    PluginLifecycleStatus,
    PluginSourceCandidate,
)
from pydantic import ValidationError

from tests.sample_factory_fixtures import atom_specs
from tests.test_sample_factory_plugin_authoring import _request


class _Resolver:
    def __init__(self, source: Path, artifact: Path) -> None:
        self.source = source
        self.artifact = artifact

    def resolve(self, source_ref: str) -> Path:
        del source_ref
        return self.source

    def resolve_artifact(self, artifact_ref: str) -> Path:
        del artifact_ref
        return self.artifact


class _LinkRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], *, timeout: float | None = None) -> tuple[int, str]:
        del timeout
        self.calls.append(argv)
        out_dir = next(item for item in argv if item.startswith("/p:OutDir="))
        target = next(item for item in argv if item.startswith("/p:TargetName="))
        output = Path(out_dir.removeprefix("/p:OutDir=").rstrip("\\"))
        name = target.removeprefix("/p:TargetName=") + ".exe"
        (output / name).write_bytes(b"linked-harness")
        return 0, "linked"


class _MultiResolver:
    def __init__(self, sources: dict[str, Path], artifacts: dict[str, Path]) -> None:
        self.sources = sources
        self.artifacts = artifacts

    def resolve(self, source_ref: str) -> Path:
        return self.sources[source_ref]

    def resolve_artifact(self, artifact_ref: str) -> Path:
        return self.artifacts[artifact_ref]


class _Vmware:
    def __init__(
        self,
        event_ids: tuple[int, ...] = (1, 10),
        events: tuple[dict[str, object], ...] | None = None,
    ) -> None:
        self.event_ids = event_ids
        self.events = events
        self.calls: list[dict[str, object]] = []

    def execute_plugin_artifact(self, **kwargs):
        self.calls.append(kwargs)
        evidence = Path(kwargs["evidence_dir"])
        evidence.mkdir(parents=True)
        sysmon_events = self.events
        if sysmon_events is None:
            sysmon_events = tuple(
                {"event_id": event_id, "record_id": event_id}
                for event_id in self.event_ids
            )
        return (
            GuestExecutionResult(
                schema_version="factory-vmware-guest-result-v1",
                run_id="vm-plugin-run",
                process_created=True,
                process_id=4321,
                exit_code=0,
                remote_artifact_path=r"C:\ProgramData\EdrEvalAgent\Runs\x\harness.exe",
                remote_artifact_sha256=kwargs["artifact_sha256"],
                started_at_utc="2026-09-07T00:00:00Z",
                finished_at_utc="2026-09-07T00:00:02Z",
                sysmon_events=sysmon_events,
            ),
            evidence,
        )


def _sysmon_event(event_id: int, **data: str) -> dict[str, object]:
    return {"event_id": event_id, "record_id": event_id, "data": data}


def _with_atom(source, request, *, atom_id: str, ph_ids: tuple[str, ...], attck_ids: tuple[str, ...]):
    source = source.model_copy(
        update={
            "atom_spec": source.atom_spec.model_copy(
                update={"atom_id": atom_id, "ph_ids": ph_ids, "attck_ids": attck_ids}
            )
        }
    )
    request = request.model_copy(
        update={"intent": request.intent.model_copy(update={"ph_ids": ph_ids})}
    )
    return source, request


def _config(root: Path) -> VmwarePluginHarnessConfig:
    msbuild = root / "MSBuild.exe"
    msbuild.write_bytes(b"fake")
    vm_config = root / "vmware.json"
    vm_config.write_text("{}", encoding="utf-8")
    return VmwarePluginHarnessConfig(
        schema_version="factory-vmware-plugin-harness-v1",
        spec=PluginHarnessSpec(
            harness_ref="plugin-harness://execution/windows-x64/v1",
            role="execution_atom",
            ph_ids=("PH-IN04",),
            profile_ids=("win11-sysmon15-no-edr",),
            architectures=("x64",),
            telemetry_sources=("sysmon",),
            input_contract_ref="contract://plugin-harness/empty-json-smoke-v1",
            oracle_ref="oracle://ph-in04/sysmon-eid1-eid10-v1",
            collector_config_ref="collector://sysmon/related-process-v1",
            isolation_profile_ref="vm-profile://windows/nat-snapshot/test",
            required_assertions=(
                "process.created",
                "process.exit_code_zero",
                "sysmon.event_id.1",
                "sysmon.event_id.10",
            ),
        ),
        vmware_verification_config=vm_config,
        profile=ProductionProfile(
            profile_id="win11-sysmon15-no-edr",
            env_detail={"network_mode": "nat"},
            security_product_enabled=False,
            isolated=False,
            rollback_capable=True,
            sensors_ready=True,
            no_edr_control=True,
        ),
        msbuild_path=msbuild,
        link_toolchain_fp="msvc-test+harness-v1",
    )


def _allowlist_config(root: Path) -> VmwarePluginHarnessConfig:
    base = _config(root)
    return base.model_copy(
        update={
            "spec": base.spec.model_copy(
                update={
                    "ph_ids": (
                        "PH-IN03",
                        "PH-IN04",
                        "PH-IN08",
                        "PH-PE05",
                        "PH-PS01",
                        "PH-EX11",
                    ),
                    "oracle_ref": "oracle://ph-matrix/sysmon-projected-v1",
                    "required_assertions": (
                        "process.created",
                        "process.exit_code_zero",
                        "sysmon.event_id.1",
                        "sysmon.event_id.7",
                        "sysmon.event_id.8",
                        "sysmon.event_id.10",
                        "sysmon.event_id.13",
                    ),
                }
            )
        }
    )


def _candidate(root: Path):
    plugin_root = root / "runtime" / "plugin-runs" / "2026" / "09" / "07" / "plugin-run-12345678"
    source_root = plugin_root / "authoring" / "final-source"
    (source_root / "src").mkdir(parents=True)
    (source_root / "src" / "EarlyApcInjection.h").write_text(
        '#pragma once\nextern "C" int EdrEvalTtp_EarlyApcInjection_Execute('
        "const char*, char*, unsigned long long);\n",
        encoding="utf-8",
    )
    (source_root / "src" / "EarlyApcInjection.cpp").write_text(
        '#include "EarlyApcInjection.h"\n', encoding="utf-8"
    )
    materialize_validation_harness(plugin_root, "EarlyApcInjection")
    artifact = plugin_root / "build" / "build1" / "EarlyApcInjection.lib"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"plugin-lib")
    artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    spec = atom_specs()[2].model_copy(update={"required_capabilities": ()})
    source = PluginSourceCandidate(
        plugin_id=spec.atom_id,
        implementation_name="EarlyApcInjection",
        source_ref="plugin-source://plugin-run-12345678/final-source",
        source_digest=source_tree_digest(source_root),
        changed_files=("src/EarlyApcInjection.h", "src/EarlyApcInjection.cpp"),
        atom_spec=spec,
        required_capabilities=(),
        provided_capabilities=spec.provided_capabilities,
    )
    build = PluginBuildResult(
        build_ref="plugin-build://plugin-run-12345678/build1",
        artifact_ref="plugin-build-artifact://plugin-run-12345678/build1",
        artifact_sha256=artifact_sha,
        source_digest=source.source_digest,
        implementation_source_digest=source_tree_digest(source_root / "src"),
        artifact_filename="EarlyApcInjection.lib",
        toolchain_fp="msvc-test",
        build_id="build1",
    )
    request = _request().model_copy(
        update={
            "intent": _request().intent.model_copy(update={"required_capabilities": ()}),
            "harness_ref": "plugin-harness://execution/windows-x64/v1",
        }
    )
    return source_root, artifact, source, build, request


class VmwarePluginHarnessTest(unittest.TestCase):
    def test_links_lib_then_requires_vm_sysmon_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root, artifact, source, build, request = _candidate(root)
            resolver = _Resolver(source_root, artifact)
            runner = _LinkRunner()
            vmware = _Vmware()
            backend = VmwarePluginHarnessBackend(
                _config(root),
                vmware=vmware,
                source_resolver=resolver,
                artifact_resolver=resolver,
                runner=runner,
            )

            result = backend.validate(
                source, build, request, plugin_run_id="plugin-run-12345678"
            )

            self.assertTrue(result.behavior_valid)
            self.assertIn(str(artifact.resolve()), (source_root.parent.parent / "harness-build" / "build1" / "PluginValidationHarness.vcxproj").read_text(encoding="utf-8"))
            receipt = json.loads(
                (source_root.parent.parent / "harness-build" / "build1" / "link-receipt.json").read_text(encoding="utf-8")
            )
            self.assertEqual(build.artifact_sha256, receipt["source_artifact_sha256"])
            self.assertEqual("msvc-test+harness-v1", receipt["toolchain_fp"])
            self.assertEqual(1, len(vmware.calls))
            self.assertTrue(vmware.calls[0]["recipe"].execution_logging)
            linked_main = (
                source_root.parent.parent / "harness-build" / "build1" / "main.cpp"
            ).read_text(encoding="utf-8")
            self.assertIn("edreval::sample_log::RecordTtpStart", linked_main)
            self.assertIn("edreval-ttp-result-v1", linked_main)
            self.assertIn(
                "edreval_execution_log.cpp",
                (source_root.parent.parent / "harness-build" / "build1" / "PluginValidationHarness.vcxproj").read_text(
                    encoding="utf-8"
                ),
            )

    def test_missing_required_sysmon_event_cannot_be_behavior_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root, artifact, source, build, request = _candidate(root)
            resolver = _Resolver(source_root, artifact)
            backend = VmwarePluginHarnessBackend(
                _config(root),
                vmware=_Vmware(event_ids=(1,)),
                source_resolver=resolver,
                artifact_resolver=resolver,
                runner=_LinkRunner(),
            )

            result = backend.validate(
                source, build, request, plugin_run_id="plugin-run-12345678"
            )

            self.assertFalse(result.behavior_valid)
            self.assertTrue(any("sysmon.event_id.10=failed" in item for item in result.assertions))

    def test_single_plugin_harness_rejects_unclosed_capability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root, artifact, source, build, request = _candidate(root)
            resolver = _Resolver(source_root, artifact)
            source = source.model_copy(update={"required_capabilities": ("cap.payload.shellcode",)})
            request = request.model_copy(
                update={
                    "intent": request.intent.model_copy(
                        update={"required_capabilities": ("cap.payload.shellcode",)}
                    )
                }
            )
            backend = VmwarePluginHarnessBackend(
                _config(root),
                vmware=_Vmware(),
                source_resolver=resolver,
                artifact_resolver=resolver,
                runner=_LinkRunner(),
            )

            with self.assertRaisesRegex(VerificationError, "依赖闭包"):
                backend.validate(
                    source, build, request, plugin_run_id="plugin-run-12345678"
                )

    def test_nat_profile_must_not_be_marked_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = _config(Path(tmp))
            with self.assertRaises(ValidationError):
                VmwarePluginHarnessConfig.model_validate(
                    config.model_dump(mode="python")
                    | {"profile": config.profile.model_copy(update={"isolated": True})}
                )

    def test_dependency_link_uses_only_declared_transitive_closure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            consumer_root, consumer_artifact, consumer_source, consumer_build, consumer = (
                _candidate(root)
            )
            capability = "cap.payload.shellcode"
            consumer = consumer.model_copy(
                update={
                    "intent": consumer.intent.model_copy(
                        update={"required_capabilities": (capability,)}
                    )
                }
            )
            consumer_source = consumer_source.model_copy(
                update={
                    "required_capabilities": (capability,),
                    "atom_spec": consumer_source.atom_spec.model_copy(
                        update={"required_capabilities": (capability,)}
                    ),
                }
            )
            producer = consumer.model_copy(
                update={
                    "request_id": "plugin-request-producer123",
                    "implementation_name": "PayloadProducer",
                    "intent": consumer.intent.model_copy(
                        update={
                            "intent_id": "intent-producer123",
                            "required_capabilities": (),
                            "provided_capabilities": (capability,),
                        }
                    ),
                }
            )
            producer_plugin_root = (
                root
                / "runtime"
                / "plugin-runs"
                / "2026"
                / "09"
                / "07"
                / "plugin-run-producer123"
            )
            producer_root = producer_plugin_root / "authoring" / "final-source"
            (producer_root / "src").mkdir(parents=True)
            for suffix in ("h", "cpp"):
                (producer_root / "src" / f"PayloadProducer.{suffix}").write_text(
                    "// producer\n", encoding="utf-8"
                )
            producer_artifact = producer_plugin_root / "build" / "build1" / "PayloadProducer.lib"
            producer_artifact.parent.mkdir(parents=True)
            producer_artifact.write_bytes(b"producer-lib")
            producer_source = PluginSourceCandidate(
                plugin_id="atom.payload.producer",
                implementation_name="PayloadProducer",
                source_ref="plugin-source://plugin-run-producer123/final-source",
                source_digest=source_tree_digest(producer_root),
                changed_files=("src/PayloadProducer.h", "src/PayloadProducer.cpp"),
                provided_capabilities=(capability,),
            )
            producer_build = PluginBuildResult(
                build_ref="plugin-build://plugin-run-producer123/build1",
                artifact_ref="plugin-build-artifact://plugin-run-producer123/build1",
                artifact_sha256=hashlib.sha256(producer_artifact.read_bytes()).hexdigest(),
                source_digest=producer_source.source_digest,
                implementation_source_digest=source_tree_digest(producer_root / "src"),
                artifact_filename="PayloadProducer.lib",
                toolchain_fp="msvc-test",
                build_id="build1",
            )
            plan = PluginDecompositionPlan(
                plan_id="plugin-plan-dependency123",
                summary="producer before consumer",
                requests=(producer, consumer),
                dependencies=(
                    PluginDependency(
                        producer_request_id=producer.request_id,
                        consumer_request_id=consumer.request_id,
                        capability=capability,
                    ),
                ),
            )
            results = (
                PluginAuthoringResult(
                    plugin_run_id="plugin-run-producer123",
                    request_id=producer.request_id,
                    status=PluginLifecycleStatus.COMPILE_VALID,
                    source=producer_source,
                    build=producer_build,
                ),
                PluginAuthoringResult(
                    plugin_run_id="plugin-run-12345678",
                    request_id=consumer.request_id,
                    status=PluginLifecycleStatus.COMPILE_VALID,
                    source=consumer_source,
                    build=consumer_build,
                ),
            )
            resolver = _MultiResolver(
                {
                    producer_source.source_ref: producer_root,
                    consumer_source.source_ref: consumer_root,
                },
                {
                    producer_build.artifact_ref: producer_artifact,
                    consumer_build.artifact_ref: consumer_artifact,
                },
            )
            vmware = _Vmware()
            backend = VmwarePluginHarnessBackend(
                _config(root),
                vmware=vmware,
                source_resolver=resolver,
                artifact_resolver=resolver,
                runner=_LinkRunner(),
            )

            link_results = backend.validate_dependency_links(plan, results)

            self.assertEqual(1, len(link_results))
            self.assertEqual((producer.request_id,), link_results[0].dependency_request_ids)
            self.assertTrue(link_results[0].behavior_valid)
            link_root = consumer_root.parent.parent / "dependency-links" / plan.plan_id
            project = (link_root / "PluginValidationHarness.vcxproj").read_text(encoding="utf-8")
            main = (link_root / "main.cpp").read_text(encoding="utf-8")
            self.assertIn(str(consumer_artifact.resolve()), project)
            self.assertIn(str(producer_artifact.resolve()), project)
            self.assertIn(str(producer_root.joinpath("src").resolve()), project)
            self.assertIn("EdrEvalTtp_PayloadProducer_Execute", main)
            self.assertIn("EdrEvalTtp_EarlyApcInjection_Execute", main)
            self.assertIn("edreval::sample_log::RecordTtpStart", main)
            self.assertIn("edreval-ttp-result-v1", main)
            self.assertIn("edreval_execution_log.cpp", project)
            self.assertNotIn('"status":"error"', main)
            self.assertEqual(1, len(vmware.calls))

    def test_joint_harness_without_payload_skips_copy(self) -> None:
        from packages.sample_factory.plugin_contract import render_joint_validation_harness_main

        payload = render_joint_validation_harness_main(
            "StartServiceByWinApi",
            ("CreateServiceByWinApi",),
            consumer_atom_id="atom.ps.start_service_winapi",
            consumer_ph_ids=("PH-EX11",),
            payload_handoff=True,
        )
        sequential = render_joint_validation_harness_main(
            "StartServiceByWinApi",
            ("CreateServiceByWinApi",),
            consumer_atom_id="atom.ps.start_service_winapi",
            consumer_ph_ids=("PH-EX11",),
            payload_handoff=False,
        )
        self.assertIn("CopyPayloadArray", payload)
        self.assertIn("notepad.exe", payload)
        self.assertNotIn("CopyPayloadArray(producer_json.data(), last_payload)", sequential)
        self.assertNotIn("notepad.exe", sequential)
        self.assertIn("const char* consumer_json = request_json;", sequential)
        self.assertIn("delegated_to_elevated_process", sequential)
        self.assertIn("SignalElevatedDone", sequential)

    def test_joint_payload_handoff_chains_later_producers(self) -> None:
        from packages.sample_factory.plugin_contract import render_joint_validation_harness_main

        chained = render_joint_validation_harness_main(
            "CreateRemoteThreadInjection",
            ("MsfCalcX64Sf033", "Rc4SystemFunction033"),
            consumer_atom_id="atom.in.create_remote_thread",
            consumer_ph_ids=("PH-IN01",),
            payload_handoff=True,
        )
        self.assertIn("EdrEvalTtp_MsfCalcX64Sf033_Execute", chained)
        self.assertIn("EdrEvalTtp_Rc4SystemFunction033_Execute", chained)
        self.assertIn("const char* producer_input = request_json;", chained)
        self.assertIn("const char* producer_input = producer_request.c_str();", chained)
        self.assertIn('producer_request = "{\\"payload\\":"', chained)
        self.assertLess(
            chained.index("EdrEvalTtp_MsfCalcX64Sf033_Execute"),
            chained.index("producer_request.c_str()"),
        )

    def test_checked_in_deployment_config_is_nat_and_matrix_bound(self) -> None:
        config = VmwarePluginHarnessConfig.load(
            Path("deployment/factory-plugin-harness.json")
        )
        self.assertFalse(config.profile.isolated)
        self.assertEqual(
            ("PH-IN01", "PH-IN02", "PH-IN03", "PH-IN04", "PH-IN05", "PH-IN06", "PH-IN07", "PH-IN08", "PH-PE01", "PH-PE02", "PH-PE05", "PH-PS01", "PH-EX02", "PH-EX11", "PH-BL07", "PH-BL08", "PH-OB05", "PH-EX01", "PH-PS02", "PH-PS03", "PH-DI01", "PH-DI02", "PH-DI03", "PH-DI04", "PH-DI05", "PH-DI06", "PH-DI07", "PH-DI08", "PH-IT01", "PH-OB08", "PH-OB09", "PH-BL10"),
            config.spec.ph_ids,
        )
        self.assertEqual(
            {
                "sysmon.event_id.1",
                "sysmon.event_id.2",
                "sysmon.event_id.7",
                "sysmon.event_id.8",
                "sysmon.event_id.10",
                "sysmon.event_id.11",
                "sysmon.event_id.13",
                "sysmon.event_id.25",
                "sysmon.event_id.26",
            },
            {item for item in config.spec.required_assertions if item.startswith("sysmon.")},
        )
        self.assertEqual(
            ("sysmon",),
            tuple(item.value for item in config.spec.telemetry_sources),
        )
        self.assertEqual(
            ("win11-sysmon15-no-edr", "win10-21h2-sysmon15-no-edr"),
            config.spec.profile_ids,
        )
        self.assertEqual("win11-sysmon15-no-edr", config.profile.profile_id)

    def test_checked_in_win10_harness_is_switchable_nat_profile(self) -> None:
        config = VmwarePluginHarnessConfig.load(
            Path("deployment/factory-plugin-harness-win10.json")
        )
        self.assertFalse(config.profile.isolated)
        self.assertEqual("win10-21h2-sysmon15-no-edr", config.profile.profile_id)
        self.assertEqual(
            ("win11-sysmon15-no-edr", "win10-21h2-sysmon15-no-edr"),
            config.spec.profile_ids,
        )
        self.assertEqual("19044", config.profile.env_detail["os_build"])
        self.assertEqual("new_dev_win10", config.profile.env_detail["snapshot"])
        self.assertEqual(
            Path("deployment/factory-vmware-verification-win10.json").resolve(),
            config.vmware_verification_config,
        )

    def test_operator_factory_config_points_at_matching_harness_pair(self) -> None:
        payload = json.loads(
            Path("deployment/factory-config.json").read_text(encoding="utf-8")
        )
        harness = VmwarePluginHarnessConfig.load(
            Path("deployment") / payload["plugin_harness_config"]
        )
        self.assertEqual(
            (Path("deployment") / payload["verification_config"]).resolve(),
            harness.vmware_verification_config,
        )
        self.assertIn(harness.profile.profile_id, harness.spec.profile_ids)

    def test_callback_exec_requires_calc_eid1_not_in08_group_oracles(self) -> None:
        from packages.sample_factory.catalog import CoverageRegistry

        coverage = CoverageRegistry.from_markdown(
            Path("docs/coverage/procedure-host-ttp-coverage-matrix.md")
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root, artifact, source, build, request = _candidate(root)
            source, request = _with_atom(
                source,
                request,
                atom_id="atom.ex.callback_exec",
                ph_ids=("PH-IN08",),
                attck_ids=("T1055",),
            )
            resolver = _Resolver(source_root, artifact)
            backend = VmwarePluginHarnessBackend(
                _allowlist_config(root),
                vmware=_Vmware(
                    events=(
                        _sysmon_event(
                            1,
                            Image=r"C:\Windows\System32\calc.exe",
                            ParentImage=r"C:\ProgramData\EdrEvalAgent\Runs\x\CallbackExecHarness.exe",
                        ),
                        _sysmon_event(10, SourceImage=r"C:\Windows\system32\svchost.exe"),
                        _sysmon_event(7, ImageLoaded=r"C:\Windows\System32\ntdll.dll"),
                    )
                ),
                source_resolver=resolver,
                artifact_resolver=resolver,
                runner=_LinkRunner(),
                coverage=coverage,
            )
            result = backend.validate(
                source, build, request, plugin_run_id="plugin-run-12345678"
            )
            self.assertTrue(result.behavior_valid)
            self.assertTrue(any("sysmon.event_id.1=passed" in item for item in result.assertions))
            self.assertFalse(any("sysmon.event_id.7=" in item for item in result.assertions))
            self.assertFalse(any("sysmon.event_id.10=" in item for item in result.assertions))

    def test_callback_exec_rejects_harness_eid1_and_matrix_siblings(self) -> None:
        from packages.sample_factory.catalog import CoverageRegistry

        coverage = CoverageRegistry.from_markdown(
            Path("docs/coverage/procedure-host-ttp-coverage-matrix.md")
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root, artifact, source, build, request = _candidate(root)
            source, request = _with_atom(
                source,
                request,
                atom_id="atom.ex.callback_exec",
                ph_ids=("PH-IN08",),
                attck_ids=("T1055",),
            )
            resolver = _Resolver(source_root, artifact)
            backend = VmwarePluginHarnessBackend(
                _allowlist_config(root),
                vmware=_Vmware(
                    events=(
                        _sysmon_event(
                            1,
                            Image=r"C:\ProgramData\EdrEvalAgent\Runs\x\CallbackExecHarness.exe",
                        ),
                        _sysmon_event(
                            10,
                            SourceImage=r"C:\ProgramData\EdrEvalAgent\Runs\x\CallbackExecHarness.exe",
                        ),
                        _sysmon_event(7),
                    )
                ),
                source_resolver=resolver,
                artifact_resolver=resolver,
                runner=_LinkRunner(),
                coverage=coverage,
            )
            result = backend.validate(
                source, build, request, plugin_run_id="plugin-run-12345678"
            )
            self.assertFalse(result.behavior_valid)
            self.assertTrue(any("sysmon.event_id.1=failed" in item for item in result.assertions))

    def test_thread_hijack_requires_eid10_not_create_remote_thread(self) -> None:
        from packages.sample_factory.catalog import CoverageRegistry

        coverage = CoverageRegistry.from_markdown(
            Path("docs/coverage/procedure-host-ttp-coverage-matrix.md")
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root, artifact, source, build, request = _candidate(root)
            source, request = _with_atom(
                source,
                request,
                atom_id="atom.in.thread_hijack",
                ph_ids=("PH-IN03",),
                attck_ids=("T1055.003",),
            )
            resolver = _Resolver(source_root, artifact)
            backend = VmwarePluginHarnessBackend(
                _allowlist_config(root),
                vmware=_Vmware(
                    events=(
                        _sysmon_event(
                            10,
                            SourceImage=r"C:\ProgramData\EdrEvalAgent\Runs\x\ThreadHijackInjectionHarness.exe",
                        ),
                    )
                ),
                source_resolver=resolver,
                artifact_resolver=resolver,
                runner=_LinkRunner(),
                coverage=coverage,
            )
            result = backend.validate(
                source, build, request, plugin_run_id="plugin-run-12345678"
            )
            self.assertTrue(result.behavior_valid)
            self.assertTrue(any("sysmon.event_id.10=passed" in item for item in result.assertions))
            self.assertFalse(any("sysmon.event_id.8=" in item for item in result.assertions))

    def test_create_service_requires_eid13_not_any_process_create(self) -> None:
        from packages.sample_factory.catalog import CoverageRegistry

        coverage = CoverageRegistry.from_markdown(
            Path("docs/coverage/procedure-host-ttp-coverage-matrix.md")
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root, artifact, source, build, request = _candidate(root)
            source, request = _with_atom(
                source,
                request,
                atom_id="atom.ps.create_service_winapi",
                ph_ids=("PH-PS01",),
                attck_ids=("T1543.003",),
            )
            resolver = _Resolver(source_root, artifact)
            backend = VmwarePluginHarnessBackend(
                _allowlist_config(root),
                vmware=_Vmware(event_ids=(1, 10)),
                source_resolver=resolver,
                artifact_resolver=resolver,
                runner=_LinkRunner(),
                coverage=coverage,
            )
            result = backend.validate(
                source, build, request, plugin_run_id="plugin-run-12345678"
            )
            self.assertFalse(result.behavior_valid)
            self.assertTrue(any("sysmon.event_id.13=failed" in item for item in result.assertions))
            self.assertFalse(any("sysmon.event_id.1=" in item for item in result.assertions))

    def test_allowlist_rejects_ph_not_in_harness_config(self) -> None:
        from packages.sample_factory.catalog import CoverageRegistry

        coverage = CoverageRegistry.from_markdown(
            Path("docs/coverage/procedure-host-ttp-coverage-matrix.md")
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root, artifact, source, build, request = _candidate(root)
            request = request.model_copy(
                update={
                    "intent": request.intent.model_copy(update={"ph_ids": ("PH-BL01",)})
                }
            )
            resolver = _Resolver(source_root, artifact)
            backend = VmwarePluginHarnessBackend(
                _allowlist_config(root),
                vmware=_Vmware(),
                source_resolver=resolver,
                artifact_resolver=resolver,
                runner=_LinkRunner(),
                coverage=coverage,
            )
            with self.assertRaisesRegex(VerificationError, "不在 Harness 允许集"):
                backend.validate(
                    source, build, request, plugin_run_id="plugin-run-12345678"
                )

    def test_upstream_producers_run_elevation_before_service_create(self) -> None:
        from packages.factory_host.plugin_harness_vmware import _ordered_upstream_producers

        incoming = {
            "uacme": [],
            "create": ["uacme"],
            "start": ["create"],
        }
        self.assertEqual(
            ("uacme", "create"),
            _ordered_upstream_producers(
                incoming, "start", ["start", "create", "uacme"]
            ),
        )


if __name__ == "__main__":
    unittest.main()
