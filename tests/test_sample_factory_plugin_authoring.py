from __future__ import annotations

import unittest

from packages.sample_factory.catalog import CoverageRegistry
from packages.sample_factory.errors import CompilationFailure
from packages.sample_factory.models import AtomRole, SafetyProfile
from packages.sample_factory.plugin_authoring import PluginAuthoringPipeline
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

from tests.sample_factory_fixtures import atom_specs


def _request() -> PluginRequest:
    return PluginRequest(
        request_id="plugin-request-12345678",
        operation=PluginOperation.CREATE,
        implementation_name="EarlyApcInjection",
        intent=TechniqueIntent(
            intent_id="intent-12345678",
            ph_ids=("PH-IN04",),
            role=AtomRole.EXECUTION_ATOM,
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
            output_ports=(),
            parameter_domains={"target": ("notepad.exe", "werfault.exe")},
            architecture="x64",
            safety_profile=SafetyProfile.MEDIUM,
            source_refs=("source://reviewed/reference",),
        ),
        build_target_ref="build-target://windows-x64",
        harness_ref="plugin-harness://execution/windows-x64/v1",
        profile_id="win11-sysmon15-no-edr",
    )


class _Author:
    def author(self, request, *, plugin_run_id):
        del plugin_run_id
        spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
        return PluginSourceCandidate(
            plugin_id=spec.atom_id,
            implementation_name=request.implementation_name,
            source_ref=f"plugin-source://{request.request_id}",
            source_digest="a" * 64,
            changed_files=(
                "src/EarlyApcInjection.cpp",
                "src/EarlyApcInjection.h",
            ),
            atom_spec=spec,
            required_capabilities=request.intent.required_capabilities,
            provided_capabilities=request.intent.provided_capabilities,
            input_ports=request.intent.input_ports,
            output_ports=request.intent.output_ports,
        )


class _Compiler:
    def compile(self, source, request, *, plugin_run_id):
        del request
        return PluginBuildResult(
            build_ref=f"plugin-build://{plugin_run_id}",
            artifact_ref=f"plugin-build-artifact://{plugin_run_id}/build1",
            artifact_sha256="e" * 64,
            source_digest=source.source_digest,
            implementation_source_digest="f" * 64,
            artifact_filename=f"{source.implementation_name}.lib",
            toolchain_fp="msvc-test@pinned",
            build_id="build1",
        )


class _FailOnceCompiler(_Compiler):
    def __init__(self) -> None:
        self.calls = []

    def compile(self, source, request, *, plugin_run_id):
        self.calls.append(source.source_digest)
        if len(self.calls) == 1:
            raise CompilationFailure(
                "compile failed",
                diagnostics_ref=f"plugin-build://{plugin_run_id}/deadbeef",
            )
        return super().compile(source, request, plugin_run_id=plugin_run_id)


class _RepairingAuthor(_Author):
    def __init__(self) -> None:
        self.repairs = []

    def repair(self, source, request, *, plugin_run_id, diagnostics_ref):
        del request
        self.repairs.append((source.source_digest, diagnostics_ref))
        return source.model_copy(
            update={
                "source_ref": f"plugin-source://{plugin_run_id}/repair-deadbeef",
                "source_digest": "b" * 64,
            }
        )


class _Harness:
    def __init__(self, *, behavior_valid: bool = True) -> None:
        self.behavior_valid = behavior_valid

    def validate(self, source, build, request, *, plugin_run_id):
        del source, build
        return PluginValidationResult(
            harness_ref=request.harness_ref,
            contract_valid=True,
            atom_valid=self.behavior_valid,
            behavior_valid=self.behavior_valid,
            evidence_ref=f"plugin-evidence://{plugin_run_id}",
            assertions=("contract", "behavior"),
        )


class PluginAuthoringPipelineTest(unittest.TestCase):
    def _pipeline(self, *, behavior_valid: bool = True, events=None):
        return PluginAuthoringPipeline(
            author=_Author(),
            compiler=_Compiler(),
            harness=_Harness(behavior_valid=behavior_valid),
            coverage=CoverageRegistry({"PH-IN04": ("T1055.004",)}),
            sink=None if events is None else events.append,
        )

    def test_author_compile_harness_stops_at_behavior_valid(self) -> None:
        events = []

        result = self._pipeline(events=events).run(_request(), approved=True)

        self.assertEqual(PluginLifecycleStatus.BEHAVIOR_VALID, result.status)
        self.assertIsNotNone(result.validation)
        self.assertTrue(events[-1][1]["dispatchable"] is False)
        self.assertEqual("sample_factory_plugin_behavior_valid", events[-1][0])

    def test_compile_failure_repairs_source_and_retries_with_new_digest(self) -> None:
        events = []
        author = _RepairingAuthor()
        compiler = _FailOnceCompiler()
        pipeline = PluginAuthoringPipeline(
            author=author,
            compiler=compiler,
            harness=_Harness(),
            coverage=CoverageRegistry({"PH-IN04": ("T1055.004",)}),
            sink=events.append,
            max_compile_attempts=2,
        )

        result = pipeline.run(
            _request(),
            approved=True,
            plugin_run_id="plugin-run-repair01",
        )

        self.assertEqual(["a" * 64, "b" * 64], compiler.calls)
        self.assertEqual(
            [("a" * 64, "plugin-build://plugin-run-repair01/deadbeef")],
            author.repairs,
        )
        self.assertEqual("b" * 64, result.source.source_digest)
        self.assertEqual(PluginLifecycleStatus.BEHAVIOR_VALID, result.status)
        self.assertIn(
            "sample_factory_plugin_source_repaired",
            [kind for kind, _data in events],
        )

    def test_requires_live_approval(self) -> None:
        with self.assertRaises(PermissionError):
            self._pipeline().run(_request(), approved=False)

    def test_harness_failure_does_not_return_candidate_as_valid(self) -> None:
        events = []

        with self.assertRaisesRegex(ValueError, "未证明"):
            self._pipeline(behavior_valid=False, events=events).run(_request(), approved=True)

        self.assertEqual("sample_factory_plugin_authoring_failed", events[-1][0])
        self.assertEqual("harness", events[-1][1]["failure_stage"])

    def test_validate_existing_skips_author_and_runs_compiler_harness(self) -> None:
        request = _request()
        source = _Author().author(request, plugin_run_id="plugin-run-source1")
        pipeline = PluginAuthoringPipeline(
            author=None,
            compiler=_Compiler(),
            harness=_Harness(),
            coverage=CoverageRegistry({"PH-IN04": ("T1055.004",)}),
        )

        result = pipeline.validate_existing(
            request,
            source,
            approved=True,
            plugin_run_id="plugin-run-validate1",
        )

        self.assertEqual(PluginLifecycleStatus.BEHAVIOR_VALID, result.status)

    def test_authoring_can_stop_at_compile_valid_without_harness(self) -> None:
        result = PluginAuthoringPipeline(
            author=_Author(),
            compiler=_Compiler(),
            harness=None,
            coverage=CoverageRegistry({"PH-IN04": ("T1055.004",)}),
        ).run(_request(), approved=True, plugin_run_id="plugin-run-compile01")

        self.assertEqual(PluginLifecycleStatus.COMPILE_VALID, result.status)
        self.assertIsNotNone(result.source)
        self.assertIsNotNone(result.build)
        self.assertIsNone(result.validation)
        self.assertEqual("independent_harness_not_configured", result.compile_only_reason)

    def test_source_without_atom_spec_can_compile_but_not_enter_harness(self) -> None:
        class SourceOnlyAuthor:
            def author(self, request, *, plugin_run_id):
                source = _Author().author(request, plugin_run_id=plugin_run_id)
                return source.model_copy(update={"atom_spec": None})

        compile_only = PluginAuthoringPipeline(
            author=SourceOnlyAuthor(),
            compiler=_Compiler(),
            harness=None,
            coverage=CoverageRegistry({"PH-IN04": ("T1055.004",)}),
        ).run(_request(), approved=True, plugin_run_id="plugin-run-sourceonly1")

        self.assertEqual(PluginLifecycleStatus.COMPILE_VALID, compile_only.status)
        assert compile_only.source is not None
        self.assertIsNone(compile_only.source.atom_spec)

        events = []
        harness_deferred = PluginAuthoringPipeline(
            author=SourceOnlyAuthor(),
            compiler=_Compiler(),
            harness=_Harness(),
            coverage=CoverageRegistry({"PH-IN04": ("T1055.004",)}),
            sink=events.append,
        ).run(_request(), approved=True, plugin_run_id="plugin-run-sourceonly2")

        self.assertEqual(PluginLifecycleStatus.COMPILE_VALID, harness_deferred.status)
        self.assertEqual("atom_spec_governance_pending", harness_deferred.compile_only_reason)
        self.assertEqual("atom_spec_governance_pending", events[-1][1]["reason"])

    def test_behavior_valid_result_requires_governed_atom_spec(self) -> None:
        request = _request()
        source = (
            _Author()
            .author(request, plugin_run_id="plugin-run-sourceonly3")
            .model_copy(update={"atom_spec": None})
        )
        build = _Compiler().compile(source, request, plugin_run_id="plugin-run-sourceonly3")
        validation = _Harness().validate(
            source,
            build,
            request,
            plugin_run_id="plugin-run-sourceonly3",
        )

        with self.assertRaisesRegex(ValueError, "behavior_valid"):
            PluginAuthoringResult(
                plugin_run_id="plugin-run-sourceonly3",
                request_id=request.request_id,
                status=PluginLifecycleStatus.BEHAVIOR_VALID,
                source=source,
                build=build,
                validation=validation,
            )

    def test_unknown_ph_fails_before_authoring(self) -> None:
        request = _request().model_copy(
            update={"intent": _request().intent.model_copy(update={"ph_ids": ("PH-ZZ99",)})}
        )
        with self.assertRaises(ValueError):
            self._pipeline().run(request, approved=True)

    def test_candidate_rejects_path_escape(self) -> None:
        request = _request()
        spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
        with self.assertRaisesRegex(ValueError, "路径非法"):
            PluginSourceCandidate(
                plugin_id=spec.atom_id,
                implementation_name=request.implementation_name,
                source_ref="plugin-source://test",
                source_digest="a" * 64,
                changed_files=("../escape.cpp",),
                atom_spec=spec,
                required_capabilities=request.intent.required_capabilities,
                provided_capabilities=request.intent.provided_capabilities,
                input_ports=request.intent.input_ports,
            )

    def test_request_requires_upper_camel_case_implementation_name(self) -> None:
        payload = _request().model_dump(mode="json")
        payload["implementation_name"] = "early_apc"
        with self.assertRaisesRegex(ValueError, "UpperCamelCase"):
            PluginRequest.model_validate(payload)


if __name__ == "__main__":
    unittest.main()
