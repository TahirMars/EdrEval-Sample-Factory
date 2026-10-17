from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from packages.sample_factory.errors import VerificationError
from packages.sample_factory.plugin_harness import (
    HarnessAssertion,
    HarnessTelemetrySource,
    JsonPluginHarnessCatalog,
    PluginHarnessObservation,
    PluginHarnessSpec,
    SystemTelemetryPluginHarness,
)
from packages.sample_factory.plugin_models import PluginBuildResult, PluginSourceCandidate

from tests.sample_factory_fixtures import atom_specs
from tests.test_sample_factory_plugin_authoring import _request


class _Executor:
    def __init__(self, observation: PluginHarnessObservation) -> None:
        self.observation = observation

    def execute(self, spec, source, build, request, *, plugin_run_id):
        del spec, source, build, request, plugin_run_id
        return self.observation


class _Resolver:
    def __init__(self, path: Path) -> None:
        self.path = path

    def resolve_artifact(self, artifact_ref: str) -> Path:
        del artifact_ref
        return self.path


class PluginHarnessTest(unittest.TestCase):
    def _spec(self) -> PluginHarnessSpec:
        return PluginHarnessSpec(
            harness_ref="plugin-harness://execution/windows-x64/v1",
            role=atom_specs()[2].role,
            profile_ids=("win11-sysmon15-no-edr",),
            architectures=("x64",),
            telemetry_sources=(HarnessTelemetrySource.SYSMON, HarnessTelemetrySource.CAPE),
            input_contract_ref="contract://execution-input-v1",
            oracle_ref="oracle://execution-effect-v1",
            collector_config_ref="collector://sysmon-v1",
            isolation_profile_ref="isolation://windows-snapshot-v1",
            required_assertions=("effect.target-state",),
        )

    def _source_and_build(self, root: Path) -> tuple[PluginSourceCandidate, PluginBuildResult, Path]:
        artifact = root / "EarlyApcInjection.lib"
        artifact.write_bytes(b"validation-only")
        artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
        spec = atom_specs()[2]
        source = PluginSourceCandidate(
            plugin_id=spec.atom_id,
            implementation_name="EarlyApcInjection",
            source_ref="plugin-source://plugin-run-12345678/final-source",
            source_digest="a" * 64,
            changed_files=("src/EarlyApcInjection.cpp", "src/EarlyApcInjection.h"),
            atom_spec=spec,
            required_capabilities=spec.required_capabilities,
            provided_capabilities=spec.provided_capabilities,
            input_ports=_request().intent.input_ports,
        )
        build = PluginBuildResult(
            build_ref="plugin-build://plugin-run-12345678/build1",
            artifact_ref="plugin-build-artifact://plugin-run-12345678/build1",
            artifact_sha256=artifact_sha256,
            source_digest=source.source_digest,
            implementation_source_digest="b" * 64,
            artifact_filename="EarlyApcInjection.lib",
            toolchain_fp="msvc-v143@pinned",
            build_id="build1",
        )
        return source, build, artifact

    def _observation(self, build: PluginBuildResult, source: PluginSourceCandidate) -> PluginHarnessObservation:
        now = datetime(2026, 9, 5, tzinfo=UTC)
        return PluginHarnessObservation(
            harness_ref="plugin-harness://execution/windows-x64/v1",
            plugin_run_id="plugin-run-12345678",
            profile_id="win11-sysmon15-no-edr",
            host_id="vm://windows-x64-01",
            process_identity="pid:4242/start:2026-09-05T00:00:00Z",
            isolation_profile_ref="isolation://windows-snapshot-v1",
            collector_config_ref="collector://sysmon-v1",
            artifact_sha256=build.artifact_sha256,
            source_digest=source.source_digest,
            telemetry_source=HarnessTelemetrySource.SYSMON,
            started_at=now,
            finished_at=now + timedelta(seconds=2),
            contract_valid=True,
            atom_valid=True,
            assertions=(
                HarnessAssertion(
                    assertion_id="effect.target-state",
                    passed=True,
                    evidence_ref="evidence://sysmon/target-state",
                ),
            ),
            evidence_ref="evidence://sysmon/plugin-run-12345678",
        )

    def test_system_telemetry_harness_returns_behavior_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source, build, artifact = self._source_and_build(Path(tmp))
            observation = self._observation(build, source)
            harness = SystemTelemetryPluginHarness(
                self._spec(), _Executor(observation), artifact_resolver=_Resolver(artifact)
            )

            result = harness.validate(
                source,
                build,
                _request(),
                plugin_run_id="plugin-run-12345678",
            )

            self.assertTrue(result.contract_valid)
            self.assertTrue(result.atom_valid)
            self.assertTrue(result.behavior_valid)
            self.assertEqual("evidence://sysmon/plugin-run-12345678", result.evidence_ref)

    def test_harness_rejects_cross_run_observation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source, build, artifact = self._source_and_build(Path(tmp))
            observation = self._observation(build, source)
            harness = SystemTelemetryPluginHarness(
                self._spec(), _Executor(observation), artifact_resolver=_Resolver(artifact)
            )

            with self.assertRaisesRegex(VerificationError, "plugin_run_id"):
                harness.validate(
                    source,
                    build,
                    _request(),
                    plugin_run_id="plugin-run-87654321",
                )

    def test_observation_cannot_use_edr_as_self_test_telemetry(self) -> None:
        with self.assertRaises(ValueError):
            PluginHarnessObservation(
                harness_ref="plugin-harness://execution/windows-x64/v1",
                plugin_run_id="plugin-run-12345678",
                profile_id="win11-sysmon15-no-edr",
                host_id="vm://windows-x64-01",
                process_identity="pid:4242/start:2026-09-05T00:00:00Z",
                isolation_profile_ref="isolation://windows-snapshot-v1",
                collector_config_ref="collector://sysmon-v1",
                artifact_sha256="a" * 64,
                source_digest="b" * 64,
                telemetry_source="edr",
                started_at=datetime(2026, 9, 5, tzinfo=UTC),
                finished_at=datetime(2026, 9, 5, 0, 0, 1, tzinfo=UTC),
                contract_valid=True,
                atom_valid=True,
                assertions=(
                    HarnessAssertion(
                        assertion_id="x", passed=True, evidence_ref="evidence://x"
                    ),
                ),
                evidence_ref="evidence://x",
            )

    def test_json_catalog_loads_and_rejects_duplicate_refs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "harnesses.json"
            payload = {"harnesses": [self._spec().model_dump(mode="json")]}
            path.write_text(json.dumps(payload), encoding="utf-8")
            catalog = JsonPluginHarnessCatalog(path)
            self.assertEqual(self._spec().harness_ref, catalog.get(self._spec().harness_ref).harness_ref)
            path.write_text(
                json.dumps({"harnesses": [payload["harnesses"][0]] * 2}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unique"):
                catalog.load()


if __name__ == "__main__":
    unittest.main()
