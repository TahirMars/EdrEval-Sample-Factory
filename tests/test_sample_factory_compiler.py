from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from packages.contract_gap import ContractGapError
from packages.sample_factory.artifacts import FilesystemArtifactPublisher
from packages.sample_factory.catalog import CoverageRegistry
from packages.sample_factory.compiler import (
    BuildTarget,
    GuardedCompilerBackend,
    JsonBuildTargetCatalog,
    MappedSourceResolver,
    source_tree_digest,
)
from packages.sample_factory.errors import BuildError, CompilationFailure
from packages.sample_factory.models import (
    GlueMaterializeItem,
    GlueOrigin,
    GlueResolution,
    HandoffMaterialize,
    SampleRecipe,
    TriggerMode,
)
from packages.sample_factory.pipeline import BuildRequest
from packages.sample_factory.runtime_logging import configure_runtime_logging
from packages.sample_factory.sources import (
    DirectoryAtomCatalogLoader,
    JsonlAtomCatalogLoader,
    JsonTelemetryContractSource,
    MatrixExpectedDetectionSource,
)

from tests.sample_factory_fixtures import (
    IMPLANT_SHA,
    atom_specs,
    provenance,
    telemetry_contracts,
)

ROOT = Path(__file__).resolve().parents[1]


class FakeGuard:
    def __init__(self) -> None:
        self.acquired = []
        self.released = []

    def heavy_env(self) -> dict[str, str]:
        return {"GOMAXPROCS": "2"}

    def acquire_heavy(self, operation: str) -> None:
        self.acquired.append(operation)

    def release_heavy(self, operation: str) -> None:
        self.released.append(operation)


class FakeBuildRunner:
    def __init__(self, *, rc: int = 0, emit_artifact: bool = True) -> None:
        self.rc = rc
        self.emit_artifact = emit_artifact
        self.calls = []

    def run(self, argv: list[str], *, timeout: float | None = None) -> tuple[int, str]:
        self.calls.append((argv, timeout))
        if self.rc == 0 and self.emit_artifact:
            output_dir = Path(argv[argv.index("--out") + 1])
            (output_dir / "sample.bin").write_bytes(b"compiled-sample")
        return self.rc, "compiler output"


def _recipe() -> SampleRecipe:
    return SampleRecipe(
        recipe_id="sf-compiler-test",
        carrier="atom.ia.document",
        loader_atoms=("atom.ob.decode",),
        execution_atoms=("atom.in.apc",),
        implant_sha256=IMPLANT_SHA,
        implant_format="shellcode",
        delivery="motw-stamped(lab)",
        trigger_mode=TriggerMode.LAB_TRIGGER,
        ph_ids=("PH-IA01", "PH-OB05", "PH-IN04"),
        evasion_tier="E2",
    )


def _request(source_digest: str) -> BuildRequest:
    return BuildRequest(
        recipe=_recipe(),
        atom_parameters={
            "atom.ia.document": {"container": "docm"},
            "atom.ob.decode": {"codec": "rc4"},
            "atom.in.apc": {"target": "notepad.exe"},
        },
        glue=GlueResolution(
            signature="a" * 64,
            origin=GlueOrigin.AGENT,
            source_ref="plugin-workspace://compiler-test",
            source_digest=source_digest,
            session_ref="agent-session://compiler-test",
            changed_files=("generated/glue.cpp",),
        ),
        build_target_ref="build-target://fake",
        materialize_items=(),
    )


class GuardedCompilerTest(unittest.TestCase):
    def _workspace(self, root: Path) -> Path:
        source = root / "plugin-workspace"
        (source / "generated").mkdir(parents=True)
        (source / "generated" / "glue.cpp").write_text("int main() { return 0; }\n")
        (source / "CMakeLists.txt").write_text("# pinned build\n")
        (source / "x64" / "Release").mkdir(parents=True)
        (source / "x64" / "Release" / "stale.cpp").write_text("ignored\n")
        return source

    def _compiler(
        self,
        root: Path,
        source: Path,
        runner,
        guard,
        *,
        include_runtime_logger: bool = False,
    ):
        sources = (
            ("{source_root}", "{source_root}\\generated\\edreval_execution_log.cpp")
            if include_runtime_logger
            else ("{source_root}",)
        )
        target = BuildTarget(
            target_ref="build-target://fake",
            argv_template=("fakecc", *sources, "--out", "{output_dir}"),
            artifact_relative="sample.bin",
            toolchain_fp="fakecc-1@pinned",
        )
        return GuardedCompilerBackend(
            targets={target.target_ref: target},
            sources=MappedSourceResolver({"plugin-workspace://compiler-test": source}),
            artifact_root=root / "artifacts",
            runner=runner,
            guard=guard,
        )

    def test_registered_target_builds_under_guard_and_hashes_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._workspace(root)
            digest = source_tree_digest(source)
            runner = FakeBuildRunner()
            guard = FakeGuard()
            compiler = self._compiler(root, source, runner, guard)

            artifact = compiler.compile(_request(digest))

            self.assertEqual(
                hashlib.sha256(b"compiled-sample").hexdigest(), artifact.artifact_sha256
            )
            self.assertEqual(digest, artifact.source_digest)
            self.assertEqual(guard.acquired, guard.released)
            self.assertEqual("fakecc" if os.name == "nt" else "env", runner.calls[0][0][0])
            self.assertEqual(
                compiler.resolve_artifact(artifact.artifact_ref).read_bytes(), b"compiled-sample"
            )
            publisher = FilesystemArtifactPublisher(root / "runtime", compiler)
            published = publisher.publish(artifact)
            self.assertEqual(
                b"compiled-sample", publisher.resolve(published.artifact_ref).read_bytes()
            )

    def test_source_digest_mismatch_rejected_before_compiler(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._workspace(root)
            runner = FakeBuildRunner()
            compiler = self._compiler(root, source, runner, FakeGuard())
            with self.assertRaises(BuildError):
                compiler.compile(_request("f" * 64))
            self.assertEqual([], runner.calls)

    def test_nonzero_rc_returns_external_diagnostics_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._workspace(root)
            compiler = self._compiler(root, source, FakeBuildRunner(rc=1), FakeGuard())
            with self.assertRaises(CompilationFailure) as ctx:
                compiler.compile(_request(source_tree_digest(source)))
            self.assertTrue(ctx.exception.diagnostics_ref.startswith("build-diagnostics://"))

    def test_handoff_symbol_gate_rejects_before_compiler_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._workspace(root)
            generated = source / "generated"
            (generated / "handoff_shellcode_v1.h").write_text(
                "static const unsigned char kHandoffShellcodeV1[] = {0x90};\n"
                "static const unsigned long long kHandoffShellcodeV1Size = 1;\n",
                encoding="utf-8",
            )
            (generated / "glue.cpp").write_text(
                '#include "handoff_shellcode_v1.h"\n'
                "auto* payload = handoff_shellcode_v1_kHandoffShellcodeV1;\n"
                "auto size = handoff_shellcode_v1_kHandoffShellcodeV1Size;\n",
                encoding="utf-8",
            )
            request = _request(source_tree_digest(source))
            request = BuildRequest(
                recipe=request.recipe,
                atom_parameters=request.atom_parameters,
                glue=request.glue,
                build_target_ref=request.build_target_ref,
                materialize_items=(
                    GlueMaterializeItem(
                        atom_id="atom.payload.lab_calc",
                        handoff_id="handoff://shellcode/v1",
                        artifact_ref="payload://x64/msf_calc_x64",
                        strategy=HandoffMaterialize.EMBED_AT_BUILD,
                    ),
                ),
            )
            runner = FakeBuildRunner()
            guard = FakeGuard()
            compiler = self._compiler(root, source, runner, guard)

            with self.assertRaises(CompilationFailure) as ctx:
                compiler.compile(request)

            self.assertTrue(ctx.exception.diagnostics_ref.startswith("build-diagnostics://"))
            self.assertEqual([], runner.calls)
            self.assertEqual([], guard.acquired)

    def test_enabled_runtime_logger_is_validated_before_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._workspace(root)
            recipe = _recipe().model_copy(update={"execution_logging": True})
            configure_runtime_logging(source, recipe)
            request = _request(source_tree_digest(source))
            request = BuildRequest(
                recipe=recipe,
                atom_parameters=request.atom_parameters,
                glue=request.glue.model_copy(update={"source_digest": source_tree_digest(source)}),
                build_target_ref=request.build_target_ref,
                materialize_items=(),
            )
            runner = FakeBuildRunner()
            compiler = self._compiler(
                root,
                source,
                runner,
                FakeGuard(),
                include_runtime_logger=True,
            )

            compiler.compile(request)

            self.assertEqual(1, len(runner.calls))

    def test_enabled_runtime_logger_rejects_build_without_source_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._workspace(root)
            recipe = _recipe().model_copy(update={"execution_logging": True})
            configure_runtime_logging(source, recipe)
            request = _request(source_tree_digest(source))
            request = BuildRequest(
                recipe=recipe,
                atom_parameters=request.atom_parameters,
                glue=request.glue.model_copy(update={"source_digest": source_tree_digest(source)}),
                build_target_ref=request.build_target_ref,
                materialize_items=(),
            )
            runner = FakeBuildRunner()
            compiler = self._compiler(root, source, runner, FakeGuard())

            with self.assertRaises(BuildError):
                compiler.compile(request)

            self.assertEqual([], runner.calls)

    def test_disabled_runtime_logger_rejects_stale_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._workspace(root)
            configure_runtime_logging(
                source, _recipe().model_copy(update={"execution_logging": True})
            )
            request = _request(source_tree_digest(source))
            runner = FakeBuildRunner()
            compiler = self._compiler(root, source, runner, FakeGuard())

            with self.assertRaises(BuildError):
                compiler.compile(request)

            self.assertEqual([], runner.calls)


class AuthoritySourceTest(unittest.TestCase):
    def test_plugin_directory_is_structured_and_fail_closed(self) -> None:
        specs = atom_specs()
        coverage = CoverageRegistry(
            {
                "PH-IA01": ("T1566.001",),
                "PH-OB05": ("T1027.013",),
                "PH-IN04": ("T1055.004",),
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index, spec in enumerate(specs):
                plugin_dir = root / "plugins" / "dispatchable" / spec.atom_id
                source_dir = plugin_dir / "src"
                source_dir.mkdir(parents=True)
                (source_dir / "atom.cpp").write_text(
                    "int fixture_atom() { return 0; }\n", encoding="utf-8"
                )
                spec_data = spec.model_dump(mode="json")
                spec_data["integration_state"] = (
                    "partial" if index == 0 else "reserved_atom"
                )
                manifest = {
                    "format_version": "sf-plugin-v1",
                    "spec": spec_data,
                    "provenance": (
                        provenance().model_dump(mode="json") if index == 0 else None
                    ),
                    "source": {
                        "root": "src",
                        "files": ["atom.cpp"],
                        "entry_point": "generated/main.cpp",
                        "lineage": f"fixture/{spec.atom_id}",
                    },
                }
                (plugin_dir / "plugin.json").write_text(
                    json.dumps(manifest), encoding="utf-8"
                )

            loaded = DirectoryAtomCatalogLoader(root, coverage).load()

        self.assertEqual(3, len(loaded._atoms))
        self.assertEqual(1, len(loaded.dispatchable_specs()))
        self.assertEqual("partial", loaded.get(specs[0].atom_id).integration_state.value)
        self.assertTrue(
            all(
                loaded.get(spec.atom_id).integration_state.value == "reserved_atom"
                for spec in specs[1:]
            )
        )

    def test_build_target_is_operator_fixed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog_path = Path(tmp) / "build-targets.json"
            catalog_path.write_text(
                json.dumps(
                    {
                        "targets": [
                            {
                                "target_ref": "build-target://initial/windows-msvc-v143-x64",
                                "argv_template": [
                                    "msbuild",
                                    "{source_root}\\generated\\sample.vcxproj",
                                    "/m:1",
                                    "/p:Configuration=Release",
                                    "/p:Platform=x64",
                                    "/p:OutDir={output_dir}\\",
                                ],
                                "artifact_relative": "sample.exe",
                                "toolchain_fp": "msvc-v143-x64@operator-pinned",
                                "timeout_s": 900,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            targets = JsonBuildTargetCatalog(catalog_path).load()

        target = targets["build-target://initial/windows-msvc-v143-x64"]
        self.assertEqual("msbuild", target.argv_template[0])
        self.assertIn("{source_root}", target.argv_template[1])
        self.assertIn("{output_dir}", target.argv_template[-1])

    def test_matrix_expected_detection_is_direct_authority_projection(self) -> None:
        coverage = CoverageRegistry.from_markdown(
            ROOT / "docs/coverage/procedure-host-ttp-coverage-matrix.md"
        )
        annotation = MatrixExpectedDetectionSource(coverage).get(("PH-IN04",), evasion_tier="E2")
        row = annotation["rows"][0]
        self.assertEqual("partial", row["endpoint_visibility"])
        self.assertIn("APC", row["expected_signals"])

    def test_json_sources_load_strict_contracts_and_pinned_atoms(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            telemetry_path = root / "telemetry.json"
            telemetry_path.write_text(
                json.dumps(
                    {"contracts": [item.model_dump(mode="json") for item in telemetry_contracts()]}
                ),
                encoding="utf-8",
            )
            source = JsonTelemetryContractSource(telemetry_path)
            self.assertEqual("atom.in.apc", source.get("telemetry://apc").atom_id)

            atom_path = root / "atoms.jsonl"
            atom_path.write_text(
                "\n".join(
                    json.dumps(
                        {
                            "spec": spec.model_dump(mode="json"),
                            "provenance": provenance().model_dump(mode="json"),
                        }
                    )
                    for spec in atom_specs()
                )
                + "\n",
                encoding="utf-8",
            )
            coverage = CoverageRegistry(
                {
                    "PH-IA01": ("T1566.001",),
                    "PH-OB05": ("T1027.013",),
                    "PH-IN04": ("T1055.004",),
                }
            )
            loaded = JsonlAtomCatalogLoader(atom_path, coverage).load()
            self.assertEqual(3, len(loaded.dispatchable_specs()))

    def test_missing_telemetry_authority_is_contract_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ContractGapError):
            JsonTelemetryContractSource(Path(tmp) / "missing.json").get("telemetry://missing")


if __name__ == "__main__":
    unittest.main()
