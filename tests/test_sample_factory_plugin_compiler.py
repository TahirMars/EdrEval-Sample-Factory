from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.compiler import BuildTarget, source_tree_digest
from packages.sample_factory.errors import CompilationFailure
from packages.sample_factory.plugin_compiler import GuardedPluginCompilerBackend
from packages.sample_factory.plugin_models import PluginSourceCandidate

from tests.sample_factory_fixtures import atom_specs
from tests.test_sample_factory_plugin_authoring import _request


class _Resolver:
    def __init__(self, root: Path) -> None:
        self.root = root

    def resolve(self, source_ref: str) -> Path:
        del source_ref
        return self.root


class _Runner:
    def run(self, argv, *, timeout=None):
        del timeout
        output = Path(argv[2])
        (output / "EarlyApcInjection.lib").write_bytes(b"plugin artifact")
        return 0, "compiled"


class _FailRunner:
    def run(self, argv, *, timeout=None):
        del argv, timeout
        return 1, "error C2660: wrong argument count"


class _Guard:
    def acquire_heavy(self, operation):
        del operation

    def release_heavy(self, operation):
        del operation

    def heavy_env(self):
        return {}


class PluginCompilerTest(unittest.TestCase):
    def test_compiles_in_plugin_run_and_hashes_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            source = (
                runtime
                / "plugin-runs"
                / "2026"
                / "09"
                / "04"
                / "plugin-run-12345678"
                / "authoring"
                / "final-source"
            )
            (source / "src").mkdir(parents=True)
            (source / "src" / "EarlyApcInjection.h").write_text(
                '#pragma once\n#include <cstddef>\nextern "C" int '
                "EdrEvalTtp_EarlyApcInjection_Execute(const char*, char*, std::size_t);\n",
                encoding="utf-8",
            )
            (source / "src" / "EarlyApcInjection.cpp").write_text(
                '#include "EarlyApcInjection.h"\nint '
                "EdrEvalTtp_EarlyApcInjection_Execute(const char*, char*, std::size_t) "
                "{ return 0; }\n",
                encoding="utf-8",
            )
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            candidate = PluginSourceCandidate(
                plugin_id=spec.atom_id,
                implementation_name="EarlyApcInjection",
                source_ref="plugin-source://plugin-run-12345678/final-source",
                source_digest=source_tree_digest(source),
                changed_files=(
                    "src/EarlyApcInjection.cpp",
                    "src/EarlyApcInjection.h",
                ),
                atom_spec=spec,
                required_capabilities=spec.required_capabilities,
                provided_capabilities=spec.provided_capabilities,
            )
            request = _request().model_copy(
                update={"build_target_ref": "build-target://plugin-test"}
            )
            compiler = GuardedPluginCompilerBackend(
                targets={
                    "build-target://plugin-test": BuildTarget(
                        target_ref="build-target://plugin-test",
                        argv_template=("compiler", "{source_root}", "{output_dir}"),
                        artifact_relative="{implementation_name}.lib",
                        toolchain_fp="compiler@pinned",
                    )
                },
                sources=_Resolver(source),
                runtime_root=runtime,
                runner=_Runner(),
                guard=_Guard(),
            )

            result = compiler.compile(
                candidate, request, plugin_run_id="plugin-run-12345678"
            )

            self.assertTrue(result.artifact_ref.startswith("plugin-build-artifact://"))
            self.assertEqual("EarlyApcInjection.lib", result.artifact_filename)
            self.assertEqual(source_tree_digest(source / "src"), result.implementation_source_digest)
            harness_main = source.parent.parent / "harness" / "main.cpp"
            self.assertTrue(harness_main.is_file())
            self.assertIn("EdrEvalTtp_EarlyApcInjection_Execute", harness_main.read_text())
            self.assertFalse((source / "main.cpp").exists())
            self.assertEqual(
                b"plugin artifact", compiler.resolve_artifact(result.artifact_ref).read_bytes()
            )
            artifact = compiler.resolve_artifact(result.artifact_ref)
            artifact.with_suffix(".pdb").write_bytes(b"sidecar-pdb")
            self.assertEqual(artifact, compiler.resolve_artifact(result.artifact_ref))

    def test_compile_failure_exposes_persisted_diagnostics_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            plugin_root = (
                runtime
                / "plugin-runs"
                / "2026"
                / "09"
                / "04"
                / "plugin-run-12345678"
            )
            source = plugin_root / "authoring" / "final-source"
            (source / "src").mkdir(parents=True)
            (source / "src" / "EarlyApcInjection.h").write_text(
                '#pragma once\n#include <cstddef>\nextern "C" int '
                "EdrEvalTtp_EarlyApcInjection_Execute(const char*, char*, std::size_t);\n",
                encoding="utf-8",
            )
            (source / "src" / "EarlyApcInjection.cpp").write_text(
                '#include "EarlyApcInjection.h"\nint '
                "EdrEvalTtp_EarlyApcInjection_Execute(const char*, char*, std::size_t) "
                "{ return 0; }\n",
                encoding="utf-8",
            )
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            candidate = PluginSourceCandidate(
                plugin_id=spec.atom_id,
                implementation_name="EarlyApcInjection",
                source_ref="plugin-source://plugin-run-12345678/final-source",
                source_digest=source_tree_digest(source),
                changed_files=(
                    "src/EarlyApcInjection.cpp",
                    "src/EarlyApcInjection.h",
                ),
                atom_spec=spec,
                required_capabilities=spec.required_capabilities,
                provided_capabilities=spec.provided_capabilities,
            )
            request = _request().model_copy(
                update={"build_target_ref": "build-target://plugin-test"}
            )
            compiler = GuardedPluginCompilerBackend(
                targets={
                    "build-target://plugin-test": BuildTarget(
                        target_ref="build-target://plugin-test",
                        argv_template=("compiler", "{source_root}", "{output_dir}"),
                        artifact_relative="{implementation_name}.lib",
                        toolchain_fp="compiler@pinned",
                    )
                },
                sources=_Resolver(source),
                runtime_root=runtime,
                runner=_FailRunner(),
                guard=_Guard(),
            )

            with self.assertRaises(CompilationFailure) as caught:
                compiler.compile(
                    candidate,
                    request,
                    plugin_run_id="plugin-run-12345678",
                )

            diagnostics_ref = caught.exception.diagnostics_ref
            self.assertIsNotNone(diagnostics_ref)
            build_id = diagnostics_ref.rsplit("/", 1)[-1]
            self.assertEqual(
                "error C2660: wrong argument count",
                (plugin_root / "build" / build_id / "diagnostics.txt").read_text(),
            )

    def test_embed_materialize_writes_handoff_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            payload_root = Path(tmp) / "payloads"
            (payload_root / "x64").mkdir(parents=True)
            (payload_root / "x64" / "msf_calc_x64.bin").write_bytes(b"\x90\xc3")
            source = (
                runtime
                / "plugin-runs"
                / "2026"
                / "09"
                / "04"
                / "plugin-run-12345678"
                / "authoring"
                / "final-source"
            )
            (source / "src").mkdir(parents=True)
            (source / "src" / "EarlyApcInjection.h").write_text(
                '#pragma once\n#include <cstddef>\nextern "C" int '
                "EdrEvalTtp_EarlyApcInjection_Execute(const char*, char*, std::size_t);\n",
                encoding="utf-8",
            )
            (source / "src" / "EarlyApcInjection.cpp").write_text(
                '#include "EarlyApcInjection.h"\nint '
                "EdrEvalTtp_EarlyApcInjection_Execute(const char*, char*, std::size_t) "
                "{ return 0; }\n",
                encoding="utf-8",
            )
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            candidate = PluginSourceCandidate(
                plugin_id=spec.atom_id,
                implementation_name="EarlyApcInjection",
                source_ref="plugin-source://plugin-run-12345678/final-source",
                source_digest=source_tree_digest(source),
                changed_files=(
                    "src/EarlyApcInjection.cpp",
                    "src/EarlyApcInjection.h",
                ),
                atom_spec=spec,
                required_capabilities=spec.required_capabilities,
                provided_capabilities=spec.provided_capabilities,
            )
            request = _request().model_copy(
                update={
                    "build_target_ref": "build-target://plugin-test",
                    "intent": _request().intent.model_copy(
                        update={
                            "produces_handoffs": ("handoff://shellcode/v1",),
                            "artifact_ref": "payload://x64/msf_calc_x64",
                        }
                    ),
                }
            )
            compiler = GuardedPluginCompilerBackend(
                targets={
                    "build-target://plugin-test": BuildTarget(
                        target_ref="build-target://plugin-test",
                        argv_template=("compiler", "{source_root}", "{output_dir}"),
                        artifact_relative="{implementation_name}.lib",
                        toolchain_fp="compiler@pinned",
                    )
                },
                sources=_Resolver(source),
                runtime_root=runtime,
                runner=_Runner(),
                guard=_Guard(),
                payload_root=payload_root,
            )

            compiler.compile(candidate, request, plugin_run_id="plugin-run-12345678")

            header = (source / "generated" / "handoff_shellcode_v1.h").read_text(encoding="utf-8")
            self.assertIn("kHandoffShellcodeV1", header)
            self.assertIn("0x90", header)


if __name__ == "__main__":
    unittest.main()
