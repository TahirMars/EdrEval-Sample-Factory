from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from packages.llm.provider import LLMTool
from packages.sample_factory.coding_agent import DeepSeekGlueAgent, LocalPluginWorkspace
from packages.sample_factory.errors import BuildError, PlanningError
from packages.sample_factory.glue import GlueCoordinator
from packages.sample_factory.models import AgentWorkspaceResult
from packages.sample_factory.runtime_logging import (
    LOGGER_CONFIG,
    LOGGER_FILES,
    LOGGER_HEADER,
    LOGGER_SOURCE,
    configure_runtime_logging,
    validate_runtime_logging,
    validate_runtime_logging_build_inputs,
)

from tests.llm_tool_fakes import as_tool_completion
from tests.sample_factory_fixtures import atom_specs


class _Agent:
    def __init__(self) -> None:
        self.tasks = []

    def run(self, task):
        self.tasks.append(task)
        return AgentWorkspaceResult(
            session_ref="agent-session://runtime-logging",
            workspace_ref=task.workspace_ref,
            changed_files=("generated/main.cpp",),
            source_digest="a" * 64,
        )


class _Completion:
    def __init__(self, files: dict[str, str]) -> None:
        self._files = files
        self._calls = 0

    def complete_tool_with_metadata(self, messages, tools: list[LLMTool], **kwargs):
        del kwargs
        self._calls += 1
        if any(message.get("role") == "tool" for message in messages):
            return as_tool_completion(
                {"action": "finish", "rationale": "runtime logging complete"},
                tools,
                call_index=self._calls,
            )
        return as_tool_completion({
                "action": "write_files",
                "files": [
                    {"path": path, "content": content}
                    for path, content in self._files.items()
                ],
                "rationale": "runtime logging test",
            }, tools, call_index=self._calls)


class _Workspace:
    def __init__(self) -> None:
        self.files: dict[str, str] = {}

    def snapshot(self, task):
        return dict(self.files)

    def apply(self, task, files):
        self.files.update(files)
        return AgentWorkspaceResult(
            session_ref="agent-session://deepseek-runtime-logging",
            workspace_ref=task.workspace_ref,
            changed_files=tuple(sorted(files)),
            source_digest="b" * 64,
        )

    def diagnostics(self, diagnostics_ref):
        return None


def _recipe(*, enabled: bool):
    from packages.sample_factory.models import SampleRecipe, TriggerMode

    return SampleRecipe(
        recipe_id="sf-runtime-log-test",
        carrier="atom.ia.document",
        loader_atoms=("atom.ob.decode",),
        execution_atoms=("atom.in.apc",),
        delivery="motw-stamped(lab)",
        trigger_mode=TriggerMode.LAB_TRIGGER,
        ph_ids=("PH-IA01", "PH-OB05", "PH-IN04"),
        evasion_tier="E2",
        execution_logging=enabled,
    )


class RuntimeLoggingSourceTest(unittest.TestCase):
    def test_enabled_materializes_deterministic_public_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recipe = _recipe(enabled=True)

            configure_runtime_logging(root, recipe)
            validate_runtime_logging(root, recipe)

            self.assertEqual(LOGGER_FILES, {path.as_posix() for path in _relative_files(root)})
            header = (root / LOGGER_HEADER).read_text(encoding="utf-8")
            source = (root / LOGGER_SOURCE).read_text(encoding="utf-8")
            config = (root / LOGGER_CONFIG).read_text(encoding="utf-8")
            self.assertIn("RecordTtpResult", header)
            self.assertIn(r"C:\\ProgramData", source)
            self.assertIn("[REDACTED]", source)
            self.assertIn('"PH-IN04"', config)
            self.assertIn('"atom.in.apc"', config)

    def test_disabled_removes_stale_public_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            configure_runtime_logging(root, _recipe(enabled=True))

            configure_runtime_logging(root, _recipe(enabled=False))
            validate_runtime_logging(root, _recipe(enabled=False))

            self.assertFalse(any((root / relative).exists() for relative in LOGGER_FILES))

    def test_modified_public_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recipe = _recipe(enabled=True)
            configure_runtime_logging(root, recipe)
            (root / LOGGER_SOURCE).write_text("tampered", encoding="utf-8")

            with self.assertRaises(BuildError):
                validate_runtime_logging(root, recipe)

    def test_direct_build_main_is_a_proven_logger_compile_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recipe = _recipe(enabled=True)
            configure_runtime_logging(root, recipe)
            main = root / "generated" / "main.cpp"
            main.write_text(
                '#include "edreval_execution_log.cpp"\nint main() { return 0; }\n',
                encoding="utf-8",
            )

            validate_runtime_logging_build_inputs(root, recipe, ["clang++", str(main)])

    def test_workspace_toggle_prunes_logger_before_snapshot(self) -> None:
        specs = atom_specs()
        agent = _Agent()
        coordinator = GlueCoordinator(agent)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = {}
            for spec in specs:
                source = root / "plugins" / spec.atom_id
                source.mkdir(parents=True)
                (source / "atom.cpp").write_text("int atom() { return 0; }\n", encoding="utf-8")
                sources[spec.atom_id] = source
            workspace = LocalPluginWorkspace(sources, workspace_root=root / "workspaces")
            parameters = {
                "atom.ia.document": {"container": "docm"},
                "atom.ob.decode": {"codec": "rc4"},
                "atom.in.apc": {"target": "notepad.exe"},
            }
            enabled = coordinator._task(
                "a" * 64,
                _recipe(enabled=True),
                specs,
                parameters,
                workspace_ref="plugin-workspace://toggle",
                build_target_ref="build-target://windows-msvc-v143-x64",
            )
            disabled = enabled.model_copy(update={"execution_logging": False})

            enabled_snapshot = workspace.snapshot(enabled)
            workspace_root = root / "workspaces" / "toggle"
            enabled_files_exist = all(
                (workspace_root / relative).is_file() for relative in LOGGER_FILES
            )
            disabled_snapshot = workspace.snapshot(disabled)

            self.assertTrue(enabled_files_exist)
            self.assertIn(LOGGER_HEADER, enabled_snapshot)
            self.assertNotIn(LOGGER_SOURCE, enabled_snapshot)
            self.assertNotIn(LOGGER_CONFIG, enabled_snapshot)
            self.assertTrue(LOGGER_FILES.isdisjoint(disabled_snapshot))
            self.assertTrue(
                all(not (workspace_root / relative).exists() for relative in LOGGER_FILES)
            )

    def test_glue_requires_all_ph_ids_and_public_api_calls(self) -> None:
        task = _task(enabled=True)
        main = '''#include "edreval_execution_log.h"
int main() {
  /* CreateProcessW notepad.exe; WaitForSingleObject */
  edreval::sample_log::Initialize();
  edreval::sample_log::RecordTtpStart("PH-IA01", "atom.ia.document", "carrier");
  edreval::sample_log::RecordTtpResult("PH-IA01", "atom.ia.document", "carrier", true, 0, 0, "ok", "opened");
  edreval::sample_log::RecordTtpStart("PH-OB05", "atom.ob.decode", "loader");
  edreval::sample_log::RecordTtpResult("PH-OB05", "atom.ob.decode", "loader", true, 0, 0, "ok", "decoded");
  edreval::sample_log::RecordTtpStart("PH-IN04", "atom.in.apc", "execution");
  edreval::sample_log::RecordTtpResult("PH-IN04", "atom.in.apc", "execution", true, 0, 0, "ok", "executed");
  edreval::sample_log::RecordSampleResult(true, 0, "ok", "complete");
  return 0;
}
'''
        project = '<ClCompile Include="edreval_execution_log.cpp" />'
        agent = DeepSeekGlueAgent(
            _Completion(
                {
                    "generated/main.cpp": main,
                    "generated/sample.vcxproj": project,
                }
            ),
            _Workspace(),
            retry_limit=1,
        )

        result = agent.run(task)

        self.assertIn("generated/main.cpp", result.changed_files)

        missing_ph = main.replace("PH-IN04", "PH-IA01")
        invalid = DeepSeekGlueAgent(
            _Completion(
                {
                    "generated/main.cpp": missing_ph,
                    "generated/sample.vcxproj": project,
                }
            ),
            _Workspace(),
            retry_limit=1,
        )
        with self.assertRaises(PlanningError):
            invalid.run(task)

    def test_glue_rejects_logger_reference_when_disabled(self) -> None:
        task = _task(enabled=False)
        agent = DeepSeekGlueAgent(
            _Completion(
                {
                    "generated/main.cpp": '#include "edreval_execution_log.h"\nint main() { return 0; }\n',
                    "generated/sample.vcxproj": "<Project />",
                }
            ),
            _Workspace(),
            retry_limit=1,
        )

        with self.assertRaises(PlanningError):
            agent.run(task)

    def test_direct_build_includes_public_source_from_main(self) -> None:
        task = _task(enabled=True).model_copy(
            update={"build_target_ref": "build-target://initial/linux-clang-mingw-x64"}
        )
        main = '''#include "edreval_execution_log.h"
#include "edreval_execution_log.cpp"
int main() {
  /* CreateProcessW notepad.exe; WaitForSingleObject */
  edreval::sample_log::Initialize();
  edreval::sample_log::RecordTtpStart("PH-IA01", "atom.ia.document", "carrier");
  edreval::sample_log::RecordTtpResult("PH-IA01", "atom.ia.document", "carrier", true, 0, 0, "ok", "opened");
  edreval::sample_log::RecordTtpStart("PH-OB05", "atom.ob.decode", "loader");
  edreval::sample_log::RecordTtpResult("PH-OB05", "atom.ob.decode", "loader", true, 0, 0, "ok", "decoded");
  edreval::sample_log::RecordTtpStart("PH-IN04", "atom.in.apc", "execution");
  edreval::sample_log::RecordTtpResult("PH-IN04", "atom.in.apc", "execution", true, 0, 0, "ok", "executed");
  edreval::sample_log::RecordSampleResult(true, 0, "ok", "complete");
  return 0;
}
'''
        agent = DeepSeekGlueAgent(
            _Completion({"generated/main.cpp": main}),
            _Workspace(),
            retry_limit=1,
        )

        result = agent.run(task)

        self.assertEqual(("generated/main.cpp",), result.changed_files)


def _relative_files(root: Path):
    return (path.relative_to(root) for path in root.rglob("*") if path.is_file())


def _task(*, enabled: bool):
    specs = atom_specs()
    parameters = {
        "atom.ia.document": {"container": "docm"},
        "atom.ob.decode": {"codec": "rc4"},
        "atom.in.apc": {"target": "notepad.exe"},
    }
    return GlueCoordinator(_Agent())._task(
        "a" * 64,
        _recipe(enabled=enabled),
        specs,
        parameters,
        workspace_ref="plugin-workspace://runtime-logging-agent",
        build_target_ref="build-target://windows-msvc-v143-x64",
    )


if __name__ == "__main__":
    unittest.main()
