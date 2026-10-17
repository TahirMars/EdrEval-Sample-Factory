from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from packages.llm.provider import LLMCompletion, LLMError, LLMTool
from packages.sample_factory.coding_agent import DeepSeekGlueAgent, LocalPluginWorkspace
from packages.sample_factory.errors import PlanningError
from packages.sample_factory.glue import GlueError
from packages.sample_factory.models import (
    GlueInjectionContract,
    GlueMaterializeItem,
    GlueTask,
    HandoffMaterialize,
    TriggerMode,
)

from tests.llm_tool_fakes import as_tool_completion


class _ScriptedCompletion:
    def __init__(self, responses: list[dict[str, object]]) -> None:
        self._responses = list(responses)
        self.calls: list[list[dict[str, object]]] = []

    def complete_tool_with_metadata(self, messages, tools: list[LLMTool], **kwargs) -> LLMCompletion:
        del kwargs
        self.calls.append([dict(item) for item in messages])
        return as_tool_completion(self._responses.pop(0), tools, call_index=len(self.calls))


class _RaisingThenScripted:
    def __init__(self, errors: list[Exception], responses: list[dict[str, object]]) -> None:
        self._errors = list(errors)
        self._responses = list(responses)
        self.calls: list[list[dict[str, object]]] = []

    def complete_tool_with_metadata(self, messages, tools: list[LLMTool], **kwargs) -> LLMCompletion:
        del kwargs
        self.calls.append([dict(item) for item in messages])
        if self._errors:
            raise self._errors.pop(0)
        return as_tool_completion(self._responses.pop(0), tools, call_index=len(self.calls))


class _MetadataCompletion:
    def __init__(self, responses: list[LLMCompletion]) -> None:
        self._responses = list(responses)
        self.calls: list[list[dict[str, object]]] = []

    def complete_tool_with_metadata(self, messages, tools: list[LLMTool], **kwargs) -> LLMCompletion:
        del kwargs
        self.calls.append([dict(item) for item in messages])
        return as_tool_completion(self._responses.pop(0), tools, call_index=len(self.calls))


def _task(*, workspace_ref: str = "plugin-workspace://agent-session-test") -> GlueTask:
    return GlueTask(
        task_id="glue-agent-session-test",
        recipe_id="sf-agent-session-test",
        workspace_ref=workspace_ref,
        atom_ids=("atom.test",),
        ph_ids=("PH-IN04",),
        atom_ph_ids=(("PH-IN04",),),
        trigger_mode=TriggerMode.LAB_TRIGGER,
        execution_logging=False,
        atom_parameters={"atom.test": {}},
        input_contracts=("schema://atom-test-input",),
        output_contracts=("none",),
        handoff_contracts=(None,),
        build_target_ref="build-target://initial/linux-clang-mingw-x64",
    )


class CodingAgentSessionTest(unittest.TestCase):
    def _workspace(self, root: Path) -> LocalPluginWorkspace:
        source = root / "plugin" / "atom.test"
        source.mkdir(parents=True)
        (source / "atom.cpp").write_text(
            "int hidden_atom_value() { return 7; } // SOURCE_SENTINEL\n",
            encoding="utf-8",
        )
        (source / "atom.lib").write_bytes(b"validation-only")
        return LocalPluginWorkspace(
            {"atom.test": source},
            workspace_root=root / "workspaces",
            diagnostics_root=root / "diagnostics",
        )

    def test_glue_seeds_plugin_source_but_never_validation_library(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = self._workspace(root)

            snapshot = workspace.snapshot(_task())

            self.assertIn("src/atom.cpp", snapshot)
            self.assertFalse(any(path.endswith(".lib") for path in snapshot))
            seeded = root / "workspaces" / "agent-session-test" / "src"
            self.assertTrue((seeded / "atom.cpp").is_file())
            self.assertFalse((seeded / "atom.lib").exists())

    def test_reads_source_incrementally_and_writes_before_finish(self) -> None:
        responses = [
            {"action": "list_files", "path": "src", "rationale": "inspect inventory"},
            {
                "action": "search",
                "path": "src",
                "query": "hidden_atom_value",
                "rationale": "find entry point",
            },
            {
                "action": "read_file",
                "path": "src/atom.cpp",
                "start_line": 1,
                "end_line": 20,
                "rationale": "read only the relevant file",
            },
            {
                "action": "write_files",
                "files": [
                    {
                        "path": "generated/main.cpp",
                        "content": "int hidden_atom_value();\nint main(){return hidden_atom_value();}\n",
                    }
                ],
                "rationale": "token=should-not-appear-in-events",
            },
            {"action": "finish", "rationale": "required entry point is complete"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _ScriptedCompletion(responses)
            events: list[tuple[str, dict[str, object]]] = []
            agent = DeepSeekGlueAgent(
                client,
                self._workspace(root),
                max_turns=8,
                sink=events.append,
            )

            result = agent.run(_task())

            self.assertEqual(("generated/main.cpp",), result.changed_files)
            self.assertEqual(5, len(client.calls))
            initial_prompt = client.calls[0][1]["content"]
            initial_payload = json.loads(initial_prompt)
            self.assertIn("source_manifest", initial_prompt)
            self.assertNotIn("SOURCE_SENTINEL", initial_prompt)
            self.assertEqual(
                ["generated", "src"], initial_payload["agent_limits"]["readable_roots"]
            )
            self.assertIsNone(initial_payload["agent_limits"]["read_budget"])
            self.assertNotIn("max_read_bytes", initial_payload["agent_limits"])
            self.assertEqual(2, initial_payload["agent_limits"]["max_read_turns_before_write"])
            self.assertEqual(
                ["generated/main.cpp", "finish"],
                initial_payload["write_plan"]["order"],
            )
            self.assertIn("SOURCE_SENTINEL", client.calls[3][-1]["content"])
            event_blob = json.dumps(events, ensure_ascii=False)
            self.assertNotIn("SOURCE_SENTINEL", event_blob)
            self.assertNotIn("should-not-appear-in-events", event_blob)
            self.assertIn("[REDACTED]", event_blob)
            actions = [
                data["action"]
                for kind, data in events
                if kind == "sample_factory_coding_model_output"
            ]
            self.assertEqual(
                ["list_files", "search", "read_file", "write_files", "finish"],
                actions,
            )

    def test_protected_handoff_read_does_not_consume_lifetime_error_budget(self) -> None:
        responses = [
            {
                "action": "read_file",
                "path": "generated/handoff_shellcode_v1.h",
                "start_line": 1,
                "end_line": 5,
                "rationale": "inspect generated handoff",
            },
            {"action": "list_files", "path": "src", "rationale": "inspect source"},
            {
                "action": "read_file",
                "path": "src/atom.cpp",
                "start_line": 1,
                "end_line": 10,
                "rationale": "read implementation",
            },
            {
                "action": "write_files",
                "files": [
                    {
                        "path": "generated/main.cpp",
                        "content": (
                            '#include "handoff_shellcode_v1.h"\n'
                            "int main(){return static_cast<int>("
                            "kHandoffShellcodeV1Size == 0 || "
                            "kHandoffShellcodeV1[0] == 0);}\n"
                        ),
                    }
                ],
                "rationale": "write glue",
            },
            {"action": "finish", "rationale": "complete"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "plugin" / "atom.test"
            source.mkdir(parents=True)
            (source / "atom.cpp").write_text("int main_atom() { return 0; }\n", encoding="utf-8")
            payload_root = root / "payload"
            payload_root.mkdir()
            (payload_root / "shellcode.bin").write_bytes(b"\x90")
            workspace = LocalPluginWorkspace(
                {"atom.test": source},
                workspace_root=root / "workspaces",
                diagnostics_root=root / "diagnostics",
                payload_root=payload_root,
            )
            task = _task().model_copy(
                update={
                    "materialize_items": (
                        GlueMaterializeItem(
                            atom_id="atom.test",
                            handoff_id="handoff://shellcode/v1",
                            artifact_ref="payload://shellcode",
                            strategy=HandoffMaterialize.EMBED_AT_BUILD,
                        ),
                    )
                }
            )
            client = _ScriptedCompletion(responses)
            agent = DeepSeekGlueAgent(client, workspace, retry_limit=2, max_turns=6)

            result = agent.run(task)

            self.assertEqual(("generated/main.cpp",), result.changed_files)
            initial_prompt = json.loads(client.calls[0][1]["content"])
            handoff = initial_prompt["embedded_handoffs"][0]
            self.assertFalse(handoff["readable"])
            self.assertNotIn("symbol_prefix", handoff)
            self.assertEqual("kHandoffShellcodeV1", handoff["array_symbol"])
            self.assertEqual("const unsigned char[]", handoff["array_symbol_cpp_type"])
            self.assertEqual("kHandoffShellcodeV1Size", handoff["size_symbol"])
            self.assertEqual("const size_t", handoff["size_symbol_cpp_type"])
            self.assertTrue(handoff["symbols_are_final_global_identifiers"])
            feedback = client.calls[1][-1]["content"]
            self.assertIn("intentionally protected", feedback)

    def test_handoff_static_gate_feedback_repairs_prefixed_symbols(self) -> None:
        wrong = (
            '#include "handoff_shellcode_v1.h"\n'
            "int main(){return static_cast<int>("
            "handoff_shellcode_v1_kHandoffShellcodeV1Size == 0 || "
            "handoff_shellcode_v1_kHandoffShellcodeV1[0] == 0);}\n"
        )
        corrected = (
            '#include "handoff_shellcode_v1.h"\n'
            "int main(){return static_cast<int>("
            "kHandoffShellcodeV1Size == 0 || "
            "kHandoffShellcodeV1[0] == 0);}\n"
        )
        responses = [
            {
                "action": "write_files",
                "files": [{"path": "generated/main.cpp", "content": wrong}],
                "rationale": "write first draft",
            },
            {"action": "finish", "rationale": "complete"},
            {
                "action": "write_files",
                "files": [{"path": "generated/main.cpp", "content": corrected}],
                "rationale": "use final handoff identifiers verbatim",
            },
            {"action": "finish", "rationale": "complete"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "plugin" / "atom.test"
            source.mkdir(parents=True)
            (source / "atom.cpp").write_text("int main_atom() { return 0; }\n", encoding="utf-8")
            payload_root = root / "payload"
            payload_root.mkdir()
            (payload_root / "shellcode.bin").write_bytes(b"\x90")
            workspace = LocalPluginWorkspace(
                {"atom.test": source},
                workspace_root=root / "workspaces",
                diagnostics_root=root / "diagnostics",
                payload_root=payload_root,
            )
            task = _task().model_copy(
                update={
                    "materialize_items": (
                        GlueMaterializeItem(
                            atom_id="atom.test",
                            handoff_id="handoff://shellcode/v1",
                            artifact_ref="payload://shellcode",
                            strategy=HandoffMaterialize.EMBED_AT_BUILD,
                        ),
                    )
                }
            )
            client = _ScriptedCompletion(responses)
            agent = DeepSeekGlueAgent(client, workspace, retry_limit=2, max_turns=6)

            result = agent.run(task)

            self.assertEqual(("generated/main.cpp",), result.changed_files)
            feedback = client.calls[2][-1]["content"]
            self.assertIn("缺少完整 C++ 标识符", feedback)
            output = workspace.snapshot(task)["generated/main.cpp"]
            self.assertEqual(corrected, output)

    def test_inspection_actions_do_not_force_a_write_draft(self) -> None:
        responses = [
            {"action": "list_files", "path": "src", "rationale": f"inspect {index}"}
            for index in range(7)
        ]
        responses.extend(
            [
                {
                    "action": "write_files",
                    "files": [
                        {
                            "path": "generated/main.cpp",
                            "content": "int hidden_atom_value();\nint main(){return hidden_atom_value();}\n",
                        }
                    ],
                    "rationale": "write first draft",
                },
                {"action": "finish", "rationale": "complete"},
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            client = _ScriptedCompletion(responses)
            agent = DeepSeekGlueAgent(
                client,
                self._workspace(Path(tmp)),
                retry_limit=2,
                max_turns=10,
            )

            result = agent.run(_task())

            self.assertEqual(("generated/main.cpp",), result.changed_files)
            for call in client.calls[1:8]:
                inspection_result = json.loads(call[-1]["content"])["result"]
                self.assertIn("src/atom.cpp", inspection_result["paths"])
                self.assertNotIn("inspection_budget_exhausted", inspection_result)

    def test_search_supports_literal_alternatives(self) -> None:
        responses = [
            {
                "action": "search",
                "path": "src",
                "query": "missing_symbol|hidden_atom_value",
                "rationale": "find one of two symbols",
            },
            {
                "action": "write_files",
                "files": [
                    {
                        "path": "generated/main.cpp",
                        "content": "int hidden_atom_value();\nint main(){return hidden_atom_value();}\n",
                    }
                ],
                "rationale": "write glue",
            },
            {"action": "finish", "rationale": "complete"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            client = _ScriptedCompletion(responses)
            agent = DeepSeekGlueAgent(client, self._workspace(Path(tmp)), max_turns=5)

            result = agent.run(_task())

            self.assertEqual(("generated/main.cpp",), result.changed_files)
            search_result = json.loads(client.calls[1][-1]["content"])["result"]
            self.assertEqual(["missing_symbol", "hidden_atom_value"], search_result["terms"])
            self.assertEqual(1, len(search_result["matches"]))

    def test_list_and_search_return_all_readable_workspace_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            agent = DeepSeekGlueAgent(
                _ScriptedCompletion([]),
                self._workspace(Path(tmp)),
            )
            snapshot = {
                **{
                    f"src/unit_{index:03d}.cpp": f"// READ_ALL_SENTINEL {index}\n"
                    for index in range(300)
                },
                "generated/main.cpp": "// READ_ALL_SENTINEL generated\n",
                "generated/handoff_shellcode_v1.h": "// protected payload bytes\n",
                "other/not_in_read_scope.cpp": "// READ_ALL_SENTINEL outside\n",
            }

            listed, _ = agent._execute_tool(
                {"action": "list_files", "path": ""},
                snapshot=snapshot,
            )
            searched, _ = agent._execute_tool(
                {
                    "action": "search",
                    "path": "",
                    "query": "READ_ALL_SENTINEL",
                },
                snapshot=snapshot,
            )

            self.assertEqual(301, len(listed["paths"]))
            self.assertFalse(listed["truncated"])
            self.assertEqual(301, len(searched["matches"]))
            self.assertNotIn("generated/handoff_shellcode_v1.h", listed["paths"])
            self.assertNotIn("other/not_in_read_scope.cpp", listed["paths"])

    def test_repeated_empty_searches_are_not_gated(self) -> None:
        responses = [
            {
                "action": "search",
                "path": "src",
                "query": "missing_symbol",
                "rationale": f"empty search {index}",
            }
            for index in range(3)
        ]
        responses.extend(
            [
                {
                    "action": "write_files",
                    "files": [{"path": "generated/main.cpp", "content": "int main(){return 0;}\n"}],
                    "rationale": "write after guidance",
                },
                {"action": "finish", "rationale": "complete"},
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            client = _ScriptedCompletion(responses)
            agent = DeepSeekGlueAgent(
                client, self._workspace(Path(tmp)), retry_limit=1, max_turns=7
            )

            result = agent.run(_task())

            self.assertEqual(("generated/main.cpp",), result.changed_files)
            for call in client.calls[1:4]:
                search_result = json.loads(call[-1]["content"])["result"]
                self.assertEqual([], search_result["matches"])
                self.assertNotIn("error", search_result)

    def test_empty_model_output_reports_safe_reasoning_metadata(self) -> None:
        client = _MetadataCompletion(
            [
                LLMCompletion(
                    content="",
                    finish_reason="length",
                    completion_tokens=8192,
                    reasoning_tokens=8192,
                    reasoning_content_chars=32000,
                ),
                LLMCompletion(
                    content=json.dumps(
                        {
                            "action": "write_files",
                            "files": [
                                {
                                    "path": "generated/main.cpp",
                                    "content": "int main(){return 0;}\n",
                                }
                            ],
                            "rationale": "write after retry",
                        }
                    ),
                    finish_reason="stop",
                    reasoning_tokens=120,
                ),
                LLMCompletion(
                    content=json.dumps({"action": "finish", "rationale": "complete"}),
                    finish_reason="stop",
                    reasoning_tokens=20,
                ),
            ]
        )
        events: list[tuple[str, dict[str, object]]] = []
        with tempfile.TemporaryDirectory() as tmp:
            agent = DeepSeekGlueAgent(
                client,
                self._workspace(Path(tmp)),
                retry_limit=2,
                max_turns=5,
                sink=events.append,
            )

            result = agent.run(_task())

            self.assertEqual(("generated/main.cpp",), result.changed_files)
            self.assertEqual(
                ["system", "user", "user"],
                [message["role"] for message in client.calls[1]],
            )
            feedback = next(
                data
                for kind, data in events
                if kind == "sample_factory_coding_feedback" and data["turn"] == 1
            )
            self.assertIn("finish_reason=length", feedback["content"])
            self.assertIn("reasoning_tokens=8192", feedback["content"])
            self.assertIn("禁止继续长推理", client.calls[1][-1]["content"])
            self.assertIn("generated/main.cpp", client.calls[1][-1]["content"])
            model_output = next(
                data
                for kind, data in events
                if kind == "sample_factory_coding_model_output" and data["turn"] == 2
            )
            self.assertIn("reasoning_tokens=120", model_output["content"])

    def test_compile_repair_resumes_same_conversation(self) -> None:
        responses = [
            {
                "action": "write_files",
                "files": [{"path": "generated/main.cpp", "content": "int main(){return 1;}\n"}],
                "rationale": "initial glue",
            },
            {"action": "finish", "rationale": "ready for controlled build"},
            {
                "action": "read_file",
                "path": "generated/main.cpp",
                "start_line": 1,
                "end_line": 20,
                "rationale": "inspect the failed generated entry point",
            },
            {
                "action": "write_files",
                "files": [{"path": "generated/main.cpp", "content": "int main(){return 0;}\n"}],
                "rationale": "apply compiler-guided repair",
            },
            {"action": "finish", "rationale": "repair complete"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostics = root / "diagnostics" / "build-1"
            diagnostics.mkdir(parents=True)
            (diagnostics / "diagnostics.txt").write_text(
                "main.cpp: return value must be zero", encoding="utf-8"
            )
            client = _ScriptedCompletion(responses)
            events: list[tuple[str, dict[str, object]]] = []
            agent = DeepSeekGlueAgent(
                client,
                self._workspace(root),
                max_turns=8,
                sink=events.append,
            )
            initial = agent.run(_task())
            repair_task = _task().model_copy(
                update={
                    "repair_of_session": initial.session_ref,
                    "diagnostics_ref": "build-diagnostics://build-1",
                }
            )

            repaired = agent.run(repair_task)

            self.assertEqual(initial.session_ref, repaired.session_ref)
            repair_messages = client.calls[2]
            self.assertGreater(len(repair_messages), 4)
            self.assertIn("resume_after_compile_failure", repair_messages[-1]["content"])
            self.assertIn("return value must be zero", repair_messages[-1]["content"])
            sessions = [data for kind, data in events if kind == "sample_factory_coding_session"]
            self.assertFalse(sessions[0]["resumed"])
            self.assertTrue(sessions[1]["resumed"])

    def test_apply_patch_updates_only_requested_generated_lines(self) -> None:
        responses = [
            {
                "action": "write_files",
                "files": [
                    {
                        "path": "generated/main.cpp",
                        "content": "int main() {\n  return 1;\n}\n",
                    }
                ],
                "rationale": "create initial entry point",
            },
            {
                "action": "apply_patch",
                "path": "generated/main.cpp",
                "start_line": 2,
                "end_line": 2,
                "replacement": "  return 0;\n",
                "rationale": "fix the return value",
            },
            {"action": "finish", "rationale": "patch is complete"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _ScriptedCompletion(responses)
            agent = DeepSeekGlueAgent(client, self._workspace(root), max_turns=5)

            self.assertEqual(
                "int main() {\n  return 0;\n}\n",
                agent._apply_patch(
                    {
                        "path": "generated/main.cpp",
                        "start_line": 2,
                        "end_line": 2,
                        "replacement": "  return 0;\n",
                    },
                    {"generated/main.cpp": "int main() {\n  return 1;\n}\n"},
                )["generated/main.cpp"],
            )

            result = agent.run(_task())

            self.assertEqual(("generated/main.cpp",), result.changed_files)
            output = (
                root / "workspaces" / "agent-session-test" / "generated" / "main.cpp"
            ).read_text(encoding="utf-8")
            self.assertEqual("int main() {\n  return 0;\n}\n", output)

    def test_large_source_read_has_no_line_or_byte_budget(self) -> None:
        responses = [
            {
                "action": "read_file",
                "path": "src/atom.cpp",
                "start_line": 1,
                "end_line": 300,
                "rationale": "read source",
            },
            {
                "action": "write_files",
                "files": [{"path": "generated/main.cpp", "content": "int main(){return 0;}\n"}],
                "rationale": "write glue",
            },
            {"action": "finish", "rationale": "complete"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "plugin" / "atom.test"
            source.mkdir(parents=True)
            source_lines = [f"// line {index:03d} " + ("x" * 1000) for index in range(1, 301)]
            (source / "atom.cpp").write_text("\n".join(source_lines) + "\n", encoding="utf-8")
            workspace = LocalPluginWorkspace(
                {"atom.test": source},
                workspace_root=root / "workspaces",
                diagnostics_root=root / "diagnostics",
            )
            client = _ScriptedCompletion(responses)
            agent = DeepSeekGlueAgent(
                client,
                workspace,
                max_turns=5,
            )

            result = agent.run(_task())

            self.assertEqual(("generated/main.cpp",), result.changed_files)
            read_result = json.loads(client.calls[1][-1]["content"])["result"]
            self.assertEqual(300, read_result["end_line"])
            self.assertIn("300: // line 300", read_result["content"])
            self.assertGreater(len(read_result["content"].encode("utf-8")), 256 * 1024)

    def test_unknown_repair_session_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            agent = DeepSeekGlueAgent(
                _ScriptedCompletion([]),
                self._workspace(Path(tmp)),
            )
            repair_task = _task().model_copy(
                update={
                    "repair_of_session": "coding-session://missing",
                    "diagnostics_ref": "build-diagnostics://missing",
                }
            )

            with self.assertRaisesRegex(GlueError, "AgentSession 不存在"):
                agent.run(repair_task)

    def test_finish_rejects_current_process_self_inject(self) -> None:
        responses = [
            {"action": "list_files", "path": "src", "rationale": "inspect"},
            {
                "action": "write_files",
                "files": [
                    {
                        "path": "generated/main.cpp",
                        "content": (
                            "const DWORD pid = GetCurrentProcessId();\nint main(){return 0;}\n"
                        ),
                    }
                ],
                "rationale": "self inject",
            },
            {"action": "finish", "rationale": "done"},
        ]
        task = _task().model_copy(
            update={
                "injection_contracts": (
                    GlueInjectionContract(
                        atom_id="atom.test",
                        sacrificial_image="notepad.exe",
                    ),
                )
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            agent = DeepSeekGlueAgent(
                _ScriptedCompletion(responses),
                self._workspace(Path(tmp)),
                retry_limit=1,
                max_turns=6,
            )
            with self.assertRaisesRegex(PlanningError, "GetCurrentProcessId"):
                agent.run(task)

    def test_parallel_readonly_tools_then_write_and_finish(self) -> None:
        responses = [
            {
                "actions": [
                    {"action": "list_files", "path": "src", "rationale": "inspect inventory"},
                    {
                        "action": "search",
                        "path": "src",
                        "query": "hidden_atom_value",
                        "rationale": "find entry point",
                    },
                    {
                        "action": "read_file",
                        "path": "src/atom.cpp",
                        "start_line": 1,
                        "end_line": 20,
                        "rationale": "read only the relevant file",
                    },
                ]
            },
            {
                "action": "write_files",
                "files": [
                    {
                        "path": "generated/main.cpp",
                        "content": "int hidden_atom_value();\nint main(){return hidden_atom_value();}\n",
                    }
                ],
                "rationale": "write glue",
            },
            {"action": "finish", "rationale": "required entry point is complete"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            client = _ScriptedCompletion(responses)
            events: list[tuple[str, dict[str, object]]] = []
            agent = DeepSeekGlueAgent(
                client,
                self._workspace(Path(tmp)),
                max_turns=6,
                sink=events.append,
            )

            result = agent.run(_task())

            self.assertEqual(("generated/main.cpp",), result.changed_files)
            self.assertEqual(3, len(client.calls))
            self.assertEqual(
                ["system", "user", "assistant", "tool", "tool", "tool"],
                [message["role"] for message in client.calls[1]],
            )
            self.assertEqual(3, len(client.calls[1][2]["tool_calls"]))
            tool_blob = "".join(
                str(message["content"])
                for message in client.calls[1]
                if message["role"] == "tool"
            )
            self.assertIn("SOURCE_SENTINEL", tool_blob)
            actions = [
                data["action"]
                for kind, data in events
                if kind == "sample_factory_coding_model_output"
            ]
            self.assertEqual(
                ["list_files,search,read_file", "write_files", "finish"],
                actions,
            )

    def test_write_and_finish_in_same_turn_are_rejected(self) -> None:
        responses = [
            {
                "actions": [
                    {
                        "action": "write_files",
                        "files": [
                            {"path": "generated/main.cpp", "content": "int main(){return 0;}\n"}
                        ],
                        "rationale": "write glue",
                    },
                    {"action": "finish", "rationale": "done"},
                ]
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            workspace = self._workspace(Path(tmp))
            agent = DeepSeekGlueAgent(
                _ScriptedCompletion(responses),
                workspace,
                retry_limit=1,
                max_turns=4,
            )

            with self.assertRaisesRegex(PlanningError, "finish 必须单独一回合"):
                agent.run(_task())
            self.assertNotIn("generated/main.cpp", workspace.snapshot(_task()))

    def test_empty_turn_does_not_consume_retry_limit(self) -> None:
        client = _MetadataCompletion(
            [
                LLMCompletion(content=""),
                LLMCompletion(
                    content=json.dumps(
                        {
                            "action": "write_files",
                            "files": [
                                {
                                    "path": "generated/main.cpp",
                                    "content": "int main(){return 0;}\n",
                                }
                            ],
                            "rationale": "write after empty turn",
                        }
                    ),
                    finish_reason="stop",
                ),
                LLMCompletion(
                    content=json.dumps({"action": "finish", "rationale": "complete"}),
                    finish_reason="stop",
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            agent = DeepSeekGlueAgent(
                client,
                self._workspace(Path(tmp)),
                retry_limit=1,
                max_turns=5,
            )

            result = agent.run(_task())

            self.assertEqual(("generated/main.cpp",), result.changed_files)
            self.assertEqual(
                ["system", "user", "user"],
                [message["role"] for message in client.calls[1]],
            )

    def test_truncated_tool_json_does_not_consume_retry_limit(self) -> None:
        client = _RaisingThenScripted(
            [
                LLMError(
                    "LLM 响应结构不合法：工具参数不是合法 JSON：Unterminated string starting at"
                )
            ],
            [
                {
                    "action": "write_files",
                    "files": [
                        {
                            "path": "generated/main.cpp",
                            "content": "int main(){return 0;}\n",
                        }
                    ],
                    "rationale": "write after truncated json",
                },
                {"action": "finish", "rationale": "complete"},
            ],
        )
        events: list[tuple[str, dict[str, object]]] = []
        with tempfile.TemporaryDirectory() as tmp:
            agent = DeepSeekGlueAgent(
                client,
                self._workspace(Path(tmp)),
                retry_limit=1,
                max_turns=5,
                sink=events.append,
            )

            result = agent.run(_task())

            self.assertEqual(("generated/main.cpp",), result.changed_files)
            feedback = next(
                data
                for kind, data in events
                if kind == "sample_factory_coding_feedback" and data["turn"] == 1
            )
            self.assertIn("Unterminated string", feedback["content"])
            self.assertIn("分文件写入", client.calls[1][-1]["content"])

    def test_parallel_write_files_are_rejected(self) -> None:
        responses = [
            {
                "actions": [
                    {
                        "action": "write_files",
                        "files": [
                            {"path": "generated/main.cpp", "content": "int main(){return 1;}\n"}
                        ],
                        "rationale": "first write",
                    },
                    {
                        "action": "write_files",
                        "files": [
                            {"path": "generated/other.cpp", "content": "int other(){return 0;}\n"}
                        ],
                        "rationale": "second write",
                    },
                ]
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            workspace = self._workspace(Path(tmp))
            agent = DeepSeekGlueAgent(
                _ScriptedCompletion(responses),
                workspace,
                retry_limit=1,
                max_turns=4,
            )

            with self.assertRaisesRegex(
                PlanningError, "write_files/apply_patch 每回合最多一个"
            ):
                agent.run(_task())
            snapshot = workspace.snapshot(_task())
            self.assertNotIn("generated/main.cpp", snapshot)
            self.assertNotIn("generated/other.cpp", snapshot)

    def test_msvc_prompt_orders_vcxproj_before_main_with_copyable_skeleton(self) -> None:
        responses = [
            {"action": "list_files", "path": "src", "rationale": "inspect inventory"},
            {"action": "list_files", "path": "generated", "rationale": "inspect generated"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            client = _ScriptedCompletion(responses)
            agent = DeepSeekGlueAgent(
                client,
                self._workspace(Path(tmp)),
                retry_limit=1,
                max_turns=2,
            )
            task = _task().model_copy(
                update={"build_target_ref": "build-target://initial/windows-msvc-v143-x64"}
            )

            with self.assertRaises(PlanningError):
                agent.run(task)

            prompt = json.loads(client.calls[0][1]["content"])
            self.assertEqual(
                ["generated/sample.vcxproj", "generated/main.cpp", "finish"],
                prompt["write_plan"]["order"],
            )
            self.assertTrue(prompt["write_plan"]["vcxproj_first"])
            self.assertIn("..\\src\\atom.cpp", prompt["write_plan"]["vcxproj_clcompile"])
            skeleton = prompt["write_plan"]["vcxproj_skeleton"]
            self.assertIn('Include="main.cpp"', skeleton)
            self.assertIn('Include="..\\src\\atom.cpp"', skeleton)
            self.assertIn("MultiThreaded", skeleton)
            self.assertIn("write_plan.vcxproj_skeleton", json.dumps(prompt["requirements"]))

    def test_msvc_apply_allows_main_cpp_before_project_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = self._workspace(Path(tmp))
            task = _task().model_copy(
                update={"build_target_ref": "build-target://initial/windows-msvc-v143-x64"}
            )

            result = workspace.apply(task, {"generated/main.cpp": "int main(){return 0;}\n"})

            self.assertEqual(("generated/main.cpp",), result.changed_files)
            snapshot = workspace.snapshot(task)
            self.assertIn("generated/main.cpp", snapshot)
            self.assertNotIn("generated/sample.vcxproj", snapshot)

    def test_msvc_length_stall_nudges_vcxproj_copy(self) -> None:
        client = _MetadataCompletion(
            [
                LLMCompletion(
                    content="",
                    finish_reason="length",
                    completion_tokens=16384,
                    reasoning_tokens=16384,
                ),
                LLMCompletion(content=""),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            agent = DeepSeekGlueAgent(
                client,
                self._workspace(Path(tmp)),
                retry_limit=1,
                max_turns=2,
            )
            task = _task().model_copy(
                update={"build_target_ref": "build-target://initial/windows-msvc-v143-x64"}
            )

            with self.assertRaises(PlanningError):
                agent.run(task)

            self.assertIn("sample.vcxproj", client.calls[1][-1]["content"])
            self.assertIn("vcxproj_skeleton", client.calls[1][-1]["content"])
            self.assertIn("禁止继续长推理", client.calls[1][-1]["content"])


if __name__ == "__main__":
    unittest.main()
