from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.llm.provider import LLMCompletion, LLMError, LLMTool, LLMToolCall
from packages.sample_factory.compiler import source_tree_digest
from packages.sample_factory.errors import PlanningError
from packages.sample_factory.plugin_authoring_agent import LLMPluginAuthoringAgent

from tests.llm_tool_fakes import as_tool_completion
from tests.sample_factory_fixtures import atom_specs
from tests.test_sample_factory_plugin_authoring import _request


class _Completion:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def complete_tool_with_metadata(self, messages, tools: list[LLMTool], **kwargs):
        del kwargs
        self.calls.append([dict(message) for message in messages])
        return as_tool_completion(self.responses.pop(0), tools, call_index=len(self.calls))


class _MetadataCompletion:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def complete_tool_with_metadata(self, messages, tools: list[LLMTool], **kwargs):
        del kwargs
        self.calls.append([dict(message) for message in messages])
        return as_tool_completion(self.responses.pop(0), tools, call_index=len(self.calls))


class _RaisingThenCompletion:
    def __init__(self, errors, responses):
        self.errors = list(errors)
        self.responses = list(responses)
        self.calls = []

    def complete_tool_with_metadata(self, messages, tools: list[LLMTool], **kwargs):
        del kwargs
        self.calls.append([dict(message) for message in messages])
        if self.errors:
            raise self.errors.pop(0)
        return as_tool_completion(self.responses.pop(0), tools, call_index=len(self.calls))


def _finish_response(spec) -> str:
    return json.dumps(
        {
            "action": "finish",
            "plugin_id": spec.atom_id,
            "rationale": "candidate source is complete",
        }
    )


class PluginAuthoringAgentTest(unittest.TestCase):
    def test_writes_only_candidate_source_and_returns_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            responses = [
                json.dumps({
                    "action": "write_files",
                    "files": [
                        {"path": "src/EarlyApcInjection.cpp", "content": "int atom() { return 0; }\n"},
                        {"path": "plugin.vcxproj", "content": "<Project />\n"},
                    ],
                    "rationale": "implement the requested contract",
                }),
                _finish_response(spec),
            ]
            agent = LLMPluginAuthoringAgent(
                _Completion(responses),
                lambda plugin_run_id: (
                    root / "plugin-runs" / plugin_run_id / "authoring" / "final-source"
                ),
            )

            result = agent.author(_request(), plugin_run_id="plugin-run-12345678")

            source = root / "plugin-runs" / "plugin-run-12345678" / "authoring" / "final-source"
            self.assertEqual(source_tree_digest(source), result.source_digest)
            self.assertEqual("plugin-source://plugin-run-12345678/final-source", result.source_ref)

    def test_multi_turn_session_writes_reads_patches_and_finishes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            responses = [
                json.dumps(
                    {
                        "action": "write_files",
                        "files": [
                            {"path": "src/EarlyApcInjection.cpp", "content": "int atom() { return 1; }\n"}
                        ],
                        "rationale": "write the implementation",
                    }
                ),
                json.dumps(
                    {
                        "action": "read_file",
                        "path": "src/EarlyApcInjection.cpp",
                        "start_line": 1,
                        "end_line": 20,
                        "rationale": "inspect the implementation",
                    }
                ),
                json.dumps(
                    {
                        "action": "apply_patch",
                        "path": "src/EarlyApcInjection.cpp",
                        "start_line": 1,
                        "end_line": 1,
                        "replacement": "int atom() { return 0; }\n",
                        "rationale": "correct the return value",
                    }
                ),
                _finish_response(spec),
            ]
            client = _Completion(responses)
            events = []
            agent = LLMPluginAuthoringAgent(
                client,
                lambda _: root / "authoring" / "final-source",
                max_turns=4,
                sink=events.append,
            )

            result = agent.author(_request(), plugin_run_id="plugin-run-12345678")

            source = root / "authoring" / "final-source"
            self.assertEqual(
                "int atom() { return 0; }\n",
                (source / "src/EarlyApcInjection.cpp").read_text(),
            )
            self.assertFalse((root / "authoring" / "working-source").exists())
            self.assertEqual(
                ("src/EarlyApcInjection.cpp", "src/EarlyApcInjection.h"),
                result.changed_files,
            )
            self.assertIsNone(result.atom_spec)
            self.assertEqual(
                3,
                sum(kind == "sample_factory_plugin_coding_tool_result" for kind, _ in events),
            )
            self.assertEqual("tool", client.calls[1][-1]["role"])
            self.assertIn("result", client.calls[1][-1]["content"])
            self.assertEqual("tool", client.calls[2][-1]["role"])
            self.assertIn("EarlyApcInjection.cpp", client.calls[2][-1]["content"])

    def test_compile_diagnostics_create_new_immutable_repair_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _Completion(
                [
                    json.dumps(
                        {
                            "action": "write_files",
                            "files": [
                                {
                                    "path": "src/EarlyApcInjection.cpp",
                                    "content": "int atom() { return 1; }\n",
                                }
                            ],
                            "rationale": "write candidate",
                        }
                    ),
                    json.dumps(
                        {
                            "action": "finish",
                            "rationale": "candidate is complete",
                        }
                    ),
                    json.dumps(
                        {
                            "action": "apply_patch",
                            "path": "src/EarlyApcInjection.cpp",
                            "start_line": 1,
                            "end_line": 1,
                            "replacement": "int atom() { return 0; }\n",
                            "rationale": "fix the compiler error",
                        }
                    ),
                    json.dumps(
                        {
                            "action": "finish",
                            "rationale": "repair is complete",
                        }
                    ),
                ]
            )
            events = []
            agent = LLMPluginAuthoringAgent(
                client,
                lambda _: root / "authoring" / "final-source",
                max_turns=2,
                sink=events.append,
            )
            request = _request()
            source = agent.author(request, plugin_run_id="plugin-run-12345678")
            original_root = root / "authoring" / "final-source"
            original_digest = source_tree_digest(original_root)
            diagnostics = root / "build" / "deadbeef" / "diagnostics.txt"
            diagnostics.parent.mkdir(parents=True)
            diagnostics.write_text("error C2660: wrong argument count\n", encoding="utf-8")

            repaired = agent.repair(
                source,
                request,
                plugin_run_id="plugin-run-12345678",
                diagnostics_ref="plugin-build://plugin-run-12345678/deadbeef",
            )

            repaired_root = root / "authoring" / "repair-deadbeef"
            self.assertEqual(original_digest, source_tree_digest(original_root))
            self.assertNotEqual(source.source_digest, repaired.source_digest)
            self.assertEqual(
                "plugin-source://plugin-run-12345678/repair-deadbeef",
                repaired.source_ref,
            )
            self.assertEqual(
                "int atom() { return 0; }\n",
                (repaired_root / "src" / "EarlyApcInjection.cpp").read_text(),
            )
            self.assertIn("error C2660", client.calls[2][1]["content"])
            self.assertIn(
                "sample_factory_plugin_coding_repair_session",
                [kind for kind, _data in events],
            )

    def test_session_can_read_existing_plugin_repository_but_cannot_write_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "dispatchable" / "atom.reference"
            reference.mkdir(parents=True)
            (reference / "plugin.cpp").write_text("int reference_entry() { return 7; }\n")
            (reference / "plugin.json").write_text('{"format_version":"sf-plugin-v1"}\n')
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            client = _Completion(
                [
                    json.dumps(
                        {
                            "action": "list_files",
                            "path": "reference/atom.reference",
                            "rationale": "inspect the existing plugin repository",
                        }
                    ),
                    json.dumps(
                        {
                            "action": "read_file",
                            "path": "reference/atom.reference/plugin.json",
                            "start_line": 1,
                            "end_line": 10,
                            "rationale": "inspect the existing manifest convention",
                        }
                    ),
                    json.dumps(
                        {
                            "action": "write_files",
                            "files": [
                                {
                                    "path": "src/EarlyApcInjection.cpp",
                                    "content": "int atom() { return 0; }\n",
                                }
                            ],
                            "rationale": "write the new candidate",
                        }
                    ),
                    _finish_response(spec),
                ]
            )
            agent = LLMPluginAuthoringAgent(
                client,
                lambda _: root / "candidate" / "final-source",
                reference_roots={"atom.reference": reference},
                max_turns=4,
            )

            result = agent.author(_request(), plugin_run_id="plugin-run-12345678")

            self.assertEqual("atom.12345678", result.plugin_id)
            tool_result = json.loads(client.calls[1][-1]["content"])
            self.assertIn("reference/atom.reference/plugin.json", tool_result["result"]["paths"])
            manifest_result = json.loads(client.calls[2][-1]["content"])
            self.assertIn("format_version", manifest_result["result"]["content"])
            self.assertFalse((reference / "src" / "atom.cpp").exists())

    def test_reference_source_with_suspected_secret_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "dispatchable" / "atom.reference"
            reference.mkdir(parents=True)
            (reference / "plugin.cpp").write_text("const char* token = secret_value;\n")
            agent = LLMPluginAuthoringAgent(
                _Completion([]),
                lambda _: root / "candidate" / "final-source",
                reference_roots={"atom.reference": reference},
            )

            with self.assertRaisesRegex(PlanningError, "疑似凭据"):
                agent.author(_request(), plugin_run_id="plugin-run-12345678")

    def test_empty_reasoning_only_response_gets_targeted_feedback_and_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            client = _MetadataCompletion(
                [
                    LLMCompletion(
                        content="",
                        finish_reason="length",
                        completion_tokens=16384,
                        reasoning_tokens=16384,
                        reasoning_content_chars=48000,
                    ),
                    LLMCompletion(
                        content=json.dumps(
                            {
                                "action": "write_files",
                                "files": [
                                    {
                                        "path": "src/EarlyApcInjection.cpp",
                                        "content": "int atom() { return 0; }\n",
                                    }
                                ],
                                "rationale": "write after empty response",
                            }
                        ),
                        finish_reason="stop",
                    ),
                    LLMCompletion(content=_finish_response(spec), finish_reason="stop"),
                ]
            )
            events = []
            agent = LLMPluginAuthoringAgent(
                client,
                lambda _: root / "authoring" / "final-source",
                retry_limit=1,
                max_turns=3,
                sink=events.append,
            )

            result = agent.author(_request(), plugin_run_id="plugin-run-12345678")

            self.assertEqual("atom.12345678", result.plugin_id)
            self.assertIn("multiple read-only tools", client.calls[0][0]["content"])
            self.assertIn("must be the only call in their turn", client.calls[0][0]["content"])
            self.assertEqual(
                ["system", "user", "user"],
                [message["role"] for message in client.calls[1]],
            )
            feedback = next(
                data for kind, data in events if kind == "sample_factory_plugin_coding_feedback"
            )
            self.assertIn("未调用工具", feedback["content"])
            self.assertEqual("no_tool_call", feedback["reason"])
            self.assertIn("finish_reason=length", feedback["content"])
            self.assertIn("reasoning_tokens=16384", feedback["content"])

    def test_truncated_tool_json_does_not_consume_retry_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            client = _RaisingThenCompletion(
                [
                    LLMError(
                        "LLM 响应结构不合法：工具参数不是合法 JSON：Unterminated string starting at"
                    )
                ],
                [
                    json.dumps(
                        {
                            "action": "write_files",
                            "files": [
                                {
                                    "path": "src/EarlyApcInjection.cpp",
                                    "content": "int atom() { return 0; }\n",
                                }
                            ],
                            "rationale": "write after truncated json",
                        }
                    ),
                    _finish_response(spec),
                ],
            )
            events = []
            agent = LLMPluginAuthoringAgent(
                client,
                lambda _: root / "authoring" / "final-source",
                retry_limit=1,
                max_turns=3,
                sink=events.append,
            )

            result = agent.author(_request(), plugin_run_id="plugin-run-12345678")

            self.assertEqual("atom.12345678", result.plugin_id)
            feedback = next(
                data
                for kind, data in events
                if kind == "sample_factory_plugin_coding_feedback"
            )
            self.assertEqual("malformed_tool_json", feedback["reason"])
            self.assertIn("分文件写入", client.calls[1][-1]["content"])

    def test_protocol_miss_does_not_share_tool_rejection_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            client = _MetadataCompletion([
                LLMCompletion(content=json.dumps({
                    "action": "write_files",
                    "files": [{"path": "../escape.cpp", "content": "bad"}],
                    "rationale": "invalid path",
                })),
                LLMCompletion(content="", finish_reason="length"),
                LLMCompletion(content=json.dumps({
                    "action": "write_files",
                    "files": [{
                        "path": "src/EarlyApcInjection.cpp",
                        "content": "int atom() { return 0; }\n",
                    }],
                    "rationale": "corrected write",
                })),
                LLMCompletion(content=_finish_response(spec)),
            ])
            events: list[tuple[str, dict[str, object]]] = []
            agent = LLMPluginAuthoringAgent(
                client,
                lambda _: root / "authoring" / "final-source",
                retry_limit=2,
                max_turns=4,
                sink=events.append,
            )

            result = agent.author(_request(), plugin_run_id="plugin-run-12345678")

            self.assertEqual("atom.12345678", result.plugin_id)
            reasons = [
                data["reason"]
                for kind, data in events
                if kind == "sample_factory_plugin_coding_feedback"
            ]
            self.assertEqual(["tool_rejected", "no_tool_call"], reasons)

    def test_parallel_readonly_tools_then_write_and_finish(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            client = _MetadataCompletion(
                [
                    LLMCompletion(
                        content="",
                        tool_calls=(
                            LLMToolCall(
                                "call_1",
                                "list_files",
                                {"path": ".", "rationale": "inspect"},
                            ),
                            LLMToolCall(
                                "call_2",
                                "search",
                                {"query": "atom", "path": ".", "rationale": "inspect"},
                            ),
                        ),
                    ),
                    LLMCompletion(
                        content=json.dumps(
                            {
                                "action": "write_files",
                                "files": [
                                    {
                                        "path": "src/EarlyApcInjection.cpp",
                                        "content": "int atom() { return 0; }\n",
                                    }
                                ],
                                "rationale": "write after parallel reads",
                            }
                        )
                    ),
                    LLMCompletion(content=_finish_response(spec)),
                ]
            )
            events: list[tuple[str, dict[str, object]]] = []
            agent = LLMPluginAuthoringAgent(
                client,
                lambda _: root / "authoring" / "final-source",
                max_turns=5,
                sink=events.append,
            )

            result = agent.author(_request(), plugin_run_id="plugin-run-12345678")

            self.assertEqual("atom.12345678", result.plugin_id)
            self.assertEqual(3, len(client.calls))
            self.assertEqual(
                ["system", "user", "assistant", "tool", "tool"],
                [message["role"] for message in client.calls[1]],
            )
            actions = [
                data["action"]
                for kind, data in events
                if kind == "sample_factory_plugin_coding_model_output"
            ]
            self.assertEqual(["list_files,search", "write_files", "finish"], actions)

    def test_parallel_write_files_are_rejected_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _MetadataCompletion(
                [
                    LLMCompletion(
                        content="",
                        tool_calls=(
                            LLMToolCall(
                                "call_1",
                                "write_files",
                                {
                                    "files": [
                                        {
                                            "path": "src/EarlyApcInjection.cpp",
                                            "content": "int a(){return 1;}\n",
                                        }
                                    ],
                                    "rationale": "first write",
                                },
                            ),
                            LLMToolCall(
                                "call_2",
                                "write_files",
                                {
                                    "files": [
                                        {
                                            "path": "src/other.cpp",
                                            "content": "int b(){return 0;}\n",
                                        }
                                    ],
                                    "rationale": "second write",
                                },
                            ),
                        ),
                    ),
                ]
            )
            events: list[tuple[str, dict[str, object]]] = []
            agent = LLMPluginAuthoringAgent(
                client,
                lambda _: root / "authoring" / "final-source",
                retry_limit=1,
                sink=events.append,
            )

            with self.assertRaisesRegex(
                PlanningError, "write_files/apply_patch 每回合最多一个"
            ):
                agent.author(_request(), plugin_run_id="plugin-run-12345678")

            feedback = next(
                data
                for kind, data in events
                if kind == "sample_factory_plugin_coding_feedback"
            )
            self.assertEqual("tool_rejected", feedback["reason"])
            self.assertFalse((root / "authoring" / "final-source").exists())

    def test_validation_feedback_names_invalid_atom_spec_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            client = _Completion(
                [
                    json.dumps(
                        {
                            "action": "write_files",
                            "files": [
                                {
                                    "path": "src/EarlyApcInjection.cpp",
                                    "content": "int atom() { return 0; }\n",
                                }
                            ],
                            "rationale": "write candidate",
                        }
                    ),
                    json.dumps(
                        {
                            "action": "finish",
                            "plugin_id": spec.atom_id,
                            "atom_spec": {"atom_id": spec.atom_id},
                            "rationale": "invalid legacy identity",
                        }
                    ),
                    _finish_response(spec),
                ]
            )
            events = []
            agent = LLMPluginAuthoringAgent(
                client,
                lambda _: root / "authoring" / "final-source",
                max_turns=3,
                sink=events.append,
            )

            result = agent.author(_request(), plugin_run_id="plugin-run-12345678")

            self.assertIsNone(result.atom_spec)
            feedback = next(
                data for kind, data in events if kind == "sample_factory_plugin_coding_feedback"
            )
            self.assertIn("atom_spec.role", feedback["content"])
            self.assertIn("Field required", feedback["content"])

    def test_prompt_includes_operator_build_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            client = _Completion(
                [
                    json.dumps(
                        {
                            "action": "write_files",
                            "files": [
                                {
                                    "path": "src/EarlyApcInjection.cpp",
                                    "content": "int atom() { return 0; }\n",
                                }
                            ],
                            "rationale": "write candidate",
                        }
                    ),
                    _finish_response(spec),
                ]
            )
            agent = LLMPluginAuthoringAgent(
                client,
                lambda _: root / "authoring" / "final-source",
                max_turns=2,
                build_contract={
                    "target_ref": "build-target://windows-x64",
                    "artifact_relative": "EarlyApcInjection.lib",
                    "toolchain_fp": "msvc-v143@pinned",
                },
            )

            agent.author(_request(), plugin_run_id="plugin-run-12345678")

            prompt = json.loads(client.calls[0][1]["content"])
            self.assertEqual(
                "EarlyApcInjection.lib", prompt["build_contract"]["artifact_relative"]
            )
            self.assertEqual(
                "edreval-ttp-result-v1",
                prompt["implementation_contract"]["result_schema_version"],
            )
            self.assertTrue(
                any("edreval-ttp-result-v1" in item for item in prompt["requirements"])
            )

    def test_finish_rejects_dll_project_when_build_target_requires_static_lib_then_repairs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            request = _request().model_copy(
                update={"build_target_ref": "build-target://initial/windows-msvc-v143-x64"}
            )
            dynamic_library = (
                '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
                "<PropertyGroup><ConfigurationType>DynamicLibrary</ConfigurationType>"
                "</PropertyGroup>"
                "<ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\">"
                "<ClCompile><RuntimeLibrary>MultiThreaded</RuntimeLibrary></ClCompile>"
                "</ItemDefinitionGroup></Project>"
            )
            static_library = dynamic_library.replace("DynamicLibrary", "StaticLibrary")
            client = _Completion(
                [
                    json.dumps(
                        {
                            "action": "write_files",
                            "files": [
                                {
                                    "path": "src/EarlyApcInjection.cpp",
                                    "content": "int atom() { return 0; }\n",
                                },
                                {
                                    "path": "generated/sample.vcxproj",
                                    "content": dynamic_library,
                                },
                            ],
                            "rationale": "write initial project",
                        }
                    ),
                    _finish_response(spec),
                    json.dumps(
                        {
                            "action": "write_files",
                            "files": [
                                {
                                    "path": "generated/sample.vcxproj",
                                    "content": static_library,
                                }
                            ],
                            "rationale": "repair artifact type",
                        }
                    ),
                    _finish_response(spec),
                ]
            )
            events = []
            agent = LLMPluginAuthoringAgent(
                client,
                lambda _: root / "authoring" / "final-source",
                max_turns=4,
                build_contract={
                    "target_ref": request.build_target_ref,
                    "artifact_relative": "EarlyApcInjection.lib",
                    "toolchain_fp": "msvc-v143@pinned",
                },
                sink=events.append,
            )

            result = agent.author(request, plugin_run_id="plugin-run-12345678")

            self.assertIsNone(result.atom_spec)
            feedback = next(
                data for kind, data in events if kind == "sample_factory_plugin_coding_feedback"
            )
            self.assertIn("ConfigurationType", feedback["content"])
            self.assertIn("StaticLibrary", feedback["content"])
            project = root / "authoring" / "final-source" / "generated" / "sample.vcxproj"
            self.assertIn("$(ProjectDir)", project.read_text(encoding="utf-8"))

    def test_permission_error_during_directory_rename_falls_back_to_verified_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            client = _Completion(
                [
                    json.dumps(
                        {
                            "action": "write_files",
                            "files": [
                                {
                                    "path": "src/EarlyApcInjection.cpp",
                                    "content": "int atom() { return 0; }\n",
                                }
                            ],
                            "rationale": "write candidate",
                        }
                    ),
                    _finish_response(spec),
                ]
            )
            agent = LLMPluginAuthoringAgent(
                client,
                lambda _: root / "authoring" / "final-source",
                max_turns=2,
            )

            with patch.object(Path, "replace", side_effect=PermissionError("scanner lock")):
                result = agent.author(_request(), plugin_run_id="plugin-run-12345678")

            final_source = root / "authoring" / "final-source"
            self.assertEqual(source_tree_digest(final_source), result.source_digest)
            self.assertFalse((root / "authoring" / "working-source").exists())

    def test_model_plugin_id_is_ignored_in_favor_of_control_plane_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _Completion(
                [
                    json.dumps(
                        {
                            "action": "write_files",
                            "files": [
                                {
                                    "path": "src/EarlyApcInjection.cpp",
                                    "content": "int atom() { return 0; }\n",
                                }
                            ],
                            "rationale": "write candidate",
                        }
                    ),
                    json.dumps(
                        {
                            "action": "finish",
                            "plugin_id": "plugin.EarlyAPC",
                            "rationale": "finish with an invalid model-selected id",
                        }
                    ),
                ]
            )
            agent = LLMPluginAuthoringAgent(
                client,
                lambda _: root / "authoring" / "final-source",
                max_turns=2,
            )

            result = agent.author(_request(), plugin_run_id="plugin-run-12345678")

            self.assertEqual("atom.12345678", result.plugin_id)

    def test_repeated_empty_response_fails_cleanly_without_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = _MetadataCompletion(
                [
                    LLMCompletion(content="", finish_reason="length"),
                    LLMCompletion(content="", finish_reason="length"),
                ]
            )
            agent = LLMPluginAuthoringAgent(
                client,
                lambda _: root / "authoring" / "final-source",
                retry_limit=1,
                max_turns=2,
            )

            with self.assertRaisesRegex(PlanningError, "达到 2 回合上限"):
                agent.author(_request(), plugin_run_id="plugin-run-12345678")

            self.assertFalse((root / "authoring" / "working-source").exists())
            self.assertFalse((root / "authoring" / "final-source").exists())

    def test_rejects_path_escape_without_leaving_partial_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            response = json.dumps(
                {
                    "action": "write_files",
                    "files": [{"path": "../escape.cpp", "content": "bad"}],
                    "rationale": "invalid path fixture",
                }
            )
            agent = LLMPluginAuthoringAgent(
                _Completion([response]),
                lambda _: root / "authoring" / "final-source",
                retry_limit=1,
            )

            with self.assertRaisesRegex(Exception, "路径非法"):
                agent.author(_request(), plugin_run_id="plugin-run-12345678")
            self.assertFalse((root / "authoring" / "final-source").exists())

    def test_msvc_candidate_requires_sample_project_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            response = json.dumps(
                {
                    "action": "write_files",
                    "files": [
                        {
                            "path": "src/EarlyApcInjection.cpp",
                            "content": "int atom() { return 0; }\n",
                        },
                        {"path": "plugin.vcxproj", "content": "<Project />\n"},
                    ],
                    "rationale": "invalid MSVC project layout fixture",
                }
            )
            request = _request().model_copy(
                update={"build_target_ref": "build-target://initial/windows-msvc-v143-x64"}
            )
            agent = LLMPluginAuthoringAgent(
                _Completion([response, _finish_response(spec)]),
                lambda plugin_run_id: root / plugin_run_id,
                retry_limit=1,
            )

            with self.assertRaisesRegex(Exception, "必须包含 generated/sample.vcxproj"):
                agent.author(request, plugin_run_id="plugin-run-12345678")
            self.assertFalse((root / "plugin-run-12345678").exists())


if __name__ == "__main__":
    unittest.main()
