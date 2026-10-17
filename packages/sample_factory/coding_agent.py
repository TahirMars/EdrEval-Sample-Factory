"""Function Calling 驱动的受限 glue coding agent。

该模块把 LLM 的职责限制为生成文本源码文件。插件源码只读地从已登记目录
materialize 到代码仓外的 workspace；模型不能给出 shell 命令、编译命令、二进制
内容或 workspace 外路径。编译仍由 operator-owned BuildTarget 执行。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Protocol, cast

from packages.llm.provider import (
    LLMCompletion,
    LLMError,
    LLMMessage,
    LLMTool,
    LLMToolCall,
    LLMToolChoice,
    is_malformed_tool_protocol_error,
)
from packages.sample_factory.agent_events import (
    AgentActivitySink,
    emit_activity,
    safe_activity_text,
)
from packages.sample_factory.build_settings import enforce_msvc_static_runtime
from packages.sample_factory.compiler import source_tree_digest
from packages.sample_factory.errors import BuildError, PlanningError
from packages.sample_factory.glue import GlueError
from packages.sample_factory.injection_contract import (
    injection_glue_requirements,
    validate_injection_glue_source,
)
from packages.sample_factory.models import (
    AgentWorkspaceResult,
    GlueTask,
)
from packages.sample_factory.runtime_logging import (
    LOGGER_CONFIG,
    LOGGER_FILES,
    LOGGER_HEADER,
    LOGGER_SOURCE,
    configure_runtime_logging,
)

_TEXT_SUFFIXES = frozenset(
    {
        ".asm",
        ".c",
        ".cc",
        ".cpp",
        ".def",
        ".go",
        ".h",
        ".hpp",
        ".idl",
        ".inl",
        ".manifest",
        ".rc",
        ".rs",
        ".s",
        ".vcxproj",
    }
)
_MAX_FILE_BYTES = 256 * 1024
_DEFAULT_MAX_TURNS = 24
_MAX_SEARCH_TERMS = 16
_READABLE_ROOTS = frozenset({"src", "generated"})
_READ_ACTIONS = frozenset({"list_files", "search", "read_file"})
_WRITE_ACTIONS = frozenset({"write_files", "apply_patch"})


class _EmptyToolTurn(PlanningError):
    """模型本回合未调用工具：消耗 max_turns，不计入连续失败。"""


class WorkspaceBackend(Protocol):
    def snapshot(self, task: GlueTask) -> dict[str, str]: ...

    def apply(self, task: GlueTask, files: Mapping[str, str]) -> AgentWorkspaceResult: ...

    def diagnostics(self, diagnostics_ref: str) -> str | None: ...


class GlueCompletionClient(Protocol):
    def complete_tool_with_metadata(
        self,
        messages: list[LLMMessage],
        tools: list[LLMTool],
        *,
        tool_choice: LLMToolChoice = "required",
    ) -> LLMCompletion: ...


_RATIONALE_SCHEMA = {"type": "string", "description": "Short reason for this call."}
_PATH_SCHEMA = {"type": "string", "description": "Workspace-relative POSIX path."}
_CODING_TOOLS = [
    LLMTool("list_files", "List readable source files below a workspace path.", {
        "type": "object",
        "properties": {"path": _PATH_SCHEMA, "rationale": _RATIONALE_SCHEMA},
        "required": ["path", "rationale"], "additionalProperties": False,
    }),
    LLMTool("search", "Search readable source files for literal terms separated by |.", {
        "type": "object",
        "properties": {
            "query": {"type": "string", "minLength": 1, "maxLength": 200},
            "path": _PATH_SCHEMA, "rationale": _RATIONALE_SCHEMA,
        },
        "required": ["query", "path", "rationale"], "additionalProperties": False,
    }),
    LLMTool("read_file", "Read an inclusive line range from one source file.", {
        "type": "object",
        "properties": {
            "path": _PATH_SCHEMA,
            "start_line": {"type": "integer", "minimum": 1},
            "end_line": {"type": "integer", "minimum": 1},
            "rationale": _RATIONALE_SCHEMA,
        },
        "required": ["path", "start_line", "end_line", "rationale"],
        "additionalProperties": False,
    }),
    LLMTool("apply_patch", "Replace an inclusive line range in a generated file.", {
        "type": "object",
        "properties": {
            "path": _PATH_SCHEMA,
            "start_line": {"type": "integer", "minimum": 1},
            "end_line": {"type": "integer", "minimum": 1},
            "replacement": {"type": "string"},
            "rationale": _RATIONALE_SCHEMA,
        },
        "required": ["path", "start_line", "end_line", "replacement", "rationale"],
        "additionalProperties": False,
    }),
    LLMTool("write_files", "Create or fully replace generated source files.", {
        "type": "object",
        "properties": {
            "files": {"type": "array", "minItems": 1, "maxItems": 64, "items": {
                "type": "object",
                "properties": {"path": _PATH_SCHEMA, "content": {"type": "string"}},
                "required": ["path", "content"], "additionalProperties": False,
            }},
            "rationale": _RATIONALE_SCHEMA,
        },
        "required": ["files", "rationale"], "additionalProperties": False,
    }),
    LLMTool("finish", "Finish after every required generated file has been written.", {
        "type": "object",
        "properties": {"rationale": _RATIONALE_SCHEMA},
        "required": ["rationale"], "additionalProperties": False,
    }),
]


class LocalPluginWorkspace(WorkspaceBackend):
    """将选中 atom 的源码片段放入代码仓外 workspace，并只允许 generated/ 写入。"""

    def __init__(
        self,
        roots: Mapping[str, str | Path],
        *,
        workspace_root: str | Path,
        diagnostics_root: str | Path | None = None,
        payload_root: str | Path | Sequence[str | Path] | None = None,
        max_file_bytes: int | None = None,
        root_resolver: Callable[[str], Path] | None = None,
        diagnostics_resolver: Callable[[str], Path] | None = None,
    ) -> None:
        self._roots = {atom_id: Path(root).resolve() for atom_id, root in roots.items()}
        self._workspace_root = Path(workspace_root).resolve()
        self._diagnostics_root = (
            None if diagnostics_root is None else Path(diagnostics_root).resolve()
        )
        if payload_root is None:
            self._payload_root: tuple[Path, ...] | None = None
        elif isinstance(payload_root, (str, Path)):
            self._payload_root = (Path(payload_root).resolve(),)
        else:
            self._payload_root = tuple(Path(item).resolve() for item in payload_root)
        self._root_resolver = root_resolver
        self._diagnostics_resolver = diagnostics_resolver
        if max_file_bytes is not None and max_file_bytes <= 0:
            raise ValueError("max_file_bytes 必须为正整数或 None")
        self._max_file_bytes = max_file_bytes
        repo_root = Path(__file__).resolve().parents[2]
        if self._workspace_root.is_relative_to(repo_root):
            raise ValueError("plugin workspace 必须位于代码仓外")
        if self._diagnostics_root is not None and self._diagnostics_root.is_relative_to(repo_root):
            raise ValueError("diagnostics workspace 必须位于代码仓外")
        for root in self._payload_root or ():
            if root.is_relative_to(repo_root):
                raise ValueError("payload root 必须位于代码仓外")

    def _root_for(self, workspace_ref: str) -> Path:
        if not workspace_ref.startswith("plugin-workspace://"):
            raise GlueError("workspace_ref 必须是 plugin-workspace:// URI")
        suffix = workspace_ref.removeprefix("plugin-workspace://").strip("/")
        if not suffix:
            raise GlueError("workspace_ref 缺少 workspace 名称")
        root = (
            (self._workspace_root / suffix).resolve()
            if self._root_resolver is None
            else self._root_resolver(workspace_ref).resolve()
        )
        if not root.is_relative_to(self._workspace_root):
            raise GlueError("workspace_ref 越出 workspace root")
        return root

    def resolve_source_root(self, workspace_ref: str) -> Path:
        """Resolve an approved workspace reference for the compiler mapping."""
        return self._root_for(workspace_ref)

    def resolve(self, source_ref: str) -> Path:
        """Compiler SourceResolver face; supports batch-derived workspace refs."""
        return self._root_for(source_ref)

    def snapshot(self, task: GlueTask) -> dict[str, str]:
        root = self._root_for(task.workspace_ref)
        self._seed(task, root)
        if task.materialize_items:
            if self._payload_root is None:
                raise GlueError(
                    "GlueTask 含 embed 物化项，但 LocalPluginWorkspace 未配置 payload_root"
                )
            from packages.sample_factory.handoff import apply_embed_materialize

            apply_embed_materialize(
                root,
                task.materialize_items,
                payload_root=self._payload_root,
            )
        configure_runtime_logging(root, task)
        project = root / "generated" / "sample.vcxproj"
        if project.is_file():
            enforce_msvc_static_runtime(root, task.build_target_ref)
        files: dict[str, str] = {}
        for path in sorted(root.rglob("*")):
            if not path.is_file() or (
                self._max_file_bytes is not None and path.stat().st_size > self._max_file_bytes
            ):
                continue
            relative = path.relative_to(root).as_posix()
            if relative in {LOGGER_SOURCE, LOGGER_CONFIG}:
                continue
            if path.suffix.lower() not in _TEXT_SUFFIXES:
                continue
            try:
                files[relative] = _read_source_text(path)
            except UnicodeDecodeError as exc:
                raise GlueError(f"workspace 源码不是受支持的 UTF-8/GB18030：{relative}") from exc
        return files

    def apply(self, task: GlueTask, files: Mapping[str, str]) -> AgentWorkspaceResult:
        root = self._root_for(task.workspace_ref)
        if not files:
            raise GlueError("coding agent 未返回任何源码文件")
        changed: list[str] = []
        for relative, content in files.items():
            path = PurePosixPath(relative)
            if (
                path.is_absolute()
                or ".." in path.parts
                or not path.parts
                or path.parts[0] != "generated"
                or path.suffix.lower() not in _TEXT_SUFFIXES
            ):
                raise GlueError(f"coding agent 只能写 generated/ 下的源码：{relative}")
            if path.name.startswith("handoff_"):
                raise GlueError(f"coding agent 不得覆盖 handoff 物化头文件：{relative}")
            if path.as_posix() in LOGGER_FILES:
                raise GlueError(f"coding agent 不得覆盖公共执行日志源码：{relative}")
            if not isinstance(content, str) or len(content.encode("utf-8")) > _MAX_FILE_BYTES:
                raise GlueError(f"coding agent 文件过大或不是文本：{relative}")
            target = (root / relative).resolve()
            if not target.is_relative_to(root) or target.parent == root:
                raise GlueError(f"coding agent 输出路径非法：{relative}")
            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            staging = target.with_name(target.name + ".part")
            staging.write_text(content, encoding="utf-8", newline="\n")
            os.chmod(staging, 0o600)
            staging.replace(target)
            changed.append(relative)
        project = root / "generated" / "sample.vcxproj"
        if project.is_file():
            enforce_msvc_static_runtime(root, task.build_target_ref)
        digest = source_tree_digest(root)
        return AgentWorkspaceResult(
            session_ref=f"coding-session://{task.task_id}",
            workspace_ref=task.workspace_ref,
            changed_files=tuple(sorted(changed)),
            source_digest=digest,
        )

    def diagnostics(self, diagnostics_ref: str) -> str | None:
        if self._diagnostics_root is None or not diagnostics_ref.startswith("build-diagnostics://"):
            return None
        build_id = diagnostics_ref.removeprefix("build-diagnostics://").strip("/")
        if not build_id or "/" in build_id:
            return None
        path = (
            (self._diagnostics_root / build_id / "diagnostics.txt").resolve()
            if self._diagnostics_resolver is None
            else self._diagnostics_resolver(build_id).resolve()
        )
        if not path.is_relative_to(self._diagnostics_root) or not path.is_file():
            return None
        return path.read_text(encoding="utf-8")

    def _seed(self, task: GlueTask, root: Path) -> None:
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        source_root = root / "src"
        source_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        for atom_id in task.atom_ids:
            source = self._roots.get(atom_id)
            if source is None:
                if any(item.atom_id == atom_id for item in task.materialize_items):
                    continue
                raise GlueError(f"未登记 atom 源码根目录：{atom_id}")
            if not source.is_dir():
                raise GlueError(f"atom 源码根目录不存在：{atom_id}")
            for path in sorted(source.rglob("*")):
                if not path.is_file() or path.suffix.lower() not in _TEXT_SUFFIXES:
                    continue
                relative = path.relative_to(source)
                target = (source_root / relative).resolve()
                if not target.is_relative_to(source_root):
                    raise GlueError(f"atom 源码清单越界：{atom_id}/{relative}")
                target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                if not target.exists():
                    shutil.copyfile(path, target)


class DeepSeekGlueAgent:
    """多轮 AgentSession；模型可读完整源码树，只能写 generated/。"""

    def __init__(
        self,
        client: GlueCompletionClient,
        workspace: WorkspaceBackend,
        *,
        retry_limit: int = 2,
        max_turns: int = _DEFAULT_MAX_TURNS,
        sink: AgentActivitySink | None = None,
    ) -> None:
        if retry_limit < 1:
            raise ValueError("retry_limit 必须至少为 1")
        self._client = client
        self._workspace = workspace
        self._retry_limit = retry_limit
        if max_turns < 2:
            raise ValueError("max_turns 必须至少为 2")
        self._max_turns = max_turns
        self._sink = sink
        self._sessions: dict[str, list[LLMMessage]] = {}
        self._sessions_lock = threading.RLock()

    def run(self, task: GlueTask) -> AgentWorkspaceResult:
        snapshot = self._workspace.snapshot(task)
        diagnostics = (
            self._workspace.diagnostics(task.diagnostics_ref) if task.diagnostics_ref else None
        )
        required_files = _required_generated_files(task.build_target_ref)
        session_ref = task.repair_of_session or self._session_ref(task)
        messages = self._resume_messages(session_ref) if task.repair_of_session else []
        if task.repair_of_session is not None and not messages:
            raise GlueError(f"AgentSession 不存在，不能续接修复：{task.repair_of_session}")
        resumed = bool(messages)
        from packages.sample_factory.handoff import (
            HANDOFF_ARRAY_CPP_TYPE,
            HANDOFF_SIZE_CPP_TYPE,
            handoff_array_symbol,
            handoff_header_path,
            handoff_size_symbol,
        )

        embed_hints = [
            {
                "atom_id": item.atom_id,
                "handoff_id": item.handoff_id,
                "header": handoff_header_path(item.handoff_id),
                "array_symbol": handoff_array_symbol(item.handoff_id),
                "array_symbol_cpp_type": HANDOFF_ARRAY_CPP_TYPE,
                "size_symbol": handoff_size_symbol(item.handoff_id),
                "size_symbol_cpp_type": HANDOFF_SIZE_CPP_TYPE,
                "symbols_are_final_global_identifiers": True,
                "readable": False,
            }
            for item in task.materialize_items
        ]
        zero_arg = any(bool(items) for items in task.consumes_handoffs) or bool(embed_hints)
        prompt: dict[str, object] = {
            "task": task.model_dump(mode="json"),
            "source_manifest": self._source_manifest(snapshot),
            "required_generated_files": list(required_files),
            "embedded_handoffs": embed_hints,
            "execution_logging_contract": _execution_logging_contract(task),
            "agent_limits": {
                "max_turns": self._max_turns,
                "readable_roots": sorted(_READABLE_ROOTS),
                "read_budget": None,
                "max_read_turns_before_write": 2,
            },
            "write_plan": _write_plan(
                task,
                snapshot,
                required_files=required_files,
                embed_hints=embed_hints,
            ),
            "requirements": [
                (
                    "embedded_handoffs headers are materialized by the control plane and are intentionally unreadable; "
                    "do not call read_file or search on them. Include the header and use the provided "
                    "array_symbol/size_symbol verbatim as complete, unqualified global C++ identifiers. "
                    "Never prepend/append the header stem, concatenate another prefix, or qualify them with ::; "
                    "never guess or output payload bytes. "
                    "Do not call a payload atom Execute() or parse its JSON to recover shellcode/PE bytes."
                    if embed_hints
                    else "No embedded handoff is available; do not create handoff headers yourself."
                ),
                "最多 2 个只读回合（可并行 list_files/search/read_file，优先读 src/*.h 里的 Execute 签名），"
                "然后必须按 write_plan.order 分次 write_files；不要通读全部 .cpp 后再写。",
                "search.query uses case-insensitive literal substrings, not regular expressions. "
                "Use | only to separate alternative literal terms, for example VirtualAlloc|CreateThread.",
                (
                    "finish 前必须按 write_plan.order 写齐 required_generated_files；"
                    "MSVC 必须先写 generated/sample.vcxproj（原样复制 write_plan.vcxproj_skeleton），"
                    "再写 generated/main.cpp，最后单独 finish"
                    if required_files
                    else "只通过 write_files 写 generated/ 下的源码文件（如 main.cpp）"
                ),
                "每个 write_files 只写 1 个文件；content 必须是完整短文本，禁止一次输出超长源码或把推理写进工具参数。",
                "不得输出 shell 命令、编译器命令、二进制、base64、私钥或凭据",
                "不得修改或重写 generated/handoff_*.h（由控制面确定性物化）",
                "使用 task.atom_parameters 和源码中已声明的函数/合同",
                (
                    "入口必须零命令行参数（仅 argv0）；从 embedded_handoffs 头文件取 shellcode/映像字节，"
                    "把 atom_parameters 中的目标路径编译期钉死；禁止 argc/argv 读取载荷文件"
                    if zero_arg
                    else "入口必须可由 task.build_target_ref 对应的固定 build target 编译"
                ),
                *injection_glue_requirements(task.injection_contracts),
                (
                    "执行日志已开启：MSVC sample.vcxproj 必须单独编译 generated/edreval_execution_log.cpp；"
                    "无工程文件的固定单文件构建必须由 main.cpp include edreval_execution_log.cpp；"
                    "main.cpp 必须 include edreval_execution_log.h，启动时调用 Initialize；"
                    "按 atom_ph_ids 映射为每个 task.ph_ids 在真实 TTP 调用前后记录 RecordTtpStart/RecordTtpResult，"
                    "所有退出路径调用 RecordSampleResult；原因/细节只写执行结果，不得传入参数、凭据、hash、payload 或环境变量；"
                    "解析 TTP 结果 JSON 的 success（不得仅用返回码）；若 outputs 含 delegated_to_elevated_process=true，"
                    "则 RecordSampleResult(true) 后立即 return 0，不得继续后续 atom（提权子进程会执行完整链）"
                    if task.execution_logging
                    else "执行日志已关闭：不得 include、引用或编译任何 edreval_execution_log 源码/符号"
                ),
            ],
        }
        if resumed:
            messages.append(
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "event": "resume_after_compile_failure",
                            "task": task.model_dump(mode="json"),
                            "compiler_diagnostics": diagnostics,
                            "source_manifest": self._source_manifest(snapshot),
                        },
                        ensure_ascii=False,
                    ),
                }
            )
        else:
            if diagnostics is not None:
                prompt["compiler_diagnostics"] = diagnostics
            messages = [
                {"role": "system", "content": self._agent_system_prompt()},
                {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
            ]
        emit_activity(
            self._sink,
            "sample_factory_coding_session",
            {
                "agent": "coding",
                "session_ref": session_ref,
                "resumed": resumed,
                "content": ("续接编译修复会话" if resumed else "启动源码工具会话"),
            },
        )

        errors: list[str] = []
        consecutive_errors = 0
        changed_files: set[str] = set()
        last_result: AgentWorkspaceResult | None = None
        for turn in range(1, self._max_turns + 1):
            pending_calls: tuple[LLMToolCall, ...] = ()
            calls_appended = False
            completed = 0
            completion = LLMCompletion(content="")
            try:
                completion = _complete_tool_with_metadata(self._client, messages)
                pending_calls = completion.tool_calls
                if not pending_calls:
                    raise _EmptyToolTurn("coding agent 本回合未调用工具")
                actions = tuple(self._parse_action(call) for call in pending_calls)
                self._validate_tool_batch(actions)
                emit_activity(
                    self._sink,
                    "sample_factory_coding_model_output",
                    {
                        "agent": "coding",
                        "session_ref": session_ref,
                        "turn": turn,
                        "action": ",".join(str(item["action"]) for item in actions),
                        "content": safe_activity_text(
                            "; ".join(self._action_summary(item) for item in actions)
                            + _completion_diagnostics(completion)
                        ),
                    },
                )
                messages.append(
                    _assistant_tool_message(pending_calls, content=completion.content)
                )
                calls_appended = True

                for call, action in zip(pending_calls, actions, strict=True):
                    if action["action"] == "finish":
                        if last_result is None or not changed_files:
                            raise GlueError("finish 前必须至少成功执行一次 write_files")
                        generated = self._generated_files(snapshot)
                        _require_generated_files(generated, required_files)
                        _require_embedded_handoff_integration(generated, task)
                        _require_execution_logging_integration(generated, task)
                        _require_injection_glue_integration(generated, task)
                        result = last_result.model_copy(
                            update={
                                "session_ref": session_ref,
                                "changed_files": tuple(sorted(changed_files)),
                            }
                        )
                        messages.append(call.result_message({"ok": True, "finished": True}))
                        self._save_session(session_ref, messages)
                        return result

                    tool_result, audit_summary = self._execute_tool(
                        action,
                        snapshot=snapshot,
                    )
                    if action["action"] == "apply_patch":
                        files = self._apply_patch(action, snapshot)
                        last_result = self._workspace.apply(task, files)
                        changed_files.update(files)
                        snapshot = self._workspace.snapshot(task)
                        tool_result = {
                            "ok": True,
                            "changed_files": sorted(files),
                            "source_digest": last_result.source_digest,
                        }
                        audit_summary = (
                            f"按行修改 {len(files)} 个 generated 文件；"
                            f"累计变更 {len(changed_files)} 个文件"
                        )
                    elif action["action"] == "write_files":
                        files = cast(dict[str, str], action["files"])
                        last_result = self._workspace.apply(task, files)
                        changed_files.update(files)
                        snapshot = self._workspace.snapshot(task)
                        tool_result = {
                            "ok": True,
                            "changed_files": sorted(files),
                            "source_digest": last_result.source_digest,
                        }
                        audit_summary = (
                            f"写入 {len(files)} 个 generated 文件；累计变更 {len(changed_files)} 个文件"
                        )
                    messages.append(call.result_message({"ok": True, "result": tool_result}))
                    completed += 1
                    emit_activity(
                        self._sink,
                        "sample_factory_coding_tool_result",
                        {
                            "agent": "coding",
                            "session_ref": session_ref,
                            "turn": turn,
                            "tool": action["action"],
                            "content": safe_activity_text(audit_summary),
                        },
                    )
                self._save_session(session_ref, messages)
                consecutive_errors = 0
            except (LLMError, PlanningError, GlueError, TimeoutError, BuildError) as exc:
                error = str(exc).splitlines()[0] + _completion_diagnostics(completion)
                errors.append(error[:500])
                protocol_jitter = isinstance(exc, _EmptyToolTurn) or is_malformed_tool_protocol_error(
                    exc
                )
                if not protocol_jitter:
                    consecutive_errors += 1
                next_write = _next_required_write(required_files, snapshot, changed_files)
                nudge = _next_write_nudge(next_write, completion)
                if isinstance(exc, _EmptyToolTurn):
                    feedback = (
                        f"上一个 AgentSession 回合未调用工具：{errors[-1]}。"
                        "禁止继续长推理；下一回合立刻调用工具，不要输出正文。"
                        "同一回合可并行多个只读工具。"
                        "write_files、apply_patch、finish 必须单独调用。"
                        + nudge
                    )
                elif is_malformed_tool_protocol_error(exc):
                    feedback = (
                        f"上一个工具调用的参数 JSON 不完整或被截断：{errors[-1]}。"
                        "请重新发起完整工具调用；write_files 必须分文件写入，"
                        "content 保持短且完整，禁止一次输出超长源码字符串。"
                        + nudge
                    )
                else:
                    feedback = (
                        f"上一个 AgentSession 动作未通过门禁：{errors[-1]}。"
                        "请根据错误选择下一个合法工具调用。"
                        + nudge
                    )
                remaining = pending_calls[completed:]
                if isinstance(exc, GlueError) and any(
                    call.name == "read_file"
                    and str(call.arguments.get("path", "")).startswith("generated/handoff_")
                    for call in remaining
                ):
                    feedback += (
                        " The requested handoff header is intentionally protected and cannot be read."
                        " Do not retry this path; include the header and use the supplied array_symbol/size_symbol."
                    )
                if pending_calls:
                    if not calls_appended:
                        messages.append(
                            _assistant_tool_message(
                                pending_calls, content=completion.content
                            )
                        )
                    for call in pending_calls[completed:]:
                        messages.append(call.result_message({"ok": False, "error": feedback}))
                else:
                    messages.append({"role": "user", "content": feedback})
                emit_activity(
                    self._sink,
                    "sample_factory_coding_feedback",
                    {
                        "agent": "coding",
                        "session_ref": session_ref,
                        "turn": turn,
                        "content": safe_activity_text(errors[-1]),
                    },
                )
                self._save_session(session_ref, messages)
                if consecutive_errors >= self._retry_limit:
                    break
        raise PlanningError(
            f"coding agent 在 {self._max_turns} 回合内未完成合法 glue："
            + " | ".join(errors or ["模型未调用 finish"])
        )

    @staticmethod
    def _agent_system_prompt() -> str:
        return (
            "你是样本工厂 glue coding agent。每一回合必须调用工具，禁止把输出配额耗在长推理或正文上。"
            "同一回合可以并行调用多个只读工具（list_files/search/read_file）。"
            "write_files、apply_patch、finish 每回合最多一个，且必须单独调用，不得与其他工具并行。"
            "最多 2 个只读回合后必须开始写入；优先读 src/*.h，不要通读全部 .cpp。"
            "MSVC 写入顺序固定：generated/sample.vcxproj（原样复制 write_plan.vcxproj_skeleton）"
            "→ generated/main.cpp → finish。"
            "每个 write_files 只写 1 个文件。payload 字节只来自 embedded_handoffs 符号，"
            "禁止调用 payload atom 的 Execute 或解析其 JSON 取 shellcode。"
            "不得在正文输出动作、命令、二进制、base64、凭据或 schema 外字段。"
        )

    @staticmethod
    def _session_ref(task: GlueTask) -> str:
        workspace_digest = hashlib.sha256(task.workspace_ref.encode("utf-8")).hexdigest()[:12]
        return f"coding-session://{task.task_id}/{workspace_digest}"

    def _resume_messages(self, session_ref: str) -> list[LLMMessage]:
        with self._sessions_lock:
            return [dict(message) for message in self._sessions.get(session_ref, [])]

    def _save_session(self, session_ref: str, messages: list[LLMMessage]) -> None:
        with self._sessions_lock:
            self._sessions[session_ref] = [dict(message) for message in messages]

    @staticmethod
    def _source_manifest(files: Mapping[str, str]) -> list[dict[str, object]]:
        return [
            {
                "path": path,
                "bytes": len(content.encode("utf-8")),
                "lines": len(content.splitlines()),
                "readable": not DeepSeekGlueAgent._protected_path(path),
            }
            for path, content in sorted(files.items())
        ]

    @staticmethod
    def _protected_path(path: str) -> bool:
        value = PurePosixPath(path)
        return value.parent.as_posix() == "generated" and value.name.startswith("handoff_")

    @staticmethod
    def _normalize_tool_path(value: object, *, allow_root: bool = False) -> str:
        if not isinstance(value, str):
            raise PlanningError("工具 path 必须是字符串")
        path = value.strip().replace("\\", "/").strip("/")
        if allow_root and path in {"", "."}:
            return ""
        parsed = PurePosixPath(path)
        if not path or parsed.is_absolute() or ".." in parsed.parts:
            raise PlanningError(f"工具 path 越界或为空：{value!r}")
        return parsed.as_posix()

    @staticmethod
    def _parse_files(values: object) -> dict[str, str]:
        if not isinstance(values, list) or not values:
            raise PlanningError("glue agent files 必须是非空数组")
        result: dict[str, str] = {}
        for item in values:
            if not isinstance(item, dict) or set(item) != {"path", "content"}:
                raise PlanningError("glue agent files 项必须恰含 path/content")
            path, content = item["path"], item["content"]
            if not isinstance(path, str) or not isinstance(content, str):
                raise PlanningError("glue agent path/content 必须是字符串")
            if path in result:
                raise PlanningError(f"glue agent 重复文件：{path}")
            result[path] = content
        return result

    @staticmethod
    def _validate_tool_batch(actions: Sequence[Mapping[str, object]]) -> None:
        names = [str(item["action"]) for item in actions]
        write_count = sum(1 for name in names if name in _WRITE_ACTIONS)
        finish_count = sum(1 for name in names if name == "finish")
        if finish_count and len(actions) != 1:
            raise PlanningError(
                "finish 必须单独一回合，不得与其他工具并行；本回合不执行任何工具"
            )
        if write_count and len(actions) != 1:
            raise PlanningError(
                "write_files/apply_patch 每回合最多一个且必须单独调用；本回合不执行任何工具"
            )

    @classmethod
    def _parse_action(cls, call: LLMToolCall) -> dict[str, object]:
        action = call.name
        data = call.arguments
        allowed = {
            "list_files": {"path", "rationale"},
            "search": {"query", "path", "rationale"},
            "read_file": {"path", "start_line", "end_line", "rationale"},
            "apply_patch": {
                "path",
                "start_line",
                "end_line",
                "replacement",
                "rationale",
            },
            "write_files": {"files", "rationale"},
            "finish": {"rationale"},
        }
        fields = allowed.get(action)
        if fields is None:
            raise PlanningError(f"未知 AgentSession action：{action}")
        if set(data) - fields:
            raise PlanningError(f"{action} 含 schema 外字段")
        parsed: dict[str, object] = {
            "action": action,
            "rationale": safe_activity_text(data.get("rationale", "")),
        }
        if action in {"list_files", "search"}:
            parsed["path"] = cls._normalize_tool_path(data.get("path", ""), allow_root=True)
        elif action in {"read_file", "apply_patch"}:
            parsed["path"] = cls._normalize_tool_path(data.get("path"))
            start, end = data.get("start_line"), data.get("end_line")
            if not isinstance(start, int) or isinstance(start, bool) or start < 1:
                raise PlanningError("read_file.start_line 必须是正整数")
            if not isinstance(end, int) or isinstance(end, bool) or end < start:
                raise PlanningError("read_file.end_line 必须不小于 start_line")
            parsed["start_line"] = start
            parsed["end_line"] = end
            if action == "apply_patch":
                replacement = data.get("replacement")
                if not isinstance(replacement, str):
                    raise PlanningError("apply_patch.replacement 必须是字符串")
                if len(replacement.encode("utf-8")) > _MAX_FILE_BYTES:
                    raise PlanningError("apply_patch.replacement 文件过大")
                parsed["replacement"] = replacement
        if action == "search":
            query = data.get("query")
            if not isinstance(query, str) or not query.strip() or len(query) > 200:
                raise PlanningError("search.query 必须是 1..200 字符的非空字符串")
            parsed["query"] = query
        elif action == "write_files":
            parsed["files"] = cls._parse_files(data.get("files"))
        return parsed

    def _execute_tool(
        self,
        action: dict[str, object],
        *,
        snapshot: Mapping[str, str],
    ) -> tuple[dict[str, object], str]:
        name = cast(str, action["action"])
        if name in {"write_files", "apply_patch"}:
            return {}, "准备受控写入"
        prefix = cast(str, action.get("path", ""))
        scoped = {
            path: content
            for path, content in sorted(snapshot.items())
            if (not prefix or path == prefix or path.startswith(prefix.rstrip("/") + "/"))
            and PurePosixPath(path).parts
            and PurePosixPath(path).parts[0] in _READABLE_ROOTS
            and not self._protected_path(path)
        }
        if name == "list_files":
            paths = list(scoped)
            return {"paths": paths, "truncated": False}, f"列出 {len(paths)} 个文件"
        if name == "read_file":
            path = prefix
            try:
                content = scoped[path]
            except KeyError as exc:
                raise GlueError(f"read_file 路径不存在或受保护：{path}") from exc
            start = cast(int, action["start_line"])
            end = cast(int, action["end_line"])
            lines = content.splitlines()
            selected = lines[start - 1 : end]
            rendered = "\n".join(
                f"{line_number}: {line}" for line_number, line in enumerate(selected, start=start)
            )
            consumed = len(rendered.encode("utf-8"))
            actual_end = start + len(selected) - 1 if selected else start - 1
            return (
                {
                    "path": path,
                    "start_line": start,
                    "end_line": actual_end,
                    "content": rendered,
                },
                f"读取 {path} 第 {start}-{actual_end} 行，共 {consumed} 字节",
            )
        if name == "search":
            query = cast(str, action["query"])
            terms = _search_terms(query)
            folded_terms = tuple(term.casefold() for term in terms)
            matches: list[dict[str, object]] = []
            consumed = 0
            for path, content in scoped.items():
                for line_number, line in enumerate(content.splitlines(), start=1):
                    if not any(term in line.casefold() for term in folded_terms):
                        continue
                    item = {"path": path, "line": line_number, "text": line[:500]}
                    item_bytes = len(json.dumps(item, ensure_ascii=False).encode("utf-8"))
                    matches.append(item)
                    consumed += item_bytes
            return (
                {"query": query, "terms": list(terms), "matches": matches},
                f"搜索 {list(terms)!r}，返回 {len(matches)} 处匹配，共 {consumed} 字节",
            )
        raise PlanningError(f"不可执行的 AgentSession action：{name}")

    @staticmethod
    def _apply_patch(
        action: Mapping[str, object],
        snapshot: Mapping[str, str],
    ) -> dict[str, str]:
        path = cast(str, action["path"])
        if not path.startswith("generated/") or DeepSeekGlueAgent._protected_path(path):
            raise GlueError("apply_patch 只能修改 generated/ 下的非物化文件")
        try:
            content = snapshot[path]
        except KeyError as exc:
            raise GlueError(f"apply_patch 文件不存在：{path}") from exc
        start = cast(int, action["start_line"])
        end = cast(int, action["end_line"])
        lines = content.splitlines(keepends=True)
        if start > len(lines) or end > len(lines):
            raise GlueError(f"apply_patch 行范围超出文件：{path} {start}-{end}")
        replacement = cast(str, action["replacement"])
        replacement_lines = replacement.splitlines(keepends=True)
        updated = "".join(lines[: start - 1] + replacement_lines + lines[end:])
        if len(updated.encode("utf-8")) > _MAX_FILE_BYTES:
            raise GlueError(f"apply_patch 结果文件过大：{path}")
        return {path: updated}

    @staticmethod
    def _generated_files(snapshot: Mapping[str, str]) -> dict[str, str]:
        return {
            path: content
            for path, content in snapshot.items()
            if path.startswith("generated/") and not DeepSeekGlueAgent._protected_path(path)
        }

    @staticmethod
    def _action_summary(action: Mapping[str, object]) -> str:
        name = str(action["action"])
        rationale = safe_activity_text(action.get("rationale", ""), max_chars=300)
        if name == "list_files":
            detail = f"list_files path={action.get('path') or '.'}"
        elif name == "search":
            detail = f"search query={action.get('query')!r} path={action.get('path') or '.'}"
        elif name == "read_file":
            detail = (
                f"read_file {action.get('path')} "
                f"lines={action.get('start_line')}-{action.get('end_line')}"
            )
        elif name == "apply_patch":
            detail = (
                f"apply_patch {action.get('path')} "
                f"lines={action.get('start_line')}-{action.get('end_line')}"
            )
        elif name == "write_files":
            files = action.get("files")
            if isinstance(files, dict):
                sizes = [
                    f"{path} ({len(str(content).encode('utf-8'))} B)"
                    for path, content in files.items()
                ]
                detail = f"{name}: " + ", ".join(sizes)
            else:
                detail = name
        else:
            detail = name
        return safe_activity_text(f"{detail}; rationale={rationale}")


def _assistant_tool_message(
    calls: Sequence[LLMToolCall], *, content: str = ""
) -> LLMMessage:
    if not calls:
        raise PlanningError("assistant tool message 至少需要一个 tool_call")
    message = calls[0].assistant_message(content=content)
    if len(calls) == 1:
        return message
    tool_calls: list[object] = []
    for call in calls:
        extra = call.assistant_message().get("tool_calls")
        if not isinstance(extra, list):
            raise PlanningError("assistant tool_calls 结构不合法")
        tool_calls.extend(extra)
    message["tool_calls"] = tool_calls
    return message


def _complete_tool_with_metadata(
    client: GlueCompletionClient, messages: list[LLMMessage]
) -> LLMCompletion:
    result = client.complete_tool_with_metadata(
        messages,
        _CODING_TOOLS,
        tool_choice="required",
    )
    if not isinstance(result, LLMCompletion):
        raise PlanningError("complete_tool_with_metadata 必须返回 LLMCompletion")
    return result


def _completion_diagnostics(completion: LLMCompletion) -> str:
    values = {
        "finish_reason": completion.finish_reason,
        "prompt_tokens": completion.prompt_tokens,
        "completion_tokens": completion.completion_tokens,
        "reasoning_tokens": completion.reasoning_tokens,
        "reasoning_chars": completion.reasoning_content_chars,
    }
    rendered = ", ".join(f"{key}={value}" for key, value in values.items() if value is not None)
    return "" if not rendered else f"; provider=[{rendered}]"


def _search_terms(query: str) -> tuple[str, ...]:
    terms = tuple(dict.fromkeys(term.strip() for term in query.split("|") if term.strip()))
    if not terms:
        raise PlanningError("search.query 必须至少包含一个字面关键词")
    if len(terms) > _MAX_SEARCH_TERMS:
        raise PlanningError(f"search.query 最多包含 {_MAX_SEARCH_TERMS} 个字面关键词")
    return terms


def _required_generated_files(build_target_ref: str) -> tuple[str, ...]:
    """按 operator 钉扎的 build target 推断 glue 必须写出的 generated 文件。"""
    if "windows-msvc" in build_target_ref or build_target_ref.endswith("msvc-v143-x64"):
        return ("generated/sample.vcxproj", "generated/main.cpp")
    if "linux-clang-mingw" in build_target_ref or "mingw" in build_target_ref:
        return ("generated/main.cpp",)
    return ()


def _msvc_clcompile_items(snapshot: Mapping[str, str], *, execution_logging: bool) -> list[str]:
    items = ["main.cpp"]
    if execution_logging:
        items.append("edreval_execution_log.cpp")
    for path in sorted(snapshot):
        posix = path.replace("\\", "/")
        if posix.startswith("src/") and posix.endswith(".cpp"):
            items.append("..\\src\\" + posix[4:].replace("/", "\\"))
    return items


def _msvc_vcxproj_skeleton(clcompile: Sequence[str]) -> str:
    compile_xml = "\n".join(f'    <ClCompile Include="{item}" />' for item in clcompile)
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Project DefaultTargets="Build" '
        'xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n'
        '  <ItemGroup Label="ProjectConfigurations">\n'
        '    <ProjectConfiguration Include="Debug|x64">'
        "<Configuration>Debug</Configuration><Platform>x64</Platform>"
        "</ProjectConfiguration>\n"
        '    <ProjectConfiguration Include="Release|x64">'
        "<Configuration>Release</Configuration><Platform>x64</Platform>"
        "</ProjectConfiguration>\n"
        "  </ItemGroup>\n"
        '  <PropertyGroup Label="Globals">'
        "<Keyword>Win32Proj</Keyword><RootNamespace>sample</RootNamespace>"
        "<WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>"
        "</PropertyGroup>\n"
        '  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.Default.props" />\n'
        "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Debug|x64'\" "
        'Label="Configuration">'
        "<ConfigurationType>Application</ConfigurationType>"
        "<UseDebugLibraries>true</UseDebugLibraries>"
        "<PlatformToolset>v143</PlatformToolset>"
        "<CharacterSet>Unicode</CharacterSet>"
        "</PropertyGroup>\n"
        "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\" "
        'Label="Configuration">'
        "<ConfigurationType>Application</ConfigurationType>"
        "<UseDebugLibraries>false</UseDebugLibraries>"
        "<PlatformToolset>v143</PlatformToolset>"
        "<WholeProgramOptimization>true</WholeProgramOptimization>"
        "<CharacterSet>Unicode</CharacterSet>"
        "</PropertyGroup>\n"
        '  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.props" />\n'
        "  <PropertyGroup>"
        "<IntDir>$(OutDir)obj\\</IntDir><TargetName>sample</TargetName>"
        "</PropertyGroup>\n"
        "  <ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='Debug|x64'\">\n"
        "    <ClCompile>"
        "<AdditionalIncludeDirectories>$(ProjectDir);$(ProjectDir)..\\src;"
        "%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>"
        "<LanguageStandard>stdcpp17</LanguageStandard>"
        "<RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>"
        "</ClCompile>\n"
        "    <Link><SubSystem>Console</SubSystem></Link>\n"
        "  </ItemDefinitionGroup>\n"
        "  <ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\">\n"
        "    <ClCompile>"
        "<AdditionalIncludeDirectories>$(ProjectDir);$(ProjectDir)..\\src;"
        "%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>"
        "<LanguageStandard>stdcpp17</LanguageStandard>"
        "<RuntimeLibrary>MultiThreaded</RuntimeLibrary>"
        "</ClCompile>\n"
        "    <Link><SubSystem>Console</SubSystem></Link>\n"
        "  </ItemDefinitionGroup>\n"
        f"  <ItemGroup>\n{compile_xml}\n  </ItemGroup>\n"
        '  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />\n'
        "</Project>\n"
    )


def _write_plan(
    task: GlueTask,
    snapshot: Mapping[str, str],
    *,
    required_files: tuple[str, ...],
    embed_hints: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    headers = [
        path
        for path in sorted(snapshot)
        if path.replace("\\", "/").startswith("src/")
        and path.replace("\\", "/").endswith((".h", ".hpp"))
    ]
    plan: dict[str, object] = {
        "order": [*required_files, "finish"],
        "max_read_turns_before_write": 2,
        "one_file_per_write_files": True,
        "prefer_read": headers,
        "main_cpp": {
            "include_headers": [PurePosixPath(path).name for path in headers],
            "embedded_handoffs": [
                {
                    "header": item["header"],
                    "array_symbol": item["array_symbol"],
                    "size_symbol": item["size_symbol"],
                }
                for item in embed_hints
            ],
            "forbid": [
                "Do not call a payload atom Execute() to obtain shellcode or PE bytes",
                "Do not parse JSON from a payload atom to recover the payload",
                "Do not read argc/argv for payload files",
                "Do not invent payload bytes or base64",
            ],
        },
    }
    if "generated/sample.vcxproj" in required_files:
        clcompile = _msvc_clcompile_items(snapshot, execution_logging=task.execution_logging)
        plan["vcxproj_first"] = True
        plan["vcxproj_clcompile"] = clcompile
        plan["vcxproj_skeleton"] = _msvc_vcxproj_skeleton(clcompile)
    return plan


def _next_required_write(
    required_files: tuple[str, ...],
    snapshot: Mapping[str, str],
    changed_files: set[str],
) -> str | None:
    present = set(snapshot) | changed_files
    for path in required_files:
        if path not in present:
            return path
    return None


def _next_write_nudge(next_write: str | None, completion: LLMCompletion) -> str:
    if next_write is None:
        return " 下一回合若 required 文件已齐，单独调用 finish。"
    stalled = completion.finish_reason == "length"
    prefix = " 禁止继续长推理。" if stalled else ""
    if next_write == "generated/sample.vcxproj":
        return (
            f"{prefix} 下一回合第一个动作必须是单独 write_files，"
            "只写 generated/sample.vcxproj，content 原样复制 write_plan.vcxproj_skeleton；"
            "不要写 main.cpp。"
        )
    return (
        f"{prefix} 下一回合第一个动作必须是单独 write_files，只写 {next_write}；"
        "content 保持短且完整。"
    )


def _require_generated_files(files: Mapping[str, str], required: tuple[str, ...]) -> None:
    if not required:
        return
    missing = [path for path in required if path not in files]
    if missing:
        raise PlanningError("glue agent 缺少 build target 必需文件：" + ", ".join(missing))


def _execution_logging_contract(task: GlueTask) -> dict[str, object]:
    return {
        "enabled": task.execution_logging,
        "output_directory": r"C:\ProgramData\EdrEvalAgent\SampleLogs",
        "header": LOGGER_HEADER if task.execution_logging else None,
        "source": LOGGER_SOURCE if task.execution_logging else None,
        "source_inclusion": (
            "sample.vcxproj compiles source separately"
            if "msvc" in task.build_target_ref
            else "main.cpp includes edreval_execution_log.cpp"
        )
        if task.execution_logging
        else None,
        "atom_ph_ids": [
            {"atom_id": atom_id, "ph_ids": list(ph_ids)}
            for atom_id, ph_ids in zip(task.atom_ids, task.atom_ph_ids, strict=True)
        ],
        "api": (
            ["Initialize", "RecordTtpStart", "RecordTtpResult", "RecordSampleResult"]
            if task.execution_logging
            else []
        ),
    }


def _require_execution_logging_integration(files: Mapping[str, str], task: GlueTask) -> None:
    combined = "\n".join(files.values())
    if not task.execution_logging:
        if "edreval_execution_log" in combined or "sample_log::" in combined:
            raise PlanningError("execution_logging=False 时 glue 不得引用公共执行日志")
        return
    main = files.get("generated/main.cpp")
    if main is None:
        raise PlanningError("execution_logging=True 时必须生成 generated/main.cpp")
    required_symbols = (
        "edreval_execution_log.h",
        "Initialize(",
        "RecordTtpStart(",
        "RecordTtpResult(",
        "RecordSampleResult(",
    )
    missing = [symbol for symbol in required_symbols if symbol not in main]
    if missing:
        raise PlanningError(
            "execution_logging=True 时 main.cpp 缺少日志接入：" + ", ".join(missing)
        )
    missing_ph_ids = [ph_id for ph_id in task.ph_ids if ph_id not in main]
    if missing_ph_ids:
        raise PlanningError(
            "execution_logging=True 时 main.cpp 未显式覆盖全部 PH：" + ", ".join(missing_ph_ids)
        )
    project = files.get("generated/sample.vcxproj")
    source_include = '#include "edreval_execution_log.cpp"'
    if project is not None:
        if "edreval_execution_log.cpp" not in project:
            raise PlanningError("MSVC 工程未编译公共执行日志实现 edreval_execution_log.cpp")
        if source_include in main:
            raise PlanningError("MSVC 工程已单独编译日志实现，main.cpp 不得重复 include .cpp")
    elif source_include not in main:
        raise PlanningError("固定单文件构建必须由 main.cpp include edreval_execution_log.cpp")


def _require_embedded_handoff_integration(files: Mapping[str, str], task: GlueTask) -> None:
    from packages.sample_factory.handoff import (
        HandoffError,
        validate_embedded_handoff_references,
    )

    try:
        validate_embedded_handoff_references(files, task.materialize_items)
    except HandoffError as exc:
        raise PlanningError(str(exc)) from exc


def _require_injection_glue_integration(files: Mapping[str, str], task: GlueTask) -> None:
    validate_injection_glue_source(files, task.injection_contracts)


def _read_source_text(path: Path) -> str:
    """读取既有 TTP 源码的封闭编码集；不做 chardet 猜测。"""
    raw = path.read_bytes()
    for encoding in ("utf-8", "gb18030"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("utf-8", raw, 0, len(raw), "unsupported source encoding")


__all__ = ["DeepSeekGlueAgent", "GlueCompletionClient", "LocalPluginWorkspace", "WorkspaceBackend"]
