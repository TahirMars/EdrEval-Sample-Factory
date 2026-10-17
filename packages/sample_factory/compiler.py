"""固定 build target + 外部源码工作区 + 资源护栏的具体编译后端。

命令来自人工登记的 BuildTarget，绝不来自 LLM。源码与输出目录必须位于本代码仓
之外；构建结果以不透明引用留在授权后端，并携带源码/工具链/产物三指纹。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from packages.labmgr.host_guard import HostResourceGuard
from packages.labmgr.process import SubprocessRunner
from packages.labmgr.resource import MemoryCappedRunner
from packages.sample_factory.build_settings import (
    effective_toolchain_fp,
    validate_msvc_static_runtime,
)
from packages.sample_factory.errors import BuildError, CompilationFailure
from packages.sample_factory.handoff import (
    HandoffError,
    validate_embedded_handoff_workspace,
)
from packages.sample_factory.models import BuiltSample
from packages.sample_factory.pipeline import BuildRequest, CompilerBackend
from packages.sample_factory.runtime_logging import validate_runtime_logging_build_inputs

_SOURCE_SUFFIXES = frozenset(
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
        ".json",
        ".manifest",
        ".rc",
        ".rs",
        ".s",
        ".toml",
        ".vcxproj",
    }
)
_SOURCE_NAMES = frozenset({"CMakeLists.txt", "Makefile", "go.mod", "go.sum", "Cargo.lock"})
_EXCLUDED_PARTS = frozenset(
    {".git", ".factory-build", "bin", "obj", "debug", "release", "x64", "x86"}
)


class BuildRunner(Protocol):
    def run(self, argv: list[str], *, timeout: float | None = None) -> tuple[int, str]: ...


class HeavyResourceGuard(Protocol):
    def heavy_env(self) -> dict[str, str]: ...

    def acquire_heavy(self, operation: str) -> None: ...

    def release_heavy(self, operation: str) -> None: ...


class SourceResolver(Protocol):
    def resolve(self, source_ref: str) -> Path: ...


@dataclass(frozen=True)
class BuildTarget:
    target_ref: str
    argv_template: tuple[str, ...]
    artifact_relative: str
    toolchain_fp: str
    timeout_s: float = 600

    def __post_init__(self) -> None:
        if not self.target_ref.startswith("build-target://"):
            raise ValueError("target_ref 必须是 build-target:// 引用")
        if not self.argv_template or not self.toolchain_fp or self.timeout_s <= 0:
            raise ValueError("build target 的 argv/toolchain/timeout 不完整")
        artifact = Path(self.artifact_relative.replace("{implementation_name}", "PluginName"))
        if artifact.is_absolute() or ".." in artifact.parts or not artifact.name:
            raise ValueError("artifact_relative 必须是受控相对路径")
        allowed = {"{source_root}", "{output_dir}", "{implementation_name}"}
        for fragment in _template_fragments(self.artifact_relative):
            if fragment not in allowed:
                raise ValueError(f"build target artifact_relative 含未知模板变量：{fragment}")
        for token in self.argv_template:
            for fragment in _template_fragments(token):
                if fragment not in allowed:
                    raise ValueError(f"build target 含未知模板变量：{fragment}")


class JsonBuildTargetCatalog:
    """加载 operator 管理的 ``build-targets.json``，不接受模型动态命令。"""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def load(self) -> dict[str, BuildTarget]:
        if not self._path.is_file():
            raise BuildError(f"build target catalog 不存在：{self._path}")
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            values = raw["targets"] if isinstance(raw, dict) else raw
            if not isinstance(values, list):
                raise TypeError("顶层必须是数组或含 targets 数组的对象")
            targets = [
                BuildTarget(
                    target_ref=str(item["target_ref"]),
                    argv_template=tuple(str(token) for token in item["argv_template"]),
                    artifact_relative=str(item["artifact_relative"]),
                    toolchain_fp=str(item["toolchain_fp"]),
                    timeout_s=float(item.get("timeout_s", 600)),
                )
                for item in values
            ]
        except Exception as exc:
            raise BuildError(f"build target catalog 非法：{exc}") from exc
        result = {target.target_ref: target for target in targets}
        if len(result) != len(targets):
            raise BuildError("build target target_ref 重复")
        return result


class MappedSourceResolver:
    """部署层显式 URI→目录映射；拒绝代码仓内源码。"""

    def __init__(self, mapping: Mapping[str, str | Path]) -> None:
        self._mapping = {key: Path(value) for key, value in mapping.items()}
        self._repo_root = Path(__file__).resolve().parents[2]

    def resolve(self, source_ref: str) -> Path:
        try:
            path = self._mapping[source_ref].resolve()
        except KeyError as exc:
            raise BuildError(f"未登记 source_ref：{source_ref}") from exc
        if not path.is_dir():
            raise BuildError(f"source_ref 目录不存在：{source_ref}")
        if path.is_relative_to(self._repo_root):
            raise BuildError("插件源码位于 EdrEvalAgent 代码仓内；按 §10.5 拒绝编译")
        return path


class GuardedCompilerBackend(CompilerBackend):
    """注册命令经 HostResourceGuard 编译。

    Linux 默认走 MemoryCappedRunner + ``env KEY=VAL`` 前缀；Windows 构建宿主
    改用 SubprocessRunner，并把护栏环境变量注入子进程 env（无 POSIX ``env``）。
    """

    def __init__(
        self,
        *,
        targets: Mapping[str, BuildTarget],
        sources: SourceResolver,
        artifact_root: str | Path,
        runner: BuildRunner | None = None,
        guard: HeavyResourceGuard | None = None,
        memory_limit_mb: int = 8192,
        artifact_root_resolver: Callable[[BuildRequest], Path] | None = None,
    ) -> None:
        self._targets = dict(targets)
        self._sources = sources
        self._artifact_root = Path(artifact_root).resolve()
        self._artifact_root_resolver = artifact_root_resolver
        if runner is not None:
            self._runner = runner
        elif os.name == "nt":
            self._runner = SubprocessRunner()
        else:
            self._runner = MemoryCappedRunner(limit_mb=memory_limit_mb)
        self._guard = guard or HostResourceGuard()
        self._repo_root = Path(__file__).resolve().parents[2]
        if self._artifact_root.is_relative_to(self._repo_root):
            raise ValueError("编译产物目录不得位于 EdrEvalAgent 代码仓")
        self._artifact_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        self._artifacts: dict[str, Path] = {}

    def compile(self, request: BuildRequest) -> BuiltSample:
        try:
            target = self._targets[request.build_target_ref]
        except KeyError as exc:
            raise BuildError(f"未登记 build target：{request.build_target_ref}") from exc
        source_root = self._sources.resolve(request.glue.source_ref)
        validate_msvc_static_runtime(source_root, request.build_target_ref)
        source_digest = source_tree_digest(source_root)
        if source_digest != request.glue.source_digest:
            raise BuildError("编译前源码摘要与 Agent/template 回执不一致")

        artifact_root = (
            self._artifact_root
            if self._artifact_root_resolver is None
            else self._artifact_root_resolver(request).resolve()
        )
        if not artifact_root.is_relative_to(self._artifact_root):
            raise BuildError("动态构建目录越出获批 artifact root")
        artifact_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        build_id = uuid4().hex
        output_dir = artifact_root / build_id
        output_dir.mkdir(parents=True, mode=0o700)
        try:
            validate_embedded_handoff_workspace(
                source_root, request.materialize_items
            )
        except HandoffError as exc:
            diagnostics_ref = self._write_diagnostics(artifact_root, build_id, str(exc))
            raise CompilationFailure(
                "embedded handoff 未通过编译前静态门禁",
                diagnostics_ref=diagnostics_ref,
            ) from exc
        argv = [
            token.replace("{source_root}", str(source_root)).replace(
                "{output_dir}", str(output_dir)
            )
            for token in target.argv_template
        ]
        validate_runtime_logging_build_inputs(source_root, request.recipe, argv)
        operation = f"sample-factory-build:{build_id[:12]}"
        self._guard.acquire_heavy(operation)
        try:
            rc, output = self._run_build(argv, timeout=target.timeout_s)
        finally:
            self._guard.release_heavy(operation)
        if rc != 0:
            diagnostics_ref = self._write_diagnostics(artifact_root, build_id, output)
            raise CompilationFailure(
                f"受控编译失败（rc={rc}, target={target.target_ref}）",
                diagnostics_ref=diagnostics_ref,
            )

        artifact = (output_dir / target.artifact_relative).resolve()
        if not artifact.is_relative_to(output_dir) or not artifact.is_file():
            diagnostics_ref = self._write_diagnostics(
                artifact_root, build_id, "expected artifact missing"
            )
            raise CompilationFailure("编译成功但登记产物缺失", diagnostics_ref=diagnostics_ref)
        digest = _sha256_file(artifact)
        artifact_ref = f"build-artifact://{build_id}"
        self._artifacts[artifact_ref] = artifact
        return BuiltSample(
            artifact_ref=artifact_ref,
            artifact_sha256=digest,
            source_digest=source_digest,
            toolchain_fp=effective_toolchain_fp(
                target.toolchain_fp, request.build_target_ref
            ),
            build_id=build_id,
        )

    def resolve_artifact(self, artifact_ref: str) -> Path:
        try:
            path = self._artifacts[artifact_ref]
        except KeyError as exc:
            raise BuildError(f"未知 build artifact：{artifact_ref}") from exc
        if not path.is_file():
            raise BuildError(f"build artifact 已丢失：{artifact_ref}")
        return path

    def discard(self, artifact_ref: str) -> None:
        path = self._artifacts.pop(artifact_ref, None)
        if path is not None and path.parent.is_relative_to(self._artifact_root):
            shutil.rmtree(path.parent)

    def _run_build(self, argv: list[str], *, timeout: float) -> tuple[int, str]:
        if os.name == "nt":
            return self._runner.run(argv, timeout=timeout)
        env_prefix = [
            "env",
            *(f"{key}={value}" for key, value in self._guard.heavy_env().items()),
        ]
        return self._runner.run(env_prefix + argv, timeout=timeout)

    def _write_diagnostics(self, artifact_root: Path, build_id: str, output: str) -> str:
        path = artifact_root / build_id / "diagnostics.txt"
        path.write_text(output[-65536:], encoding="utf-8")
        return f"build-diagnostics://{build_id}"


def source_tree_digest(
    root: str | Path,
    *,
    exclude_relative_prefixes: Sequence[str] = (),
) -> str:
    """对源码闭包的相对路径+内容做稳定摘要，忽略 VCS 与编译产物目录。"""
    base = Path(root).resolve()
    if not base.is_dir():
        raise BuildError(f"源码根目录不存在：{base}")
    files = source_tree_files(
        base, exclude_relative_prefixes=exclude_relative_prefixes
    )
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(base).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(path.stat().st_size.to_bytes(8, "big"))
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                digest.update(chunk)
    return digest.hexdigest()


def source_tree_files(
    root: str | Path,
    *,
    exclude_relative_prefixes: Sequence[str] = (),
) -> tuple[Path, ...]:
    """Return the exact, path-safe source closure used by ``source_tree_digest``."""

    base = Path(root).resolve()
    if not base.is_dir():
        raise BuildError(f"源码根目录不存在：{base}")
    excluded = tuple(exclude_relative_prefixes)
    files = [
        path
        for path in base.rglob("*")
        if path.is_file()
        and not any(part.lower() in _EXCLUDED_PARTS for part in path.relative_to(base).parts)
        and (path.suffix.lower() in _SOURCE_SUFFIXES or path.name in _SOURCE_NAMES)
        and not any(
            path.relative_to(base).as_posix().startswith(prefix) for prefix in excluded
        )
    ]
    if not files:
        raise BuildError("源码工作区没有可摘要的源码/构建描述文件")
    result = tuple(sorted(files, key=lambda item: item.relative_to(base).as_posix()))
    for path in result:
        if path.is_symlink() or not path.resolve().is_relative_to(base):
            raise BuildError(f"源码闭包包含符号链接或路径逃逸：{path}")
    return result


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _template_fragments(token: str) -> tuple[str, ...]:
    fragments = []
    start = 0
    while (left := token.find("{", start)) >= 0:
        right = token.find("}", left + 1)
        if right < 0:
            raise ValueError(f"build target 模板括号未闭合：{token}")
        fragments.append(token[left : right + 1])
        start = right + 1
    if "}" in token[start:]:
        raise ValueError(f"build target 模板括号不匹配：{token}")
    return tuple(fragments)


__all__ = [
    "BuildRunner",
    "BuildTarget",
    "JsonBuildTargetCatalog",
    "GuardedCompilerBackend",
    "HeavyResourceGuard",
    "MappedSourceResolver",
    "SourceResolver",
    "source_tree_digest",
    "source_tree_files",
]
