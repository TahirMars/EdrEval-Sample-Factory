"""Guarded compiler backend for one plugin candidate."""

from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from packages.labmgr.host_guard import HostResourceGuard
from packages.labmgr.process import SubprocessRunner
from packages.labmgr.resource import MemoryCappedRunner
from packages.sample_factory.build_settings import (
    effective_toolchain_fp,
    validate_msvc_static_library,
    validate_msvc_static_runtime,
)
from packages.sample_factory.compiler import (
    BuildRunner,
    BuildTarget,
    HeavyResourceGuard,
    source_tree_digest,
)
from packages.sample_factory.errors import BuildError, CompilationFailure, PlanningError
from packages.sample_factory.handoff import HandoffError, apply_embed_materialize
from packages.sample_factory.models import GlueMaterializeItem, HandoffMaterialize
from packages.sample_factory.plugin_contract import (
    materialize_validation_harness,
    validate_candidate_source_snapshot,
)
from packages.sample_factory.plugin_models import (
    PluginBuildResult,
    PluginRequest,
    PluginSourceCandidate,
)


class PluginCandidateSourceResolver(Protocol):
    def resolve(self, source_ref: str) -> Path: ...


class GuardedPluginCompilerBackend:
    def __init__(
        self,
        *,
        targets: Mapping[str, BuildTarget],
        sources: PluginCandidateSourceResolver,
        runtime_root: str | Path,
        runner: BuildRunner | None = None,
        guard: HeavyResourceGuard | None = None,
        memory_limit_mb: int = 8192,
        payload_root: str | Path | Sequence[str | Path] | None = None,
    ) -> None:
        self._targets = dict(targets)
        self._sources = sources
        self._runtime_root = Path(runtime_root).resolve()
        if payload_root is None:
            self._payload_root: tuple[Path, ...] | None = None
        elif isinstance(payload_root, (str, Path)):
            self._payload_root = (Path(payload_root).resolve(),)
        else:
            self._payload_root = tuple(Path(item).resolve() for item in payload_root)
        self._runner = (
            runner
            if runner is not None
            else (SubprocessRunner() if os.name == "nt" else MemoryCappedRunner(limit_mb=memory_limit_mb))
        )
        self._guard = guard or HostResourceGuard()

    def compile(
        self,
        source: PluginSourceCandidate,
        request: PluginRequest,
        *,
        plugin_run_id: str,
    ) -> PluginBuildResult:
        try:
            target = self._targets[request.build_target_ref]
        except KeyError as exc:
            raise BuildError(f"未登记 plugin build target：{request.build_target_ref}") from exc
        artifact_relative = target.artifact_relative.replace(
            "{implementation_name}", request.implementation_name
        )
        if Path(artifact_relative).suffix.lower() != ".lib":
            raise BuildError("单插件编译目标必须声明 .lib 静态库产物")
        source_root = self._sources.resolve(source.source_ref).resolve()
        if source_tree_digest(source_root) != source.source_digest:
            raise BuildError("插件编译前 source_digest 不一致")
        if source.implementation_name != request.implementation_name:
            raise BuildError("插件候选 implementation_name 与请求不一致")
        snapshot = {
            path.relative_to(source_root).as_posix(): path.read_text(encoding="utf-8")
            for path in source_root.rglob("*")
            if path.is_file() and path.suffix.lower() != ".lib"
        }
        try:
            validate_candidate_source_snapshot(snapshot, request.implementation_name)
        except (PlanningError, ValueError) as exc:
            raise BuildError(str(exc)) from exc
        implementation_root = source_root / "src"
        implementation_source_digest = source_tree_digest(implementation_root)
        validate_msvc_static_runtime(source_root, request.build_target_ref)
        validate_msvc_static_library(source_root, request.build_target_ref)
        plugin_root = source_root.parent.parent
        if plugin_root.name != plugin_run_id or not plugin_root.is_relative_to(self._runtime_root):
            raise BuildError("插件源码不属于当前 plugin_run_id")
        self._materialize_embedded_payload(source_root, source, request)
        materialize_validation_harness(plugin_root, request.implementation_name)
        build_id = uuid4().hex
        output = plugin_root / "build" / build_id
        output.mkdir(parents=True, mode=0o700)
        argv = [
            token.replace("{source_root}", str(source_root))
            .replace("{output_dir}", str(output))
            .replace("{implementation_name}", request.implementation_name)
            for token in target.argv_template
        ]
        operation = f"sample-factory-plugin-build:{build_id[:12]}"
        self._guard.acquire_heavy(operation)
        try:
            rc, diagnostics = self._runner.run(argv, timeout=target.timeout_s)
        finally:
            self._guard.release_heavy(operation)
        (output / "diagnostics.txt").write_text(
            diagnostics[-65536:], encoding="utf-8"
        )
        if rc != 0:
            diagnostics_ref = f"plugin-build://{plugin_run_id}/{build_id}"
            raise CompilationFailure(
                f"插件受控编译失败（rc={rc}, diagnostics={diagnostics_ref}）",
                diagnostics_ref=diagnostics_ref,
            )
        artifact = (output / artifact_relative).resolve()
        if not artifact.is_relative_to(output) or not artifact.is_file():
            raise BuildError("插件编译成功但登记产物缺失")
        if artifact.suffix.lower() != ".lib":
            raise BuildError("单插件编译目标必须产出 .lib 静态库")
        canonical_name = f"{request.implementation_name}.lib"
        if artifact.name != canonical_name:
            canonical_artifact = (output / canonical_name).resolve()
            if not canonical_artifact.is_relative_to(output):  # pragma: no cover
                raise BuildError("规范化插件制品路径越界")
            shutil.move(artifact, canonical_artifact)
            artifact = canonical_artifact
        digest = _sha256_file(artifact)
        return PluginBuildResult(
            build_ref=f"plugin-build://{plugin_run_id}/{build_id}",
            artifact_ref=f"plugin-build-artifact://{plugin_run_id}/{build_id}",
            artifact_sha256=digest,
            source_digest=source.source_digest,
            implementation_source_digest=implementation_source_digest,
            artifact_filename=canonical_name,
            toolchain_fp=effective_toolchain_fp(
                target.toolchain_fp, request.build_target_ref
            ),
            build_id=build_id,
        )

    def resolve_artifact(self, artifact_ref: str) -> Path:
        prefix = "plugin-build-artifact://"
        if not artifact_ref.startswith(prefix):
            raise BuildError("plugin artifact ref 非法")
        parts = artifact_ref.removeprefix(prefix).split("/")
        if len(parts) != 2 or not parts[0].startswith("plugin-run-"):
            raise BuildError("plugin artifact ref 非法")
        matches = tuple(
            self._runtime_root.glob(
                f"plugin-runs/*/*/*/{parts[0]}/build/{parts[1]}/*"
            )
        )
        artifacts = [
            path
            for path in matches
            if path.is_file() and path.suffix.lower() == ".lib"
        ]
        if len(artifacts) != 1:
            raise BuildError("无法解析唯一 plugin build artifact")
        return artifacts[0].resolve()

    def _materialize_embedded_payload(
        self,
        source_root: Path,
        source: PluginSourceCandidate,
        request: PluginRequest,
    ) -> None:
        artifact_ref = request.intent.artifact_ref
        handoffs = request.intent.produces_handoffs
        if artifact_ref is None or not handoffs:
            return
        if self._payload_root is None:
            raise BuildError("embed_at_build 插件编译缺少 payload_root")
        try:
            apply_embed_materialize(
                source_root,
                tuple(
                    GlueMaterializeItem(
                        atom_id=source.plugin_id,
                        handoff_id=handoff_id,
                        artifact_ref=artifact_ref,
                        strategy=HandoffMaterialize.EMBED_AT_BUILD,
                    )
                    for handoff_id in handoffs
                ),
                payload_root=self._payload_root,
            )
        except HandoffError as exc:
            raise BuildError(str(exc)) from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = ["GuardedPluginCompilerBackend", "PluginCandidateSourceResolver"]
