"""Immutable source snapshots for each compile attempt."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from os import open as open_descriptor
from pathlib import Path
from uuid import uuid4

from packages.sample_factory.cas import ContentAddressedStore, ObjectNamespace
from packages.sample_factory.compiler import source_tree_digest, source_tree_files
from packages.sample_factory.errors import BuildError
from packages.sample_factory.run_models import utc_now


@dataclass(frozen=True)
class SourceSnapshot:
    source_digest: str
    snapshot_root: Path
    manifest_path: Path
    compile_attempt: int
    final_build_input: bool


class SourceSnapshotRepository:
    def __init__(
        self,
        *,
        max_file_bytes: int = 16 * 1024 * 1024,
        max_total_bytes: int = 64 * 1024 * 1024,
        cas: ContentAddressedStore | None = None,
    ) -> None:
        if max_file_bytes < 1 or max_total_bytes < max_file_bytes:
            raise ValueError("源码快照大小限制非法")
        self._max_file_bytes = max_file_bytes
        self._max_total_bytes = max_total_bytes
        self._cas = cas

    def capture(
        self,
        source_root: str | Path,
        snapshot_parent: str | Path,
        *,
        expected_digest: str,
        compile_attempt: int,
        final_build_input: bool = False,
    ) -> SourceSnapshot:
        if compile_attempt < 1:
            raise ValueError("compile_attempt 必须至少为 1")
        source = Path(source_root).resolve()
        parent = Path(snapshot_parent).resolve()
        parent.mkdir(parents=True, exist_ok=True)
        name = (
            "final-build-input"
            if final_build_input
            else f"generated-attempt-{compile_attempt:02d}"
        )
        target = (parent / name).resolve()
        if not target.is_relative_to(parent):
            raise BuildError("源码快照目标路径越界")
        manifest = parent / f"{name}.manifest.json"

        actual_digest = source_tree_digest(source)
        if actual_digest != expected_digest:
            raise BuildError(
                "源码快照前 source_digest 已变化："
                f"expected={expected_digest}, actual={actual_digest}"
            )
        if target.exists():
            if source_tree_digest(target) != expected_digest:
                raise BuildError(f"已有源码快照与 source_digest 冲突：{target}")
            if not manifest.is_file():
                raise BuildError(f"已有源码快照缺少提交 manifest：{target}")
            return SourceSnapshot(
                source_digest=expected_digest,
                snapshot_root=target,
                manifest_path=manifest,
                compile_attempt=compile_attempt,
                final_build_input=final_build_input,
            )

        staging = parent / f".t{uuid4().hex[:12]}.part"
        files: list[dict[str, object]] = []
        total_bytes = 0
        try:
            os.mkdir(_extended_path(staging), 0o700)
            for path in source_tree_files(source):
                relative = path.relative_to(source)
                size = path.stat().st_size
                total_bytes += size
                if size > self._max_file_bytes or total_bytes > self._max_total_bytes:
                    raise BuildError("源码快照超过 operator 配置的大小限制")
                destination = (staging / relative).resolve()
                if not destination.is_relative_to(staging):
                    raise BuildError(f"源码快照相对路径越界：{relative.as_posix()}")
                os.makedirs(_extended_path(destination.parent), exist_ok=True)
                _copy_file(path, destination)
                files.append(
                    {
                        "path": relative.as_posix(),
                        "sha256": _sha256_file(destination),
                        "size": size,
                        "object_ref": (
                            None
                            if self._cas is None
                            else self._cas.put_file(
                                ObjectNamespace.SOURCES, destination
                            ).object_ref
                        ),
                    }
                )
            copied_digest = source_tree_digest(staging)
            if copied_digest != expected_digest:
                raise BuildError(
                    "源码快照复制后摘要不一致："
                    f"expected={expected_digest}, actual={copied_digest}"
                )
            os.replace(_extended_path(staging), _extended_path(target))
            _atomic_write_manifest(
                manifest,
                {
                    "schema_version": "sample-factory-source-snapshot-v1",
                    "captured_at": utc_now().isoformat(),
                    "compile_attempt": compile_attempt,
                    "final_build_input": final_build_input,
                    "source_digest": expected_digest,
                    "file_count": len(files),
                    "total_bytes": total_bytes,
                    "files": files,
                },
            )
        except OSError as exc:
            _remove_tree(staging)
            raise BuildError(f"源码快照复制失败：{exc}") from exc
        except Exception:
            _remove_tree(staging)
            raise
        return SourceSnapshot(
            source_digest=expected_digest,
            snapshot_root=target,
            manifest_path=manifest,
            compile_attempt=compile_attempt,
            final_build_input=final_build_input,
        )


class SourceReplayService:
    def __init__(self, cas: ContentAddressedStore) -> None:
        self._cas = cas

    def restore(self, manifest_path: str | Path, destination: str | Path) -> str:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        if manifest.get("schema_version") != "sample-factory-source-snapshot-v1":
            raise BuildError("source replay manifest schema 非法")
        expected_digest = manifest.get("source_digest")
        files = manifest.get("files")
        if not isinstance(expected_digest, str) or not isinstance(files, list):
            raise BuildError("source replay manifest 缺少 digest/files")
        target = Path(destination).resolve()
        if target.exists() and any(target.iterdir()):
            raise BuildError("source replay 目标目录必须为空")
        target.mkdir(parents=True, exist_ok=True)
        for item in files:
            if not isinstance(item, dict):
                raise BuildError("source replay file entry 非法")
            relative_value = item.get("path")
            object_ref = item.get("object_ref")
            expected_file_sha = item.get("sha256")
            if (
                not isinstance(relative_value, str)
                or not isinstance(object_ref, str)
                or not isinstance(expected_file_sha, str)
            ):
                raise BuildError("source replay 需要完整 object_ref")
            relative = Path(relative_value)
            destination_path = (target / relative).resolve()
            if relative.is_absolute() or not destination_path.is_relative_to(target):
                raise BuildError("source replay 路径越界")
            source = self._cas.resolve(object_ref)
            if _sha256_file(source) != expected_file_sha:
                raise BuildError("source replay 对象摘要与 manifest 不一致")
            os.makedirs(_extended_path(destination_path.parent), exist_ok=True)
            _copy_file(source, destination_path)
        actual_digest = source_tree_digest(target)
        if actual_digest != expected_digest:
            raise BuildError("source replay tree digest 不一致")
        return actual_digest


def _extended_path(path: Path) -> str:
    """Return a filesystem path that bypasses Win32 MAX_PATH when needed."""
    resolved = os.path.abspath(os.fspath(path))
    if os.name != "nt" or resolved.startswith("\\\\?\\"):
        return resolved
    if resolved.startswith("\\\\"):
        return "\\\\?\\UNC\\" + resolved.lstrip("\\")
    return "\\\\?\\" + resolved


def _copy_file(source: Path, destination: Path) -> None:
    shutil.copyfile(_extended_path(source), _extended_path(destination))


def _remove_tree(path: Path) -> None:
    if os.path.isdir(_extended_path(path)):
        shutil.rmtree(_extended_path(path))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(_extended_path(path), "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_manifest(path: Path, payload: object) -> None:
    staging = path.with_name(f".{path.name}.{uuid4().hex}.part")
    encoded = (
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    descriptor = open_descriptor(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        pending = memoryview(encoded)
        while pending:
            written = os.write(descriptor, pending)
            if written <= 0:  # pragma: no cover - OS failure
                raise OSError("source manifest write returned zero bytes")
            pending = pending[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(staging, path)


__all__ = ["SourceReplayService", "SourceSnapshot", "SourceSnapshotRepository"]
