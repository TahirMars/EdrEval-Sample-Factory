"""Content-addressed storage for external factory runtime objects."""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

from packages.sample_factory.errors import BuildError


class ObjectNamespace(StrEnum):
    ARTIFACTS = "artifacts"
    SOURCES = "sources"
    INPUTS = "inputs"
    INTERMEDIATES = "intermediates"
    TOOLS = "tools"


@dataclass(frozen=True)
class StoredObject:
    namespace: ObjectNamespace
    sha256: str
    size: int
    object_ref: str
    path: Path


class ContentAddressedStore:
    def __init__(self, runtime_root: str | Path) -> None:
        self._runtime_root = Path(runtime_root).resolve()
        self._store_root = self._runtime_root / "store"
        control_repo = Path(__file__).resolve().parents[2]
        if self._runtime_root.is_relative_to(control_repo):
            raise ValueError("CAS runtime_root 不得位于 EdrEvalAgent 代码仓")

    def put_file(
        self,
        namespace: ObjectNamespace,
        source: str | Path,
        *,
        expected_sha256: str | None = None,
    ) -> StoredObject:
        source_path = Path(source).resolve()
        if not source_path.is_file() or source_path.is_symlink():
            raise BuildError(f"CAS 输入不是普通文件：{source_path}")
        digest = _sha256_file(source_path)
        if expected_sha256 is not None and digest != expected_sha256:
            raise BuildError("CAS 输入 SHA-256 与预期不一致")
        target = self._path(namespace, digest)
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if target.exists():
            if not target.is_file() or target.is_symlink() or _sha256_file(target) != digest:
                raise BuildError("CAS 已有同名但内容或类型不一致的对象")
        else:
            staging = target.parent / f".{digest}.{uuid4().hex}.part"
            shutil.copyfile(source_path, staging)
            os.chmod(staging, 0o600)
            if _sha256_file(staging) != digest:
                staging.unlink(missing_ok=True)
                raise BuildError("CAS 复制后 SHA-256 改变")
            os.replace(staging, target)
        return StoredObject(
            namespace=namespace,
            sha256=digest,
            size=target.stat().st_size,
            object_ref=f"object://{namespace.value}/sha256/{digest}",
            path=target,
        )

    def resolve(self, object_ref: str) -> Path:
        prefix = "object://"
        if not object_ref.startswith(prefix):
            raise BuildError(f"CAS 对象引用非法：{object_ref}")
        parts = object_ref.removeprefix(prefix).split("/")
        if len(parts) != 3 or parts[1] != "sha256":
            raise BuildError(f"CAS 对象引用非法：{object_ref}")
        try:
            namespace = ObjectNamespace(parts[0])
        except ValueError as exc:
            raise BuildError(f"CAS namespace 非法：{parts[0]}") from exc
        digest = parts[2]
        path = self._path(namespace, digest)
        if not path.is_file() or path.is_symlink() or _sha256_file(path) != digest:
            raise BuildError(f"CAS 对象不存在或完整性失败：{object_ref}")
        return path

    def verify(self, object_ref: str) -> StoredObject:
        path = self.resolve(object_ref)
        parts = object_ref.removeprefix("object://").split("/")
        namespace = ObjectNamespace(parts[0])
        return StoredObject(namespace, parts[2], path.stat().st_size, object_ref, path)

    def storage_report(self) -> dict[str, object]:
        namespaces: dict[str, dict[str, int]] = {}
        total_count = 0
        total_bytes = 0
        for namespace in ObjectNamespace:
            root = self._store_root / namespace.value / "sha256"
            objects = [
                path
                for path in root.glob("*/*")
                if path.is_file()
                and len(path.name) == 64
                and path.parent.name == path.name[:2]
            ]
            size = sum(path.stat().st_size for path in objects)
            namespaces[namespace.value] = {"object_count": len(objects), "bytes": size}
            total_count += len(objects)
            total_bytes += size
        return {
            "object_count": total_count,
            "bytes": total_bytes,
            "namespaces": namespaces,
        }

    def _path(self, namespace: ObjectNamespace, digest: str) -> Path:
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise BuildError("CAS SHA-256 非法")
        path = (
            self._store_root
            / namespace.value
            / "sha256"
            / digest[:2]
            / digest
        ).resolve()
        if not path.is_relative_to(self._store_root):  # pragma: no cover - digest validation
            raise BuildError("CAS 路径越界")
        return path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = ["ContentAddressedStore", "ObjectNamespace", "StoredObject"]
