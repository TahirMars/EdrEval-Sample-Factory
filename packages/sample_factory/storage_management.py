"""Reference-aware CAS reporting and approval-gated garbage collection."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from packages.sample_factory.cas import ContentAddressedStore, ObjectNamespace

_OBJECT_REF_RE = re.compile(
    r"object://(artifacts|sources|inputs|intermediates|tools)/sha256/([0-9a-f]{64})"
)


class StorageManager:
    def __init__(
        self,
        *,
        factory_root: str | Path,
        runtime_root: str | Path,
        catalog_root: str | Path,
        manifest_root: str | Path,
    ) -> None:
        self._factory_root = Path(factory_root).resolve()
        self._runtime_root = Path(runtime_root).resolve()
        self._catalog_root = Path(catalog_root).resolve()
        self._manifest_root = Path(manifest_root).resolve()
        for name, path in {
            "runtime_root": self._runtime_root,
            "catalog_root": self._catalog_root,
            "manifest_root": self._manifest_root,
        }.items():
            if not path.is_relative_to(self._factory_root):
                raise ValueError(f"{name} 不在 factory_root 下")
        self._cas = ContentAddressedStore(self._runtime_root)

    def gc_plan(self, *, grace_days: int = 30) -> dict[str, object]:
        if grace_days < 1:
            raise ValueError("GC grace_days 必须至少为 1")
        refs = self._collect_refs()
        cutoff = datetime.now(UTC) - timedelta(days=grace_days)
        candidates: list[dict[str, object]] = []
        retained = 0
        for namespace in ObjectNamespace:
            root = self._runtime_root / "store" / namespace.value / "sha256"
            for path in root.glob("*/*"):
                if not path.is_file() or not re.fullmatch(r"[0-9a-f]{64}", path.name):
                    continue
                object_ref = f"object://{namespace.value}/sha256/{path.name}"
                modified = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
                if object_ref in refs or modified > cutoff:
                    retained += 1
                    continue
                candidates.append(
                    {
                        "object_ref": object_ref,
                        "path": path.as_posix(),
                        "bytes": path.stat().st_size,
                        "modified_at": modified.isoformat(),
                    }
                )
        candidates.sort(key=lambda item: str(item["object_ref"]))
        return {
            "schema_version": "sample-factory-gc-plan-v1",
            "grace_days": grace_days,
            "referenced_count": len(refs),
            "retained_object_count": retained,
            "candidate_count": len(candidates),
            "candidate_bytes": sum(
                value for item in candidates if isinstance((value := item["bytes"]), int)
            ),
            "candidates": candidates,
        }

    def collect(self, *, grace_days: int = 30, approved: bool) -> dict[str, object]:
        if not approved:
            raise PermissionError("CAS GC 删除需要显式人工审批")
        first = self.gc_plan(grace_days=grace_days)
        deleted = []
        candidates = first["candidates"]
        if not isinstance(candidates, list):  # pragma: no cover - internal schema
            raise AssertionError("GC plan candidates shape")
        for candidate in candidates:
            if not isinstance(candidate, dict):  # pragma: no cover
                continue
            object_ref = candidate.get("object_ref")
            path_value = candidate.get("path")
            if not isinstance(object_ref, str) or not isinstance(path_value, str):
                continue
            if object_ref in self._collect_refs():
                continue
            path = Path(path_value).resolve()
            store_root = (self._runtime_root / "store").resolve()
            if not path.is_relative_to(store_root) or not path.is_file():
                continue
            verified = self._cas.verify(object_ref)
            if verified.path != path:
                raise ValueError("GC plan 路径与 CAS 引用不一致")
            path.unlink()
            deleted.append(object_ref)
        return {"deleted_count": len(deleted), "deleted_refs": deleted}

    def _collect_refs(self) -> set[str]:
        roots = (
            self._runtime_root / "runs",
            self._runtime_root / "plugin-runs",
            self._runtime_root / "learning",
            self._runtime_root / "exports",
            self._catalog_root,
            self._manifest_root,
        )
        refs: set[str] = set()
        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file() or path.suffix.lower() not in {".json", ".jsonl"}:
                    continue
                text = path.read_text(encoding="utf-8")
                refs.update(match.group(0) for match in _OBJECT_REF_RE.finditer(text))
        return refs


__all__ = ["StorageManager"]
