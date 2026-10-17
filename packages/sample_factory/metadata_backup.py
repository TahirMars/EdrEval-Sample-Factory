"""Metadata-only factory backup with path and checksum verification."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path, PurePosixPath

_TEXT_SUFFIXES = frozenset(
    {".json", ".jsonl", ".md", ".toml", ".txt", ".cpp", ".c", ".h", ".hpp", ".rc", ".def", ".vcxproj"}
)
_EXCLUDED_RUNTIME = frozenset({"store", "exports", "temp"})


class MetadataBackupService:
    def __init__(self, factory_root: str | Path) -> None:
        self._root = Path(factory_root).resolve()

    def create(self, destination: str | Path, *, approved: bool) -> dict[str, object]:
        if not approved:
            raise PermissionError("工厂元数据备份需要人工审批")
        target = Path(destination).resolve()
        if target.exists():
            raise FileExistsError(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        files = self._files()
        entries = []
        with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for source, relative in files:
                data = source.read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                archive.writestr(relative, data)
                entries.append({"path": relative, "sha256": digest, "size": len(data)})
            manifest = {
                "schema_version": "sample-factory-metadata-backup-v1",
                "entries": entries,
                "excluded": ["runtime/store", "runtime/exports", "runtime/temp", "secrets"],
            }
            archive.writestr(
                "backup-manifest.json",
                json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            )
        return {"backup_path": target.as_posix(), "file_count": len(entries)}

    @staticmethod
    def restore(
        backup: str | Path, destination: str | Path, *, approved: bool
    ) -> dict[str, object]:
        if not approved:
            raise PermissionError("工厂元数据恢复需要人工审批")
        source = Path(backup).resolve()
        target = Path(destination).resolve()
        control_repo = Path(__file__).resolve().parents[2]
        if target == control_repo or target.is_relative_to(control_repo):
            raise ValueError("元数据恢复目标不得位于 EdrEvalAgent 代码仓")
        if not source.is_file():
            raise FileNotFoundError(source)
        if target.exists() and any(target.iterdir()):
            raise ValueError("元数据恢复目标必须为空")
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(source, "r") as archive:
            manifest = json.loads(archive.read("backup-manifest.json").decode("utf-8"))
            if manifest.get("schema_version") != "sample-factory-metadata-backup-v1":
                raise ValueError("元数据备份 schema 非法")
            entries = manifest.get("entries")
            if not isinstance(entries, list):
                raise ValueError("元数据备份 entries 非法")
            restored = 0
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError("元数据备份 entry 非法")
                relative_value = entry.get("path")
                expected = entry.get("sha256")
                if not isinstance(relative_value, str) or not isinstance(expected, str):
                    raise ValueError("元数据备份 entry 字段非法")
                relative = PurePosixPath(relative_value)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("元数据备份包含路径穿越")
                if relative.parts[0] not in {"catalog", "manifests", "runtime", "layout.json", ".gitignore", "README.md"}:
                    raise ValueError("元数据备份包含未知顶层路径")
                data = archive.read(relative_value)
                if hashlib.sha256(data).hexdigest() != expected:
                    raise ValueError("元数据备份文件 SHA-256 不一致")
                output = (target / Path(*relative.parts)).resolve()
                if not output.is_relative_to(target):
                    raise ValueError("元数据恢复路径越界")
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(data)
                restored += 1
        return {"destination": target.as_posix(), "restored_file_count": restored}

    def _files(self) -> tuple[tuple[Path, str], ...]:
        result = []
        for name in (".gitignore", "README.md", "layout.json"):
            path = self._root / name
            if path.is_file():
                result.append((path, name))
        for top in ("catalog", "manifests", "runtime"):
            root = self._root / top
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file() or path.is_symlink():
                    continue
                relative = path.relative_to(self._root)
                if top == "runtime" and len(relative.parts) > 1 and relative.parts[1] in _EXCLUDED_RUNTIME:
                    continue
                if path.suffix.lower() not in _TEXT_SUFFIXES and path.suffix.lower() != ".sqlite":
                    continue
                if _looks_sensitive(relative.as_posix()):
                    raise ValueError(f"元数据备份发现敏感路径：{relative.as_posix()}")
                result.append((path, relative.as_posix()))
        result.sort(key=lambda item: item[1])
        return tuple(result)


def _looks_sensitive(path: str) -> bool:
    return bool(re.search(r"(?i)(^|/)(secrets?|credentials?|private[-_]?keys?)(/|$)", path))


__all__ = ["MetadataBackupService"]
