"""黄金回归集 append-only JSONL manifest。"""

from __future__ import annotations

import json
import os
from os import open as open_descriptor
from pathlib import Path

from packages.sample_factory.errors import ManifestError
from packages.sample_factory.file_lock import exclusive_file_lock
from packages.sample_factory.identity import canonical_json
from packages.sample_factory.models import RegressionManifestEntry


class ManifestRepository:
    """跨进程文件锁 + 单次 O_APPEND 写；重复同内容幂等，冲突拒绝。"""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    def append(self, entry: RegressionManifestEntry) -> str:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self._path.with_suffix(self._path.suffix + ".lock")
        encoded = canonical_json(entry.model_dump(mode="json"))
        with exclusive_file_lock(lock_path):
            existing = {item.sample_id: item for item in self.entries()}
            prior = existing.get(entry.sample_id)
            if prior is not None:
                if prior != entry:
                    raise ManifestError(f"sample_id 已存在但内容冲突：{entry.sample_id}")
                return self._ref(entry.sample_id)
            descriptor = open_descriptor(
                self._path,
                os.O_APPEND | os.O_CREAT | os.O_WRONLY,
                0o600,
            )
            try:
                pending = memoryview((encoded + "\n").encode("utf-8"))
                while pending:
                    written = os.write(descriptor, pending)
                    if written <= 0:  # pragma: no cover - OS write failure path
                        raise OSError("manifest append returned zero bytes")
                    pending = pending[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return self._ref(entry.sample_id)

    def entries(self) -> tuple[RegressionManifestEntry, ...]:
        if not self._path.exists():
            return ()
        result: list[RegressionManifestEntry] = []
        for line_number, line in enumerate(
            self._path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                result.append(RegressionManifestEntry.model_validate(value))
            except Exception as exc:
                raise ManifestError(f"manifest 第 {line_number} 行损坏：{exc}") from exc
        return tuple(result)

    def _ref(self, sample_id: str) -> str:
        return f"{self._path.as_posix()}#{sample_id}"


__all__ = ["ManifestRepository"]
