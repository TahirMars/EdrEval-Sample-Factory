"""Atomic run packages for one-plugin authoring and validation."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from packages.sample_factory.agent_events import safe_activity_text
from packages.sample_factory.file_lock import exclusive_file_lock
from packages.sample_factory.plugin_models import PluginAuthoringResult, PluginRequest

_PLUGIN_RUN_RE = re.compile(r"plugin-run-[a-z0-9-]{8,79}")
_SENSITIVE_RE = re.compile(
    r"(?i)^(password|passwd|authorization|cookie|api[_-]?key|access[_-]?token|secret)$"
)


class PluginRunRepository:
    def __init__(self, runtime_root: str | Path) -> None:
        self._runtime_root = Path(runtime_root).resolve()
        self._root = self._runtime_root / "plugin-runs"

    def create(self, plugin_run_id: str, request: PluginRequest) -> Path:
        if not _PLUGIN_RUN_RE.fullmatch(plugin_run_id):
            raise ValueError("plugin_run_id 非法")
        now = datetime.now(UTC)
        target = (
            self._root
            / f"{now.year:04d}"
            / f"{now.month:02d}"
            / f"{now.day:02d}"
            / plugin_run_id
        ).resolve()
        if not target.is_relative_to(self._root.resolve()):
            raise ValueError("plugin run 路径越界")
        if target.exists():
            raise FileExistsError(plugin_run_id)
        target.mkdir(parents=True, mode=0o700)
        for name in ("authoring", "build", "harness", "verification", "result"):
            (target / name).mkdir()
        _atomic_json(target / "request.json", request.model_dump(mode="json"))
        _atomic_json(
            target / "state.json",
            {
                "schema_version": "sample-factory-plugin-run-state-v1",
                "plugin_run_id": plugin_run_id,
                "status": "RUNNING",
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
            },
        )
        (target / "events.jsonl").touch(mode=0o600)
        return target

    def append_event(
        self, root: Path, event: tuple[str, dict[str, object]]
    ) -> None:
        kind, data = event
        payload = {
            "recorded_at": datetime.now(UTC).isoformat(),
            "event": kind,
            "data": _sanitize(data),
        }
        encoded = (
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("utf-8")
        with exclusive_file_lock(root / ".events.lock"), (root / "events.jsonl").open(
            "ab"
        ) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())

    def complete(self, root: Path, result: PluginAuthoringResult) -> None:
        _atomic_json(root / "result" / "result.json", result.model_dump(mode="json"))
        now = datetime.now(UTC).isoformat()
        current = json.loads((root / "state.json").read_text(encoding="utf-8"))
        _atomic_json(
            root / "state.json",
            {
                "schema_version": "sample-factory-plugin-run-state-v1",
                "plugin_run_id": result.plugin_run_id,
                "status": "SUCCEEDED",
                "lifecycle_status": result.status.value,
                "created_at": current["created_at"],
                "updated_at": now,
            },
        )

    def fail(self, root: Path, exc: BaseException) -> None:
        now = datetime.now(UTC).isoformat()
        current = json.loads((root / "state.json").read_text(encoding="utf-8"))
        _atomic_json(
            root / "state.json",
            {
                "schema_version": "sample-factory-plugin-run-state-v1",
                "plugin_run_id": root.name,
                "status": "FAILED",
                "created_at": current["created_at"],
                "error_type": type(exc).__name__,
                "error": safe_activity_text(str(exc), max_chars=2000),
                "updated_at": now,
            },
        )

    def find(self, plugin_run_id: str) -> Path:
        if not _PLUGIN_RUN_RE.fullmatch(plugin_run_id):
            raise ValueError("plugin_run_id 非法")
        matches = tuple(self._root.glob(f"*/*/*/{plugin_run_id}"))
        if len(matches) != 1:
            raise FileNotFoundError(f"不存在唯一 plugin run：{plugin_run_id}")
        return matches[0].resolve()

    def list_runs(self) -> tuple[dict[str, object], ...]:
        result = []
        for path in sorted(self._root.glob("*/*/*/plugin-run-*"), reverse=True):
            state = json.loads((path / "state.json").read_text(encoding="utf-8"))
            request = json.loads((path / "request.json").read_text(encoding="utf-8"))
            result.append(
                {
                    "plugin_run_id": path.name,
                    "request_id": request.get("request_id"),
                    "operation": request.get("operation"),
                    "status": state.get("status"),
                    "lifecycle_status": state.get("lifecycle_status"),
                    "updated_at": state.get("updated_at"),
                    "run_path": path.as_posix(),
                }
            )
        return tuple(result)

    def payload(self, plugin_run_id: str) -> dict[str, object]:
        root = self.find(plugin_run_id)
        result_path = root / "result" / "result.json"
        return {
            "request": json.loads((root / "request.json").read_text(encoding="utf-8")),
            "state": json.loads((root / "state.json").read_text(encoding="utf-8")),
            "result": (
                None
                if not result_path.is_file()
                else json.loads(result_path.read_text(encoding="utf-8"))
            ),
            "run_path": root.as_posix(),
        }


def _atomic_json(path: Path, value: object) -> None:
    staging = path.with_name(f".{path.name}.{uuid4().hex}.part")
    staging.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(staging, path)


def _sanitize(value: object, *, key: str | None = None) -> object:
    if key is not None and _SENSITIVE_RE.fullmatch(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {
            str(item_key): _sanitize(item, key=str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if isinstance(value, str):
        return safe_activity_text(value, max_chars=4000)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return safe_activity_text(value, max_chars=4000)


__all__ = ["PluginRunRepository"]
