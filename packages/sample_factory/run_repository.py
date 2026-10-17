"""Atomic filesystem repository for immutable factory run facts."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from os import open as open_descriptor
from pathlib import Path
from typing import Any
from uuid import uuid4

from packages.sample_factory.agent_events import safe_activity_text
from packages.sample_factory.file_lock import exclusive_file_lock
from packages.sample_factory.paths import RunLayout
from packages.sample_factory.run_models import (
    AttemptRecord,
    AttemptStatus,
    RunEnvelope,
    RunState,
    RunStatus,
    utc_now,
)

Event = tuple[str, dict[str, object]]
EventSink = Callable[[Event], None]
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)^(password|passwd|authorization|cookie|api[_-]?key|access[_-]?token)$"
)
_REFERENCE_PREFIXES = ("secret://", "lab-secret://")
_RUN_ID_RE = re.compile(r"run-[a-z0-9-]{8,79}")
_ATTEMPT_ID_RE = re.compile(r"attempt-[a-z0-9-]{8,79}")


@dataclass(frozen=True)
class RunHandle:
    envelope: RunEnvelope
    root: Path


@dataclass(frozen=True)
class AttemptHandle:
    record: AttemptRecord
    root: Path


class RunRepository:
    """Persist one run as append-only events plus atomically replaced state."""

    def __init__(self, runtime_root: str | Path) -> None:
        self.layout = RunLayout(runtime_root)

    def create(self, envelope: RunEnvelope) -> RunHandle:
        target = self.layout.run_root(envelope)
        target.parent.mkdir(parents=True, exist_ok=True)
        self.layout.temp_root.mkdir(parents=True, exist_ok=True)
        staging = self.layout.temp_root / f"run-create-{uuid4().hex}.part"
        if target.exists():
            raise FileExistsError(f"run_id 已存在：{envelope.run_id}")
        try:
            staging.mkdir(mode=0o700)
            _atomic_write_json(staging / "run.json", envelope.model_dump(mode="json"))
            now = envelope.created_at
            state = RunState(
                run_id=envelope.run_id,
                status=RunStatus.CREATED,
                created_at=now,
                updated_at=now,
            )
            _atomic_write_json(staging / "state.json", state.model_dump(mode="json"))
            (staging / "events.jsonl").touch(mode=0o600)
            (staging / "attempts").mkdir()
            os.replace(staging, target)
        except Exception:
            _remove_empty_staging(staging)
            raise
        return RunHandle(envelope=envelope, root=target)

    def mark_running(self, handle: RunHandle) -> RunState:
        return self._update_state(handle, status=RunStatus.RUNNING)

    def start_attempt(
        self,
        handle: RunHandle,
        *,
        attempt_id: str,
        attempt_number: int,
        seed: int,
        workspace_ref: str,
    ) -> AttemptHandle:
        now = utc_now()
        record = AttemptRecord(
            run_id=handle.envelope.run_id,
            attempt_id=attempt_id,
            attempt_number=attempt_number,
            seed=seed,
            workspace_ref=workspace_ref,
            status=AttemptStatus.RUNNING,
            started_at=now,
            updated_at=now,
        )
        target = self.layout.attempt_root(handle.root, record)
        if target.exists():
            existing = AttemptRecord.model_validate(_read_json(target / "attempt.json"))
            if existing.attempt_id != record.attempt_id:
                raise ValueError(f"attempt 目录身份冲突：{target}")
            return AttemptHandle(existing, target)

        staging = handle.root / "attempts" / f".{record.attempt_id}.{uuid4().hex}.part"
        staging.mkdir(mode=0o700)
        try:
            for name in (
                "planning",
                "source",
                "workspace",
                "build",
                "verification",
                "logs",
                "result",
            ):
                (staging / name).mkdir()
            _atomic_write_json(staging / "attempt.json", record.model_dump(mode="json"))
            os.replace(staging, target)
        except Exception:
            _remove_empty_staging(staging)
            raise

        with exclusive_file_lock(handle.root / ".state.lock"):
            state = self.read_state(handle)
            updated = state.model_copy(
                update={
                    "status": RunStatus.RUNNING,
                    "updated_at": now,
                    "attempt_count": state.attempt_count + 1,
                }
            )
            _atomic_write_json(handle.root / "state.json", updated.model_dump(mode="json"))
        return AttemptHandle(record, target)

    def complete_attempt(
        self,
        handle: RunHandle,
        attempt: AttemptHandle,
        *,
        status: AttemptStatus,
        result_status: str | None = None,
        error_type: str | None = None,
        error: str | None = None,
    ) -> AttemptRecord:
        current = AttemptRecord.model_validate(_read_json(attempt.root / "attempt.json"))
        if current.status is not AttemptStatus.RUNNING:
            return current
        now = utc_now()
        updated = current.model_copy(
            update={
                "status": status,
                "updated_at": now,
                "result_status": result_status,
                "error_type": error_type,
                "error": None if error is None else safe_activity_text(error, max_chars=2000),
            }
        )
        updated = AttemptRecord.model_validate(updated.model_dump(mode="python"))
        _atomic_write_json(attempt.root / "attempt.json", updated.model_dump(mode="json"))
        with exclusive_file_lock(handle.root / ".state.lock"):
            state = self.read_state(handle)
            state_updated = state.model_copy(
                update={
                    "updated_at": now,
                    "completed_attempt_count": state.completed_attempt_count + 1,
                }
            )
            _atomic_write_json(
                handle.root / "state.json", state_updated.model_dump(mode="json")
            )
        return updated

    def write_attempt_result(
        self, attempt: AttemptHandle, payload: Mapping[str, Any]
    ) -> Path:
        target = attempt.root / "result" / "result.json"
        _atomic_write_json(target, _sanitize(payload))
        return target

    def finish(
        self,
        handle: RunHandle,
        *,
        status: RunStatus,
        result_status: str | None = None,
        error_type: str | None = None,
        error: str | None = None,
    ) -> RunState:
        return self._update_state(
            handle,
            status=status,
            result_status=result_status,
            error_type=error_type,
            error=None if error is None else safe_activity_text(error, max_chars=2000),
        )

    def append_event(
        self,
        handle: RunHandle,
        kind: str,
        data: Mapping[str, object],
        *,
        attempt_id: str | None = None,
    ) -> None:
        payload = {
            "recorded_at": utc_now().isoformat(),
            "run_id": handle.envelope.run_id,
            "attempt_id": attempt_id,
            "event": kind,
            "data": _sanitize(data),
        }
        encoded = (
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("utf-8")
        path = handle.root / "events.jsonl"
        with exclusive_file_lock(handle.root / ".events.lock"):
            descriptor = open_descriptor(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                pending = memoryview(encoded)
                while pending:
                    written = os.write(descriptor, pending)
                    if written <= 0:  # pragma: no cover - OS failure
                        raise OSError("event append returned zero bytes")
                    pending = pending[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def read_state(self, handle: RunHandle) -> RunState:
        return RunState.model_validate(_read_json(handle.root / "state.json"))

    def list_runs(self) -> tuple[tuple[RunEnvelope, RunState, Path], ...]:
        result = []
        for path in self.layout.runs_root.glob("*/*/*/run-*"):
            if not path.is_dir():
                continue
            try:
                envelope = RunEnvelope.model_validate(_read_json(path / "run.json"))
                state = RunState.model_validate(_read_json(path / "state.json"))
            except Exception as exc:
                raise ValueError(f"运行包损坏：{path}: {exc}") from exc
            if envelope.run_id != state.run_id or path.name != envelope.run_id:
                raise ValueError(f"运行包身份不一致：{path}")
            result.append((envelope, state, path.resolve()))
        result.sort(key=lambda item: (item[0].created_at, item[0].run_id), reverse=True)
        return tuple(result)

    def find_run(self, run_id: str) -> RunHandle:
        if not _RUN_ID_RE.fullmatch(run_id):
            raise ValueError("run_id 非法")
        matches = tuple(self.layout.runs_root.glob(f"*/*/*/{run_id}"))
        if len(matches) != 1:
            raise FileNotFoundError(f"不存在唯一运行包：{run_id}")
        envelope = RunEnvelope.model_validate(_read_json(matches[0] / "run.json"))
        if envelope.run_id != run_id:
            raise ValueError(f"运行包身份不一致：{matches[0]}")
        return RunHandle(envelope=envelope, root=matches[0].resolve())

    def run_payload(self, run_id: str) -> dict[str, object]:
        handle = self.find_run(run_id)
        state = self.read_state(handle)
        attempts = []
        for path in sorted((handle.root / "attempts").glob("*-attempt-*")):
            record = AttemptRecord.model_validate(_read_json(path / "attempt.json"))
            attempts.append(record.model_dump(mode="json"))
        return {
            "run": handle.envelope.model_dump(mode="json"),
            "state": state.model_dump(mode="json"),
            "attempts": attempts,
            "run_path": handle.root.as_posix(),
        }

    def reconcile_report(self) -> dict[str, object]:
        issues: list[dict[str, object]] = []
        try:
            runs = self.list_runs()
        except ValueError as exc:
            return {
                "healthy": False,
                "issues": [{"kind": "corrupt_run", "detail": str(exc)}],
            }
        for envelope, state, path in runs:
            if state.status in {RunStatus.CREATED, RunStatus.RUNNING}:
                issues.append(
                    {
                        "kind": "unfinished_run",
                        "run_id": envelope.run_id,
                        "status": state.status.value,
                        "updated_at": state.updated_at.isoformat(),
                        "run_path": path.as_posix(),
                    }
                )
            attempt_paths = tuple((path / "attempts").glob("*-attempt-*"))
            if len(attempt_paths) != state.attempt_count:
                issues.append(
                    {
                        "kind": "attempt_count_mismatch",
                        "run_id": envelope.run_id,
                        "state_count": state.attempt_count,
                        "directory_count": len(attempt_paths),
                    }
                )
        return {"healthy": not issues, "run_count": len(runs), "issues": issues}

    def find_attempt(self, handle: RunHandle, attempt_id: str) -> AttemptHandle:
        if not _ATTEMPT_ID_RE.fullmatch(attempt_id):
            raise ValueError("attempt_id 非法")
        matches = tuple((handle.root / "attempts").glob(f"*-{attempt_id}"))
        if len(matches) != 1:
            raise FileNotFoundError(f"run 中不存在唯一 attempt：{attempt_id}")
        record = AttemptRecord.model_validate(_read_json(matches[0] / "attempt.json"))
        return AttemptHandle(record, matches[0])

    def _update_state(self, handle: RunHandle, **changes: object) -> RunState:
        with exclusive_file_lock(handle.root / ".state.lock"):
            state = self.read_state(handle)
            changes.setdefault("updated_at", utc_now())
            updated = state.model_copy(update=changes)
            updated = RunState.model_validate(updated.model_dump(mode="python"))
            _atomic_write_json(handle.root / "state.json", updated.model_dump(mode="json"))
            return updated


class RecordingEventSink:
    """Persist events with run identity, then forward them to the human-facing sink."""

    def __init__(
        self,
        repository: RunRepository,
        handle: RunHandle,
        delegate: EventSink | None = None,
        *,
        initial_attempt_id: str | None = None,
    ) -> None:
        self._repository = repository
        self._handle = handle
        self._delegate = delegate
        self._attempt_id = initial_attempt_id
        self._attempts: dict[str, AttemptHandle] = {}

    @property
    def current_attempt_id(self) -> str | None:
        return self._attempt_id

    def __call__(self, event: Event) -> None:
        kind, original = event
        data = dict(original)
        event_attempt = data.get("attempt_id")
        if isinstance(event_attempt, str):
            self._attempt_id = event_attempt
        if kind == "sample_factory_batch_attempt_started" and self._attempt_id is not None:
            attempt_number = data.get("attempt")
            seed = data.get("seed")
            workspace_ref = data.get("workspace_ref")
            if (
                isinstance(attempt_number, int)
                and isinstance(seed, int)
                and isinstance(workspace_ref, str)
            ):
                self._attempts[self._attempt_id] = self._repository.start_attempt(
                    self._handle,
                    attempt_id=self._attempt_id,
                    attempt_number=attempt_number,
                    seed=seed,
                    workspace_ref=workspace_ref,
                )
        data.setdefault("run_id", self._handle.envelope.run_id)
        if self._attempt_id is not None:
            data.setdefault("attempt_id", self._attempt_id)
        self._repository.append_event(
            self._handle,
            kind,
            data,
            attempt_id=self._attempt_id,
        )
        if self._delegate is not None:
            self._delegate((kind, data))
        if kind == "sample_factory_batch_attempt_finished":
            self._finish_batch_attempt(data)
            self._attempt_id = None

    def fail_current(self, exc: BaseException) -> None:
        if self._attempt_id is None:
            return
        attempt = self._attempts.get(self._attempt_id)
        if attempt is None:
            return
        status = (
            AttemptStatus.STOPPED
            if type(exc).__name__ == "ProductionStopped"
            else AttemptStatus.FAILED
        )
        self._repository.complete_attempt(
            self._handle,
            attempt,
            status=status,
            error_type=type(exc).__name__,
            error=str(exc),
        )

    def _finish_batch_attempt(self, data: Mapping[str, object]) -> None:
        if self._attempt_id is None:
            return
        attempt = self._attempts.get(self._attempt_id)
        if attempt is None:
            return
        error_type = data.get("error_type")
        result_status = data.get("status")
        if isinstance(error_type, str):
            status = (
                AttemptStatus.STOPPED
                if error_type == "ProductionStopped"
                else AttemptStatus.FAILED
            )
        elif result_status == "SUCCESS":
            status = AttemptStatus.SUCCEEDED
        else:
            status = AttemptStatus.FAILED
            error_type = "ProductionFailed"
        error = data.get("error")
        self._repository.complete_attempt(
            self._handle,
            attempt,
            status=status,
            result_status=result_status if isinstance(result_status, str) else None,
            error_type=error_type if isinstance(error_type, str) else None,
            error=error if isinstance(error, str) else None,
        )


def _atomic_write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(f".{path.name}.{uuid4().hex}.part")
    encoded = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    descriptor = open_descriptor(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        pending = memoryview(encoded)
        while pending:
            written = os.write(descriptor, pending)
            if written <= 0:  # pragma: no cover - OS failure
                raise OSError("atomic JSON write returned zero bytes")
            pending = pending[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(staging, path)


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _remove_empty_staging(path: Path) -> None:
    if not path.exists():
        return
    for child in sorted(path.rglob("*"), reverse=True):
        if child.is_file():
            child.unlink()
        elif child.is_dir():
            child.rmdir()
    path.rmdir()


def _sanitize(value: object, *, key: str | None = None) -> object:
    if key is not None and _SENSITIVE_KEY_RE.fullmatch(key):
        if isinstance(value, str) and value.startswith(_REFERENCE_PREFIXES):
            return value
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(item_key): _sanitize(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if isinstance(value, str):
        return safe_activity_text(value, max_chars=4000)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return safe_activity_text(value, max_chars=4000)


__all__ = [
    "AttemptHandle",
    "RecordingEventSink",
    "RunHandle",
    "RunRepository",
]
