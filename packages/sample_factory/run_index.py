"""Rebuildable SQLite projection over immutable run packages."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from uuid import uuid4

from packages.sample_factory.run_repository import RunRepository


class RunIndex:
    def __init__(self, runtime_root: str | Path) -> None:
        self._runtime_root = Path(runtime_root).resolve()
        self._path = self._runtime_root / "index" / "runs.sqlite"

    @property
    def path(self) -> Path:
        return self._path

    def rebuild(self, repository: RunRepository) -> dict[str, object]:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        staging = self._path.with_name(f".{self._path.name}.{uuid4().hex}.part")
        connection = sqlite3.connect(staging)
        try:
            connection.execute(
                """
                CREATE TABLE runs (
                    run_id TEXT PRIMARY KEY,
                    run_kind TEXT NOT NULL,
                    requested_strategy TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_status TEXT,
                    attempt_count INTEGER NOT NULL,
                    completed_attempt_count INTEGER NOT NULL,
                    run_path TEXT NOT NULL
                )
                """
            )
            rows = repository.list_runs()
            connection.executemany(
                """
                INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        envelope.run_id,
                        envelope.run_kind.value,
                        envelope.planning_strategy.value,
                        envelope.worker_id,
                        envelope.created_at.isoformat(),
                        state.updated_at.isoformat(),
                        state.status.value,
                        state.result_status,
                        state.attempt_count,
                        state.completed_attempt_count,
                        path.as_posix(),
                    )
                    for envelope, state, path in rows
                ],
            )
            connection.commit()
        finally:
            connection.close()
        os.replace(staging, self._path)
        return {"index_path": self._path.as_posix(), "run_count": len(rows)}

    def list(self, *, status: str | None = None, limit: int = 100) -> tuple[dict[str, object], ...]:
        if limit < 1 or limit > 10000:
            raise ValueError("run index limit 必须位于 1..10000")
        if not self._path.is_file():
            raise FileNotFoundError("运行索引不存在，请先执行 run-index-rebuild")
        connection = sqlite3.connect(self._path)
        connection.row_factory = sqlite3.Row
        try:
            if status is None:
                rows = connection.execute(
                    "SELECT * FROM runs ORDER BY created_at DESC, run_id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM runs WHERE status=? "
                    "ORDER BY created_at DESC, run_id DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
        finally:
            connection.close()
        return tuple(dict(row) for row in rows)


__all__ = ["RunIndex"]
