"""Safe path construction for the factory runtime data plane."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from packages.sample_factory.run_models import AttemptRecord, RunEnvelope


@dataclass(frozen=True)
class RunLayout:
    runtime_root: Path

    def __init__(self, runtime_root: str | Path) -> None:
        object.__setattr__(self, "runtime_root", Path(runtime_root).resolve())

    @property
    def runs_root(self) -> Path:
        return self._inside(self.runtime_root / "runs")

    @property
    def temp_root(self) -> Path:
        return self._inside(self.runtime_root / "temp")

    @property
    def locks_root(self) -> Path:
        return self._inside(self.runtime_root / "locks")

    def run_root(self, envelope: RunEnvelope) -> Path:
        created = envelope.created_at
        return self._inside(
            self.runs_root
            / f"{created.year:04d}"
            / f"{created.month:02d}"
            / f"{created.day:02d}"
            / envelope.run_id
        )

    def attempt_root(self, run_root: Path, record: AttemptRecord) -> Path:
        return self._inside(
            run_root
            / "attempts"
            / f"{record.attempt_number:04d}-{record.attempt_id}"
        )

    def dated_run_root(self, created_at: datetime, run_id: str) -> Path:
        return self._inside(
            self.runs_root
            / f"{created_at.year:04d}"
            / f"{created_at.month:02d}"
            / f"{created_at.day:02d}"
            / run_id
        )

    def _inside(self, candidate: Path) -> Path:
        resolved = candidate.resolve()
        if not resolved.is_relative_to(self.runtime_root):
            raise ValueError(f"factory runtime 路径越界：{resolved}")
        return resolved


__all__ = ["RunLayout"]
