"""Auditable demand queue between online evaluation and offline factory."""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from packages.sample_factory.agent_events import safe_activity_text
from packages.sample_factory.file_lock import exclusive_file_lock


class DemandStatus(StrEnum):
    PENDING = "PENDING"
    CLAIMED = "CLAIMED"
    FULFILLED = "FULFILLED"
    FAILED = "FAILED"


class SampleDemand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["sample-factory-demand-v1"] = "sample-factory-demand-v1"
    request_id: str = Field(pattern=r"^demand-[a-z0-9-]{8,}$")
    requested_at: datetime
    requested_by: str = Field(min_length=1)
    ph_ids: tuple[str, ...] = Field(min_length=1)
    profile_id: str = Field(min_length=1)
    architecture: Literal["x86", "x64"]
    max_stages: int = Field(default=1, ge=1, le=8)
    sample_count: int = Field(default=1, ge=1, le=1000)
    planning_strategy: Literal["auto", "exploit", "mutate", "explore"] = "auto"
    rationale: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def _timestamp(self) -> Self:
        if self.requested_at.tzinfo is None:
            raise ValueError("SampleDemand.requested_at 必须带时区")
        return self

    @field_validator("rationale")
    @classmethod
    def _no_credentials(cls, value: str) -> str:
        safe = safe_activity_text(value, max_chars=1000)
        if "[REDACTED" in safe:
            raise ValueError("SampleDemand.rationale 不得包含凭据材料")
        return value


class FactoryWorkQueue:
    def __init__(self, runtime_root: str | Path) -> None:
        self._root = Path(runtime_root).resolve() / "state" / "demands"

    def submit(self, demand: SampleDemand, *, approved: bool) -> str:
        if not approved:
            raise PermissionError("在线动态样本工单需要人工或策略审批")
        target = self._path(demand.request_id)
        payload: dict[str, object] = {
            "demand": demand.model_dump(mode="json"),
            "status": DemandStatus.PENDING.value,
            "updated_at": datetime.now(UTC).isoformat(),
            "worker_id": None,
            "result_refs": [],
            "error": None,
        }
        self._create(target, payload)
        return f"factory-demand://{demand.request_id}"

    def claim(self, request_id: str, *, worker_id: str) -> dict[str, object]:
        if not worker_id.strip():
            raise ValueError("worker_id 不得为空")
        path = self._path(request_id)
        with exclusive_file_lock(path.with_suffix(".lock")):
            payload = self._read(path)
            if payload["status"] != DemandStatus.PENDING.value:
                raise ValueError("只有 PENDING 工单可以认领")
            payload["status"] = DemandStatus.CLAIMED.value
            payload["worker_id"] = worker_id
            payload["updated_at"] = datetime.now(UTC).isoformat()
            self._replace(path, payload)
        return payload

    def complete(
        self,
        request_id: str,
        *,
        worker_id: str,
        result_refs: tuple[str, ...],
        error: str | None = None,
    ) -> dict[str, object]:
        path = self._path(request_id)
        with exclusive_file_lock(path.with_suffix(".lock")):
            payload = self._read(path)
            if (
                payload["status"] != DemandStatus.CLAIMED.value
                or payload["worker_id"] != worker_id
            ):
                raise ValueError("工单未由当前 worker 认领")
            if bool(result_refs) == bool(error):
                raise ValueError("工单完成必须且只能提供 result_refs 或 error")
            if any(
                not ref.startswith(("artifact://", "object://", "bundle://", "export://"))
                for ref in result_refs
            ):
                raise ValueError("工单 result_refs 类型非法")
            payload["status"] = (
                DemandStatus.FULFILLED.value if result_refs else DemandStatus.FAILED.value
            )
            payload["result_refs"] = list(result_refs)
            payload["error"] = (
                None if error is None else safe_activity_text(error, max_chars=2000)
            )
            payload["updated_at"] = datetime.now(UTC).isoformat()
            self._replace(path, payload)
        return payload

    def list(self) -> tuple[dict[str, object], ...]:
        return tuple(self._read(path) for path in sorted(self._root.glob("demand-*.json")))

    def _path(self, request_id: str) -> Path:
        if not re.fullmatch(r"demand-[a-z0-9-]{8,79}", request_id):
            raise ValueError("demand request_id 非法")
        return self._root / f"{request_id}.json"

    def _create(self, path: Path, payload: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with exclusive_file_lock(path.with_suffix(".lock")):
            if path.exists():
                raise FileExistsError(path)
            self._write(path, payload, replace=False)

    def _replace(self, path: Path, payload: object) -> None:
        if not path.is_file():
            raise FileNotFoundError(path)
        self._write(path, payload, replace=True)

    @staticmethod
    def _write(path: Path, payload: object, *, replace: bool) -> None:
        staging = path.with_name(f".{path.name}.{uuid4().hex}.part")
        staging.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        if not replace and path.exists():
            staging.unlink()
            raise FileExistsError(path)
        os.replace(staging, path)

    @staticmethod
    def _read(path: Path) -> dict[str, object]:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"工单文件损坏：{path}")
        return value


__all__ = ["DemandStatus", "FactoryWorkQueue", "SampleDemand"]
