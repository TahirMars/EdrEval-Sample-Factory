"""Typed identities and lifecycle records for one factory run."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, Self
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_ID_RE = re.compile(r"[a-z][a-z0-9-]{7,79}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class RunKind(StrEnum):
    SAMPLE_PRODUCTION = "sample_production"
    PLUGIN_AUTHORING = "plugin_authoring"
    PLUGIN_VALIDATION = "plugin_validation"
    PLUGIN_REGRESSION = "plugin_regression"


class PlanningStrategy(StrEnum):
    AUTO = "auto"
    EXPLOIT = "exploit"
    MUTATE = "mutate"
    EXPLORE = "explore"


class RunStatus(StrEnum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


class AttemptStatus(StrEnum):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def new_run_id() -> str:
    return f"run-{uuid4().hex}"


def new_attempt_id() -> str:
    return f"attempt-{uuid4().hex}"


def utc_now() -> datetime:
    return datetime.now(UTC)


class RunEnvelope(_FrozenModel):
    schema_version: Literal["sample-factory-run-v1"] = "sample-factory-run-v1"
    run_id: str
    run_kind: RunKind
    planning_strategy: PlanningStrategy
    worker_id: str = Field(min_length=1)
    created_at: datetime
    config_fingerprint: str
    request_snapshot: dict[str, Any]

    @field_validator("run_id")
    @classmethod
    def _run_id(cls, value: str) -> str:
        if not _ID_RE.fullmatch(value) or not value.startswith("run-"):
            raise ValueError("run_id 必须是 run- 开头的安全标识符")
        return value

    @field_validator("config_fingerprint")
    @classmethod
    def _config_fingerprint(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("config_fingerprint 必须是 sha256")
        return value

    @field_validator("created_at")
    @classmethod
    def _aware_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("created_at 必须包含时区")
        return value


class RunState(_FrozenModel):
    schema_version: Literal["sample-factory-run-state-v1"] = (
        "sample-factory-run-state-v1"
    )
    run_id: str
    status: RunStatus
    created_at: datetime
    updated_at: datetime
    attempt_count: int = Field(default=0, ge=0)
    completed_attempt_count: int = Field(default=0, ge=0)
    result_status: str | None = None
    error_type: str | None = None
    error: str | None = None

    @field_validator("run_id")
    @classmethod
    def _run_id(cls, value: str) -> str:
        if not _ID_RE.fullmatch(value) or not value.startswith("run-"):
            raise ValueError("run state 的 run_id 非法")
        return value

    @model_validator(mode="after")
    def _state_invariants(self) -> Self:
        if self.completed_attempt_count > self.attempt_count:
            raise ValueError("completed_attempt_count 不得大于 attempt_count")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at 不得早于 created_at")
        if self.status is RunStatus.FAILED and not self.error_type:
            raise ValueError("FAILED run 必须记录 error_type")
        return self


class AttemptRecord(_FrozenModel):
    schema_version: Literal["sample-factory-attempt-v1"] = "sample-factory-attempt-v1"
    run_id: str
    attempt_id: str
    attempt_number: int = Field(ge=1)
    seed: int
    workspace_ref: str = Field(min_length=1)
    status: AttemptStatus
    started_at: datetime
    updated_at: datetime
    result_status: str | None = None
    error_type: str | None = None
    error: str | None = None

    @field_validator("run_id")
    @classmethod
    def _run_id(cls, value: str) -> str:
        if not _ID_RE.fullmatch(value) or not value.startswith("run-"):
            raise ValueError("attempt 的 run_id 非法")
        return value

    @field_validator("attempt_id")
    @classmethod
    def _attempt_id(cls, value: str) -> str:
        if not _ID_RE.fullmatch(value) or not value.startswith("attempt-"):
            raise ValueError("attempt_id 必须是 attempt- 开头的安全标识符")
        return value

    @model_validator(mode="after")
    def _attempt_invariants(self) -> Self:
        if self.updated_at < self.started_at:
            raise ValueError("attempt updated_at 不得早于 started_at")
        if self.status is AttemptStatus.FAILED and not self.error_type:
            raise ValueError("FAILED attempt 必须记录 error_type")
        return self


__all__ = [
    "AttemptRecord",
    "AttemptStatus",
    "PlanningStrategy",
    "RunEnvelope",
    "RunKind",
    "RunState",
    "RunStatus",
    "new_attempt_id",
    "new_run_id",
    "utc_now",
]
