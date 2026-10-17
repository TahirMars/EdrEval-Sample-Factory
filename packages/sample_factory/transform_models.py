"""Registered transform and pinned tool contracts for build DAG nodes."""

from __future__ import annotations

import re
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from packages.sample_factory.build_graph import BuildPhase

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolFingerprint(_FrozenModel):
    tool_ref: str = Field(pattern=r"^tool://.+")
    version: str = Field(min_length=1)
    sha256: str
    license_ref: str = Field(pattern=r"^license://.+")

    @model_validator(mode="after")
    def _sha(self) -> Self:
        if not _SHA256_RE.fullmatch(self.sha256):
            raise ValueError("ToolFingerprint sha256 必须是完整小写 SHA-256")
        return self


class TransformSpec(_FrozenModel):
    transform_ref: str = Field(pattern=r"^transform://.+")
    version: int = Field(ge=1)
    phase: BuildPhase
    input_types: tuple[str, ...] = Field(min_length=1)
    output_types: tuple[str, ...] = Field(min_length=1)
    executor_ref: str = Field(pattern=r"^executor://.+")
    tool: ToolFingerprint | None = None
    deterministic: bool
    network_allowed: bool = False
    timeout_seconds: int = Field(default=300, ge=1, le=3600)


__all__ = ["ToolFingerprint", "TransformSpec"]
