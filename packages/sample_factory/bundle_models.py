"""Typed multi-stage sample bundle contracts."""

from __future__ import annotations

import re
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ArtifactMember(_FrozenModel):
    member_id: str = Field(pattern=r"^member-[a-z0-9-]{8,}$")
    role: str = Field(min_length=1)
    relative_path: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
    artifact_ref: str = Field(pattern=r"^object://artifacts/sha256/[0-9a-f]{64}$")
    sha256: str
    format: str = Field(min_length=1)

    @model_validator(mode="after")
    def _member_sha(self) -> Self:
        if not _SHA256_RE.fullmatch(self.sha256):
            raise ValueError("ArtifactMember sha256 必须是完整小写 SHA-256")
        if ".." in self.relative_path.split("/"):
            raise ValueError("ArtifactMember relative_path 不得路径穿越")
        return self


class ArtifactSet(_FrozenModel):
    artifact_set_id: str = Field(pattern=r"^artifact-set-[a-z0-9-]{8,}$")
    members: tuple[ArtifactMember, ...] = Field(min_length=1)
    entry_member_id: str = Field(min_length=1)

    @model_validator(mode="after")
    def _set_invariants(self) -> Self:
        ids = [member.member_id for member in self.members]
        paths = [member.relative_path.casefold() for member in self.members]
        if len(ids) != len(set(ids)) or len(paths) != len(set(paths)):
            raise ValueError("ArtifactSet member_id 和 relative_path 必须唯一")
        if self.entry_member_id not in ids:
            raise ValueError("ArtifactSet entry_member_id 不存在")
        return self


class StageHandoff(_FrozenModel):
    from_stage_id: str = Field(pattern=r"^stage-[0-9]{2}$")
    to_stage_id: str = Field(pattern=r"^stage-[0-9]{2}$")
    output_ref: str = Field(min_length=1)
    input_port: str = Field(min_length=1)


class ExecutionStage(_FrozenModel):
    stage_id: str = Field(pattern=r"^stage-[0-9]{2}$")
    artifact_set_id: str = Field(pattern=r"^artifact-set-[a-z0-9-]{8,}$")
    trigger_mode: str = Field(min_length=1)
    input_refs: tuple[str, ...] = ()
    output_refs: tuple[str, ...] = ()


class SampleBundle(_FrozenModel):
    bundle_id: str = Field(pattern=r"^bundle-[a-z0-9-]{8,}$")
    stages: tuple[ExecutionStage, ...] = Field(min_length=1)
    artifact_sets: tuple[ArtifactSet, ...] = Field(min_length=1)
    handoffs: tuple[StageHandoff, ...] = ()
    entry_stage_id: str = Field(pattern=r"^stage-[0-9]{2}$")

    @model_validator(mode="after")
    def _bundle_invariants(self) -> Self:
        stage_ids = [stage.stage_id for stage in self.stages]
        set_ids = [item.artifact_set_id for item in self.artifact_sets]
        if len(stage_ids) != len(set(stage_ids)):
            raise ValueError("SampleBundle stage_id 必须唯一")
        if len(set_ids) != len(set(set_ids)):
            raise ValueError("SampleBundle 不得重复引用 ArtifactSet")
        if self.entry_stage_id not in stage_ids:
            raise ValueError("SampleBundle entry_stage_id 不存在")
        if any(stage.artifact_set_id not in set_ids for stage in self.stages):
            raise ValueError("SampleBundle stage 引用了不存在的 ArtifactSet")
        edges = {(item.from_stage_id, item.to_stage_id) for item in self.handoffs}
        if any(source not in stage_ids or target not in stage_ids for source, target in edges):
            raise ValueError("SampleBundle handoff 引用了不存在的 stage")
        if any(source == target for source, target in edges):
            raise ValueError("SampleBundle 不允许 stage 自环")
        if _has_cycle(stage_ids, edges):
            raise ValueError("SampleBundle stage handoff 必须是 DAG")
        return self


def _has_cycle(nodes: list[str], edges: set[tuple[str, str]]) -> bool:
    outgoing: dict[str, list[str]] = {node: [] for node in nodes}
    indegree = dict.fromkeys(nodes, 0)
    for source, target in edges:
        outgoing[source].append(target)
        indegree[target] += 1
    queue = [node for node in nodes if indegree[node] == 0]
    visited = 0
    while queue:
        node = queue.pop()
        visited += 1
        for target in outgoing[node]:
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    return visited != len(nodes)


__all__ = ["ArtifactMember", "ArtifactSet", "ExecutionStage", "SampleBundle", "StageHandoff"]
