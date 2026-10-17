"""Planner-facing hybrid experience retrieval with deterministic hard filters."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, Self
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from packages.sample_factory.identity import canonical_json
from packages.sample_factory.run_models import PlanningStrategy

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class KnowledgeMaturity(StrEnum):
    HYPOTHESIS = "hypothesis"
    STATICALLY_VALID = "statically_valid"
    BUILD_VALID = "build_valid"
    BEHAVIOR_VALID = "behavior_valid"
    REPLAY_STABLE = "replay_stable"
    PROMOTED = "promoted"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


_MATURITY_RANK = {
    KnowledgeMaturity.HYPOTHESIS: 0,
    KnowledgeMaturity.STATICALLY_VALID: 1,
    KnowledgeMaturity.BUILD_VALID: 2,
    KnowledgeMaturity.BEHAVIOR_VALID: 3,
    KnowledgeMaturity.REPLAY_STABLE: 4,
    KnowledgeMaturity.PROMOTED: 5,
    KnowledgeMaturity.DEPRECATED: -1,
    KnowledgeMaturity.REVOKED: -2,
}


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExperienceRecord(_FrozenModel):
    experience_id: str = Field(pattern=r"^experience-[a-z0-9-]{8,}$")
    version: int = Field(ge=1)
    maturity: KnowledgeMaturity
    ph_sequence: tuple[str, ...] = Field(min_length=1)
    atom_ids: tuple[str, ...] = Field(min_length=1)
    capabilities: tuple[str, ...] = Field(min_length=1)
    profile_ids: tuple[str, ...] = Field(min_length=1)
    architecture: str = Field(min_length=1)
    parameter_policy_refs: tuple[str, ...] = ()
    transform_pipeline_ref: str | None = None
    atom_parameters: dict[str, dict[str, Any]] = Field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()
    success_count: int = Field(default=0, ge=0)
    failure_count: int = Field(default=0, ge=0)
    semantic_summary: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def _evidence_maturity(self) -> Self:
        if _MATURITY_RANK[self.maturity] >= _MATURITY_RANK[
            KnowledgeMaturity.BEHAVIOR_VALID
        ] and not self.evidence_refs:
            raise ValueError("behavior_valid 及以上经验必须携带 evidence_refs")
        return self


class ExperienceSearchQuery(_FrozenModel):
    strategy: PlanningStrategy
    ph_ids: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    profile_id: str = Field(min_length=1)
    architecture: str = Field(min_length=1)
    minimum_maturity: KnowledgeMaturity = KnowledgeMaturity.HYPOTHESIS
    semantic_query: str | None = None
    limit: int = Field(default=8, ge=1, le=32)

    @model_validator(mode="after")
    def _strategy_maturity(self) -> Self:
        minimum = _MATURITY_RANK[self.minimum_maturity]
        if self.strategy is PlanningStrategy.EXPLOIT and minimum < _MATURITY_RANK[
            KnowledgeMaturity.REPLAY_STABLE
        ]:
            raise ValueError("exploit 至少要求 replay_stable 经验")
        if self.minimum_maturity in {
            KnowledgeMaturity.DEPRECATED,
            KnowledgeMaturity.REVOKED,
        }:
            raise ValueError("检索不得以 deprecated/revoked 作为最低成熟度")
        return self


class ExperienceCandidate(_FrozenModel):
    experience: ExperienceRecord
    structural_score: float = Field(ge=0, le=1)
    semantic_score: float | None = Field(default=None, ge=0, le=1)
    final_score: float = Field(ge=0, le=1)
    reasons: tuple[str, ...] = Field(min_length=1)


class ExperienceSearchResult(_FrozenModel):
    schema_version: str = "sample-factory-experience-search-v1"
    experience_set_version: str
    learning_snapshot_ref: str
    candidates: tuple[ExperienceCandidate, ...]

    @field_validator("experience_set_version")
    @classmethod
    def _set_version(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("experience_set_version 必须是 sha256")
        return value


class ExperienceMetadataStore(Protocol):
    def records(self) -> Sequence[ExperienceRecord]: ...

    def get(self, experience_id: str, version: int | None = None) -> ExperienceRecord: ...


class SemanticExperienceIndex(Protocol):
    """Optional RAG scorer; it cannot add records omitted by hard filtering."""

    def score(
        self, query: str, records: Sequence[ExperienceRecord]
    ) -> Mapping[tuple[str, int], float]: ...


class InMemoryExperienceStore:
    def __init__(self, records: Sequence[ExperienceRecord] = ()) -> None:
        self._records = tuple(records)

    def records(self) -> Sequence[ExperienceRecord]:
        return self._records

    def get(self, experience_id: str, version: int | None = None) -> ExperienceRecord:
        matches = [
            item
            for item in self._records
            if item.experience_id == experience_id
            and (version is None or item.version == version)
        ]
        if not matches:
            raise KeyError(experience_id)
        return max(matches, key=lambda item: item.version)


class FilesystemExperienceStore:
    """Immutable JSON experience versions suitable for tracked catalog metadata."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root).resolve()

    def records(self) -> Sequence[ExperienceRecord]:
        result = []
        for path in sorted(self._root.glob("experience-*/v*.json")):
            try:
                result.append(
                    ExperienceRecord.model_validate_json(
                        path.read_text(encoding="utf-8")
                    )
                )
            except Exception as exc:
                raise ValueError(f"经验记录损坏：{path}: {exc}") from exc
        return tuple(result)

    def get(self, experience_id: str, version: int | None = None) -> ExperienceRecord:
        matches = [
            item
            for item in self.records()
            if item.experience_id == experience_id
            and (version is None or item.version == version)
        ]
        if not matches:
            raise KeyError(experience_id)
        return max(matches, key=lambda item: item.version)

    def put(self, record: ExperienceRecord, *, approved: bool = False) -> str:
        if record.maturity is KnowledgeMaturity.PROMOTED and not approved:
            raise PermissionError("promoted 经验写入需要人工审批")
        target_dir = (self._root / record.experience_id).resolve()
        if not target_dir.is_relative_to(self._root):  # pragma: no cover - schema guard
            raise ValueError("经验路径越界")
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / f"v{record.version:06d}.json"
        encoded = (
            json.dumps(
                record.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        if target.exists():
            if target.read_text(encoding="utf-8") != encoded:
                raise ValueError("同一经验版本已存在但内容冲突")
            return f"experience://{record.experience_id}/v{record.version}"
        prior_versions = [
            item for item in self.records() if item.experience_id == record.experience_id
        ]
        if prior_versions:
            prior = max(prior_versions, key=lambda item: item.version)
            if record.version != prior.version + 1:
                raise ValueError("经验版本必须连续递增")
            prior_rank = _MATURITY_RANK[prior.maturity]
            next_rank = _MATURITY_RANK[record.maturity]
            if record.maturity not in {
                KnowledgeMaturity.DEPRECATED,
                KnowledgeMaturity.REVOKED,
            } and (next_rank < prior_rank or next_rank > prior_rank + 1):
                raise ValueError("经验成熟度不得倒退或跨级晋升")
        elif record.version != 1:
            raise ValueError("新经验首个版本必须是 v1")
        staging = target.with_name(f".{target.name}.{uuid4().hex}.part")
        staging.write_text(encoded, encoding="utf-8", newline="\n")
        os.replace(staging, target)
        return f"experience://{record.experience_id}/v{record.version}"

    def advance(
        self,
        experience_id: str,
        maturity: KnowledgeMaturity,
        *,
        approved: bool,
        evidence_refs: tuple[str, ...] = (),
    ) -> str:
        if not approved:
            raise PermissionError("经验成熟度推进需要人工审批")
        prior = self.get(experience_id)
        merged_evidence = tuple(dict.fromkeys((*prior.evidence_refs, *evidence_refs)))
        record = prior.model_copy(
            update={
                "version": prior.version + 1,
                "maturity": maturity,
                "evidence_refs": merged_evidence,
            }
        )
        return self.put(record, approved=approved)


class HybridExperienceRetriever:
    """Structured search first; semantic retrieval only reranks legal candidates."""

    def __init__(
        self,
        store: ExperienceMetadataStore,
        semantic_index: SemanticExperienceIndex | None = None,
    ) -> None:
        self._store = store
        self._semantic_index = semantic_index

    def search(self, query: ExperienceSearchQuery) -> ExperienceSearchResult:
        records = tuple(self._hard_filter(query, self._store.records()))
        semantic_scores: Mapping[tuple[str, int], float] = {}
        if query.semantic_query and self._semantic_index is not None and records:
            semantic_scores = self._semantic_index.score(query.semantic_query, records)

        candidates = []
        for record in records:
            structural, reasons = _structural_score(query, record)
            semantic = semantic_scores.get((record.experience_id, record.version))
            if semantic is not None and not 0 <= semantic <= 1:
                raise ValueError("semantic index score 必须位于 [0, 1]")
            final = structural if semantic is None else structural * 0.8 + semantic * 0.2
            candidates.append(
                ExperienceCandidate(
                    experience=record,
                    structural_score=structural,
                    semantic_score=semantic,
                    final_score=final,
                    reasons=tuple(reasons),
                )
            )
        candidates.sort(
            key=lambda item: (
                -item.final_score,
                item.experience.experience_id,
                -item.experience.version,
            )
        )
        selected = tuple(candidates[: query.limit])
        set_version = _experience_set_version(self._store.records())
        snapshot_digest = hashlib.sha256(
            canonical_json(
                {
                    "experience_set_version": set_version,
                    "query": query.model_dump(mode="json"),
                    "selected": [
                        {
                            "experience_id": item.experience.experience_id,
                            "version": item.experience.version,
                            "final_score": item.final_score,
                        }
                        for item in selected
                    ],
                }
            ).encode("utf-8")
        ).hexdigest()
        return ExperienceSearchResult(
            experience_set_version=set_version,
            learning_snapshot_ref=f"learning-snapshot://sha256/{snapshot_digest}",
            candidates=selected,
        )

    @staticmethod
    def _hard_filter(
        query: ExperienceSearchQuery, records: Sequence[ExperienceRecord]
    ) -> tuple[ExperienceRecord, ...]:
        minimum = _MATURITY_RANK[query.minimum_maturity]
        result = []
        for record in records:
            if _MATURITY_RANK[record.maturity] < minimum:
                continue
            if record.maturity in {
                KnowledgeMaturity.DEPRECATED,
                KnowledgeMaturity.REVOKED,
            }:
                continue
            if query.profile_id not in record.profile_ids:
                continue
            if record.architecture not in {query.architecture, "any"}:
                continue
            if query.ph_ids and not set(query.ph_ids).issubset(record.ph_sequence):
                continue
            if not set(query.required_capabilities).issubset(record.capabilities):
                continue
            result.append(record)
        return tuple(result)


class ExperienceToolService:
    """Narrow tool-call facade exposed to the Planner."""

    def __init__(
        self, retriever: HybridExperienceRetriever, store: ExperienceMetadataStore
    ) -> None:
        self._retriever = retriever
        self._store = store

    def call(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if name == "experience.search":
            query = ExperienceSearchQuery.model_validate(dict(arguments))
            return self._retriever.search(query).model_dump(mode="json")
        if name == "experience.get":
            unknown = set(arguments) - {"experience_id", "version"}
            if unknown:
                raise ValueError(f"experience.get 未知字段：{sorted(unknown)}")
            experience_id = arguments.get("experience_id")
            version = arguments.get("version")
            if not isinstance(experience_id, str) or (
                version is not None and not isinstance(version, int)
            ):
                raise ValueError("experience.get 参数类型非法")
            return self._store.get(experience_id, version).model_dump(mode="json")
        raise ValueError(f"未知经验工具：{name}")


def select_planning_strategy(
    retriever: HybridExperienceRetriever,
    *,
    seed: int,
    ph_ids: tuple[str, ...],
    profile_id: str,
    architecture: str,
) -> PlanningStrategy:
    stable = retriever.search(
        ExperienceSearchQuery(
            strategy=PlanningStrategy.EXPLOIT,
            ph_ids=ph_ids,
            profile_id=profile_id,
            architecture=architecture,
            minimum_maturity=KnowledgeMaturity.REPLAY_STABLE,
            limit=1,
        )
    ).candidates
    behavior = retriever.search(
        ExperienceSearchQuery(
            strategy=PlanningStrategy.MUTATE,
            ph_ids=ph_ids,
            profile_id=profile_id,
            architecture=architecture,
            minimum_maturity=KnowledgeMaturity.BEHAVIOR_VALID,
            limit=1,
        )
    ).candidates
    bucket = seed % 10
    if stable:
        if bucket < 5:
            return PlanningStrategy.EXPLOIT
        if bucket < 8:
            return PlanningStrategy.MUTATE
        return PlanningStrategy.EXPLORE
    if behavior:
        return PlanningStrategy.MUTATE if bucket < 6 else PlanningStrategy.EXPLORE
    return PlanningStrategy.EXPLORE


def _structural_score(
    query: ExperienceSearchQuery, record: ExperienceRecord
) -> tuple[float, list[str]]:
    maturity = max(0, _MATURITY_RANK[record.maturity]) / 5
    attempts = record.success_count + record.failure_count
    success_rate = record.success_count / attempts if attempts else 0.5
    capability_bonus = min(len(query.required_capabilities), 4) * 0.025
    score = min(1.0, maturity * 0.55 + success_rate * 0.35 + capability_bonus + 0.1)
    reasons = [
        f"maturity={record.maturity.value}",
        f"success={record.success_count}/{attempts}",
        "hard_contracts=matched",
    ]
    return score, reasons


def _experience_set_version(records: Sequence[ExperienceRecord]) -> str:
    identity = [
        {
            "experience_id": item.experience_id,
            "version": item.version,
            "maturity": item.maturity.value,
        }
        for item in sorted(records, key=lambda item: (item.experience_id, item.version))
    ]
    return hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()


__all__ = [
    "ExperienceCandidate",
    "ExperienceMetadataStore",
    "ExperienceRecord",
    "ExperienceSearchQuery",
    "ExperienceSearchResult",
    "ExperienceToolService",
    "FilesystemExperienceStore",
    "HybridExperienceRetriever",
    "InMemoryExperienceStore",
    "KnowledgeMaturity",
    "SemanticExperienceIndex",
    "select_planning_strategy",
]
