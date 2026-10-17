"""Pinned filesystem vector index used only to rerank legal experience records."""

from __future__ import annotations

import json
import math
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from packages.sample_factory.experience import ExperienceRecord


class EmbeddingBackend(Protocol):
    @property
    def model_fingerprint(self) -> str: ...

    def embed(self, text: str) -> Sequence[float]: ...


class _VectorEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    experience_id: str
    version: int = Field(ge=1)
    vector: tuple[float, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _finite(self) -> _VectorEntry:
        if any(not math.isfinite(item) for item in self.vector):
            raise ValueError("经验向量不得包含 NaN/Infinity")
        return self


class _VectorIndexDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "sample-factory-vector-index-v1"
    model_fingerprint: str = Field(min_length=1)
    dimension: int = Field(ge=1)
    entries: tuple[_VectorEntry, ...]

    @model_validator(mode="after")
    def _dimension(self) -> _VectorIndexDocument:
        keys = [(item.experience_id, item.version) for item in self.entries]
        if len(keys) != len(set(keys)):
            raise ValueError("经验向量索引 key 不得重复")
        if any(len(item.vector) != self.dimension for item in self.entries):
            raise ValueError("经验向量维度与索引声明不一致")
        return self


class FilesystemSemanticExperienceIndex:
    def __init__(self, path: str | Path, backend: EmbeddingBackend) -> None:
        self._path = Path(path).resolve()
        self._backend = backend

    def build(self, records: Sequence[ExperienceRecord], *, approved: bool) -> None:
        if not approved:
            raise PermissionError("经验向量索引构建需要人工审批")
        entries = []
        dimension = 0
        for record in records:
            vector = tuple(float(item) for item in self._backend.embed(record.semantic_summary))
            if not vector or any(not math.isfinite(item) for item in vector):
                raise ValueError("embedding backend 返回非法向量")
            if dimension == 0:
                dimension = len(vector)
            if len(vector) != dimension:
                raise ValueError("embedding backend 返回不一致维度")
            entries.append(
                _VectorEntry(
                    experience_id=record.experience_id,
                    version=record.version,
                    vector=vector,
                )
            )
        if dimension == 0:
            dimension = 1
        document = _VectorIndexDocument(
            model_fingerprint=self._backend.model_fingerprint,
            dimension=dimension,
            entries=tuple(entries),
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        staging = self._path.with_name(f".{self._path.name}.{uuid4().hex}.part")
        staging.write_text(
            json.dumps(
                document.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(staging, self._path)

    def score(
        self, query: str, records: Sequence[ExperienceRecord]
    ) -> dict[tuple[str, int], float]:
        if not self._path.is_file() or not records:
            return {}
        document = _VectorIndexDocument.model_validate_json(
            self._path.read_text(encoding="utf-8")
        )
        if document.model_fingerprint != self._backend.model_fingerprint:
            raise ValueError("embedding 模型指纹与向量索引不一致")
        query_vector = tuple(float(item) for item in self._backend.embed(query))
        if len(query_vector) != document.dimension:
            raise ValueError("query embedding 维度与索引不一致")
        by_key = {
            (entry.experience_id, entry.version): entry.vector
            for entry in document.entries
        }
        result = {}
        for record in records:
            key = (record.experience_id, record.version)
            vector = by_key.get(key)
            if vector is not None:
                result[key] = _cosine_01(query_vector, vector)
        return result


def _cosine_01(left: Sequence[float], right: Sequence[float]) -> float:
    left_norm = math.sqrt(sum(item * item for item in left))
    right_norm = math.sqrt(sum(item * item for item in right))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    cosine = sum(a * b for a, b in zip(left, right, strict=True)) / (
        left_norm * right_norm
    )
    return max(0.0, min(1.0, (cosine + 1.0) / 2.0))


__all__ = ["EmbeddingBackend", "FilesystemSemanticExperienceIndex"]
