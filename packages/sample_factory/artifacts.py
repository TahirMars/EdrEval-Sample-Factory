"""外部内容寻址工件仓的本地实现（测试/单机档）。"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from packages.sample_factory.cas import ContentAddressedStore, ObjectNamespace
from packages.sample_factory.models import BuiltSample
from packages.sample_factory.pipeline import ArtifactPublisher, PublishedArtifact


class BuildArtifactResolver(Protocol):
    def resolve_artifact(self, artifact_ref: str) -> Path: ...


class FilesystemArtifactPublisher(ArtifactPublisher):
    """二进制仅复制到代码仓外的 content-addressed root。"""

    def __init__(self, runtime_root: str | Path, resolver: BuildArtifactResolver) -> None:
        self._runtime_root = Path(runtime_root).resolve()
        self._resolver = resolver
        repo_root = Path(__file__).resolve().parents[2]
        if self._runtime_root.is_relative_to(repo_root):
            raise ValueError("样本工件仓不得位于 EdrEvalAgent 代码仓")
        self._cas = ContentAddressedStore(self._runtime_root)

    def publish(self, artifact: BuiltSample) -> PublishedArtifact:
        source = self._resolver.resolve_artifact(artifact.artifact_ref)
        stored = self._cas.put_file(
            ObjectNamespace.ARTIFACTS,
            source,
            expected_sha256=artifact.artifact_sha256,
        )
        return PublishedArtifact(
            artifact_ref=stored.object_ref,
            artifact_sha256=artifact.artifact_sha256,
        )

    def resolve(self, artifact_ref: str) -> Path:
        return self._cas.resolve(artifact_ref)


__all__ = ["BuildArtifactResolver", "FilesystemArtifactPublisher"]
