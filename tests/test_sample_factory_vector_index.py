from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.vector_index import FilesystemSemanticExperienceIndex

from tests.test_sample_factory_experience import _record


class _Embedding:
    def __init__(self, fingerprint: str = "embedding-fixture@1") -> None:
        self._fingerprint = fingerprint

    @property
    def model_fingerprint(self) -> str:
        return self._fingerprint

    def embed(self, text: str):
        lowered = text.lower()
        return (float("apc" in lowered), float("execution" in lowered), 1.0)


class VectorIndexTest(unittest.TestCase):
    def test_build_and_score_are_model_pinned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vectors.json"
            record = _record("experience-vector01")
            index = FilesystemSemanticExperienceIndex(path, _Embedding())
            index.build((record,), approved=True)

            scores = index.score("APC execution", (record,))

            self.assertGreater(scores[(record.experience_id, record.version)], 0.9)
            with self.assertRaisesRegex(ValueError, "模型指纹"):
                FilesystemSemanticExperienceIndex(
                    path, _Embedding("embedding-fixture@2")
                ).score("APC execution", (record,))

    def test_build_requires_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(PermissionError):
            FilesystemSemanticExperienceIndex(
                Path(tmp) / "vectors.json", _Embedding()
            ).build((_record("experience-vector02"),), approved=False)


if __name__ == "__main__":
    unittest.main()
