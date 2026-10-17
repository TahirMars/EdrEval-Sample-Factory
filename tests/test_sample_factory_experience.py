from __future__ import annotations

import unittest

from packages.sample_factory.experience import (
    ExperienceRecord,
    ExperienceSearchQuery,
    ExperienceToolService,
    FilesystemExperienceStore,
    HybridExperienceRetriever,
    InMemoryExperienceStore,
    KnowledgeMaturity,
)
from packages.sample_factory.run_models import PlanningStrategy


def _record(
    experience_id: str,
    *,
    profile: str = "win11",
    architecture: str = "x64",
    maturity: KnowledgeMaturity = KnowledgeMaturity.REPLAY_STABLE,
) -> ExperienceRecord:
    return ExperienceRecord(
        experience_id=experience_id,
        version=1,
        maturity=maturity,
        ph_sequence=("PH-IN04",),
        atom_ids=("atom.in.apc",),
        capabilities=("cap.process.injection",),
        profile_ids=(profile,),
        architecture=architecture,
        evidence_refs=("factory-run://run-12345678",),
        success_count=8,
        failure_count=2,
        semantic_summary="APC execution in a Windows process",
    )


class _SemanticIndex:
    def __init__(self) -> None:
        self.received = ()

    def score(self, query, records):
        del query
        self.received = tuple(records)
        return {(item.experience_id, item.version): 1.0 for item in records}


class ExperienceRetrievalTest(unittest.TestCase):
    def test_structured_filters_run_before_semantic_rag(self) -> None:
        allowed = _record("experience-allowed1")
        wrong_profile = _record("experience-wrong-profile", profile="win10")
        revoked = _record(
            "experience-revoked1", maturity=KnowledgeMaturity.REVOKED
        )
        store = InMemoryExperienceStore((allowed, wrong_profile, revoked))
        semantic = _SemanticIndex()
        retriever = HybridExperienceRetriever(store, semantic)

        result = retriever.search(
            ExperienceSearchQuery(
                strategy=PlanningStrategy.EXPLOIT,
                ph_ids=("PH-IN04",),
                required_capabilities=("cap.process.injection",),
                profile_id="win11",
                architecture="x64",
                minimum_maturity=KnowledgeMaturity.REPLAY_STABLE,
                semantic_query="similar execution",
            )
        )

        self.assertEqual((allowed,), semantic.received)
        self.assertEqual(
            ["experience-allowed1"],
            [item.experience.experience_id for item in result.candidates],
        )
        self.assertTrue(result.learning_snapshot_ref.startswith("learning-snapshot://sha256/"))

    def test_exploit_rejects_low_maturity_query(self) -> None:
        with self.assertRaisesRegex(ValueError, "replay_stable"):
            ExperienceSearchQuery(
                strategy=PlanningStrategy.EXPLOIT,
                profile_id="win11",
                architecture="x64",
                minimum_maturity=KnowledgeMaturity.HYPOTHESIS,
            )

    def test_tool_service_returns_structured_results_and_rejects_unknown_tool(self) -> None:
        store = InMemoryExperienceStore((_record("experience-tool-test"),))
        service = ExperienceToolService(HybridExperienceRetriever(store), store)

        payload = service.call(
            "experience.search",
            {
                "strategy": "exploit",
                "ph_ids": ["PH-IN04"],
                "required_capabilities": ["cap.process.injection"],
                "profile_id": "win11",
                "architecture": "x64",
                "minimum_maturity": "replay_stable",
            },
        )

        self.assertEqual(
            "experience-tool-test",
            payload["candidates"][0]["experience"]["experience_id"],
        )
        with self.assertRaisesRegex(ValueError, "未知经验工具"):
            service.call("experience.delete", {})

    def test_filesystem_store_is_immutable_and_promoted_requires_approval(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            store = FilesystemExperienceStore(Path(tmp) / "records")
            record = _record("experience-stored01")
            ref = store.put(record)
            self.assertEqual("experience://experience-stored01/v1", ref)
            self.assertEqual(record, store.get(record.experience_id))
            self.assertEqual(ref, store.put(record))
            promoted = record.model_copy(
                update={"version": 2, "maturity": KnowledgeMaturity.PROMOTED}
            )
            with self.assertRaises(PermissionError):
                store.put(promoted)
            self.assertEqual(
                "experience://experience-stored01/v2",
                store.put(promoted, approved=True),
            )

    def test_store_rejects_version_gap_and_maturity_jump(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            store = FilesystemExperienceStore(Path(tmp) / "records")
            base = _record(
                "experience-sequence1", maturity=KnowledgeMaturity.BUILD_VALID
            )
            store.put(base)
            with self.assertRaisesRegex(ValueError, "连续"):
                store.put(base.model_copy(update={"version": 3}))
            with self.assertRaisesRegex(ValueError, "跨级"):
                store.put(
                    base.model_copy(
                        update={
                            "version": 2,
                            "maturity": KnowledgeMaturity.PROMOTED,
                        }
                    ),
                    approved=True,
                )


if __name__ == "__main__":
    unittest.main()
