from __future__ import annotations

import unittest

from packages.sample_factory.ai_planner import FactoryPlanningAgent
from packages.sample_factory.experience import (
    ExperienceRecord,
    HybridExperienceRetriever,
    InMemoryExperienceStore,
    KnowledgeMaturity,
)
from packages.sample_factory.run_models import PlanningStrategy

from tests.test_sample_factory_ai_pipeline import (
    FakeCompletionClient,
    _composition,
    _context,
    catalog,
)


def _experience() -> ExperienceRecord:
    context = _context()
    return ExperienceRecord(
        experience_id="experience-planner01",
        version=1,
        maturity=KnowledgeMaturity.REPLAY_STABLE,
        ph_sequence=("PH-IA01", "PH-OB05", "PH-IN04"),
        atom_ids=("atom.ia.document", "atom.ob.decode", "atom.in.apc"),
        capabilities=("cap.sample.chain",),
        profile_ids=(context.profile.profile_id,),
        architecture="x64",
        atom_parameters={
            "atom.ia.document": {"container": "docm"},
            "atom.ob.decode": {"codec": "rc4"},
            "atom.in.apc": {"target": "notepad.exe"},
        },
        evidence_refs=("factory-run://run-12345678",),
        success_count=5,
        semantic_summary="Reviewed sample chain",
    )


class PlannerExperienceTest(unittest.TestCase):
    def test_exploit_injects_stable_experience_and_records_snapshot(self) -> None:
        retriever = HybridExperienceRetriever(InMemoryExperienceStore((_experience(),)))
        client = FakeCompletionClient([_composition()])
        planner = FactoryPlanningAgent(
            client,
            catalog(),
            planning_strategy=PlanningStrategy.EXPLOIT,
            experience_retriever=retriever,
        )

        result = planner.plan(_context())

        self.assertEqual(PlanningStrategy.EXPLOIT, result.planning_strategy)
        self.assertEqual(("experience://experience-planner01/v1",), result.experience_refs)
        self.assertIsNotNone(result.experience_set_version)
        self.assertIsNotNone(result.learning_snapshot_ref)
        prompt = client.calls[0][1]["content"]
        self.assertIn("experience-planner01", prompt)

    def test_explore_supports_empty_cold_start_snapshot(self) -> None:
        planner = FactoryPlanningAgent(
            FakeCompletionClient([_composition()]),
            catalog(),
            planning_strategy=PlanningStrategy.EXPLORE,
            experience_retriever=HybridExperienceRetriever(InMemoryExperienceStore()),
        )

        result = planner.plan(_context())

        self.assertEqual(PlanningStrategy.EXPLORE, result.planning_strategy)
        self.assertEqual((), result.experience_refs)
        self.assertIsNotNone(result.learning_snapshot_ref)

    def test_auto_selects_exploit_deterministically_when_stable_exists(self) -> None:
        context = _context().model_copy(update={"seed": 42})
        planner = FactoryPlanningAgent(
            FakeCompletionClient([_composition()]),
            catalog(),
            planning_strategy=PlanningStrategy.AUTO,
            experience_retriever=HybridExperienceRetriever(
                InMemoryExperienceStore((_experience(),))
            ),
        )

        result = planner.plan(context)

        self.assertEqual(PlanningStrategy.EXPLOIT, result.planning_strategy)
        self.assertIsNotNone(result.learning_snapshot_ref)


if __name__ == "__main__":
    unittest.main()
