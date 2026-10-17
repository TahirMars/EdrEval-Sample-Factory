from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.experience_extractor import ExperienceExtractor

from tests.sample_factory_fixtures import atom_specs
from tests.test_sample_factory_ai_pipeline import AIDrivenPipelineTest, FakeCompiler


class ExperienceExtractorTest(unittest.TestCase):
    def test_verified_result_becomes_behavior_valid_proposal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = AIDrivenPipelineTest()
            factory, _, _, _ = fixture._factory(tmp, FakeCompiler())
            result = factory.produce(fixture._request())
            specs = atom_specs()

            proposal = ExperienceExtractor(Path(tmp) / "proposals").extract_success(
                result,
                specs,
                capabilities_by_atom={
                    spec.atom_id: (f"cap.{spec.role.value}",) for spec in specs
                },
                architecture="x64",
            )

            self.assertIsNotNone(proposal)
            assert proposal is not None
            payload = json.loads(proposal.read_text(encoding="utf-8"))
            self.assertEqual("behavior_valid", payload["maturity"])
            self.assertEqual(list(result.plan.recipe.atom_ids), payload["atom_ids"])
            self.assertIn(f"factory-run://{result.run_id}", payload["evidence_refs"])

    def test_missing_capability_contract_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = AIDrivenPipelineTest()
            factory, _, _, _ = fixture._factory(tmp, FakeCompiler())
            result = factory.produce(fixture._request())

            with self.assertRaisesRegex(ValueError, "capabilities"):
                ExperienceExtractor(Path(tmp) / "proposals").extract_success(
                    result,
                    atom_specs(),
                    capabilities_by_atom={},
                    architecture="x64",
                )


if __name__ == "__main__":
    unittest.main()
