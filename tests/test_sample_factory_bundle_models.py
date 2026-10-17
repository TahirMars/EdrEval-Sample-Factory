from __future__ import annotations

import unittest

from packages.sample_factory.bundle_models import (
    ArtifactMember,
    ArtifactSet,
    ExecutionStage,
    SampleBundle,
    StageHandoff,
)


def _member(member_id: str = "member-12345678", path: str = "sample.exe") -> ArtifactMember:
    return ArtifactMember(
        member_id=member_id,
        role="entry",
        relative_path=path,
        artifact_ref="object://artifacts/sha256/" + "a" * 64,
        sha256="a" * 64,
        format="pe",
    )


class BundleModelsTest(unittest.TestCase):
    def test_two_stage_bundle_validates_dag_and_artifact_members(self) -> None:
        first = ArtifactSet(
            artifact_set_id="artifact-set-12345678",
            members=(_member(),),
            entry_member_id="member-12345678",
        )
        second = ArtifactSet(
            artifact_set_id="artifact-set-87654321",
            members=(_member("member-87654321", "stage2.dll"),),
            entry_member_id="member-87654321",
        )
        bundle = SampleBundle(
            bundle_id="bundle-12345678",
            stages=(
                ExecutionStage(
                    stage_id="stage-01",
                    artifact_set_id=first.artifact_set_id,
                    trigger_mode="lab_trigger",
                ),
                ExecutionStage(
                    stage_id="stage-02",
                    artifact_set_id=second.artifact_set_id,
                    trigger_mode="lab_trigger",
                ),
            ),
            artifact_sets=(first, second),
            handoffs=(
                StageHandoff(
                    from_stage_id="stage-01",
                    to_stage_id="stage-02",
                    output_ref="object://artifacts/sha256/" + "a" * 64,
                    input_port="port.stage2.input",
                ),
            ),
            entry_stage_id="stage-01",
        )
        self.assertEqual("bundle-12345678", bundle.bundle_id)

    def test_bundle_rejects_cycle_and_duplicate_paths(self) -> None:
        with self.assertRaisesRegex(ValueError, "relative_path"):
            ArtifactSet(
                artifact_set_id="artifact-set-12345678",
                members=(_member(), _member("member-87654321", "SAMPLE.EXE")),
                entry_member_id="member-12345678",
            )

        first = ArtifactSet(
            artifact_set_id="artifact-set-12345678",
            members=(_member(),),
            entry_member_id="member-12345678",
        )
        with self.assertRaisesRegex(ValueError, "DAG"):
            SampleBundle(
                bundle_id="bundle-12345678",
                stages=(
                    ExecutionStage(stage_id="stage-01", artifact_set_id=first.artifact_set_id, trigger_mode="x"),
                    ExecutionStage(stage_id="stage-02", artifact_set_id=first.artifact_set_id, trigger_mode="x"),
                ),
                artifact_sets=(first,),
                handoffs=(
                    StageHandoff(from_stage_id="stage-01", to_stage_id="stage-02", output_ref="x", input_port="y"),
                    StageHandoff(from_stage_id="stage-02", to_stage_id="stage-01", output_ref="x", input_port="y"),
                ),
                entry_stage_id="stage-01",
            )


if __name__ == "__main__":
    unittest.main()
