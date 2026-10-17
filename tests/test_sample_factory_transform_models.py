from __future__ import annotations

import unittest

from packages.sample_factory.build_graph import (
    BuildGraphExecutor,
    BuildNode,
    BuildNodeResult,
    FrozenBuildPlan,
)
from packages.sample_factory.transform_models import ToolFingerprint, TransformSpec


class _Executor:
    def execute(self, node, inputs):
        del inputs
        return BuildNodeResult(node_id=node.node_id, outputs={node.output_ids[0]: "object://x"})


class TransformModelsTest(unittest.TestCase):
    def test_registered_transform_binds_phase_executor_and_tool(self) -> None:
        transform = TransformSpec(
            transform_ref="transform://package/msi/v1",
            version=1,
            phase="post_build",
            input_types=("pe",),
            output_types=("msi",),
            executor_ref="executor://msi",
            tool=ToolFingerprint(
                tool_ref="tool://wix/4",
                version="4.0",
                sha256="a" * 64,
                license_ref="license://wix",
            ),
            deterministic=False,
        )
        node = BuildNode(
            node_id="node-msi1",
            phase="post_build",
            output_ids=("msi",),
            executor_ref="executor://msi",
            transform_ref=transform.transform_ref,
            tool_ref=transform.tool.tool_ref,
        )
        plan = FrozenBuildPlan(
            plan_id="build-plan-12345678",
            nodes=(node,),
            final_output_ids=("msi",),
        )

        result = BuildGraphExecutor(
            {"executor://msi": _Executor()}, {transform.transform_ref: transform}
        ).execute(plan)
        self.assertIn("msi", result.final_outputs)

    def test_unregistered_transform_is_rejected_before_executor(self) -> None:
        plan = FrozenBuildPlan(
            plan_id="build-plan-12345678",
            nodes=(
                BuildNode(
                    node_id="node-msi1",
                    phase="post_build",
                    output_ids=("msi",),
                    executor_ref="executor://msi",
                    transform_ref="transform://missing",
                ),
            ),
            final_output_ids=("msi",),
        )
        with self.assertRaisesRegex(ValueError, "TransformSpec"):
            BuildGraphExecutor({"executor://msi": _Executor()}).execute(plan)


if __name__ == "__main__":
    unittest.main()
