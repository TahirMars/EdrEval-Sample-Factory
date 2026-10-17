from __future__ import annotations

import unittest

from packages.sample_factory.build_graph import (
    BuildGraphExecutor,
    BuildNode,
    BuildNodeResult,
    BuildPhase,
    FrozenBuildPlan,
)


class _Executor:
    def __init__(self) -> None:
        self.calls = []

    def execute(self, node, inputs):
        self.calls.append((node.node_id, dict(inputs)))
        return BuildNodeResult(
            node_id=node.node_id,
            outputs={item: f"object://intermediates/sha256/{item}" for item in node.output_ids},
        )


class BuildGraphTest(unittest.TestCase):
    def test_executes_frozen_dag_in_dependency_order(self) -> None:
        plan = FrozenBuildPlan(
            plan_id="build-plan-12345678",
            initial_inputs={"source": "object://sources/sha256/source"},
            nodes=(
                BuildNode(
                    node_id="node-build",
                    phase=BuildPhase.BUILD,
                    input_ids=("source",),
                    output_ids=("binary",),
                    executor_ref="executor://build",
                ),
                BuildNode(
                    node_id="node-package",
                    phase=BuildPhase.POST_BUILD,
                    dependencies=("node-build",),
                    input_ids=("binary",),
                    output_ids=("package",),
                    executor_ref="executor://package",
                ),
            ),
            final_output_ids=("package",),
        )
        build, package = _Executor(), _Executor()

        result = BuildGraphExecutor(
            {"executor://build": build, "executor://package": package}
        ).execute(plan)

        self.assertEqual(["node-build", "node-package"], [item.node_id for item in result.node_results])
        self.assertIn("package", result.final_outputs)
        self.assertEqual({"binary": "object://intermediates/sha256/binary"}, package.calls[0][1])

    def test_rejects_cycle_and_unregistered_executor(self) -> None:
        with self.assertRaisesRegex(ValueError, "DAG"):
            FrozenBuildPlan(
                plan_id="build-plan-12345678",
                nodes=(
                    BuildNode(node_id="node-one1", phase="build", dependencies=("node-two2",), output_ids=("one",), executor_ref="executor://x"),
                    BuildNode(node_id="node-two2", phase="build", dependencies=("node-one1",), output_ids=("two",), executor_ref="executor://x"),
                ),
                final_output_ids=("two",),
            )
        plan = FrozenBuildPlan(
            plan_id="build-plan-87654321",
            nodes=(BuildNode(node_id="node-one1", phase="build", output_ids=("one",), executor_ref="executor://missing"),),
            final_output_ids=("one",),
        )
        with self.assertRaisesRegex(ValueError, "未登记"):
            BuildGraphExecutor({}).execute(plan)


if __name__ == "__main__":
    unittest.main()
