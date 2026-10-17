"""Frozen build DAG execution without model-provided commands."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from packages.sample_factory.transform_models import TransformSpec


class BuildPhase(StrEnum):
    SOURCE = "source"
    PRE_BUILD = "pre_build"
    BUILD = "build"
    POST_BUILD = "post_build"
    ASSEMBLE = "assemble"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BuildNode(_FrozenModel):
    node_id: str = Field(pattern=r"^node-[a-z0-9-]{4,}$")
    phase: BuildPhase
    dependencies: tuple[str, ...] = ()
    input_ids: tuple[str, ...] = ()
    output_ids: tuple[str, ...] = Field(min_length=1)
    executor_ref: str = Field(pattern=r"^executor://.+")
    transform_ref: str | None = None
    tool_ref: str | None = None

    @model_validator(mode="after")
    def _node_unique(self) -> Self:
        if len(self.dependencies) != len(set(self.dependencies)):
            raise ValueError("BuildNode dependencies 不得重复")
        if len(self.output_ids) != len(set(self.output_ids)):
            raise ValueError("BuildNode output_ids 不得重复")
        return self


class FrozenBuildPlan(_FrozenModel):
    plan_id: str = Field(pattern=r"^build-plan-[a-z0-9-]{8,}$")
    nodes: tuple[BuildNode, ...] = Field(min_length=1)
    initial_inputs: dict[str, str] = Field(default_factory=dict)
    final_output_ids: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _dag_closure(self) -> Self:
        node_ids = [node.node_id for node in self.nodes]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("FrozenBuildPlan node_id 必须唯一")
        known = set(node_ids)
        if any(dep not in known for node in self.nodes for dep in node.dependencies):
            raise ValueError("FrozenBuildPlan dependency 引用了未知节点")
        if _cycle(node_ids, {(dep, node.node_id) for node in self.nodes for dep in node.dependencies}):
            raise ValueError("FrozenBuildPlan 必须是 DAG")
        output_ids = [output for node in self.nodes for output in node.output_ids]
        if len(output_ids) != len(set(output_ids)):
            raise ValueError("FrozenBuildPlan output_id 必须由唯一节点产生")
        available = set(self.initial_inputs) | set(output_ids)
        if any(input_id not in available for node in self.nodes for input_id in node.input_ids):
            raise ValueError("FrozenBuildPlan input_id 没有生产者")
        if any(item not in output_ids for item in self.final_output_ids):
            raise ValueError("FrozenBuildPlan final_output_ids 没有生产者")
        return self


class BuildNodeResult(_FrozenModel):
    node_id: str
    outputs: dict[str, str]
    diagnostics_ref: str | None = None


class BuiltGraph(_FrozenModel):
    plan_id: str
    node_results: tuple[BuildNodeResult, ...]
    final_outputs: dict[str, str]


class BuildNodeExecutor(Protocol):
    def execute(
        self, node: BuildNode, inputs: Mapping[str, str]
    ) -> BuildNodeResult: ...


class BuildGraphExecutor:
    def __init__(
        self,
        executors: Mapping[str, BuildNodeExecutor],
        transforms: Mapping[str, TransformSpec] | None = None,
    ) -> None:
        self._executors = dict(executors)
        self._transforms = dict(transforms or {})

    def execute(self, plan: FrozenBuildPlan) -> BuiltGraph:
        values = dict(plan.initial_inputs)
        completed: set[str] = set()
        results = []
        pending = list(plan.nodes)
        while pending:
            ready = [
                node
                for node in pending
                if set(node.dependencies).issubset(completed)
            ]
            if not ready:  # pragma: no cover - schema validates DAG
                raise ValueError("BuildGraph 没有可执行节点")
            ready.sort(key=lambda node: node.node_id)
            for node in ready:
                self._validate_transform(node)
                executor = self._executors.get(node.executor_ref)
                if executor is None:
                    raise ValueError(f"未登记 BuildNode executor：{node.executor_ref}")
                inputs = {input_id: values[input_id] for input_id in node.input_ids}
                result = executor.execute(node, inputs)
                if result.node_id != node.node_id:
                    raise ValueError("BuildNodeResult.node_id 与请求不一致")
                if set(result.outputs) != set(node.output_ids):
                    raise ValueError("BuildNodeResult.outputs 与冻结计划不一致")
                if any(not value for value in result.outputs.values()):
                    raise ValueError("BuildNodeResult 输出引用不得为空")
                values.update(result.outputs)
                results.append(result)
                completed.add(node.node_id)
                pending.remove(node)
        return BuiltGraph(
            plan_id=plan.plan_id,
            node_results=tuple(results),
            final_outputs={item: values[item] for item in plan.final_output_ids},
        )

    def _validate_transform(self, node: BuildNode) -> None:
        if node.transform_ref is None:
            if node.tool_ref is not None:
                raise ValueError("无 transform_ref 的 BuildNode 不得携带 tool_ref")
            return
        transform = self._transforms.get(node.transform_ref)
        if transform is None:
            raise ValueError(f"未登记 TransformSpec：{node.transform_ref}")
        if transform.phase is not node.phase or transform.executor_ref != node.executor_ref:
            raise ValueError("BuildNode 与 TransformSpec phase/executor 不一致")
        expected_tool = None if transform.tool is None else transform.tool.tool_ref
        if node.tool_ref != expected_tool:
            raise ValueError("BuildNode 与 TransformSpec tool_ref 不一致")


def _cycle(nodes: list[str], edges: set[tuple[str, str]]) -> bool:
    outgoing: dict[str, list[str]] = {node: [] for node in nodes}
    indegree = dict.fromkeys(nodes, 0)
    for source, target in edges:
        outgoing[source].append(target)
        indegree[target] += 1
    queue = [node for node, value in indegree.items() if value == 0]
    visited = 0
    while queue:
        node = queue.pop()
        visited += 1
        for target in outgoing[node]:
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    return visited != len(nodes)


__all__ = [
    "BuildGraphExecutor",
    "BuildNode",
    "BuildNodeExecutor",
    "BuildNodeResult",
    "BuildPhase",
    "BuiltGraph",
    "FrozenBuildPlan",
]
