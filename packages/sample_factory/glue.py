"""模板优先、无头 coding agent 兜底的胶水协调器。

Agent 只在外部 ``plugin-workspace://`` 工作区改源码。控制面不接收源码正文，
只验证变更路径、会话引用和源码摘要；构建命令来自 ``build-target://`` 注册项。
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Protocol

from packages.sample_factory.errors import CatalogError, SampleFactoryError
from packages.sample_factory.handoff import materialize_items_for
from packages.sample_factory.identity import canonical_json
from packages.sample_factory.injection_contract import glue_injection_contracts
from packages.sample_factory.models import (
    AgentWorkspaceResult,
    AtomSpec,
    GlueOrigin,
    GlueResolution,
    GlueTask,
    SampleRecipe,
    TemplateStatus,
)

_SOURCE_SUFFIXES = frozenset(
    {
        ".asm",
        ".c",
        ".cc",
        ".cpp",
        ".def",
        ".go",
        ".h",
        ".hpp",
        ".idl",
        ".inl",
        ".manifest",
        ".rc",
        ".rs",
        ".s",
        ".vcxproj",
    }
)


class GlueError(SampleFactoryError, ValueError):
    """胶水模板或 Agent 工作区结果非法。"""


class HeadlessCodingAgent(Protocol):
    """pi/opencode/其他 harness 的可替换驱动合同。"""

    def run(self, task: GlueTask) -> AgentWorkspaceResult: ...


@dataclass(frozen=True)
class GlueTemplate:
    signature: str
    template_ref: str
    source_digest: str


@dataclass(frozen=True)
class TemplateStats:
    attempts: int = 0
    functional_successes: int = 0

    @property
    def success_rate(self) -> float:
        return 0.0 if self.attempts == 0 else self.functional_successes / self.attempts

    @property
    def status(self) -> TemplateStatus:
        if self.functional_successes >= 10 and self.success_rate >= 0.8:
            return TemplateStatus.VERIFIED
        if self.functional_successes >= 3:
            return TemplateStatus.CANDIDATE
        return TemplateStatus.OBSERVED


class GlueCoordinator:
    """解析已验证模板；未命中时发起受限 AgentSession。"""

    def __init__(self, agent: HeadlessCodingAgent) -> None:
        self._agent = agent
        self._templates: dict[str, GlueTemplate] = {}
        self._stats: dict[str, TemplateStats] = {}

    def resolve(
        self,
        recipe: SampleRecipe,
        specs: tuple[AtomSpec, ...],
        atom_parameters: Mapping[str, Mapping[str, object]],
        *,
        workspace_ref: str,
        build_target_ref: str,
        force_agent: bool = False,
    ) -> GlueResolution:
        signature = glue_signature(recipe, specs)
        template = self._templates.get(signature)
        if template is not None and not force_agent:
            return GlueResolution(
                signature=signature,
                origin=GlueOrigin.TEMPLATE,
                source_ref=template.template_ref,
                source_digest=template.source_digest,
            )

        task = self._task(
            signature,
            recipe,
            specs,
            atom_parameters,
            workspace_ref=workspace_ref,
            build_target_ref=build_target_ref,
        )
        result = self._agent.run(task)
        self._validate_agent_result(task, result)
        return GlueResolution(
            signature=signature,
            origin=GlueOrigin.AGENT,
            source_ref=result.workspace_ref,
            source_digest=result.source_digest,
            session_ref=result.session_ref,
            changed_files=result.changed_files,
        )

    def repair(
        self,
        previous: GlueResolution,
        recipe: SampleRecipe,
        specs: tuple[AtomSpec, ...],
        atom_parameters: Mapping[str, Mapping[str, object]],
        *,
        workspace_ref: str,
        build_target_ref: str,
        diagnostics_ref: str,
    ) -> GlueResolution:
        if previous.session_ref is None:
            raise GlueError("确定性模板失败不能伪装成可续接 AgentSession")
        base = self._task(
            previous.signature,
            recipe,
            specs,
            atom_parameters,
            workspace_ref=workspace_ref,
            build_target_ref=build_target_ref,
        )
        task = base.model_copy(
            update={
                "repair_of_session": previous.session_ref,
                "diagnostics_ref": diagnostics_ref,
            }
        )
        result = self._agent.run(task)
        self._validate_agent_result(task, result)
        return GlueResolution(
            signature=previous.signature,
            origin=GlueOrigin.AGENT,
            source_ref=result.workspace_ref,
            source_digest=result.source_digest,
            session_ref=result.session_ref,
            changed_files=result.changed_files,
        )

    def record_functional_truth(
        self,
        resolution: GlueResolution,
        *,
        v2_passed: bool,
        v3_passed: bool,
    ) -> TemplateStats:
        old = self._stats.get(resolution.signature, TemplateStats())
        success = v2_passed and v3_passed
        updated = TemplateStats(
            attempts=old.attempts + 1,
            functional_successes=old.functional_successes + int(success),
        )
        self._stats[resolution.signature] = updated
        return updated

    def promote(
        self,
        signature: str,
        *,
        template_ref: str,
        source_digest: str,
    ) -> None:
        stats = self._stats.get(signature, TemplateStats())
        if stats.status is not TemplateStatus.VERIFIED:
            raise GlueError("模板尚未达到 >=10 样本且 V2/V3 通过率 >=80% 的晋升门槛")
        if not template_ref.startswith("glue-template://"):
            raise GlueError("template_ref 必须是外部 glue-template:// 引用")
        if len(source_digest) != 64 or any(ch not in "0123456789abcdef" for ch in source_digest):
            raise GlueError("source_digest 必须是 sha256")
        self._templates[signature] = GlueTemplate(signature, template_ref, source_digest)

    @staticmethod
    def _task(
        signature: str,
        recipe: SampleRecipe,
        specs: tuple[AtomSpec, ...],
        atom_parameters: Mapping[str, Mapping[str, object]],
        *,
        workspace_ref: str,
        build_target_ref: str,
    ) -> GlueTask:
        try:
            injection_contracts = glue_injection_contracts(specs, atom_parameters)
        except CatalogError as exc:
            raise GlueError(str(exc)) from exc
        return GlueTask(
            task_id=f"glue-{signature[:16]}",
            recipe_id=recipe.recipe_id,
            workspace_ref=workspace_ref,
            atom_ids=recipe.atom_ids,
            ph_ids=recipe.ph_ids,
            atom_ph_ids=tuple(spec.ph_ids for spec in specs),
            trigger_mode=recipe.trigger_mode,
            execution_logging=recipe.execution_logging,
            pointer_mode=recipe.pointer_mode,
            atom_parameters={
                atom_id: dict(atom_parameters.get(atom_id, {})) for atom_id in recipe.atom_ids
            },
            input_contracts=tuple(spec.inputs_schema_ref for spec in specs),
            output_contracts=tuple(spec.output_contract for spec in specs),
            handoff_contracts=tuple(spec.handoff_contract for spec in specs),
            produces_handoffs=tuple(spec.produces_handoffs for spec in specs),
            consumes_handoffs=tuple(spec.consumes_handoffs for spec in specs),
            materialize_items=materialize_items_for(specs),
            injection_contracts=injection_contracts,
            build_target_ref=build_target_ref,
        )

    @staticmethod
    def _validate_agent_result(task: GlueTask, result: AgentWorkspaceResult) -> None:
        if result.workspace_ref != task.workspace_ref:
            raise GlueError("Agent 结果越出了获批 workspace_ref")
        if len(result.changed_files) > 64:
            raise GlueError("Agent 单次改动文件数超过 64")
        if len(set(result.changed_files)) != len(result.changed_files):
            raise GlueError("Agent changed_files 不得重复")
        for item in result.changed_files:
            path = PurePosixPath(item)
            if (
                path.is_absolute()
                or ".." in path.parts
                or path.suffix.lower() not in _SOURCE_SUFFIXES
            ):
                raise GlueError(f"Agent 变更路径越界或不是允许的源码类型：{item}")
            if any(
                part.lower() in {"release", "debug", "x64", "bin", "obj"} for part in path.parts
            ):
                raise GlueError(f"Agent 不得把构建产物目录作为源码变更：{item}")


def glue_signature(recipe: SampleRecipe, specs: tuple[AtomSpec, ...]) -> str:
    if tuple(spec.atom_id for spec in specs) != recipe.atom_ids:
        raise GlueError("AtomSpec 顺序必须与 SampleRecipe.atom_ids 一致")
    payload = {
        "atom_ids": recipe.atom_ids,
        "c2_pointer_schemas": [spec.c2_pointer_schema for spec in specs],
        "handoff_contracts": [spec.handoff_contract for spec in specs],
        "produces_handoffs": [list(spec.produces_handoffs) for spec in specs],
        "consumes_handoffs": [list(spec.consumes_handoffs) for spec in specs],
        "materialize": [spec.materialize.value for spec in specs],
        "artifact_refs": [spec.artifact_ref for spec in specs],
        "input_contracts": [spec.inputs_schema_ref for spec in specs],
        "output_contracts": [spec.output_contract for spec in specs],
        "execution_logging": recipe.execution_logging,
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


__all__ = [
    "GlueCoordinator",
    "GlueError",
    "GlueTemplate",
    "HeadlessCodingAgent",
    "TemplateStats",
    "glue_signature",
]
