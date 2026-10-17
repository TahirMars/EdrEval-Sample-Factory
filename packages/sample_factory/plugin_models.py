"""Typed contracts for one-plugin authoring and independent validation."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from packages.sample_factory.models import AtomRole, AtomSpec, SafetyProfile
from packages.sample_factory.plugin_contract import (
    PLUGIN_ABI_VERSION,
    canonical_source_paths,
    plugin_entry_symbol,
    validate_implementation_name,
)

_CAPABILITY_RE = re.compile(r"cap\.[a-z0-9][a-z0-9._-]*")
_PORT_RE = re.compile(r"port\.[a-z0-9][a-z0-9._-]*")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SOURCE_SUFFIXES = frozenset(
    {
        ".asm",
        ".c",
        ".cc",
        ".cpp",
        ".def",
        ".h",
        ".hpp",
        ".idl",
        ".inl",
        ".rc",
        ".s",
        ".vcxproj",
    }
)


class PluginOperation(StrEnum):
    CREATE = "create"
    REPAIR = "repair"
    UPGRADE = "upgrade"
    GENERALIZE = "generalize"


class PluginLifecycleStatus(StrEnum):
    REQUESTED = "requested"
    SCAFFOLDED = "scaffolded"
    COMPILE_VALID = "compile_valid"
    CONTRACT_VALID = "contract_valid"
    ATOM_VALID = "atom_valid"
    BEHAVIOR_VALID = "behavior_valid"
    REVIEWED = "reviewed"
    DISPATCHABLE = "dispatchable"
    FAILED = "failed"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PortContract(_FrozenModel):
    port_id: str
    value_type: str = Field(min_length=1)
    semantic: str = Field(min_length=1)
    architecture: Literal["x86", "x64", "any"] = "any"
    required: bool = True

    @field_validator("port_id")
    @classmethod
    def _port_id(cls, value: str) -> str:
        if not _PORT_RE.fullmatch(value):
            raise ValueError("port_id 必须符合 port.<name>")
        return value


class TechniqueIntent(_FrozenModel):
    intent_id: str = Field(pattern=r"^intent-[a-z0-9-]{8,}$")
    ph_ids: tuple[str, ...] = ()
    role: AtomRole
    required_capabilities: tuple[str, ...] = ()
    provided_capabilities: tuple[str, ...] = Field(min_length=1)
    input_ports: tuple[PortContract, ...] = ()
    output_ports: tuple[PortContract, ...] = ()
    parameter_domains: dict[str, tuple[Any, ...]] = Field(default_factory=dict)
    produces_handoffs: tuple[str, ...] = ()
    consumes_handoffs: tuple[str, ...] = ()
    artifact_ref: str | None = None
    platform: Literal["windows"] = "windows"
    architecture: Literal["x86", "x64"]
    safety_profile: SafetyProfile
    verification_contract_ref: str | None = None
    source_refs: tuple[str, ...] = Field(min_length=1)

    @field_validator("required_capabilities", "provided_capabilities")
    @classmethod
    def _capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(
            not _CAPABILITY_RE.fullmatch(item) for item in value
        ):
            raise ValueError("capability 必须唯一且符合 cap.<name>")
        return value

    @field_validator("produces_handoffs", "consumes_handoffs")
    @classmethod
    def _handoffs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("handoff id 不得重复")
        for item in value:
            if not item.startswith("handoff://") or len(item) < len("handoff://x"):
                raise ValueError(f"handoff id 必须是 handoff://… 引用：{item}")
        return value

    @field_validator("artifact_ref")
    @classmethod
    def _artifact_ref(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.startswith(("payload://", "lab-secret://", "secret://")):
            raise ValueError("artifact_ref 只允许 payload:// 或 lab-secret:// / secret://")
        return value

    @model_validator(mode="after")
    def _ports_unique(self) -> Self:
        port_ids = [item.port_id for item in (*self.input_ports, *self.output_ports)]
        if len(port_ids) != len(set(port_ids)):
            raise ValueError("TechniqueIntent port_id 不得重复")
        if self.role is not AtomRole.CARRIER and not self.input_ports:
            raise ValueError("非 carrier TTP 插件必须声明至少一个输入 Port")
        # PH-IN08 also permits loader variants; PH-IN01..07 are unambiguous execution atoms.
        injection_execution_ph = {f"PH-IN{index:02d}" for index in range(1, 8)}
        matched = sorted(set(self.ph_ids) & injection_execution_ph)
        if matched and self.role is not AtomRole.EXECUTION_ATOM:
            raise ValueError(f"{matched} 按主机执行原子契约必须使用 execution_atom 角色")
        if self.artifact_ref is not None and not self.produces_handoffs:
            raise ValueError("embed artifact_ref 必须声明 produces_handoffs")
        if self.produces_handoffs and self.consumes_handoffs:
            overlap = sorted(set(self.produces_handoffs) & set(self.consumes_handoffs))
            if overlap:
                raise ValueError(f"TechniqueIntent 不得自产自消 handoff：{overlap}")
        return self

    @field_validator("parameter_domains")
    @classmethod
    def _parameter_domains(cls, value: dict[str, tuple[Any, ...]]) -> dict[str, tuple[Any, ...]]:
        if any(not key or not values for key, values in value.items()):
            raise ValueError("parameter_domains 的参数名和候选值域不得为空")
        return value


class PluginRequest(_FrozenModel):
    schema_version: Literal["sample-factory-plugin-request-v2"] = "sample-factory-plugin-request-v2"
    request_id: str = Field(pattern=r"^plugin-request-[a-z0-9-]{8,}$")
    operation: PluginOperation
    implementation_name: str
    intent: TechniqueIntent
    build_target_ref: str = Field(pattern=r"^build-target://.+")
    harness_ref: str | None = Field(default=None, pattern=r"^plugin-harness://.+")
    profile_id: str = Field(min_length=1)
    intake_ref: str | None = Field(
        default=None, pattern=r"^plugin-intake://plugin-intake-[a-z0-9-]{8,79}$"
    )
    seed_source_ref: str | None = Field(
        default=None, pattern=r"^plugin-seed://atom\.[a-z0-9][a-z0-9._-]*$"
    )
    requested_by_run_id: str | None = None

    @field_validator("implementation_name")
    @classmethod
    def _implementation_name(cls, value: str) -> str:
        return validate_implementation_name(value)

    @property
    def entry_symbol(self) -> str:
        return plugin_entry_symbol(self.implementation_name)

    @property
    def seed_plugin_id(self) -> str | None:
        if self.seed_source_ref is None:
            return None
        return self.seed_source_ref.removeprefix("plugin-seed://")

    @field_validator("requested_by_run_id")
    @classmethod
    def _parent_run(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("run-"):
            raise ValueError("requested_by_run_id 必须以 run- 开头")
        return value


class PluginDependency(_FrozenModel):
    producer_request_id: str = Field(pattern=r"^plugin-request-[a-z0-9-]{8,}$")
    consumer_request_id: str = Field(pattern=r"^plugin-request-[a-z0-9-]{8,}$")
    capability: str = Field(pattern=r"^cap\.[a-z0-9][a-z0-9._-]*$")
    producer_port_id: str | None = Field(default=None, pattern=r"^port\.[a-z0-9][a-z0-9._-]*$")
    consumer_port_id: str | None = Field(default=None, pattern=r"^port\.[a-z0-9][a-z0-9._-]*$")

    @model_validator(mode="after")
    def _not_self(self) -> Self:
        if self.producer_request_id == self.consumer_request_id:
            raise ValueError("PluginDependency 不得指向自身")
        if (self.producer_port_id is None) != (self.consumer_port_id is None):
            raise ValueError("PluginDependency 端口绑定必须同时声明 producer/consumer")
        return self


class PluginDecompositionPlan(_FrozenModel):
    plan_id: str = Field(pattern=r"^plugin-plan-[a-z0-9-]{8,79}$")
    summary: str = Field(min_length=1, max_length=4000)
    requests: tuple[PluginRequest, ...] = Field(min_length=1, max_length=16)
    dependencies: tuple[PluginDependency, ...] = ()
    external_capabilities: tuple[str, ...] = ()

    @field_validator("external_capabilities")
    @classmethod
    def _external_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(
            not _CAPABILITY_RE.fullmatch(item) for item in value
        ):
            raise ValueError("external_capabilities 必须唯一且符合 cap.<name>")
        return value

    @model_validator(mode="after")
    def _graph_is_valid(self) -> Self:
        request_ids = [item.request_id for item in self.requests]
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("PluginDecompositionPlan request_id 不得重复")
        implementation_names = [item.implementation_name for item in self.requests]
        if len(implementation_names) != len(set(implementation_names)):
            raise ValueError("PluginDecompositionPlan implementation_name 不得重复")
        known = set(request_ids)
        edges: dict[str, set[str]] = {item: set() for item in request_ids}
        inbound_capabilities: dict[str, set[str]] = {item: set() for item in request_ids}
        for dependency in self.dependencies:
            if (
                dependency.producer_request_id not in known
                or dependency.consumer_request_id not in known
            ):
                raise ValueError("PluginDependency 引用了计划外 request_id")
            producer = next(
                item for item in self.requests if item.request_id == dependency.producer_request_id
            )
            consumer = next(
                item for item in self.requests if item.request_id == dependency.consumer_request_id
            )
            if dependency.capability not in producer.intent.provided_capabilities:
                raise ValueError("依赖能力不是 producer 的 provided_capabilities")
            if dependency.capability not in consumer.intent.required_capabilities:
                raise ValueError("依赖能力不是 consumer 的 required_capabilities")
            if dependency.producer_port_id is not None:
                producer_port = next(
                    (
                        item
                        for item in producer.intent.output_ports
                        if item.port_id == dependency.producer_port_id
                    ),
                    None,
                )
                consumer_port = next(
                    (
                        item
                        for item in consumer.intent.input_ports
                        if item.port_id == dependency.consumer_port_id
                    ),
                    None,
                )
                if producer_port is None or consumer_port is None:
                    raise ValueError("PluginDependency 引用了不存在的输入/输出 Port")
                if producer_port.value_type != consumer_port.value_type:
                    raise ValueError("PluginDependency Port value_type 不兼容")
                architectures = {producer_port.architecture, consumer_port.architecture}
                if "any" not in architectures and len(architectures) != 1:
                    raise ValueError("PluginDependency Port architecture 不兼容")
            if dependency.consumer_request_id in edges[dependency.producer_request_id]:
                raise ValueError("PluginDependency 不得重复")
            edges[dependency.producer_request_id].add(dependency.consumer_request_id)
            inbound_capabilities[dependency.consumer_request_id].add(dependency.capability)
        external = set(self.external_capabilities)
        for request in self.requests:
            unresolved = set(request.intent.required_capabilities) - (
                inbound_capabilities[request.request_id] | external
            )
            if unresolved:
                raise ValueError(
                    f"{request.request_id} required_capabilities 未由依赖边或 external_capabilities 提供"
                )
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> None:
            if node in visiting:
                raise ValueError("PluginDecompositionPlan 依赖图存在环")
            if node in visited:
                return
            visiting.add(node)
            for child in edges[node]:
                visit(child)
            visiting.remove(node)
            visited.add(node)

        for request_id in request_ids:
            visit(request_id)
        return self


class PluginSourceCandidate(_FrozenModel):
    plugin_id: str = Field(pattern=r"^atom\.[a-z0-9][a-z0-9._-]*$")
    implementation_name: str
    source_ref: str = Field(pattern=r"^plugin-source://.+")
    source_digest: str
    changed_files: tuple[str, ...] = Field(min_length=1)
    # Source may reach compile_valid before governance/validation produces a full AtomSpec.
    atom_spec: AtomSpec | None = None
    required_capabilities: tuple[str, ...] = ()
    provided_capabilities: tuple[str, ...] = Field(min_length=1)
    input_ports: tuple[PortContract, ...] = ()
    output_ports: tuple[PortContract, ...] = ()

    @field_validator("implementation_name")
    @classmethod
    def _implementation_name(cls, value: str) -> str:
        return validate_implementation_name(value)

    @field_validator("source_digest")
    @classmethod
    def _source_digest(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("plugin source_digest 必须是 sha256")
        return value

    @field_validator("changed_files")
    @classmethod
    def _changed_files(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("plugin changed_files 不得重复")
        for item in value:
            path = PurePosixPath(item)
            if (
                path.is_absolute()
                or ".." in path.parts
                or path.suffix.lower() not in _SOURCE_SUFFIXES
            ):
                raise ValueError(f"plugin changed_files 路径非法：{item}")
        return value

    @model_validator(mode="after")
    def _canonical_implementation_files(self) -> Self:
        missing = sorted(set(canonical_source_paths(self.implementation_name)) - set(self.changed_files))
        if missing:
            raise ValueError(f"plugin changed_files 缺少规范实现文件：{missing}")
        forbidden = {"main", "wmain", "winmain", "wwinmain", "dllmain"}
        if any(PurePosixPath(item).stem.lower() in forbidden for item in self.changed_files):
            raise ValueError("TTP 插件候选不得携带 main/DllMain 入口源码")
        return self


class PluginBuildResult(_FrozenModel):
    build_ref: str = Field(pattern=r"^plugin-build://.+")
    artifact_ref: str = Field(pattern=r"^plugin-build-artifact://.+")
    artifact_sha256: str
    source_digest: str
    implementation_source_digest: str
    artifact_filename: str
    purpose: Literal["validation_only"] = "validation_only"
    abi_version: Literal["edreval-ttp-c-v1"] = PLUGIN_ABI_VERSION
    toolchain_fp: str = Field(min_length=1)
    build_id: str = Field(min_length=1)

    @field_validator("source_digest", "implementation_source_digest", "artifact_sha256")
    @classmethod
    def _source_digest(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("plugin build source_digest 必须是 sha256")
        return value

    @field_validator("artifact_filename")
    @classmethod
    def _artifact_filename(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.name != value or path.suffix.lower() != ".lib":
            raise ValueError("plugin validation artifact 必须是无目录的 .lib 文件名")
        return value


class PluginValidationResult(_FrozenModel):
    harness_ref: str = Field(pattern=r"^plugin-harness://.+")
    contract_valid: bool
    atom_valid: bool
    behavior_valid: bool
    evidence_ref: str = Field(min_length=1)
    assertions: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _ordered_truth(self) -> Self:
        if self.atom_valid and not self.contract_valid:
            raise ValueError("atom_valid 要求 contract_valid")
        if self.behavior_valid and not self.atom_valid:
            raise ValueError("behavior_valid 要求 atom_valid")
        return self


class PluginAuthoringResult(_FrozenModel):
    plugin_run_id: str = Field(pattern=r"^plugin-run-[a-z0-9-]{8,}$")
    request_id: str
    status: PluginLifecycleStatus
    source: PluginSourceCandidate | None = None
    build: PluginBuildResult | None = None
    validation: PluginValidationResult | None = None
    compile_only_reason: Literal[
        "independent_harness_not_configured",
        "atom_spec_governance_pending",
    ] | None = None
    failure_stage: str | None = None
    error: str | None = None

    @model_validator(mode="after")
    def _result_invariants(self) -> Self:
        if self.status is PluginLifecycleStatus.BEHAVIOR_VALID and (
            self.source is None
            or self.source.atom_spec is None
            or self.build is None
            or self.validation is None
            or not self.validation.behavior_valid
        ):
            raise ValueError("behavior_valid 结果必须携带源码、构建和通过的验证回执")
        if self.status is PluginLifecycleStatus.FAILED and not self.failure_stage:
            raise ValueError("FAILED plugin run 必须记录 failure_stage")
        if (
            self.status is not PluginLifecycleStatus.COMPILE_VALID
            and self.compile_only_reason is not None
        ):
            raise ValueError("compile_only_reason 仅允许用于 compile_valid 结果")
        if self.status in {
            PluginLifecycleStatus.REVIEWED,
            PluginLifecycleStatus.DISPATCHABLE,
        }:
            raise ValueError("PluginAuthoringPipeline 不得直接产生 reviewed/dispatchable")
        return self


__all__ = [
    "PluginAuthoringResult",
    "PluginBuildResult",
    "PluginDecompositionPlan",
    "PluginDependency",
    "PluginLifecycleStatus",
    "PluginOperation",
    "PluginRequest",
    "PluginSourceCandidate",
    "PluginValidationResult",
    "PortContract",
    "TechniqueIntent",
]
