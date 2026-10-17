"""Operator-owned seed source author for jointly verifiable TTP plugins."""

from __future__ import annotations

import shutil
from collections.abc import Callable
from pathlib import Path, PurePosixPath

from packages.sample_factory.catalog import CoverageRegistry
from packages.sample_factory.compiler import source_tree_digest, source_tree_files
from packages.sample_factory.models import (
    AtomRole,
    AtomSpec,
    HandoffMaterialize,
    IntegrationState,
    TriggerMode,
)
from packages.sample_factory.plugin_contract import (
    canonical_source_paths,
    validate_candidate_source_snapshot,
)
from packages.sample_factory.plugin_models import PluginRequest, PluginSourceCandidate

_ALLOWED_SUFFIXES = frozenset(
    {".asm", ".c", ".cc", ".cpp", ".def", ".h", ".hpp", ".idl", ".inl", ".rc", ".s", ".vcxproj"}
)
_SKIP_GENERATED_PREFIXES = ("handoff_",)
# 蓝本 §5.1 核心族 + 主机执行扩展族；仅 injection 触发牺牲进程合同。
_VARIANT_FAMILY_BY_ATOM_PREFIX = {
    "in": "injection",
    "ob": "obfuscation",
    "pe": "privesc",
    "ps": "persistence",
    "bl": "blind",
    "di": "discovery",
    "ex": "execution",
    "it": "tool_transfer",
    "hj": "hijack",
    "ia": "delivery",
    "ld": "payload",
    "payload": "payload",
}
_VARIANT_FAMILY_BY_PH_PREFIX = {
    "IN": "injection",
    "OB": "obfuscation",
    "PE": "privesc",
    "PS": "persistence",
    "BL": "blind",
    "DI": "discovery",
    "EX": "execution",
    "IT": "tool_transfer",
    "HJ": "hijack",
    "IA": "delivery",
}


def variant_family_for_plugin(
    plugin_id: str,
    *,
    role: AtomRole,
    ph_ids: tuple[str, ...] = (),
) -> str:
    """Derive AtomSpec.variant_family from atom id / role / PH — never default all to injection."""
    if role is AtomRole.LOADER_ATOM:
        return "payload"
    parts = plugin_id.split(".")
    if len(parts) >= 2 and parts[0] == "atom":
        prefix = parts[1]
        if prefix in _VARIANT_FAMILY_BY_ATOM_PREFIX:
            return _VARIANT_FAMILY_BY_ATOM_PREFIX[prefix]
    for ph_id in ph_ids:
        token = ph_id.removeprefix("PH-")
        family_key = "".join(ch for ch in token if ch.isalpha())
        if family_key[:2] in _VARIANT_FAMILY_BY_PH_PREFIX:
            return _VARIANT_FAMILY_BY_PH_PREFIX[family_key[:2]]
        if family_key in _VARIANT_FAMILY_BY_PH_PREFIX:
            return _VARIANT_FAMILY_BY_PH_PREFIX[family_key]
    raise ValueError(
        f"无法推导 variant_family：plugin_id={plugin_id} ph_ids={list(ph_ids)}"
    )


class SeedPluginAuthoringBackend:
    """Copy a catalog candidate tree; do not invent PH/capability contracts."""

    def __init__(
        self,
        catalog_root: str | Path,
        root_resolver: Callable[[str], Path],
        *,
        coverage: CoverageRegistry | None = None,
    ) -> None:
        self._catalog_root = Path(catalog_root).resolve()
        self._root_resolver = root_resolver
        self._coverage = coverage

    def author(self, request: PluginRequest, *, plugin_run_id: str) -> PluginSourceCandidate:
        plugin_id = request.seed_plugin_id
        if plugin_id is None:
            raise ValueError("SeedPluginAuthoringBackend 需要 plugin-seed:// atom id")
        seed_root = (self._catalog_root / "plugins" / "candidate" / plugin_id).resolve()
        candidate_root = (self._catalog_root / "plugins" / "candidate").resolve()
        if not seed_root.is_relative_to(candidate_root) or not seed_root.is_dir():
            raise FileNotFoundError(f"插件种子不存在：{plugin_id}")
        final_root = self._root_resolver(plugin_run_id).resolve()
        if final_root.exists():
            raise FileExistsError(f"plugin candidate source 已存在：{final_root}")
        final_root.mkdir(parents=True, mode=0o700)
        copied: list[str] = []
        for path in source_tree_files(seed_root):
            relative = path.relative_to(seed_root).as_posix()
            posix = PurePosixPath(relative)
            if posix.suffix.lower() not in _ALLOWED_SUFFIXES:
                continue
            if posix.parts[:1] == ("generated",) and posix.name.startswith(_SKIP_GENERATED_PREFIXES):
                continue
            destination = (final_root / relative).resolve()
            if not destination.is_relative_to(final_root):
                raise ValueError(f"插件种子路径越界：{relative}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            copied.append(relative)
        snapshot = {
            path.relative_to(final_root).as_posix(): path.read_text(encoding="utf-8")
            for path in source_tree_files(final_root)
        }
        validate_candidate_source_snapshot(snapshot, request.implementation_name)
        missing = sorted(set(canonical_source_paths(request.implementation_name)) - set(copied))
        if missing:
            raise ValueError(f"插件种子缺少规范实现文件：{missing}")
        return PluginSourceCandidate(
            plugin_id=plugin_id,
            implementation_name=request.implementation_name,
            source_ref=f"plugin-source://{plugin_run_id}/final-source",
            source_digest=source_tree_digest(final_root),
            changed_files=tuple(sorted(copied)),
            atom_spec=_atom_spec_from_request(plugin_id, request, self._coverage),
            required_capabilities=request.intent.required_capabilities,
            provided_capabilities=request.intent.provided_capabilities,
            input_ports=request.intent.input_ports,
            output_ports=request.intent.output_ports,
        )


def _atom_spec_from_request(
    plugin_id: str, request: PluginRequest, coverage: CoverageRegistry | None
) -> AtomSpec:
    intent = request.intent
    loader = intent.role is AtomRole.LOADER_ATOM
    if intent.ph_ids:
        if coverage is None:
            raise ValueError("有 PH 的插件种子必须通过覆盖矩阵填写 attck_ids")
        attck_ids = coverage.attack_ids_for(intent.ph_ids)
    else:
        attck_ids = ()
    return AtomSpec(
        atom_id=plugin_id,
        role=intent.role,
        integration_state=IntegrationState.PARTIAL,
        ph_ids=intent.ph_ids,
        attck_ids=attck_ids,
        variant_family=variant_family_for_plugin(
            plugin_id, role=intent.role, ph_ids=intent.ph_ids
        ),
        required_capabilities=intent.required_capabilities,
        provided_capabilities=intent.provided_capabilities,
        inputs_schema_ref=f"schema://plugin-seed/{plugin_id}",
        param_domains=intent.parameter_domains,
        output_contract="shellcode" if loader else "exe",
        handoff_contract=next(iter(intent.produces_handoffs or intent.consumes_handoffs), None),
        produces_handoffs=intent.produces_handoffs,
        consumes_handoffs=intent.consumes_handoffs,
        materialize=(
            HandoffMaterialize.EMBED_AT_BUILD
            if intent.artifact_ref is not None
            else HandoffMaterialize.NONE
        ),
        artifact_ref=intent.artifact_ref,
        verification_profile="standard",
        safety_profile=intent.safety_profile,
        trigger_modes=(TriggerMode.LAB_TRIGGER,),
        requires_implant=False,
        env_prerequisites=("windows-11",),
        toolchain_ref=request.build_target_ref,
    )


__all__ = ["SeedPluginAuthoringBackend", "variant_family_for_plugin"]
