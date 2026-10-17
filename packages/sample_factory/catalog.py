"""PH 权威映射与原子目录门禁。"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packages.sample_factory.capability import validate_capability_closure
from packages.sample_factory.errors import CatalogError, FactoryDenied
from packages.sample_factory.handoff import validate_handoff_closure
from packages.sample_factory.injection_contract import validate_injection_parameters
from packages.sample_factory.models import (
    AtomRole,
    AtomSpec,
    IntegrationState,
    PluginProvenance,
    ProductionProfile,
    SafetyProfile,
    SampleRecipe,
)

_MATRIX_ROW_RE = re.compile(r"^\|\s*(PH-[A-Z]{2}[0-9]{2})\s*\|\s*([^|]+)\|")
_ATTCK_RE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")

# 必须与 procedure-host-ttp-coverage-matrix.md §3.7 / §8 现行行数一致。
PH_MATRIX_ROW_COUNT = 66


@dataclass(frozen=True)
class CoverageRow:
    ph_id: str
    attack_ids: tuple[str, ...]
    technique: str
    data_sources: str
    endpoint_visibility: str
    audit_prerequisites: str
    detection_layers: str
    matrix_evasion_tier: str
    expected_signals: str


@dataclass(frozen=True)
class CoverageRegistry:
    """PH 行到 ATT&CK ID 的只读权威投影。"""

    mapping: Mapping[str, tuple[str, ...]]
    rows: Mapping[str, CoverageRow] = field(default_factory=dict)
    source_ref: str = "docs/coverage/procedure-host-ttp-coverage-matrix.md#5"

    @classmethod
    def from_markdown(
        cls, path: str | Path, *, expected_count: int = PH_MATRIX_ROW_COUNT
    ) -> CoverageRegistry:
        rows: dict[str, tuple[str, ...]] = {}
        details: dict[str, CoverageRow] = {}
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            match = _MATRIX_ROW_RE.match(line)
            if match is None:
                continue
            ph_id, attack_cell = match.groups()
            attack_ids = tuple(dict.fromkeys(_ATTCK_RE.findall(attack_cell)))
            if not attack_ids:
                raise CatalogError(f"{ph_id} 缺 ATT&CK 映射")
            if ph_id in rows:
                raise CatalogError(f"覆盖矩阵重复 ph_id：{ph_id}")
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) != 13:
                raise CatalogError(f"{ph_id} 覆盖矩阵列数改变：期望 13，实得 {len(cells)}")
            rows[ph_id] = attack_ids
            details[ph_id] = CoverageRow(
                ph_id=ph_id,
                attack_ids=attack_ids,
                technique=cells[2],
                data_sources=cells[4],
                endpoint_visibility=cells[5],
                audit_prerequisites=cells[6],
                detection_layers=cells[9],
                matrix_evasion_tier=cells[10],
                expected_signals=cells[11],
            )
        if len(rows) != expected_count:
            raise CatalogError(f"PH 行数不符：期望 {expected_count}，实得 {len(rows)}")
        return cls(mapping=rows, rows=details, source_ref=Path(path).as_posix() + "#5")

    def attack_ids_for(self, ph_ids: tuple[str, ...]) -> tuple[str, ...]:
        result: list[str] = []
        for ph_id in ph_ids:
            try:
                ids = self.mapping[ph_id]
            except KeyError as exc:
                raise CatalogError(f"ph_id 未出现在权威 PH 矩阵：{ph_id}") from exc
            for attack_id in ids:
                if attack_id not in result:
                    result.append(attack_id)
        return tuple(result)


class AtomCatalog:
    """注册、解析并校验可调度原子；状态与 PH 映射均 fail-closed。"""

    _DISPATCHABLE = frozenset({IntegrationState.IMPLEMENTED, IntegrationState.PARTIAL})

    def __init__(self, coverage: CoverageRegistry) -> None:
        self._coverage = coverage
        self._atoms: dict[str, AtomSpec] = {}
        self._provenance: dict[str, PluginProvenance] = {}
        self._source_roots: dict[str, Path] = {}

    @property
    def coverage(self) -> CoverageRegistry:
        return self._coverage

    def register(
        self,
        spec: AtomSpec,
        provenance: PluginProvenance | None = None,
        *,
        source_root: str | Path | None = None,
    ) -> None:
        if spec.atom_id in self._atoms:
            raise CatalogError(f"atom_id 重复：{spec.atom_id}")
        if spec.integration_state in self._DISPATCHABLE:
            if provenance is None or not (provenance.audit_passed and provenance.pinned):
                raise CatalogError(
                    f"{spec.atom_id} 为可调度状态，但缺 audit-passed + pinned + 人审来源证明"
                )
            self._provenance[spec.atom_id] = provenance
        if source_root is not None:
            self._source_roots[spec.atom_id] = Path(source_root).resolve()
        if spec.ph_ids:
            authoritative = self._coverage.attack_ids_for(spec.ph_ids)
            if set(spec.attck_ids) != set(authoritative):
                raise CatalogError(
                    f"{spec.atom_id} 的 attck_ids 与 PH 矩阵不一致："
                    f"声明 {spec.attck_ids}，权威 {authoritative}"
                )
        self._atoms[spec.atom_id] = spec

    def get(self, atom_id: str) -> AtomSpec:
        try:
            return self._atoms[atom_id]
        except KeyError as exc:
            raise CatalogError(f"未注册 atom：{atom_id}") from exc

    def dispatchable_specs(self) -> tuple[AtomSpec, ...]:
        return tuple(
            spec for spec in self._atoms.values() if spec.integration_state in self._DISPATCHABLE
        )

    @property
    def source_roots(self) -> Mapping[str, Path]:
        return dict(self._source_roots)

    def validate_recipe(
        self,
        recipe: SampleRecipe,
        atom_parameters: Mapping[str, Mapping[str, Any]],
        profile: ProductionProfile,
        *,
        high_risk_approved: bool,
    ) -> tuple[AtomSpec, ...]:
        specs = tuple(self.get(atom_id) for atom_id in recipe.atom_ids)
        self._validate_roles(recipe, specs)

        blocked = [
            spec.atom_id for spec in specs if spec.integration_state not in self._DISPATCHABLE
        ]
        if blocked:
            raise CatalogError(f"不可调度 atom（planned/reserved/gap/rejected）：{blocked}")

        covered = {ph_id for spec in specs for ph_id in spec.ph_ids}
        missing = [ph_id for ph_id in recipe.ph_ids if ph_id not in covered]
        self._coverage.attack_ids_for(recipe.ph_ids)
        if missing:
            raise CatalogError(f"Recipe ph_ids 未被所选 atom 覆盖：{missing}")

        for spec in specs:
            if recipe.trigger_mode not in spec.trigger_modes:
                raise CatalogError(
                    f"{spec.atom_id} 不支持 trigger_mode={recipe.trigger_mode.value}"
                )
            if spec.requires_implant and recipe.implant_sha256 is None:
                raise CatalogError(f"{spec.atom_id} requires_implant=True，但 Recipe 无 implant")
            self._validate_parameters(spec, atom_parameters.get(spec.atom_id, {}))
            validate_injection_parameters(spec, atom_parameters.get(spec.atom_id, {}))

        unknown_params = set(atom_parameters) - set(recipe.atom_ids)
        if unknown_params:
            raise CatalogError(f"参数引用了 Recipe 外 atom：{sorted(unknown_params)}")

        if any(spec.safety_profile is SafetyProfile.HIGH_RISK for spec in specs):
            self._validate_high_risk(profile, high_risk_approved=high_risk_approved)
        validate_handoff_closure(specs)
        validate_capability_closure(specs)
        return specs

    @staticmethod
    def _validate_roles(recipe: SampleRecipe, specs: tuple[AtomSpec, ...]) -> None:
        by_id = {spec.atom_id: spec for spec in specs}
        if recipe.carrier is not None and by_id[recipe.carrier].role is not AtomRole.CARRIER:
            raise CatalogError("SampleRecipe.carrier 必须引用 role=carrier")
        wrong_loaders = [
            atom_id
            for atom_id in recipe.loader_atoms
            if by_id[atom_id].role is not AtomRole.LOADER_ATOM
        ]
        wrong_execution = [
            atom_id
            for atom_id in recipe.execution_atoms
            if by_id[atom_id].role is not AtomRole.EXECUTION_ATOM
        ]
        if wrong_loaders or wrong_execution:
            raise CatalogError(
                f"Recipe atom 角色不匹配：loader={wrong_loaders}, execution={wrong_execution}"
            )

    @staticmethod
    def _validate_parameters(spec: AtomSpec, supplied: Mapping[str, Any]) -> None:
        expected = set(spec.param_domains)
        actual = set(supplied)
        if actual != expected:
            raise CatalogError(
                f"{spec.atom_id} 参数键不完整：期望 {sorted(expected)}，实得 {sorted(actual)}"
            )
        for key, value in supplied.items():
            if value not in spec.param_domains[key]:
                raise CatalogError(f"{spec.atom_id}.{key}={value!r} 不在声明参数域内")

    @staticmethod
    def _validate_high_risk(
        profile: ProductionProfile,
        *,
        high_risk_approved: bool,
    ) -> None:
        prerequisites = (
            profile.high_risk_enabled,
            profile.isolated,
            profile.rollback_capable,
            profile.sensors_ready,
            high_risk_approved,
        )
        if not all(prerequisites):
            raise FactoryDenied("high_risk atom 需要独立高危 profile、审批、隔离、回滚与传感器")


__all__ = ["AtomCatalog", "CoverageRegistry", "CoverageRow"]
