"""文件化权威来源适配器；缺失时按项目 Contract Gap 格式失败。"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from packages.contract_gap import ContractGap, ContractGapError
from packages.sample_factory.catalog import AtomCatalog, CoverageRegistry
from packages.sample_factory.errors import CatalogError
from packages.sample_factory.models import AtomSpec, PluginProvenance, TelemetryContract
from packages.sample_factory.plugin_contract import (
    PLUGIN_ABI_VERSION,
    plugin_entry_symbol,
    validate_candidate_source_snapshot,
    validate_catalog_source_files,
    validate_implementation_name,
)


class _PluginManifestEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    spec: AtomSpec
    provenance: PluginProvenance | None = None


class _PluginSourceManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root: str
    files: list[str] = Field(min_length=1)
    entry_point: str | None = None
    implementation_name: str | None = None
    public_header: str | None = None
    lineage: str
    source_digest: str | None = None

    @field_validator("source_digest")
    @classmethod
    def _source_digest(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("source_digest 必须是 64 位小写十六进制")
        return value

    @field_validator("root", "lineage")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("plugin source manifest 字段不得为空")
        return value

    @field_validator("implementation_name")
    @classmethod
    def _implementation_name(cls, value: str | None) -> str | None:
        return None if value is None else validate_implementation_name(value)


class _PluginGlueManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_kind: Literal["source"]
    entry_point: str = Field(min_length=1)


class _PluginValidationBuildManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    purpose: Literal["validation_only"]
    abi_version: Literal["edreval-ttp-c-v1"] = PLUGIN_ABI_VERSION
    entry_symbol: str = Field(min_length=1)
    artifact_filename: str = Field(pattern=r"^[A-Z][A-Za-z0-9]{2,79}\.lib$")
    artifact_ref: str = Field(pattern=r"^object://artifacts/sha256/[0-9a-f]{64}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    toolchain_fp: str = Field(min_length=1)
    harness_ref: str = Field(pattern=r"^plugin-harness://.+")
    evidence_ref: str = Field(min_length=1)

    @model_validator(mode="after")
    def _artifact_identity(self) -> Self:
        if not self.artifact_ref.endswith("/" + self.artifact_sha256):
            raise ValueError("validation_build artifact_ref 与 artifact_sha256 不一致")
        return self


class _DirectoryPluginManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format_version: Literal["sf-plugin-v1", "sf-plugin-v2"]
    spec: AtomSpec
    provenance: PluginProvenance | None = None
    source: _PluginSourceManifest | None = None
    glue: _PluginGlueManifest | None = None
    validation_build: _PluginValidationBuildManifest | None = None

    @model_validator(mode="after")
    def _version_contract(self) -> Self:
        if self.format_version == "sf-plugin-v1":
            if self.source is not None and self.source.entry_point is None:
                raise ValueError("sf-plugin-v1 source 必须声明 entry_point")
            if self.glue is not None or self.validation_build is not None:
                raise ValueError("sf-plugin-v1 不接受 glue/validation_build")
            return self
        if (
            self.source is None
            or self.source.implementation_name is None
            or self.source.public_header is None
            or self.source.entry_point is not None
            or self.glue is None
            or self.validation_build is None
        ):
            raise ValueError(
                "sf-plugin-v2 必须声明规范 source、source-only glue 和 validation_build"
            )
        return self


class JsonlAtomCatalogLoader:
    """加载 git 跟踪的原子元数据；插件源码仍只由 repository_ref 指向外部仓。"""

    def __init__(self, path: str | Path, coverage: CoverageRegistry) -> None:
        self._path = Path(path)
        self._coverage = coverage

    def load(self) -> AtomCatalog:
        if not self._path.is_file():
            raise ContractGapError(
                ContractGap(
                    capability="AI 样本工厂选择已固化 TTP 插件",
                    missing="AtomSpec + provenance JSONL 目录",
                    checked=(self._path.as_posix(), "sample-factory blueprint §5.1"),
                    risk="从未审计源码目录猜插件状态会绕过 reserved_atom 与供应链双闸",
                )
            )
        catalog = AtomCatalog(self._coverage)
        for line_number, line in enumerate(
            self._path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            try:
                entry = _PluginManifestEntry.model_validate_json(line)
                catalog.register(entry.spec, entry.provenance)
            except Exception as exc:
                raise CatalogError(f"Atom catalog 第 {line_number} 行非法：{exc}") from exc
        return catalog


class DirectoryAtomCatalogLoader:
    """加载 ``plugins/dispatchable/<atom_id>/plugin.json`` 插件布局。"""

    def __init__(self, root: str | Path, coverage: CoverageRegistry) -> None:
        self._root = Path(root)
        self._coverage = coverage

    def load(self) -> AtomCatalog:
        plugin_root = self._root / "plugins" / "dispatchable"
        if not plugin_root.is_dir():
            raise ContractGapError(
                ContractGap(
                    capability="读取初始 TTP 插件目录",
                    missing="plugins/dispatchable/<atom_id>/plugin.json",
                    checked=(plugin_root.as_posix(), "sample-factory initial plugin format"),
                    risk="没有显式插件描述时不能审计来源、角色、PH 映射和状态",
                )
            )
        catalog = AtomCatalog(self._coverage)
        implementation_names: set[str] = set()
        manifests = sorted(plugin_root.glob("*/plugin.json"))
        if not manifests:
            raise ContractGapError(
                ContractGap(
                    capability="读取初始 TTP 插件目录",
                    missing="至少一份 plugin.json",
                    checked=(plugin_root.as_posix(),),
                    risk="空目录不能提供可验证的 TTP 选件空间",
                )
            )
        for path in manifests:
            try:
                manifest = _DirectoryPluginManifest.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
                expected_id = path.parent.name
                if manifest.spec.atom_id != expected_id:
                    raise CatalogError(
                        f"目录名与 spec.atom_id 不一致：{expected_id} != {manifest.spec.atom_id}"
                    )
                self._validate_source_manifest(path.parent, manifest)
                source_root = None
                if manifest.source is not None:
                    source_root = path.parent / manifest.source.root
                    name = manifest.source.implementation_name
                    if name is not None:
                        if name in implementation_names:
                            raise CatalogError(f"implementation_name 重复：{name}")
                        implementation_names.add(name)
                catalog.register(
                    manifest.spec,
                    manifest.provenance,
                    source_root=source_root,
                )
            except Exception as exc:
                raise CatalogError(f"插件描述非法：{path}: {exc}") from exc
        return catalog

    @staticmethod
    def _validate_source_manifest(
        plugin_dir: Path,
        manifest: _DirectoryPluginManifest,
    ) -> None:
        from packages.sample_factory.models import HandoffMaterialize

        source = manifest.source
        spec = manifest.spec
        if source is None:
            if spec.materialize is not HandoffMaterialize.EMBED_AT_BUILD:
                raise CatalogError(
                    f"{spec.atom_id} 缺少 source 清单，且不是 embed_at_build 支撑原子"
                )
            return
        root = (plugin_dir / source.root).resolve()
        if not root.is_relative_to(plugin_dir.resolve()) or not root.is_dir():
            raise CatalogError(f"source.root 越界或不存在：{source.root}")
        paths = set()
        for relative in source.files:
            candidate = (root / relative).resolve()
            if not candidate.is_relative_to(root) or not candidate.is_file():
                raise CatalogError(f"源码清单文件越界或不存在：{relative}")
            if relative in paths:
                raise CatalogError(f"源码清单重复：{relative}")
            paths.add(relative)
        actual_paths = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file()
        }
        if manifest.format_version == "sf-plugin-v2":
            assert source.implementation_name is not None
            assert source.public_header is not None
            assert manifest.glue is not None
            assert manifest.validation_build is not None
            validate_catalog_source_files(source.files, source.implementation_name)
            if paths != actual_paths:
                raise CatalogError("sf-plugin-v2 source.files 必须精确覆盖实现源码目录")
            validate_candidate_source_snapshot(
                {
                    f"src/{relative}": (root / relative).read_text(encoding="utf-8")
                    for relative in source.files
                },
                source.implementation_name,
            )
            if source.public_header != f"{source.implementation_name}.h":
                raise CatalogError("public_header 必须与 implementation_name 同名")
            validation = manifest.validation_build
            if validation.entry_symbol != plugin_entry_symbol(source.implementation_name):
                raise CatalogError("validation_build.entry_symbol 与实现名称不一致")
            if validation.artifact_filename != f"{source.implementation_name}.lib":
                raise CatalogError("validation_build 静态库文件名与实现名称不一致")
            if source.source_digest != validation.source_digest:
                raise CatalogError("validation_build 未绑定当前发布源码摘要")
            entry_point = manifest.glue.entry_point
        else:
            assert source.entry_point is not None
            entry_point = source.entry_point
        if source.source_digest is not None:
            from packages.sample_factory.compiler import source_tree_digest

            if source_tree_digest(root) != source.source_digest:
                raise CatalogError(
                    f"{spec.atom_id} source_digest 与源码闭包不一致：{source.source_digest}"
                )
        entry = (plugin_dir / entry_point).resolve()
        if not entry.is_relative_to(plugin_dir.resolve()):
            raise CatalogError(f"entry_point 越界：{entry_point}")
        if entry.exists():
            raise CatalogError("entry_point 不应预先存在；它由 glue agent 生成")


class JsonTelemetryContractSource:
    """从 JSON 文档加载双类遥测合同并按 contract_id 解析。"""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._contracts: dict[str, TelemetryContract] | None = None

    def get(self, contract_ref: str) -> TelemetryContract:
        contracts = self._load()
        try:
            return contracts[contract_ref]
        except KeyError as exc:
            raise ContractGapError(
                ContractGap(
                    capability=f"验证原子遥测合同 {contract_ref}",
                    missing="匹配的 positive/absence required/optional 断言",
                    checked=(self._path.as_posix(), "sample-factory pipeline §6.2"),
                    risk="没有独立遥测 oracle 时无法证明目标 TTP 实际发生",
                )
            ) from exc

    def _load(self) -> dict[str, TelemetryContract]:
        if self._contracts is not None:
            return self._contracts
        if not self._path.is_file():
            raise ContractGapError(
                ContractGap(
                    capability="流水线 A V2 遥测验证",
                    missing="遥测合同 JSON 文档",
                    checked=(self._path.as_posix(), "sample-factory SF-1"),
                    risk="缺合同仍判 SUCCESS 会制造虚假功能真值",
                )
            )
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            values = raw["contracts"] if isinstance(raw, dict) else raw
            if not isinstance(values, list):
                raise TypeError("顶层必须是数组或含 contracts 数组的对象")
            contracts = [TelemetryContract.model_validate(value) for value in values]
        except Exception as exc:
            raise CatalogError(f"遥测合同文档非法：{exc}") from exc
        by_id = {item.contract_id: item for item in contracts}
        if len(by_id) != len(contracts):
            raise CatalogError("遥测合同 contract_id 重复")
        self._contracts = by_id
        return by_id


class MatrixExpectedDetectionSource:
    """只投影 PH 权威矩阵的现有结论，不生成检测可见性。"""

    def __init__(self, coverage: CoverageRegistry) -> None:
        self._coverage = coverage

    def get(self, ph_ids: tuple[str, ...], *, evasion_tier: str) -> dict[str, object]:
        rows = []
        for ph_id in ph_ids:
            try:
                row = self._coverage.rows[ph_id]
            except KeyError as exc:
                raise ContractGapError(
                    ContractGap(
                        capability=f"生成 {ph_id} 的期望检测标注",
                        missing="PH 覆盖矩阵结构化行",
                        checked=(self._coverage.source_ref, ph_id),
                        risk="自行补检测可见性会违反不虚构检测结论硬边界",
                    )
                ) from exc
            rows.append(
                {
                    "ph_id": row.ph_id,
                    "attck_ids": list(row.attack_ids),
                    "data_sources": row.data_sources,
                    "endpoint_visibility": row.endpoint_visibility,
                    "audit_prerequisites": row.audit_prerequisites,
                    "detection_layers": row.detection_layers,
                    "matrix_evasion_tier": row.matrix_evasion_tier,
                    "expected_signals": row.expected_signals,
                }
            )
        return {
            "source_ref": self._coverage.source_ref,
            "ph_ids": list(ph_ids),
            "sample_evasion_tier": evasion_tier,
            "rows": rows,
        }


__all__ = [
    "DirectoryAtomCatalogLoader",
    "JsonTelemetryContractSource",
    "JsonlAtomCatalogLoader",
    "MatrixExpectedDetectionSource",
]
