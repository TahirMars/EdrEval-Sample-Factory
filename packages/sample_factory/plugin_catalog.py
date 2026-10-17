"""Human-gated promotion of behavior-valid plugin candidates."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from packages.sample_factory.cas import ContentAddressedStore, ObjectNamespace, StoredObject
from packages.sample_factory.catalog import CoverageRegistry
from packages.sample_factory.compiler import source_tree_digest, source_tree_files
from packages.sample_factory.models import AtomSpec, PluginProvenance
from packages.sample_factory.plugin_contract import (
    PLUGIN_ABI_VERSION,
    plugin_entry_symbol,
    validate_candidate_source_snapshot,
    validate_catalog_source_files,
)
from packages.sample_factory.plugin_models import PluginAuthoringResult, PluginLifecycleStatus
from packages.sample_factory.telemetry_catalog import (
    project_sysmon_telemetry_contract,
    upsert_telemetry_contracts,
)

# Authoring 摘要不含 compile 时 EMBED_AT_BUILD 写入的 generated/handoff_*.h。
_CONTROL_PLANE_HANDOFF_PREFIXES = ("generated/handoff_",)


class PluginSourceResolver(Protocol):
    def resolve(self, source_ref: str) -> Path: ...


class PluginBuildArtifactResolver(Protocol):
    def resolve_artifact(self, artifact_ref: str) -> Path: ...


class PluginRunSourceResolver:
    def __init__(self, runtime_root: str | Path) -> None:
        self._root = Path(runtime_root).resolve() / "plugin-runs"

    def resolve(self, source_ref: str) -> Path:
        prefix = "plugin-source://"
        if not source_ref.startswith(prefix):
            raise ValueError("plugin source ref 非法")
        parts = source_ref.removeprefix(prefix).split("/")
        if len(parts) != 2 or re.fullmatch(
            r"(?:final-source|repair-[0-9a-f]{8,64})", parts[1]
        ) is None:
            raise ValueError(
                "plugin source ref 必须指向 <plugin_run_id>/final-source 或 repair-<build_id>"
            )
        plugin_run_id, source_name = parts
        if re.fullmatch(r"plugin-run-[a-z0-9-]{8,79}", plugin_run_id) is None:
            raise ValueError("plugin source run id 非法")
        matches = tuple(
            self._root.glob(f"*/*/*/{plugin_run_id}/authoring/{source_name}")
        )
        if len(matches) != 1:
            raise FileNotFoundError(f"无法解析唯一插件源码：{source_ref}")
        path = matches[0].resolve()
        if not path.is_relative_to(self._root):
            raise ValueError("plugin source 路径越界")
        return path


class PluginCatalogPromotionService:
    def __init__(
        self,
        catalog_root: str | Path,
        resolver: PluginSourceResolver,
        *,
        artifact_resolver: PluginBuildArtifactResolver | None = None,
        artifact_store: ContentAddressedStore | None = None,
        coverage: CoverageRegistry | None = None,
        profile_id: str | None = None,
    ) -> None:
        self._root = Path(catalog_root).resolve()
        self._resolver = resolver
        self._artifact_resolver = artifact_resolver
        self._artifact_store = artifact_store
        self._coverage = coverage
        self._profile_id = profile_id

    def review(
        self,
        result: PluginAuthoringResult,
        provenance: PluginProvenance,
        *,
        approved: bool,
    ) -> Path:
        if not approved:
            raise PermissionError("插件 reviewed 晋升需要人工审批")
        if result.status is not PluginLifecycleStatus.BEHAVIOR_VALID:
            raise ValueError("只有 behavior_valid 插件可以进入 reviewed")
        if (
            result.source is None
            or result.source.atom_spec is None
            or result.build is None
            or result.validation is None
        ):
            raise ValueError("插件晋升缺少源码、静态库、AtomSpec 或验证证据")
        if not provenance.audit_passed or not provenance.pinned:
            raise ValueError("reviewed 插件必须通过审计并钉扎 revision")
        if self._artifact_resolver is None or self._artifact_store is None:
            raise ValueError("插件晋升必须配置验证制品解析器和外部 CAS")
        source_root = self._resolver.resolve(result.source.source_ref).resolve()
        authoring_digest = source_tree_digest(
            source_root,
            exclude_relative_prefixes=_CONTROL_PLANE_HANDOFF_PREFIXES,
        )
        if authoring_digest != result.source.source_digest:
            raise ValueError(
                "候选源码闭包 SHA 与 Authoring 结果不一致"
                f"（plugin_id={result.source.plugin_id}）"
            )
        snapshot = {
            path.relative_to(source_root).as_posix(): path.read_text(encoding="utf-8")
            for path in source_tree_files(source_root)
        }
        validate_candidate_source_snapshot(snapshot, result.source.implementation_name)
        implementation_digest = source_tree_digest(source_root / "src")
        if implementation_digest != result.build.implementation_source_digest:
            raise ValueError("验证静态库与待发布实现源码摘要不一致")
        artifact = self._artifact_resolver.resolve_artifact(result.build.artifact_ref)
        stored = self._artifact_store.put_file(
            ObjectNamespace.ARTIFACTS,
            artifact,
            expected_sha256=result.build.artifact_sha256,
        )
        published = result.model_copy(
            update={
                "source": result.source.model_copy(
                    update={"atom_spec": self._published_spec(result.source.atom_spec)}
                )
            }
        )

        target = self._root / "plugins" / "reviewed" / result.source.plugin_id
        dispatchable = self._root / "plugins" / "dispatchable" / result.source.plugin_id
        refresh_dispatchable = dispatchable.exists() and _reviewed_source_revision_matches(
            dispatchable, published, implementation_digest, stored
        )
        if target.exists():
            if not _reviewed_source_revision_matches(
                target, published, implementation_digest, stored
            ):
                raise ValueError(
                    "reviewed 插件版本已存在；新源码必须使用新插件 revision"
                    f"（plugin_id={result.source.plugin_id}）"
                )
            _refresh_reviewed_manifest(target, published, provenance)
            if refresh_dispatchable:
                _refresh_reviewed_manifest(dispatchable, published, provenance)
            return target
        self._write_plugin(target, source_root, published, provenance, stored)
        return target

    def promote_dispatchable(self, plugin_id: str, *, approved: bool) -> Path:
        if not approved:
            raise PermissionError("插件 dispatchable 晋升需要独立人工审批")
        source = (self._root / "plugins" / "reviewed" / plugin_id).resolve()
        reviewed_root = (self._root / "plugins" / "reviewed").resolve()
        if not source.is_relative_to(reviewed_root) or not (source / "plugin.json").is_file():
            raise ValueError("reviewed 插件不存在或路径非法")
        target = (self._root / "plugins" / "dispatchable" / plugin_id).resolve()
        dispatch_root = (self._root / "plugins" / "dispatchable").resolve()
        if not target.is_relative_to(dispatch_root):
            raise ValueError("dispatchable 插件路径越界")
        if target.exists():
            if _directory_digest(target) != _directory_digest(source):
                raise ValueError("dispatchable 插件已存在但内容冲突")
            return target
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = target.parent / f".{plugin_id}.{uuid4().hex}.part"
        shutil.copytree(source, staging)
        os.replace(staging, target)
        return target

    def list_catalog(self) -> dict[str, list[str]]:
        result = {}
        for status in ("candidate", "reviewed", "dispatchable", "deprecated"):
            root = self._root / "plugins" / status
            result[status] = (
                sorted(
                    path.name
                    for path in root.iterdir()
                    if path.is_dir() and (path / "plugin.json").is_file()
                )
                if root.is_dir()
                else []
            )
        return result

    def _published_spec(self, spec: AtomSpec) -> AtomSpec:
        if self._coverage is None or not self._profile_id:
            return spec
        contract = project_sysmon_telemetry_contract(
            spec, self._coverage, self._profile_id
        )
        if contract is None:
            return spec
        upsert_telemetry_contracts(
            self._root / "telemetry" / "contracts.json", (contract,)
        )
        if spec.telemetry_contract_ref in {None, contract.contract_id}:
            return spec.model_copy(update={"telemetry_contract_ref": contract.contract_id})
        raise ValueError(
            f"{spec.atom_id} 已声明 {spec.telemetry_contract_ref}，"
            f"与覆盖矩阵投影 {contract.contract_id} 不一致"
        )

    @staticmethod
    def _write_plugin(
        target: Path,
        source_root: Path,
        result: PluginAuthoringResult,
        provenance: PluginProvenance,
        stored: StoredObject,
    ) -> None:
        if (
            result.source is None
            or result.source.atom_spec is None
            or result.build is None
            or result.validation is None
        ):  # pragma: no cover
            raise AssertionError("plugin promotion invariant")
        if target.exists():
            raise ValueError("reviewed 插件版本已存在；新源码必须使用新插件 revision")
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = target.parent / f".{target.name}.{uuid4().hex}.part"
        source_target = staging / "src"
        source_target.mkdir(parents=True)
        files = []
        try:
            implementation_root = source_root / "src"
            for path in source_tree_files(implementation_root):
                relative = path.relative_to(implementation_root)
                destination = (source_target / relative).resolve()
                if not destination.is_relative_to(source_target.resolve()):
                    raise ValueError("插件源码路径越界")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
                files.append(relative.as_posix())
            files = list(
                validate_catalog_source_files(files, result.source.implementation_name)
            )
            implementation_digest = source_tree_digest(source_target)
            if implementation_digest != result.build.implementation_source_digest:
                raise ValueError("reviewed 插件复制后实现源码摘要改变")
            payload = {
                "format_version": "sf-plugin-v2",
                "spec": result.source.atom_spec.model_dump(mode="json"),
                "provenance": provenance.model_dump(mode="json"),
                "source": {
                    "root": "src",
                    "files": files,
                    "implementation_name": result.source.implementation_name,
                    "public_header": f"{result.source.implementation_name}.h",
                    "source_digest": implementation_digest,
                    "lineage": (
                        f"{result.plugin_run_id};"
                        f"evidence={result.validation.evidence_ref}"
                    ),
                },
                "glue": {
                    "input_kind": "source",
                    "entry_point": "generated/main.cpp",
                },
                "validation_build": {
                    "purpose": "validation_only",
                    "abi_version": PLUGIN_ABI_VERSION,
                    "entry_symbol": plugin_entry_symbol(result.source.implementation_name),
                    "artifact_filename": result.build.artifact_filename,
                    "artifact_ref": stored.object_ref,
                    "artifact_sha256": stored.sha256,
                    "source_digest": implementation_digest,
                    "candidate_source_digest": result.source.source_digest,
                    "toolchain_fp": result.build.toolchain_fp,
                    "harness_ref": result.validation.harness_ref,
                    "evidence_ref": result.validation.evidence_ref,
                },
            }
            (staging / "plugin.json").write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            os.replace(staging, target)
        except Exception:
            if staging.exists():
                shutil.rmtree(staging)
            raise


def _reviewed_source_revision_matches(
    target: Path,
    result: PluginAuthoringResult,
    implementation_digest: str,
    stored: StoredObject,
) -> bool:
    if result.source is None or result.validation is None:
        return False
    manifest_path = target / "plugin.json"
    if not manifest_path.is_file():
        return False
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    lineage = str(manifest.get("source", {}).get("lineage", ""))
    run_id, _, _rest = lineage.partition(";")
    validation = manifest.get("validation_build", {})
    return (
        run_id == result.plugin_run_id
        and manifest.get("source", {}).get("source_digest") == implementation_digest
        and validation.get("candidate_source_digest") == result.source.source_digest
        and validation.get("artifact_sha256") == stored.sha256
    )


def _refresh_reviewed_manifest(
    target: Path,
    result: PluginAuthoringResult,
    provenance: PluginProvenance,
) -> None:
    if result.source is None or result.source.atom_spec is None or result.validation is None:
        raise ValueError("刷新 reviewed 清单缺少源码或验证结果")
    manifest_path = (target / "plugin.json").resolve()
    if not manifest_path.is_relative_to(target.resolve()) or not manifest_path.is_file():
        raise ValueError("reviewed 插件缺少 plugin.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    lineage = f"{result.plugin_run_id};evidence={result.validation.evidence_ref}"
    manifest["spec"] = result.source.atom_spec.model_dump(mode="json")
    manifest.setdefault("source", {})["lineage"] = lineage
    validation = manifest.setdefault("validation_build", {})
    validation["evidence_ref"] = result.validation.evidence_ref
    validation["harness_ref"] = result.validation.harness_ref
    manifest["provenance"] = provenance.model_dump(mode="json")
    staging = manifest_path.with_name(f".{manifest_path.name}.{uuid4().hex}.part")
    try:
        staging.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(staging, manifest_path)
    except Exception:
        if staging.exists():
            staging.unlink()
        raise


def _directory_digest(root: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    for path in sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(root).as_posix(),
    ):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(path.read_bytes())
    return digest.hexdigest()


__all__ = [
    "PluginCatalogPromotionService",
    "PluginBuildArtifactResolver",
    "PluginRunSourceResolver",
    "PluginSourceResolver",
]
