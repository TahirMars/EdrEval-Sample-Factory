"""Approved export views over immutable artifact CAS objects."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Literal
from uuid import uuid4

from packages.sample_factory.bundle_models import SampleBundle
from packages.sample_factory.cas import ContentAddressedStore, ObjectNamespace
from packages.sample_factory.errors import FactoryDenied

_SAFE_EXPORT_ID = re.compile(r"export-[a-z0-9-]{8,79}")
_ALLOWED_SUFFIXES = frozenset({".exe", ".dll", ".msi", ".zip"})
_EXPORT_STAGES = ("approved", "published", "revoked")
_VMWARE_EVIDENCE_PREFIX = "vmware-evidence://"
_TELEMETRY_PROJECTION = "telemetry-projection.json"
ExportStage = Literal["approved", "published"]


@dataclass(frozen=True)
class ExportResult:
    export_id: str
    export_ref: str
    artifact_sha256: str
    artifact_path: Path
    manifest_path: Path


class ArtifactExportService:
    def __init__(self, runtime_root: str | Path, cas: ContentAddressedStore) -> None:
        self._runtime_root = Path(runtime_root).resolve()
        self._exports_root = self._runtime_root / "exports"
        self._cas = cas

    def export(
        self,
        *,
        export_id: str,
        artifact_ref: str,
        filename: str,
        approved: bool,
        source_included: bool = False,
        destination: ExportStage = "approved",
        sample_record: Mapping[str, object] | None = None,
        telemetry_evidence_dir: str | Path | None = None,
        telemetry_evidence_ref: str | None = None,
    ) -> ExportResult:
        if not approved:
            raise FactoryDenied("样本导出必须获得本轮人工审批")
        if source_included:
            raise FactoryDenied("源码外发需要独立审批流程，普通 artifact export 不支持")
        if destination not in {"approved", "published"}:
            raise ValueError("导出目的只允许 approved 或 published")
        if not _SAFE_EXPORT_ID.fullmatch(export_id):
            raise ValueError("export_id 非法")
        pure_name = PurePath(filename)
        if (
            pure_name.name != filename
            or pure_name.suffix.lower() not in _ALLOWED_SUFFIXES
            or filename in {".", ".."}
        ):
            raise ValueError("导出文件名或后缀不在 allowlist")

        stored = self._cas.verify(artifact_ref)
        if stored.namespace is not ObjectNamespace.ARTIFACTS:
            raise ValueError("普通样本导出只接受 artifacts namespace")
        if destination == "published" and telemetry_evidence_dir is None:
            raise ValueError("发布转到必须附带样本遥测证据")
        telemetry_source = (
            None if telemetry_evidence_dir is None else Path(telemetry_evidence_dir)
        )
        target_root = (self._exports_root / destination / export_id).resolve()
        if not target_root.is_relative_to(self._exports_root):  # pragma: no cover
            raise ValueError("导出路径越界")
        if target_root.exists():
            existing = _read_export_manifest(target_root)
            existing_checksums = _read_export_checksums(target_root)
            telemetry_ok = telemetry_source is None or _telemetry_checksums_match(
                telemetry_source, existing_checksums
            )
            if (
                existing.get("artifact_sha256") == stored.sha256
                and existing.get("filename") == filename
                and existing.get("destination", "approved") == destination
                and telemetry_ok
            ):
                return ExportResult(
                    export_id=export_id,
                    export_ref=f"export://{destination}/{export_id}",
                    artifact_sha256=stored.sha256,
                    artifact_path=target_root / filename,
                    manifest_path=target_root / "manifest.json",
                )
            raise FileExistsError(f"export_id 已存在：{export_id}")
        staging = self._exports_root / "pending" / f".{export_id}.{uuid4().hex}.part"
        staging.mkdir(parents=True, mode=0o700)
        try:
            artifact_path = staging / filename
            try:
                os.link(stored.path, artifact_path)
            except OSError:
                shutil.copyfile(stored.path, artifact_path)
            if _sha256_file(artifact_path) != stored.sha256:
                raise ValueError("导出后 artifact SHA-256 改变")
            checksums = {filename: stored.sha256}
            if sample_record is not None:
                sample_path = staging / "sample.json"
                sample_path.write_text(
                    json.dumps(
                        dict(sample_record),
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
                checksums["sample.json"] = _sha256_file(sample_path)
            if telemetry_source is not None:
                checksums.update(
                    _copy_telemetry_evidence(telemetry_source, staging / "telemetry")
                )
            payload = {
                "schema_version": "sample-factory-export-v1",
                "export_id": export_id,
                "destination": destination,
                "artifact_ref": artifact_ref,
                "artifact_sha256": stored.sha256,
                "filename": filename,
                "source_included": False,
                "sample_id": sample_record.get("sample_id") if sample_record else None,
                "telemetry_evidence_ref": telemetry_evidence_ref,
                "telemetry_dir": None if telemetry_source is None else "telemetry",
            }
            (staging / "manifest.json").write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            (staging / "checksums.json").write_text(
                json.dumps(
                    checksums,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
            target_root.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staging, target_root)
        except Exception:
            if staging.exists():
                shutil.rmtree(staging)
            raise
        return ExportResult(
            export_id=export_id,
            export_ref=f"export://{destination}/{export_id}",
            artifact_sha256=stored.sha256,
            artifact_path=target_root / filename,
            manifest_path=target_root / "manifest.json",
        )


class ArtifactReplayService:
    def __init__(self, cas: ContentAddressedStore) -> None:
        self._cas = cas

    def replay(self, artifact_ref: str) -> dict[str, object]:
        stored = self._cas.verify(artifact_ref)
        if stored.namespace is not ObjectNamespace.ARTIFACTS:
            raise ValueError("artifact replay 只接受 artifacts namespace")
        return {
            "mode": "artifact",
            "artifact_ref": stored.object_ref,
            "artifact_sha256": stored.sha256,
            "size": stored.size,
            "verified": True,
        }


class BundleExportService:
    def __init__(self, runtime_root: str | Path, cas: ContentAddressedStore) -> None:
        self._runtime_root = Path(runtime_root).resolve()
        self._exports_root = self._runtime_root / "exports"
        self._cas = cas

    def export(
        self, bundle: SampleBundle, *, export_id: str, approved: bool
    ) -> ExportResult:
        if not approved:
            raise FactoryDenied("Bundle 导出必须获得本轮人工审批")
        if not _SAFE_EXPORT_ID.fullmatch(export_id):
            raise ValueError("export_id 非法")
        target_root = (self._exports_root / "approved" / export_id).resolve()
        if target_root.exists():
            raise FileExistsError(export_id)
        staging = self._exports_root / "pending" / f".{export_id}.{uuid4().hex}.part"
        staging.mkdir(parents=True, mode=0o700)
        checksums: dict[str, str] = {}
        try:
            sets = {item.artifact_set_id: item for item in bundle.artifact_sets}
            for stage in bundle.stages:
                artifact_set = sets[stage.artifact_set_id]
                for member in artifact_set.members:
                    source = self._cas.resolve(member.artifact_ref)
                    if _sha256_file(source) != member.sha256:
                        raise ValueError("Bundle member SHA-256 与合同不一致")
                    relative = PurePath(stage.stage_id) / PurePath(member.relative_path)
                    destination = (staging / relative).resolve()
                    if not destination.is_relative_to(staging):
                        raise ValueError("Bundle 导出路径越界")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        os.link(source, destination)
                    except OSError:
                        shutil.copyfile(source, destination)
                    relative_name = relative.as_posix()
                    if relative_name in checksums:
                        raise ValueError("Bundle 导出相对路径冲突")
                    checksums[relative_name] = member.sha256
            (staging / "bundle.json").write_text(
                json.dumps(
                    bundle.model_dump(mode="json"),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
            (staging / "checksums.json").write_text(
                json.dumps(checksums, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            target_root.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staging, target_root)
        except Exception:
            if staging.exists():
                shutil.rmtree(staging)
            raise
        bundle_digest = hashlib.sha256(
            json.dumps(
                bundle.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        return ExportResult(
            export_id=export_id,
            export_ref=f"export://approved/{export_id}",
            artifact_sha256=bundle_digest,
            artifact_path=target_root,
            manifest_path=target_root / "bundle.json",
        )


def produced_sample_export_id(sample_id: str) -> str:
    export_id = f"export-{sample_id}"
    if not _SAFE_EXPORT_ID.fullmatch(export_id):
        raise ValueError(f"sample_id 无法构成合法 export_id：{sample_id}")
    return export_id


def list_export_packages(runtime_root: str | Path) -> dict[str, tuple[dict[str, object], ...]]:
    """Index committed export packages under runtime/exports/{approved,published,revoked}."""

    root = Path(runtime_root).resolve() / "exports"
    indexed: dict[str, tuple[dict[str, object], ...]] = {}
    for stage in _EXPORT_STAGES:
        items: list[dict[str, object]] = []
        stage_root = root / stage
        if stage_root.is_dir():
            for child in sorted(stage_root.iterdir(), key=lambda path: path.name):
                if not child.is_dir() or child.name.startswith("."):
                    continue
                payload = _read_export_manifest(child)
                if not payload:
                    continue
                items.append(
                    {
                        **payload,
                        "export_id": str(payload.get("export_id") or child.name),
                        "destination": str(payload.get("destination") or stage),
                        "export_ref": f"export://{stage}/{child.name}",
                        "package_path": child.as_posix(),
                    }
                )
        indexed[stage] = tuple(items)
    return indexed


def locate_sample_telemetry_evidence(
    runtime_root: str | Path, artifact_sha256: str
) -> tuple[Path, str]:
    """Find the VMware verification evidence directory for a produced sample SHA-256."""
    root = Path(runtime_root).resolve()
    matches: list[tuple[str, Path, str]] = []
    for result_path in root.glob("runs/*/*/*/run-*/attempts/*-attempt-*/result/result.json"):
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("artifact_sha256") != artifact_sha256:
            continue
        ref = payload.get("verification_ref")
        if not isinstance(ref, str) or not ref.startswith(_VMWARE_EVIDENCE_PREFIX):
            continue
        relative = PurePath(ref[len(_VMWARE_EVIDENCE_PREFIX) :])
        if relative.is_absolute() or ".." in relative.parts:
            continue
        evidence_dir = (root / relative).resolve()
        if not evidence_dir.is_relative_to(root) or not evidence_dir.is_dir():
            continue
        if not (evidence_dir / _TELEMETRY_PROJECTION).is_file():
            continue
        status = str(payload.get("status") or "")
        matches.append((status, evidence_dir, ref))
    if not matches:
        raise FileNotFoundError(
            f"找不到样本 {artifact_sha256[:12]} 的遥测证据（runtime/runs/.../verification）"
        )
    matches.sort(key=lambda item: (item[0] != "SUCCESS", item[2]))
    return matches[0][1], matches[0][2]


def _copy_telemetry_evidence(source: Path, destination: Path) -> dict[str, str]:
    source_root = source.resolve()
    dest_root = destination.resolve()
    if not source_root.is_dir():
        raise ValueError("遥测证据目录不存在")
    dest_root.mkdir(parents=True, exist_ok=True)
    checksums: dict[str, str] = {}
    for relative, path in _iter_telemetry_files(source_root):
        target = (dest_root / relative).resolve()
        if not target.is_relative_to(dest_root):
            raise ValueError("遥测证据导出路径越界")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        digest = _sha256_file(target)
        if digest != _sha256_file(path):
            raise ValueError("导出后遥测证据 SHA-256 改变")
        checksums[f"telemetry/{relative.as_posix()}"] = digest
    if f"telemetry/{_TELEMETRY_PROJECTION}" not in checksums:
        raise ValueError("遥测证据缺少 telemetry-projection.json")
    return checksums


def _telemetry_checksums_match(source: Path, existing: Mapping[str, object]) -> bool:
    checksums = {
        f"telemetry/{relative.as_posix()}": _sha256_file(path)
        for relative, path in _iter_telemetry_files(source.resolve())
    }
    if f"telemetry/{_TELEMETRY_PROJECTION}" not in checksums:
        return False
    return all(existing.get(key) == digest for key, digest in checksums.items())


def _iter_telemetry_files(source_root: Path) -> tuple[tuple[PurePath, Path], ...]:
    items: list[tuple[PurePath, Path]] = []
    if not source_root.is_dir():
        return ()
    for path in sorted(source_root.rglob("*")):
        if not path.is_file():
            continue
        relative = PurePath(path.relative_to(source_root).as_posix())
        if any(part.startswith(".") or part in {".", ".."} for part in relative.parts):
            continue
        items.append((relative, path))
    return tuple(items)


def _read_export_manifest(package_root: Path) -> dict[str, object]:
    return _read_json_object(package_root / "manifest.json")


def _read_export_checksums(package_root: Path) -> dict[str, object]:
    return _read_json_object(package_root / "checksums.json")


def _read_json_object(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "ArtifactExportService",
    "ArtifactReplayService",
    "BundleExportService",
    "ExportResult",
    "list_export_packages",
    "locate_sample_telemetry_evidence",
    "produced_sample_export_id",
]
