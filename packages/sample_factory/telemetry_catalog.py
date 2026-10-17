"""Project operator-owned Sysmon telemetry contracts from the PH coverage matrix."""

from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

from packages.sample_factory.catalog import CoverageRegistry
from packages.sample_factory.errors import VerificationError
from packages.sample_factory.models import (
    AtomSpec,
    SignalKind,
    SignalLevel,
    TelemetryAssertion,
    TelemetryContract,
)
from packages.sample_factory.plugin_harness_oracles import (
    ATOM_HARNESS_ORACLES,
    matrix_sysmon_event_ids,
)


def project_sysmon_telemetry_contract(
    spec: AtomSpec,
    coverage: CoverageRegistry,
    profile_id: str,
) -> TelemetryContract | None:
    """Return a Sysmon contract only when every PH row lists explicit EID numbers."""

    if not spec.ph_ids or not profile_id.strip():
        return None
    try:
        matrix_ids = matrix_sysmon_event_ids(coverage, spec.ph_ids)
    except VerificationError:
        return None
    variant = ATOM_HARNESS_ORACLES.get(spec.atom_id)
    assertions: list[TelemetryAssertion] = []
    required_tokens: list[str] = []
    for ph_id in spec.ph_ids:
        row = coverage.rows.get(ph_id)
        if row is None or not row.attack_ids:
            return None
        technique = row.attack_ids[0]
        required_eids = (
            tuple(item.event_id for item in variant.required) if variant is not None else matrix_ids
        )
        optional_eids = tuple(item for item in matrix_ids if item not in required_eids)
        matchers = () if variant is None else variant.required
        for event_id in required_eids:
            matcher = next((item for item in matchers if item.event_id == event_id), None)
            match_fields: dict[str, object] = {"event_id": event_id, "technique": technique}
            if matcher is not None:
                if matcher.image_endswith:
                    match_fields["image_endswith"] = list(matcher.image_endswith)
                if matcher.parent_image_endswith:
                    match_fields["parent_image_endswith"] = list(matcher.parent_image_endswith)
                if matcher.source_image_contains:
                    match_fields["source_image_contains"] = list(matcher.source_image_contains)
                if matcher.target_image_endswith:
                    match_fields["target_image_endswith"] = list(matcher.target_image_endswith)
                if matcher.target_object_contains:
                    match_fields["target_object_contains"] = list(matcher.target_object_contains)
                if matcher.target_filename_contains:
                    match_fields["target_filename_contains"] = list(matcher.target_filename_contains)
                if matcher.command_line_contains:
                    match_fields["command_line_contains"] = list(matcher.command_line_contains)
            required_tokens.append(f"eid{event_id}")
            description = (
                f"{ph_id} 变体必过 Sysmon EID{event_id} × {technique}"
                if variant is not None
                else f"{ph_id} 矩阵数据源投影：Sysmon EID{event_id} × {technique}"
            )
            if matcher is not None and matcher.functional:
                description = (
                    f"{ph_id} 功能真值（载荷已执行）Sysmon EID{event_id} × {technique}；"
                    "不是该行映射/stomping 变体的 TTP oracle"
                )
            assertions.append(
                TelemetryAssertion(
                    assertion_id=f"{spec.atom_id}.{ph_id.lower()}.sysmon.event_id.{event_id}",
                    kind=SignalKind.POSITIVE,
                    level=SignalLevel.REQUIRED,
                    match_fields=match_fields,
                    description=description,
                )
            )
        for event_id in optional_eids:
            assertions.append(
                TelemetryAssertion(
                    assertion_id=f"{spec.atom_id}.{ph_id.lower()}.sysmon.event_id.{event_id}.optional",
                    kind=SignalKind.POSITIVE,
                    level=SignalLevel.OPTIONAL,
                    match_fields={"event_id": event_id, "technique": technique},
                    description=(
                        f"{ph_id} 矩阵行内其他变体可能产生 Sysmon EID{event_id}，"
                        "本实现不作为 Harness 必过"
                    ),
                )
            )
    if not assertions:
        return None
    ph_token = "-".join(ph_id.lower() for ph_id in spec.ph_ids)
    event_token = "-".join(dict.fromkeys(required_tokens))
    return TelemetryContract(
        contract_id=f"telemetry://{spec.atom_id}/{ph_token}/sysmon-{event_token}-v1",
        atom_id=spec.atom_id,
        profile_ids=(profile_id,),
        source_ref=f"{coverage.source_ref} ({', '.join(spec.ph_ids)})",
        assertions=tuple(assertions),
    )


def upsert_telemetry_contracts(
    path: str | Path, contracts: tuple[TelemetryContract, ...]
) -> Path:
    """Merge contracts by contract_id into catalog/telemetry/contracts.json."""

    target = Path(path).resolve()
    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    by_id: dict[str, dict[str, object]] = {}
    if target.is_file():
        raw = json.loads(target.read_text(encoding="utf-8"))
        values = raw["contracts"] if isinstance(raw, dict) else raw
        if not isinstance(values, list):
            raise ValueError("遥测合同文档顶层必须是数组或含 contracts 数组的对象")
        for item in values:
            parsed = TelemetryContract.model_validate(item)
            by_id[parsed.contract_id] = parsed.model_dump(mode="json")
    for contract in contracts:
        by_id[contract.contract_id] = contract.model_dump(mode="json")
    payload = {"contracts": [by_id[key] for key in sorted(by_id)]}
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    staging = target.with_name(f".{target.name}.{uuid4().hex}.part")
    try:
        _atomic_write_text(staging, encoded)
        os.replace(staging, target)
    except Exception:
        if staging.exists():
            staging.unlink()
        raise
    return target


def _atomic_write_text(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        pending = memoryview(content.encode("utf-8"))
        while pending:
            written = os.write(descriptor, pending)
            if written <= 0:  # pragma: no cover - OS failure
                raise OSError("telemetry contract write returned zero bytes")
            pending = pending[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = ["project_sysmon_telemetry_contract", "upsert_telemetry_contracts"]
