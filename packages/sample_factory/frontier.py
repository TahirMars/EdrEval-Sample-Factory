"""evasion_frontier 紧迫工单的确定性筛选。"""

from __future__ import annotations

from dataclasses import dataclass

from packages.sample_factory.models import ComboRecord, ComboStatus
from packages.schemas.enums import ResultClass


@dataclass(frozen=True)
class UrgentFinding:
    record_id: str
    combo_digest: str
    ph_sequence: tuple[str, ...]
    profile_id: str
    evasion_tier: str
    baseline_record_id: str | None


def select_urgent_findings(
    records: tuple[ComboRecord, ...],
    *,
    no_edr_profile_ids: frozenset[str] = frozenset(),
) -> tuple[UrgentFinding, ...]:
    """筛 A SUCCESS + B missed_detection + E3/E4；no-edr 不能单独成工单。"""
    baselines: dict[tuple[tuple[str, ...], str], str] = {}
    for record in records:
        tier = str(record.parameters_canonical.get("evasion_tier", ""))
        outcome = record.detection_outcome
        if (
            record.status is ComboStatus.SUCCESS
            and tier in {"E0", "E1", "E2"}
            and outcome is not None
            and outcome.result_class is ResultClass.DETECTED
        ):
            baselines[(record.ph_sequence, record.profile_id)] = record.record_id

    findings: list[UrgentFinding] = []
    for record in records:
        tier = str(record.parameters_canonical.get("evasion_tier", ""))
        outcome = record.detection_outcome
        if (
            record.status is ComboStatus.SUCCESS
            and record.profile_id not in no_edr_profile_ids
            and tier in {"E3", "E4"}
            and outcome is not None
            and outcome.result_class is ResultClass.MISSED_DETECTION
        ):
            findings.append(
                UrgentFinding(
                    record_id=record.record_id,
                    combo_digest=record.combo_digest,
                    ph_sequence=record.ph_sequence,
                    profile_id=record.profile_id,
                    evasion_tier=tier,
                    baseline_record_id=baselines.get((record.ph_sequence, record.profile_id)),
                )
            )
    return tuple(findings)


__all__ = ["UrgentFinding", "select_urgent_findings"]
