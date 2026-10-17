"""Deterministic extraction of learnable experience from a verified result."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from packages.sample_factory.experience import ExperienceRecord, KnowledgeMaturity
from packages.sample_factory.models import AtomSpec

if TYPE_CHECKING:
    from packages.sample_factory.pipeline import ProductionResult


class ExperienceExtractor:
    """Convert verified production facts into an outbox proposal.

    Capability names are supplied by the authoritative catalog resolver. The extractor
    never derives them from ATT&CK IDs or free-form rationale.
    """

    def __init__(self, proposal_root: str | Path) -> None:
        self._root = Path(proposal_root).resolve()

    def extract_success(
        self,
        result: ProductionResult,
        specs: Sequence[AtomSpec],
        *,
        capabilities_by_atom: Mapping[str, Sequence[str]],
        architecture: str,
    ) -> Path | None:
        if not result.produced or result.plan is None or result.record is None:
            return None
        if result.truth is None or not result.truth.success:
            return None
        recipe = result.plan.recipe
        capabilities = tuple(
            sorted(
                {
                    capability
                    for spec in specs
                    for capability in capabilities_by_atom.get(spec.atom_id, ())
                }
            )
        )
        if not capabilities:
            raise ValueError("经验提取需要权威 catalog 提供 capabilities_by_atom")
        missing = set(recipe.atom_ids) - {spec.atom_id for spec in specs}
        if missing:
            raise ValueError(f"经验提取 specs 缺少 atom：{sorted(missing)}")
        experience_id = f"experience-{result.plan.combination_fingerprint[:16]}"
        record = ExperienceRecord(
            experience_id=experience_id,
            version=1,
            maturity=KnowledgeMaturity.BEHAVIOR_VALID,
            ph_sequence=recipe.ph_ids,
            atom_ids=recipe.atom_ids,
            capabilities=capabilities,
            profile_ids=(result.record.profile_id,),
            architecture=architecture,
            atom_parameters={
                key: dict(value) for key, value in result.plan.atom_parameters.items()
            },
            evidence_refs=tuple(
                ref
                for ref in (
                    None if result.run_id is None else f"factory-run://{result.run_id}",
                    (
                        None
                        if result.run_id is None or result.attempt_id is None
                        else f"factory-attempt://{result.run_id}/{result.attempt_id}"
                    ),
                    result.artifact_ref,
                    result.verification_ref,
                )
                if ref is not None
            ),
            success_count=1,
            semantic_summary=(
                f"Verified composition {' -> '.join(recipe.atom_ids)} "
                f"for profile {result.record.profile_id}"
            ),
        )
        self._root.mkdir(parents=True, exist_ok=True)
        if result.artifact_sha256 is None:
            raise ValueError("成功经验缺少 artifact_sha256")
        target = self._root / f"{experience_id}-{result.artifact_sha256}.json"
        staging = target.with_name(f".{target.name}.part")
        encoded = (
            json.dumps(
                record.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True
            )
            + "\n"
        )
        if target.exists():
            if target.read_text(encoding="utf-8") != encoded:
                raise ValueError("同一经验候选身份已存在但内容冲突")
            return target
        staging.write_text(
            encoded,
            encoding="utf-8",
            newline="\n",
        )
        os.replace(staging, target)
        return target


__all__ = ["ExperienceExtractor"]
