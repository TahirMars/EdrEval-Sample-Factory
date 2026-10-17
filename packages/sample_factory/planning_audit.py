"""Fail-closed JSON persistence for accepted AI sample plans."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from packages.sample_factory.ai_planner import PlannedRecipe
from packages.sample_factory.errors import PlanningAuditError
from packages.sample_factory.models import FactoryPlanningContext, PlannedComposition


class PlanningAuditRepository:
    """Write one immutable UTF-8 JSON document per accepted planning result."""

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        root_resolver: Callable[[str, str], Path] | None = None,
    ) -> None:
        if (root is None) == (root_resolver is None):
            raise ValueError("planning audit 必须且只能配置固定 root 或 run root resolver")
        self._root = None if root is None else Path(root).resolve()
        self._root_resolver = root_resolver

    @property
    def root(self) -> Path:
        if self._root is None:
            raise ValueError("run-scoped planning audit 没有固定 root")
        return self._root

    def record(
        self,
        plan: PlannedRecipe,
        context: FactoryPlanningContext,
        *,
        worker_id: str,
        approved: bool,
        high_risk_approved: bool,
        workspace_ref: str,
        build_target_ref: str,
        regression_set_version: str,
        run_id: str | None = None,
        attempt_id: str | None = None,
        batch_id: str | None = None,
        batch_attempt: int | None = None,
        excluded_compositions: tuple[PlannedComposition, ...] = (),
    ) -> str:
        now = datetime.now(UTC)
        audit_id = uuid4().hex
        filename = (
            f"{now.strftime('%Y%m%dT%H%M%S%fZ')}-"
            f"{plan.recipe.recipe_id}-{audit_id[:12]}.json"
        )
        payload = {
            "schema_version": "sample-factory-planning-audit-v1",
            "audit_id": audit_id,
            "recorded_at": now.isoformat(),
            "worker_id": worker_id,
            "run_id": run_id,
            "attempt_id": attempt_id,
            "approvals": {
                "approved": approved,
                "high_risk_approved": high_risk_approved,
            },
            "planning_context": context.model_dump(mode="json"),
            "accepted_composition": plan.composition.model_dump(mode="json"),
            "recipe": plan.recipe.model_dump(mode="json"),
            "atom_parameters": plan.atom_parameters,
            "rationale": plan.rationale,
            "plan_fingerprint": plan.plan_fingerprint,
            "combination_fingerprint": plan.combination_fingerprint,
            "planning_strategy": plan.planning_strategy.value,
            "experience_refs": list(plan.experience_refs),
            "experience_set_version": plan.experience_set_version,
            "learning_snapshot_ref": plan.learning_snapshot_ref,
            "workspace_ref": workspace_ref,
            "build_target_ref": build_target_ref,
            "regression_set_version": regression_set_version,
            "batch": {
                "batch_id": batch_id,
                "attempt": batch_attempt,
                "excluded_combinations": [
                    item.model_dump(mode="json") for item in excluded_compositions
                ],
            },
        }
        root = self._resolve_root(run_id, attempt_id)
        try:
            root.mkdir(parents=True, mode=0o700, exist_ok=True)
            target = root / filename
            staging = target.with_name(target.name + ".part")
            staging.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            os.chmod(staging, 0o600)
            if target.exists():  # pragma: no cover - UUID collision guard
                raise FileExistsError(target)
            staging.replace(target)
        except Exception as exc:
            raise PlanningAuditError(f"规划审计 JSON 写入失败：{root}: {exc}") from exc
        if run_id is not None and attempt_id is not None and self._root_resolver is not None:
            return f"planning-audit://{run_id}/{attempt_id}/{filename}"
        return f"planning-audit://{filename}"

    def _resolve_root(self, run_id: str | None, attempt_id: str | None) -> Path:
        if self._root_resolver is None:
            if self._root is None:  # pragma: no cover - constructor invariant
                raise AssertionError("planning audit root missing")
            return self._root
        if run_id is None or attempt_id is None:
            raise PlanningAuditError("run-scoped planning audit 缺少 run_id/attempt_id")
        return self._root_resolver(run_id, attempt_id).resolve()


__all__ = ["PlanningAuditRepository"]
