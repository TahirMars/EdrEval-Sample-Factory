"""Approval-gated cleanup for failed or superseded plugin-run packages."""

from __future__ import annotations

import json
import shutil
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path

from packages.sample_factory.errors import FactoryDenied

_PLUGIN_RUNS = "plugin-runs"


def plan_plugin_run_cleanup(runtime_root: str | Path) -> dict[str, object]:
    """Return failed / superseded plugin-run packages without deleting them."""
    root = (Path(runtime_root).resolve() / _PLUGIN_RUNS)
    records = tuple(_iter_plugin_run_records(root))
    by_plugin: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in records:
        by_plugin[str(item["plugin_key"])].append(item)

    candidates: list[dict[str, object]] = []
    seen: set[str] = set()

    def mark(item: Mapping[str, object], reason: str) -> None:
        plugin_run_id = str(item["plugin_run_id"])
        if plugin_run_id in seen:
            return
        seen.add(plugin_run_id)
        candidates.append(
            {
                "plugin_run_id": plugin_run_id,
                "plugin_id": item.get("plugin_id"),
                "implementation_name": item.get("implementation_name"),
                "lifecycle_status": item.get("lifecycle_status"),
                "run_status": item.get("run_status"),
                "updated_at": item.get("updated_at"),
                "run_path": item["run_path"],
                "reason": reason,
            }
        )

    for item in records:
        if item["run_status"] == "FAILED" or item["lifecycle_status"] == "failed":
            mark(item, f"state FAILED: {item.get('error') or 'unknown'}")

    for _plugin_key, items in by_plugin.items():
        behavior_valid = [
            item for item in items if item["lifecycle_status"] == "behavior_valid"
        ]
        compile_valid = [
            item for item in items if item["lifecycle_status"] == "compile_valid"
        ]
        if behavior_valid:
            newest = max(behavior_valid, key=lambda item: str(item["updated_at"]))
            for item in behavior_valid:
                if item["plugin_run_id"] != newest["plugin_run_id"]:
                    mark(
                        item,
                        "older behavior_valid; keep "
                        f"{newest['plugin_run_id']}",
                    )
            for item in compile_valid:
                mark(
                    item,
                    "compile_valid superseded by behavior_valid "
                    f"{newest['plugin_run_id']}",
                )
            continue
        if len(compile_valid) > 1:
            newest = max(compile_valid, key=lambda item: str(item["updated_at"]))
            for item in compile_valid:
                if item["plugin_run_id"] == newest["plugin_run_id"]:
                    continue
                mark(
                    item,
                    "older compile_valid duplicate; keep "
                    f"{newest['plugin_run_id']}",
                )

    candidates.sort(key=lambda item: str(item["plugin_run_id"]))
    retained = [
        {
            "plugin_run_id": item["plugin_run_id"],
            "plugin_id": item.get("plugin_id"),
            "implementation_name": item.get("implementation_name"),
            "lifecycle_status": item.get("lifecycle_status"),
        }
        for item in records
        if str(item["plugin_run_id"]) not in seen
    ]
    retained.sort(key=lambda item: str(item["plugin_run_id"]))
    return {
        "schema_version": "sample-factory-plugin-run-cleanup-plan-v1",
        "runtime_root": Path(runtime_root).resolve().as_posix(),
        "plugin_run_count": len(records),
        "candidate_count": len(candidates),
        "retained_count": len(retained),
        "candidates": candidates,
        "retained": retained,
    }


def execute_plugin_run_cleanup(
    runtime_root: str | Path,
    *,
    approved: bool,
) -> dict[str, object]:
    """Delete failed / superseded plugin-run packages after human approval."""
    if not approved:
        raise FactoryDenied("清理失败/重复插件运行包需要本轮人工审批")
    plan = plan_plugin_run_cleanup(runtime_root)
    runtime = Path(runtime_root).resolve()
    plugin_runs_root = (runtime / _PLUGIN_RUNS).resolve()
    deleted: list[dict[str, object]] = []
    for item in plan["candidates"]:
        assert isinstance(item, dict)
        path = Path(str(item["run_path"])).resolve()
        if not path.is_relative_to(plugin_runs_root):
            raise ValueError(f"plugin run 路径越界：{path}")
        if not path.name.startswith("plugin-run-") or not path.is_dir():
            raise ValueError(f"不是可删除的 plugin-run 目录：{path}")
        shutil.rmtree(path)
        deleted.append(
            {
                "plugin_run_id": item["plugin_run_id"],
                "implementation_name": item.get("implementation_name"),
                "reason": item.get("reason"),
                "run_path": path.as_posix(),
            }
        )
    return {
        "schema_version": "sample-factory-plugin-run-cleanup-result-v1",
        "runtime_root": runtime.as_posix(),
        "deleted": True,
        "deleted_count": len(deleted),
        "retained_count": plan["retained_count"],
        "deleted_runs": deleted,
        "plan": plan,
    }


def _iter_plugin_run_records(plugin_runs_root: Path) -> list[dict[str, object]]:
    if not plugin_runs_root.is_dir():
        return []
    records: list[dict[str, object]] = []
    for state_path in sorted(plugin_runs_root.glob("*/*/*/plugin-run-*/state.json")):
        run = state_path.parent
        state = json.loads(state_path.read_text(encoding="utf-8"))
        request = json.loads((run / "request.json").read_text(encoding="utf-8"))
        result_path = run / "result" / "result.json"
        result = (
            json.loads(result_path.read_text(encoding="utf-8"))
            if result_path.is_file()
            else None
        )
        source = None if not isinstance(result, dict) else result.get("source")
        plugin_id = None
        if isinstance(source, dict) and isinstance(source.get("plugin_id"), str):
            plugin_id = source["plugin_id"]
        if plugin_id is None:
            seed = request.get("seed_source_ref")
            if isinstance(seed, str) and seed.startswith("plugin-seed://"):
                plugin_id = seed.removeprefix("plugin-seed://")
        implementation_name = request.get("implementation_name")
        lifecycle = state.get("lifecycle_status")
        if lifecycle is None and isinstance(result, dict):
            lifecycle = result.get("status")
        plugin_key = plugin_id or implementation_name or run.name
        records.append(
            {
                "plugin_run_id": run.name,
                "plugin_id": plugin_id,
                "plugin_key": plugin_key,
                "implementation_name": implementation_name,
                "lifecycle_status": lifecycle,
                "run_status": state.get("status"),
                "updated_at": state.get("updated_at") or "",
                "error": state.get("error") or "",
                "run_path": run.resolve().as_posix(),
            }
        )
    return records


__all__ = [
    "execute_plugin_run_cleanup",
    "plan_plugin_run_cleanup",
]
