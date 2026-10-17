"""Pick one canonical plugin-run per TTP plugin without deleting history."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

PLUGIN_LIFECYCLE_RANK = {
    "dispatchable": 90,
    "reviewed": 80,
    "behavior_valid": 70,
    "atom_valid": 60,
    "contract_valid": 50,
    "compile_valid": 40,
    "scaffolded": 30,
    "requested": 20,
    "failed": 10,
    "deprecated": 2,
    "revoked": 1,
    "seed_only": 0,
}


def plugin_run_identity(item: Mapping[str, object]) -> str:
    plugin_id = str(item.get("plugin_id") or "").strip()
    if plugin_id:
        return f"plugin:{plugin_id}"
    name = str(item.get("implementation_name") or "").strip()
    if name:
        return f"name:{name}"
    return f"run:{item.get('plugin_run_id') or ''}"


def plugin_run_sort_key(item: Mapping[str, object]) -> tuple[object, ...]:
    return (
        PLUGIN_LIFECYCLE_RANK.get(str(item.get("lifecycle_status") or ""), -1),
        str(item.get("updated_at") or ""),
        str(item.get("plugin_run_id") or ""),
    )


def select_canonical_plugin_runs(
    runs: Sequence[Mapping[str, object]],
) -> tuple[dict[str, object], ...]:
    """Keep the highest-lifecycle run per plugin_id; attach superseded_runs count."""
    groups: dict[str, list[dict[str, object]]] = {}
    for item in runs:
        if not isinstance(item, Mapping):
            continue
        payload = dict(item)
        groups.setdefault(plugin_run_identity(payload), []).append(payload)
    selected: list[dict[str, object]] = []
    for bucket in groups.values():
        best = dict(max(bucket, key=plugin_run_sort_key))
        best["superseded_runs"] = len(bucket) - 1
        selected.append(best)
    selected.sort(
        key=lambda item: (
            str(item.get("implementation_name") or ""),
            str(item.get("plugin_id") or ""),
            str(item.get("plugin_run_id") or ""),
        )
    )
    return tuple(selected)


__all__ = [
    "PLUGIN_LIFECYCLE_RANK",
    "plugin_run_identity",
    "plugin_run_sort_key",
    "select_canonical_plugin_runs",
]
