"""Deterministic capability closure and candidate path discovery."""

from __future__ import annotations

from collections.abc import Sequence

from packages.sample_factory.errors import CatalogError
from packages.sample_factory.models import AtomSpec


def validate_capability_closure(specs: Sequence[AtomSpec]) -> None:
    if not any(spec.required_capabilities or spec.provided_capabilities for spec in specs):
        return
    incomplete = [spec.atom_id for spec in specs if not spec.provided_capabilities]
    if incomplete:
        raise CatalogError(f"能力合同不完整，Atom 缺少 provided_capabilities：{incomplete}")
    available: set[str] = set()
    for spec in specs:
        missing = set(spec.required_capabilities) - available
        if missing:
            raise CatalogError(
                f"{spec.atom_id} required_capabilities 未被前序 Atom 提供：{sorted(missing)}"
            )
        available.update(spec.provided_capabilities)


def capability_paths(
    specs: Sequence[AtomSpec], *, max_depth: int = 6, limit: int = 32
) -> tuple[tuple[str, ...], ...]:
    if max_depth < 1 or limit < 1:
        raise ValueError("capability path budget 必须为正数")
    candidates = tuple(spec for spec in specs if spec.provided_capabilities)
    paths: list[tuple[str, ...]] = []

    def visit(
        selected: tuple[AtomSpec, ...], available: frozenset[str], remaining: tuple[AtomSpec, ...]
    ) -> None:
        if len(paths) >= limit or len(selected) >= max_depth:
            return
        for spec in remaining:
            if not set(spec.required_capabilities).issubset(available):
                continue
            next_selected = (*selected, spec)
            paths.append(tuple(item.atom_id for item in next_selected))
            visit(
                next_selected,
                available | frozenset(spec.provided_capabilities),
                tuple(item for item in remaining if item.atom_id != spec.atom_id),
            )

    visit((), frozenset(), candidates)
    paths.sort(key=lambda path: (len(path), path))
    return tuple(paths[:limit])


__all__ = ["capability_paths", "validate_capability_closure"]
