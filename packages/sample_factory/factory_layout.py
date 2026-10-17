"""Bootstrap the external sample-factory repository without catalog data."""

from __future__ import annotations

import json
import os
from os import open as open_descriptor
from pathlib import Path
from uuid import uuid4

_TRACKED_DIRECTORIES = (
    "catalog/plugins/candidate",
    "catalog/plugins/reviewed",
    "catalog/plugins/dispatchable",
    "catalog/plugins/deprecated",
    "catalog/telemetry",
    "catalog/build-targets",
    "catalog/transforms",
    "catalog/harnesses",
    "catalog/payloads",
    "catalog/plugin-plans",
    "catalog/experience/schemas",
    "catalog/experience/composition-patterns",
    "catalog/experience/recipes",
    "catalog/experience/parameter-policies",
    "catalog/experience/transform-pipelines",
    "catalog/experience/anti-patterns",
    "catalog/experience/review-queue",
    "catalog/experience/records",
    "manifests",
    "tooling",
    "scripts",
    "docs",
)
_RUNTIME_DIRECTORIES = (
    "runtime/runs",
    "runtime/plugin-runs",
    "runtime/learning/extracted",
    "runtime/learning/proposals",
    "runtime/learning/evaluations",
    "runtime/store/artifacts/sha256",
    "runtime/store/intermediates/sha256",
    "runtime/store/sources/sha256",
    "runtime/store/inputs/payloads",
    "runtime/store/tools/sha256",
    "runtime/exports/pending",
    "runtime/exports/approved",
    "runtime/exports/published",
    "runtime/exports/revoked",
    "runtime/index",
    "runtime/state",
    "runtime/quarantine",
    "runtime/locks",
    "runtime/temp",
)
_GITIGNORE = """# Sample Factory runtime data plane: never commit generated artifacts or secrets.
/runtime/
/tool-store/
/secrets/
*.exe
*.dll
*.msi
*.pdb
*.bin
*.lib
*.part
"""
_README = """# EdrEval Sample Factory Repository

This repository separates the Git-tracked factory catalog from the ignored runtime data plane.

- `catalog/`: reviewed plugin metadata/source, telemetry contracts, build targets, transforms, harness contracts, and experience metadata. Plugin `.lib` files are validation-only CAS artifacts and are never Glue inputs.
- `manifests/`: stable regression manifests. Generated binaries do not belong here.
- `tooling/`: pinned tool metadata and invocation contracts. Tool binaries stay under ignored runtime storage.
- `runtime/`: run workspaces, source snapshots, build output, VM evidence, object storage, exports, indexes, and temporary state. The entire directory is Git-ignored.
- secrets: stored outside this repository and referenced only through approved secret URIs.

Recreate empty directories with:

```powershell
python -m packages.sample_factory init-layout --root <factory-repository>
```

`layout.json` is the machine-readable directory contract. A new catalog is not production-ready until authoritative plugins, telemetry contracts, build targets, and required payload objects have been imported and preflight passes.
"""


def initialize_factory_layout(root: str | Path) -> dict[str, object]:
    """Create the v2 skeleton idempotently; never invent catalog contracts."""

    target = Path(root).resolve()
    control_repo = Path(__file__).resolve().parents[2]
    if target == control_repo or target.is_relative_to(control_repo):
        raise ValueError("样本工厂目录不得位于 EdrEvalAgent 代码仓内")
    target.mkdir(parents=True, exist_ok=True)

    for relative in (*_TRACKED_DIRECTORIES, *_RUNTIME_DIRECTORIES):
        directory = (target / relative).resolve()
        if not directory.is_relative_to(target):  # pragma: no cover - constants invariant
            raise ValueError(f"factory layout 路径越界：{relative}")
        directory.mkdir(parents=True, exist_ok=True)

    gitignore = target / ".gitignore"
    if gitignore.exists():
        current = gitignore.read_text(encoding="utf-8")
        current_lines = set(current.splitlines())
        missing = [line for line in _GITIGNORE.splitlines() if line and line not in current_lines]
        if missing:
            raise ValueError("现有 .gitignore 缺少 factory v2 规则，拒绝自动覆盖")
    else:
        _atomic_write_text(gitignore, _GITIGNORE)

    readme = target / "README.md"
    if readme.exists():
        if readme.read_text(encoding="utf-8") != _README:
            raise ValueError("现有 README.md 与 sample-factory-layout-v2 不一致")
    else:
        _atomic_write_text(readme, _README)

    layout_manifest = target / "layout.json"
    payload = {
        "schema_version": "sample-factory-layout-v2",
        "catalog_root": "catalog",
        "manifest_root": "manifests",
        "runtime_root": "runtime",
        "tracked_directories": list(_TRACKED_DIRECTORIES),
        "runtime_directories": list(_RUNTIME_DIRECTORIES),
    }
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if layout_manifest.exists():
        current_layout = json.loads(layout_manifest.read_text(encoding="utf-8"))
        if current_layout.get("schema_version") != "sample-factory-layout-v2":
            raise ValueError("现有 layout.json 不是 sample-factory-layout-v2")
        if layout_manifest.read_text(encoding="utf-8") != encoded:
            _atomic_write_text(layout_manifest, encoded)
    else:
        _atomic_write_text(layout_manifest, encoded)

    contracts_path = target / "catalog" / "telemetry" / "contracts.json"
    if not contracts_path.exists():
        _atomic_write_text(
            contracts_path,
            json.dumps({"contracts": []}, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n",
        )

    catalog_ready = (
        any((target / "catalog" / "plugins" / "dispatchable").glob("*/plugin.json"))
        and (target / "catalog" / "telemetry" / "contracts.json").is_file()
        and (target / "catalog" / "build-targets" / "build-targets.json").is_file()
    )
    return {
        "schema_version": "sample-factory-layout-v2",
        "root": target.as_posix(),
        "tracked_directory_count": len(_TRACKED_DIRECTORIES),
        "runtime_directory_count": len(_RUNTIME_DIRECTORIES),
        "catalog_ready": catalog_ready,
    }


def _atomic_write_text(path: Path, content: str) -> None:
    staging = path.with_name(f".{path.name}.{uuid4().hex}.part")
    descriptor = open_descriptor(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        pending = memoryview(content.encode("utf-8"))
        while pending:
            written = os.write(descriptor, pending)
            if written <= 0:  # pragma: no cover - OS failure
                raise OSError("factory layout write returned zero bytes")
            pending = pending[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(staging, path)


__all__ = ["initialize_factory_layout"]
