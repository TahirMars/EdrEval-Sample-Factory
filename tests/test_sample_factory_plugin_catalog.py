from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from packages.sample_factory.cas import ContentAddressedStore
from packages.sample_factory.catalog import CoverageRegistry, CoverageRow
from packages.sample_factory.compiler import source_tree_digest
from packages.sample_factory.models import PluginProvenance
from packages.sample_factory.plugin_catalog import (
    PluginCatalogPromotionService,
    PluginRunSourceResolver,
)
from packages.sample_factory.plugin_models import (
    PluginAuthoringResult,
    PluginBuildResult,
    PluginLifecycleStatus,
    PluginSourceCandidate,
    PluginValidationResult,
)

from tests.sample_factory_fixtures import atom_specs


class _Resolver:
    def __init__(self, root: Path) -> None:
        self.root = root

    def resolve(self, source_ref: str) -> Path:
        if source_ref != "plugin-source://candidate":
            raise KeyError(source_ref)
        return self.root


class _ArtifactResolver:
    def __init__(self, artifact: Path) -> None:
        self.artifact = artifact

    def resolve_artifact(self, artifact_ref: str) -> Path:
        if artifact_ref != "plugin-build-artifact://candidate/build1":
            raise KeyError(artifact_ref)
        return self.artifact


class PluginCatalogPromotionTest(unittest.TestCase):
    def test_run_source_resolver_accepts_immutable_repair_revision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            source = (
                runtime
                / "plugin-runs"
                / "2026"
                / "09"
                / "07"
                / "plugin-run-12345678"
                / "authoring"
                / "repair-deadbeef"
            )
            source.mkdir(parents=True)

            resolved = PluginRunSourceResolver(runtime).resolve(
                "plugin-source://plugin-run-12345678/repair-deadbeef"
            )

            self.assertEqual(source.resolve(), resolved)

            with self.assertRaises(ValueError):
                PluginRunSourceResolver(runtime).resolve(
                    "plugin-source://plugin-run-*/repair-deadbeef"
                )

    def test_review_and_dispatchable_require_separate_approvals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "candidate"
            (source / "src").mkdir(parents=True)
            (source / "src" / "EarlyApcInjection.h").write_text(
                '#pragma once\n#include <cstddef>\nextern "C" int '
                "EdrEvalTtp_EarlyApcInjection_Execute(const char*, char*, std::size_t);\n",
                encoding="utf-8",
            )
            (source / "src" / "EarlyApcInjection.cpp").write_text(
                '#include "EarlyApcInjection.h"\nint '
                "EdrEvalTtp_EarlyApcInjection_Execute(const char*, char*, std::size_t) "
                "{ return 0; }\n",
                encoding="utf-8",
            )
            (source / "generated").mkdir()
            (source / "generated" / "sample.vcxproj").write_text(
                "<Project />\n", encoding="utf-8"
            )
            digest = source_tree_digest(source)
            implementation_digest = source_tree_digest(source / "src")
            artifact = root / "EarlyApcInjection.lib"
            artifact.write_bytes(b"validation library")
            artifact_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
            source_candidate = PluginSourceCandidate(
                plugin_id=spec.atom_id,
                implementation_name="EarlyApcInjection",
                source_ref="plugin-source://candidate",
                source_digest=digest,
                changed_files=(
                    "generated/sample.vcxproj",
                    "src/EarlyApcInjection.cpp",
                    "src/EarlyApcInjection.h",
                ),
                atom_spec=spec,
                required_capabilities=spec.required_capabilities,
                provided_capabilities=spec.provided_capabilities,
            )
            result = PluginAuthoringResult(
                plugin_run_id="plugin-run-12345678",
                request_id="plugin-request-12345678",
                status=PluginLifecycleStatus.BEHAVIOR_VALID,
                source=source_candidate,
                build=PluginBuildResult(
                    build_ref="plugin-build://candidate",
                    artifact_ref="plugin-build-artifact://candidate/build1",
                    artifact_sha256=artifact_digest,
                    source_digest=digest,
                    implementation_source_digest=implementation_digest,
                    artifact_filename="EarlyApcInjection.lib",
                    toolchain_fp="msvc@pinned",
                    build_id="build1",
                ),
                validation=PluginValidationResult(
                    harness_ref="plugin-harness://execution/windows-x64/v1",
                    contract_valid=True,
                    atom_valid=True,
                    behavior_valid=True,
                    evidence_ref="plugin-evidence://candidate",
                ),
            )
            provenance = PluginProvenance(
                repository_ref="plugin://reviewed/atom.in.apc",
                source_revision=digest,
                source_refs=("https://example.invalid/reference",),
                audit_passed=True,
                pinned=True,
                reviewed_by="reviewer-1",
                reviewed_at=datetime(2026, 9, 4, tzinfo=UTC),
            )
            service = PluginCatalogPromotionService(
                root / "catalog",
                _Resolver(source),
                artifact_resolver=_ArtifactResolver(artifact),
                artifact_store=ContentAddressedStore(root / "runtime"),
            )

            with self.assertRaises(PermissionError):
                service.review(result, provenance, approved=False)
            reviewed = service.review(result, provenance, approved=True)
            self.assertTrue((reviewed / "plugin.json").is_file())
            self.assertFalse((reviewed / "src" / "generated" / "main.cpp").exists())
            self.assertFalse(any(reviewed.rglob("*.lib")))
            manifest = json.loads((reviewed / "plugin.json").read_text(encoding="utf-8"))
            self.assertEqual("sf-plugin-v2", manifest["format_version"])
            self.assertEqual("source", manifest["glue"]["input_kind"])
            self.assertEqual("validation_only", manifest["validation_build"]["purpose"])
            self.assertTrue(manifest["validation_build"]["artifact_ref"].startswith(
                "object://artifacts/sha256/"
            ))
            with self.assertRaises(PermissionError):
                service.promote_dispatchable(spec.atom_id, approved=False)
            dispatched = service.promote_dispatchable(spec.atom_id, approved=True)
            self.assertTrue((dispatched / "plugin.json").is_file())

    def test_review_ignores_embed_handoff_header_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service, result, provenance, source = _behavior_valid_review_setup(root)
            (source / "generated" / "handoff_shellcode_v1.h").write_text(
                "/* auto-generated from handoff://shellcode/v1; do not edit */\n"
                "static const unsigned char kHandoffShellcodeV1[] = {0x90};\n",
                encoding="utf-8",
            )
            self.assertNotEqual(
                source_tree_digest(source),
                result.source.source_digest,
            )

            reviewed = service.review(result, provenance, approved=True)
            self.assertTrue((reviewed / "plugin.json").is_file())
            self.assertFalse((reviewed / "src" / "handoff_shellcode_v1.h").exists())
            again = service.review(result, provenance, approved=True)
            self.assertEqual(reviewed, again)

    def test_review_same_source_refreshes_new_harness_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service, result, provenance, source = _behavior_valid_review_setup(root)
            reviewed = service.review(result, provenance, approved=True)
            updated = result.model_copy(
                update={
                    "validation": result.validation.model_copy(
                        update={
                            "evidence_ref": "plugin-evidence://candidate/reverified",
                        }
                    )
                }
            )
            again = service.review(updated, provenance, approved=True)
            self.assertEqual(reviewed, again)
            manifest = json.loads((reviewed / "plugin.json").read_text(encoding="utf-8"))
            self.assertEqual(
                "plugin-run-12345678;evidence=plugin-evidence://candidate/reverified",
                manifest["source"]["lineage"],
            )
            self.assertEqual(
                "plugin-evidence://candidate/reverified",
                manifest["validation_build"]["evidence_ref"],
            )

    def test_review_rejects_existing_plugin_from_different_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service, result, provenance, source = _behavior_valid_review_setup(root)
            service.review(result, provenance, approved=True)
            other_run = result.model_copy(update={"plugin_run_id": "plugin-run-abcdef01"})

            with self.assertRaisesRegex(ValueError, "新源码必须使用新插件 revision"):
                service.review(other_run, provenance, approved=True)

    def test_review_projects_sysmon_contract_from_coverage_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _service, result, provenance, source = _behavior_valid_review_setup(root)
            assert result.source is not None and result.source.atom_spec is not None
            spec = result.source.atom_spec.model_copy(
                update={"telemetry_contract_ref": None}
            )
            result = result.model_copy(
                update={"source": result.source.model_copy(update={"atom_spec": spec})}
            )
            service = PluginCatalogPromotionService(
                root / "catalog",
                _Resolver(source),
                artifact_resolver=_ArtifactResolver(root / "EarlyApcInjection.lib"),
                artifact_store=ContentAddressedStore(root / "runtime"),
                coverage=CoverageRegistry(
                    {"PH-IN04": ("T1055.004",)},
                    rows={
                        "PH-IN04": CoverageRow(
                            ph_id="PH-IN04",
                            attack_ids=("T1055.004",),
                            technique="APC Injection",
                            data_sources="Sysmon EID1(创建挂起进程) EID10",
                            endpoint_visibility="partial",
                            audit_prerequisites="需Sysmon",
                            detection_layers="behavior",
                            matrix_evasion_tier="E2",
                            expected_signals="CREATE_SUSPENDED + APC 排队访问组合",
                        )
                    },
                    source_ref="docs/coverage/procedure-host-ttp-coverage-matrix.md#test",
                ),
                profile_id="win11-sysmon15-no-edr",
            )

            reviewed = service.review(result, provenance, approved=True)
            manifest = json.loads((reviewed / "plugin.json").read_text(encoding="utf-8"))
            self.assertEqual(
                "telemetry://atom.in.apc/ph-in04/sysmon-eid1-eid10-v1",
                manifest["spec"]["telemetry_contract_ref"],
            )
            contracts = json.loads(
                (root / "catalog" / "telemetry" / "contracts.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(1, len(contracts["contracts"]))
            self.assertEqual(
                [1, 10],
                [
                    item["match_fields"]["event_id"]
                    for item in contracts["contracts"][0]["assertions"]
                ],
            )

    def test_review_rejects_non_handoff_source_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service, result, provenance, source = _behavior_valid_review_setup(root)
            (source / "generated" / "notes.h").write_text(
                "#pragma once\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "候选源码闭包 SHA"):
                service.review(result, provenance, approved=True)


def _behavior_valid_review_setup(root: Path):
    source = root / "candidate"
    (source / "src").mkdir(parents=True)
    (source / "src" / "EarlyApcInjection.h").write_text(
        '#pragma once\n#include <cstddef>\nextern "C" int '
        "EdrEvalTtp_EarlyApcInjection_Execute(const char*, char*, std::size_t);\n",
        encoding="utf-8",
    )
    (source / "src" / "EarlyApcInjection.cpp").write_text(
        '#include "EarlyApcInjection.h"\nint '
        "EdrEvalTtp_EarlyApcInjection_Execute(const char*, char*, std::size_t) "
        "{ return 0; }\n",
        encoding="utf-8",
    )
    (source / "generated").mkdir()
    (source / "generated" / "sample.vcxproj").write_text(
        "<Project />\n", encoding="utf-8"
    )
    digest = source_tree_digest(source)
    implementation_digest = source_tree_digest(source / "src")
    artifact = root / "EarlyApcInjection.lib"
    artifact.write_bytes(b"validation library")
    artifact_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
    result = PluginAuthoringResult(
        plugin_run_id="plugin-run-12345678",
        request_id="plugin-request-12345678",
        status=PluginLifecycleStatus.BEHAVIOR_VALID,
        source=PluginSourceCandidate(
            plugin_id=spec.atom_id,
            implementation_name="EarlyApcInjection",
            source_ref="plugin-source://candidate",
            source_digest=digest,
            changed_files=(
                "generated/sample.vcxproj",
                "src/EarlyApcInjection.cpp",
                "src/EarlyApcInjection.h",
            ),
            atom_spec=spec,
            required_capabilities=spec.required_capabilities,
            provided_capabilities=spec.provided_capabilities,
        ),
        build=PluginBuildResult(
            build_ref="plugin-build://candidate",
            artifact_ref="plugin-build-artifact://candidate/build1",
            artifact_sha256=artifact_digest,
            source_digest=digest,
            implementation_source_digest=implementation_digest,
            artifact_filename="EarlyApcInjection.lib",
            toolchain_fp="msvc@pinned",
            build_id="build1",
        ),
        validation=PluginValidationResult(
            harness_ref="plugin-harness://execution/windows-x64/v1",
            contract_valid=True,
            atom_valid=True,
            behavior_valid=True,
            evidence_ref="plugin-evidence://candidate",
        ),
    )
    provenance = PluginProvenance(
        repository_ref="plugin://reviewed/atom.in.apc",
        source_revision=digest,
        source_refs=("https://example.invalid/reference",),
        audit_passed=True,
        pinned=True,
        reviewed_by="reviewer-1",
        reviewed_at=datetime(2026, 9, 4, tzinfo=UTC),
    )
    service = PluginCatalogPromotionService(
        root / "catalog",
        _Resolver(source),
        artifact_resolver=_ArtifactResolver(artifact),
        artifact_store=ContentAddressedStore(root / "runtime"),
    )
    return service, result, provenance, source


if __name__ == "__main__":
    unittest.main()
