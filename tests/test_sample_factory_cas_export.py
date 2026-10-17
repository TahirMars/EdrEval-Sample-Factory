from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.bundle_models import (
    ArtifactMember,
    ArtifactSet,
    ExecutionStage,
    SampleBundle,
)
from packages.sample_factory.cas import ContentAddressedStore, ObjectNamespace
from packages.sample_factory.errors import BuildError, FactoryDenied
from packages.sample_factory.export import (
    ArtifactExportService,
    ArtifactReplayService,
    BundleExportService,
    list_export_packages,
    locate_sample_telemetry_evidence,
    produced_sample_export_id,
)


class CasAndExportTest(unittest.TestCase):
    def test_cas_is_namespaced_sharded_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.exe"
            source.write_bytes(b"synthetic artifact")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            cas = ContentAddressedStore(root / "runtime")

            first = cas.put_file(
                ObjectNamespace.ARTIFACTS, source, expected_sha256=digest
            )
            second = cas.put_file(ObjectNamespace.ARTIFACTS, source)

            self.assertEqual(first, second)
            self.assertEqual(
                root
                / "runtime"
                / "store"
                / "artifacts"
                / "sha256"
                / digest[:2]
                / digest,
                first.path,
            )
            self.assertEqual(source.read_bytes(), cas.resolve(first.object_ref).read_bytes())
            report = cas.storage_report()
            self.assertEqual(1, report["object_count"])
            self.assertEqual(len(b"synthetic artifact"), report["bytes"])

    def test_cas_rejects_hash_mismatch_and_bad_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.exe"
            source.write_bytes(b"synthetic artifact")
            cas = ContentAddressedStore(root / "runtime")

            with self.assertRaises(BuildError):
                cas.put_file(ObjectNamespace.ARTIFACTS, source, expected_sha256="0" * 64)
            with self.assertRaises(BuildError):
                cas.resolve("object://artifacts/sha256/../../escape")

    def test_export_requires_approval_and_emits_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.bin"
            source.write_bytes(b"synthetic artifact")
            cas = ContentAddressedStore(root / "runtime")
            stored = cas.put_file(ObjectNamespace.ARTIFACTS, source)
            exporter = ArtifactExportService(root / "runtime", cas)

            with self.assertRaises(FactoryDenied):
                exporter.export(
                    export_id="export-12345678",
                    artifact_ref=stored.object_ref,
                    filename="sample.exe",
                    approved=False,
                )
            result = exporter.export(
                export_id="export-12345678",
                artifact_ref=stored.object_ref,
                filename="sample.exe",
                approved=True,
            )

            self.assertEqual(stored.sha256, hashlib.sha256(result.artifact_path.read_bytes()).hexdigest())
            checksums = json.loads(
                (result.artifact_path.parent / "checksums.json").read_text(encoding="utf-8")
            )
            self.assertEqual(stored.sha256, checksums["sample.exe"])
            replay = ArtifactReplayService(cas).replay(stored.object_ref)
            self.assertTrue(replay["verified"])

    def test_export_rejects_path_and_source_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.bin"
            source.write_bytes(b"synthetic artifact")
            cas = ContentAddressedStore(root / "runtime")
            stored = cas.put_file(ObjectNamespace.ARTIFACTS, source)
            exporter = ArtifactExportService(root / "runtime", cas)

            with self.assertRaises(ValueError):
                exporter.export(
                    export_id="export-12345678",
                    artifact_ref=stored.object_ref,
                    filename="../sample.exe",
                    approved=True,
                )
            with self.assertRaises(FactoryDenied):
                exporter.export(
                    export_id="export-12345679",
                    artifact_ref=stored.object_ref,
                    filename="sample.exe",
                    approved=True,
                    source_included=True,
                )

    def test_bundle_export_commits_all_stages_together(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cas = ContentAddressedStore(root / "runtime")
            first_source = root / "first.bin"
            second_source = root / "second.bin"
            first_source.write_bytes(b"first")
            second_source.write_bytes(b"second")
            first = cas.put_file(ObjectNamespace.ARTIFACTS, first_source)
            second = cas.put_file(ObjectNamespace.ARTIFACTS, second_source)
            bundle = SampleBundle(
                bundle_id="bundle-12345678",
                artifact_sets=(
                    ArtifactSet(
                        artifact_set_id="artifact-set-12345678",
                        members=(
                            ArtifactMember(
                                member_id="member-12345678",
                                role="entry",
                                relative_path="stage1.exe",
                                artifact_ref=first.object_ref,
                                sha256=first.sha256,
                                format="pe",
                            ),
                        ),
                        entry_member_id="member-12345678",
                    ),
                    ArtifactSet(
                        artifact_set_id="artifact-set-87654321",
                        members=(
                            ArtifactMember(
                                member_id="member-87654321",
                                role="entry",
                                relative_path="stage2.dll",
                                artifact_ref=second.object_ref,
                                sha256=second.sha256,
                                format="pe",
                            ),
                        ),
                        entry_member_id="member-87654321",
                    ),
                ),
                stages=(
                    ExecutionStage(stage_id="stage-01", artifact_set_id="artifact-set-12345678", trigger_mode="lab_trigger"),
                    ExecutionStage(stage_id="stage-02", artifact_set_id="artifact-set-87654321", trigger_mode="lab_trigger"),
                ),
                entry_stage_id="stage-01",
            )

            result = BundleExportService(root / "runtime", cas).export(
                bundle, export_id="export-bundle001", approved=True
            )

            self.assertTrue((result.artifact_path / "stage-01" / "stage1.exe").is_file())
            self.assertTrue((result.artifact_path / "stage-02" / "stage2.dll").is_file())
            self.assertTrue((result.artifact_path / "bundle.json").is_file())

    def test_published_export_requires_telemetry_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.bin"
            source.write_bytes(b"synthetic artifact")
            cas = ContentAddressedStore(root / "runtime")
            stored = cas.put_file(ObjectNamespace.ARTIFACTS, source)
            exporter = ArtifactExportService(root / "runtime", cas)
            with self.assertRaisesRegex(ValueError, "遥测证据"):
                exporter.export(
                    export_id="export-abcd1234-bbbbccccdddd",
                    artifact_ref=stored.object_ref,
                    filename="abcd1234-bbbbccccdddd.exe",
                    approved=True,
                    destination="published",
                    sample_record={"sample_id": "abcd1234-bbbbccccdddd"},
                )

    def test_published_export_copies_telemetry_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.bin"
            source.write_bytes(b"synthetic artifact")
            cas = ContentAddressedStore(root / "runtime")
            stored = cas.put_file(ObjectNamespace.ARTIFACTS, source)
            evidence_dir, evidence_ref = _seed_telemetry_evidence(root / "runtime", stored.sha256)
            exporter = ArtifactExportService(root / "runtime", cas)
            sample_record = {
                "sample_id": "abcd1234-bbbbccccdddd",
                "ph_sequence": ["PH-IN04", "PH-IN08"],
            }

            result = exporter.export(
                export_id="export-abcd1234-bbbbccccdddd",
                artifact_ref=stored.object_ref,
                filename="abcd1234-bbbbccccdddd.exe",
                approved=True,
                destination="published",
                sample_record=sample_record,
                telemetry_evidence_dir=evidence_dir,
                telemetry_evidence_ref=evidence_ref,
            )

            package = result.artifact_path.parent
            checksums = json.loads((package / "checksums.json").read_text(encoding="utf-8"))
            manifest = json.loads((package / "manifest.json").read_text(encoding="utf-8"))
            self.assertTrue((package / "telemetry" / "telemetry-projection.json").is_file())
            self.assertTrue((package / "telemetry" / "guest-result.json").is_file())
            self.assertTrue((package / "telemetry" / "sample-logs" / "sample.jsonl").is_file())
            self.assertIn("telemetry/telemetry-projection.json", checksums)
            self.assertIn("telemetry/sample-logs/sample.jsonl", checksums)
            self.assertEqual("telemetry", manifest["telemetry_dir"])
            self.assertEqual(evidence_ref, manifest["telemetry_evidence_ref"])
            packages = list_export_packages(root / "runtime")
            self.assertEqual(1, len(packages["published"]))
            self.assertEqual(0, len(packages["approved"]))
            self.assertEqual(
                (evidence_dir, evidence_ref),
                locate_sample_telemetry_evidence(root / "runtime", stored.sha256),
            )

            again = exporter.export(
                export_id="export-abcd1234-bbbbccccdddd",
                artifact_ref=stored.object_ref,
                filename="abcd1234-bbbbccccdddd.exe",
                approved=True,
                destination="published",
                sample_record=sample_record,
                telemetry_evidence_dir=evidence_dir,
                telemetry_evidence_ref=evidence_ref,
            )
            self.assertEqual(result.export_ref, again.export_ref)
            self.assertEqual(
                "export-abcd1234-bbbbccccdddd",
                produced_sample_export_id("abcd1234-bbbbccccdddd"),
            )


def _seed_telemetry_evidence(runtime_root: Path, artifact_sha256: str) -> tuple[Path, str]:
    evidence = (
        runtime_root
        / "runs"
        / "2026"
        / "09"
        / "09"
        / "run-12345678"
        / "attempts"
        / "0001-attempt-12345678"
        / "verification"
        / "verification-aabbccddeeff"
    )
    evidence.mkdir(parents=True)
    (evidence / "telemetry-projection.json").write_text("[]\n", encoding="utf-8")
    (evidence / "guest-result.json").write_text("{}\n", encoding="utf-8")
    logs = evidence / "sample-logs"
    logs.mkdir()
    (logs / "sample.jsonl").write_text('{"event":"sample_start"}\n', encoding="utf-8")
    relative = evidence.relative_to(runtime_root).as_posix()
    evidence_ref = f"vmware-evidence://{relative}"
    result_path = evidence.parents[1] / "result" / "result.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(
        json.dumps(
            {
                "artifact_sha256": artifact_sha256,
                "status": "SUCCESS",
                "verification_ref": evidence_ref,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return evidence, evidence_ref


if __name__ == "__main__":
    unittest.main()
