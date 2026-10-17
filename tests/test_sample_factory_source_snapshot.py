from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.cas import ContentAddressedStore
from packages.sample_factory.compiler import source_tree_digest
from packages.sample_factory.errors import BuildError
from packages.sample_factory.source_snapshot import SourceReplayService, SourceSnapshotRepository


class SourceSnapshotRepositoryTest(unittest.TestCase):
    def test_captures_compile_attempt_and_final_build_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "workspace"
            (source / "generated").mkdir(parents=True)
            (source / "generated" / "main.cpp").write_text(
                "int main() { return 0; }\n", encoding="utf-8"
            )
            (source / "sample.vcxproj").write_text("<Project />\n", encoding="utf-8")
            (source / "sample.rc").write_text("1 VERSIONINFO\n", encoding="utf-8")
            (source / "exports.def").write_text("EXPORTS\n", encoding="utf-8")
            digest = source_tree_digest(source)
            cas = ContentAddressedStore(root / "runtime")
            repository = SourceSnapshotRepository(cas=cas)

            attempt = repository.capture(
                source,
                root / "snapshots",
                expected_digest=digest,
                compile_attempt=1,
            )
            final = repository.capture(
                source,
                root / "snapshots",
                expected_digest=digest,
                compile_attempt=1,
                final_build_input=True,
            )

            self.assertEqual(digest, source_tree_digest(attempt.snapshot_root))
            self.assertEqual(digest, source_tree_digest(final.snapshot_root))
            manifest = json.loads(final.manifest_path.read_text(encoding="utf-8"))
            self.assertTrue(manifest["final_build_input"])
            self.assertEqual(4, manifest["file_count"])
            self.assertEqual(
                ["exports.def", "generated/main.cpp", "sample.rc", "sample.vcxproj"],
                [item["path"] for item in manifest["files"]],
            )
            self.assertTrue(
                all(item["object_ref"].startswith("object://sources/sha256/") for item in manifest["files"])
            )
            restored = root / "restored"
            restored_digest = SourceReplayService(cas).restore(final.manifest_path, restored)
            self.assertEqual(digest, restored_digest)

    def test_rejects_changed_source_after_digest_was_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "workspace"
            source.mkdir()
            main = source / "main.cpp"
            main.write_text("int main() { return 0; }\n", encoding="utf-8")
            digest = source_tree_digest(source)
            main.write_text("int main() { return 1; }\n", encoding="utf-8")

            with self.assertRaises(BuildError):
                SourceSnapshotRepository().capture(
                    source,
                    root / "snapshots",
                    expected_digest=digest,
                    compile_attempt=1,
                )

    def test_capture_uses_short_staging_under_windows_max_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "workspace"
            generated = source / "generated"
            generated.mkdir(parents=True)
            (generated / "edreval_execution_log_config.h").write_text(
                "#pragma once\n", encoding="utf-8"
            )
            (generated / "main.cpp").write_text("int main(){return 0;}\n", encoding="utf-8")
            digest = source_tree_digest(source)

            relative = Path("generated") / "edreval_execution_log_config.h"
            old_staging = ".generated-attempt-01." + ("0" * 32) + ".part"
            base = root / "runtime" / "runs" / "2026" / "09" / "08"
            pad = "n"
            parent = base / pad / "source"
            while len(str(parent / old_staging / relative)) <= 260:
                pad += "n"
                parent = base / pad / "source"
            new_staging = ".t" + ("0" * 12) + ".part"
            self.assertGreater(len(str(parent / old_staging / relative)), 260)
            self.assertLess(len(str(parent / new_staging / relative)), 260)

            snapshot = SourceSnapshotRepository().capture(
                source,
                parent,
                expected_digest=digest,
                compile_attempt=1,
            )

            copied = snapshot.snapshot_root / "generated" / "edreval_execution_log_config.h"
            self.assertTrue(copied.is_file())
            self.assertEqual("generated-attempt-01", snapshot.snapshot_root.name)
            leftover = [
                item.name
                for item in parent.iterdir()
                if item.name.endswith(".part")
            ]
            self.assertEqual([], leftover)


if __name__ == "__main__":
    unittest.main()
