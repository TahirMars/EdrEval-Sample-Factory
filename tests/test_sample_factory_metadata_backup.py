from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.metadata_backup import MetadataBackupService


class MetadataBackupTest(unittest.TestCase):
    def test_backup_and_restore_exclude_runtime_objects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            factory = root / "factory"
            (factory / "catalog").mkdir(parents=True)
            (factory / "manifests").mkdir()
            (factory / "runtime" / "runs").mkdir(parents=True)
            (factory / "runtime" / "store" / "artifacts").mkdir(parents=True)
            (factory / "catalog" / "contract.json").write_text("{}\n", encoding="utf-8")
            (factory / "runtime" / "runs" / "run.json").write_text("{}\n", encoding="utf-8")
            (factory / "runtime" / "store" / "artifacts" / "sample.exe").write_bytes(b"binary")
            backup = root / "metadata.zip"
            service = MetadataBackupService(factory)

            with self.assertRaises(PermissionError):
                service.create(backup, approved=False)
            created = service.create(backup, approved=True)
            restored = root / "restored"
            result = service.restore(backup, restored, approved=True)

            self.assertEqual(2, created["file_count"])
            self.assertEqual(2, result["restored_file_count"])
            self.assertTrue((restored / "catalog" / "contract.json").is_file())
            self.assertTrue((restored / "runtime" / "runs" / "run.json").is_file())
            self.assertFalse((restored / "runtime" / "store").exists())

    def test_restore_refuses_nonempty_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            factory = root / "factory"
            factory.mkdir()
            (factory / "layout.json").write_text("{}\n", encoding="utf-8")
            backup = root / "metadata.zip"
            MetadataBackupService(factory).create(backup, approved=True)
            destination = root / "restored"
            destination.mkdir()
            (destination / "existing").write_text("x", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "必须为空"):
                MetadataBackupService.restore(backup, destination, approved=True)


if __name__ == "__main__":
    unittest.main()
