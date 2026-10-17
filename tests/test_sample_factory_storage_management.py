from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from packages.sample_factory.cas import ContentAddressedStore, ObjectNamespace
from packages.sample_factory.storage_management import StorageManager


class StorageManagementTest(unittest.TestCase):
    def test_gc_plan_retains_referenced_and_finds_old_unreferenced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "runtime"
            catalog = root / "catalog"
            manifests = root / "manifests"
            source1, source2 = root / "one.bin", root / "two.bin"
            source1.write_bytes(b"one")
            source2.write_bytes(b"two")
            cas = ContentAddressedStore(runtime)
            retained = cas.put_file(ObjectNamespace.ARTIFACTS, source1)
            unreferenced = cas.put_file(ObjectNamespace.ARTIFACTS, source2)
            old = time.time() - 40 * 86400
            os.utime(retained.path, (old, old))
            os.utime(unreferenced.path, (old, old))
            run = runtime / "runs" / "2026" / "09" / "04" / "run-12345678"
            run.mkdir(parents=True)
            (run / "result.json").write_text(
                json.dumps({"artifact_ref": retained.object_ref}), encoding="utf-8"
            )
            manager = StorageManager(
                factory_root=root,
                runtime_root=runtime,
                catalog_root=catalog,
                manifest_root=manifests,
            )

            plan = manager.gc_plan(grace_days=30)

            self.assertEqual(1, plan["candidate_count"])
            self.assertEqual(unreferenced.object_ref, plan["candidates"][0]["object_ref"])
            with self.assertRaises(PermissionError):
                manager.collect(grace_days=30, approved=False)
            deleted = manager.collect(grace_days=30, approved=True)
            self.assertEqual(1, deleted["deleted_count"])
            self.assertTrue(retained.path.is_file())
            self.assertFalse(unreferenced.path.exists())


if __name__ == "__main__":
    unittest.main()
