from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.factory_layout import initialize_factory_layout


class FactoryLayoutTest(unittest.TestCase):
    def test_initializes_v2_layout_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "factory"

            first = initialize_factory_layout(root)
            second = initialize_factory_layout(root)

            self.assertEqual(first, second)
            self.assertFalse(first["catalog_ready"])
            self.assertTrue((root / "catalog" / "plugins" / "dispatchable").is_dir())
            self.assertTrue((root / "runtime" / "runs").is_dir())
            self.assertTrue((root / "runtime" / "runs").is_dir())
            self.assertIn("/runtime/", (root / ".gitignore").read_text(encoding="utf-8"))
            self.assertIn("`runtime/`", (root / "README.md").read_text(encoding="utf-8"))
            contracts = json.loads(
                (root / "catalog" / "telemetry" / "contracts.json").read_text(encoding="utf-8")
            )
            self.assertEqual({"contracts": []}, contracts)
            manifest = json.loads((root / "layout.json").read_text(encoding="utf-8"))
            self.assertEqual("sample-factory-layout-v2", manifest["schema_version"])

    def test_refuses_to_overwrite_incompatible_gitignore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "factory"
            root.mkdir()
            (root / ".gitignore").write_text("*.tmp\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "gitignore"):
                initialize_factory_layout(root)


if __name__ == "__main__":
    unittest.main()
