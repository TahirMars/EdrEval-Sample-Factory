from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.plugin_run_repository import PluginRunRepository

from tests.test_sample_factory_plugin_authoring import _request


class PluginRunRepositoryTest(unittest.TestCase):
    def test_create_event_and_complete_are_run_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repository = PluginRunRepository(Path(tmp) / "runtime")
            request = _request()
            root = repository.create("plugin-run-12345678", request)
            repository.append_event(root, ("plugin_test", {"secret": "hidden"}))

            self.assertTrue((root / "request.json").is_file())
            self.assertTrue((root / "authoring").is_dir())
            event = json.loads((root / "events.jsonl").read_text(encoding="utf-8"))
            self.assertEqual("[REDACTED]", event["data"]["secret"])
            self.assertEqual("plugin-request-12345678", json.loads(
                (root / "request.json").read_text(encoding="utf-8")
            )["request_id"])

    def test_unknown_plugin_run_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            PluginRunRepository(Path(tmp) / "runtime").create(
                "plugin-run-../../escape", _request()
            )


if __name__ == "__main__":
    unittest.main()
