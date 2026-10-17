from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from packages.sample_factory.cli import cleanup_plugin_runs
from packages.sample_factory.errors import FactoryDenied
from packages.sample_factory.plugin_run_cleanup import (
    execute_plugin_run_cleanup,
    plan_plugin_run_cleanup,
)


def _write_run(
    root: Path,
    *,
    plugin_run_id: str,
    day: str,
    implementation_name: str,
    plugin_id: str,
    run_status: str,
    lifecycle: str | None,
    updated_at: str,
    error: str | None = None,
) -> Path:
    run = root / "plugin-runs" / "2026" / "09" / day / plugin_run_id
    for name in ("authoring", "build", "harness", "verification", "result"):
        (run / name).mkdir(parents=True, exist_ok=True)
    (run / "request.json").write_text(
        json.dumps(
            {
                "schema_version": "sample-factory-plugin-request-v2",
                "request_id": f"req-{plugin_run_id[-8:]}",
                "operation": "create",
                "implementation_name": implementation_name,
                "intent": {
                    "intent_id": "intent-1",
                    "ph_ids": ["PH-EX02"],
                    "role": "execution_atom",
                    "required_capabilities": [],
                    "provided_capabilities": [],
                    "input_ports": [],
                    "output_ports": [],
                    "parameter_domains": {},
                    "produces_handoffs": [],
                    "consumes_handoffs": [],
                    "platform": "windows",
                    "architecture": "x64",
                    "safety_profile": "low",
                    "source_refs": [f"plugin-seed://{plugin_id}"],
                },
                "build_target_ref": "build-target://initial/windows-msvc-v143-x64-plugin",
                "profile_id": "win10-21h2-sysmon15-no-edr",
                "seed_source_ref": f"plugin-seed://{plugin_id}",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    state = {
        "schema_version": "sample-factory-plugin-run-state-v1",
        "plugin_run_id": plugin_run_id,
        "status": run_status,
        "created_at": updated_at,
        "updated_at": updated_at,
    }
    if lifecycle is not None:
        state["lifecycle_status"] = lifecycle
    if error is not None:
        state["error"] = error
    (run / "state.json").write_text(
        json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (run / "events.jsonl").write_text("", encoding="utf-8")
    if lifecycle is not None and lifecycle != "failed":
        (run / "result" / "result.json").write_text(
            json.dumps(
                {
                    "plugin_run_id": plugin_run_id,
                    "request_id": f"req-{plugin_run_id[-8:]}",
                    "status": lifecycle,
                    "source": {
                        "plugin_id": plugin_id,
                        "implementation_name": implementation_name,
                        "source_digest": "a" * 64,
                        "changed_files": ["src/X.cpp"],
                        "source_ref": f"plugin-source://{plugin_run_id}/final-source",
                        "required_capabilities": [],
                        "provided_capabilities": [],
                        "input_ports": [],
                        "output_ports": [],
                        "atom_spec": None,
                    },
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return run


class PluginRunCleanupTest(unittest.TestCase):
    def test_plan_and_execute_remove_failed_and_superseded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_run(
                root,
                plugin_run_id="plugin-run-failed0001",
                day="08",
                implementation_name="CreateProcessCmd",
                plugin_id="atom.ex.create_process_cmd",
                run_status="FAILED",
                lifecycle=None,
                updated_at="2026-09-08T01:00:00+00:00",
                error="Canonical Harness 未证明插件行为有效",
            )
            _write_run(
                root,
                plugin_run_id="plugin-run-oldcompile01",
                day="09",
                implementation_name="UacmeCMLuaUtil",
                plugin_id="atom.pe.uacme_cmluautil",
                run_status="SUCCEEDED",
                lifecycle="compile_valid",
                updated_at="2026-09-09T01:00:00+00:00",
            )
            _write_run(
                root,
                plugin_run_id="plugin-run-oldbehav001",
                day="10",
                implementation_name="UacmeCMLuaUtil",
                plugin_id="atom.pe.uacme_cmluautil",
                run_status="SUCCEEDED",
                lifecycle="behavior_valid",
                updated_at="2026-09-10T01:00:00+00:00",
            )
            _write_run(
                root,
                plugin_run_id="plugin-run-newbehav001",
                day="11",
                implementation_name="UacmeCMLuaUtil",
                plugin_id="atom.pe.uacme_cmluautil",
                run_status="SUCCEEDED",
                lifecycle="behavior_valid",
                updated_at="2026-09-11T01:00:00+00:00",
            )
            _write_run(
                root,
                plugin_run_id="plugin-run-keeploader1",
                day="11",
                implementation_name="GetFromDisk",
                plugin_id="atom.ld.get_from_disk",
                run_status="SUCCEEDED",
                lifecycle="compile_valid",
                updated_at="2026-09-11T02:00:00+00:00",
            )

            plan = plan_plugin_run_cleanup(root)
            ids = {item["plugin_run_id"] for item in plan["candidates"]}
            self.assertEqual(
                {
                    "plugin-run-failed0001",
                    "plugin-run-oldcompile01",
                    "plugin-run-oldbehav001",
                },
                ids,
            )
            self.assertEqual(2, plan["retained_count"])

            with self.assertRaises(FactoryDenied):
                execute_plugin_run_cleanup(root, approved=False)

            result = execute_plugin_run_cleanup(root, approved=True)
            self.assertEqual(3, result["deleted_count"])
            self.assertFalse(
                (root / "plugin-runs" / "2026" / "09" / "08" / "plugin-run-failed0001").exists()
            )
            self.assertTrue(
                (root / "plugin-runs" / "2026" / "09" / "11" / "plugin-run-newbehav001").exists()
            )
            self.assertTrue(
                (root / "plugin-runs" / "2026" / "09" / "11" / "plugin-run-keeploader1").exists()
            )

    def test_cli_wrapper_preview_without_approve(self) -> None:
        from tests.test_sample_factory_plugin_run_validation import _factory_config

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _factory_config(root)
            _write_run(
                root / "runtime",
                plugin_run_id="plugin-run-failed0002",
                day="08",
                implementation_name="CreateProcessCmd",
                plugin_id="atom.ex.create_process_cmd",
                run_status="FAILED",
                lifecycle=None,
                updated_at=datetime.now(UTC).isoformat(),
                error="boom",
            )
            preview = cleanup_plugin_runs(config, approved=False)
            self.assertEqual(1, preview["candidate_count"])
            self.assertTrue(
                (root / "runtime" / "plugin-runs" / "2026" / "09" / "08" / "plugin-run-failed0002").exists()
            )
            applied = cleanup_plugin_runs(config, approved=True)
            self.assertEqual(1, applied["deleted_count"])
            self.assertFalse(
                (root / "runtime" / "plugin-runs" / "2026" / "09" / "08" / "plugin-run-failed0002").exists()
            )


if __name__ == "__main__":
    unittest.main()
