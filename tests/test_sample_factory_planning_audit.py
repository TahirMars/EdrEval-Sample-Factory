from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.ai_planner import FactoryPlanningAgent
from packages.sample_factory.errors import PlanningAuditError
from packages.sample_factory.planning_audit import PlanningAuditRepository

from tests.sample_factory_fixtures import catalog
from tests.test_sample_factory_ai_pipeline import (
    FakeCompletionClient,
    _composition,
    _context,
)


class PlanningAuditRepositoryTest(unittest.TestCase):
    def _plan(self):
        return FactoryPlanningAgent(
            FakeCompletionClient([_composition()]), catalog()
        ).plan(_context())

    def test_accepted_selection_is_written_as_auditable_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "planning-audits"
            repository = PlanningAuditRepository(root)

            audit_ref = repository.record(
                self._plan(),
                _context(),
                worker_id="audit-worker",
                approved=True,
                high_risk_approved=False,
                workspace_ref="plugin-workspace://audit-run",
                build_target_ref="build-target://windows-msvc-v143-x64",
                regression_set_version="audit-v1",
            )

            files = list(root.glob("*.json"))
            self.assertEqual(1, len(files))
            self.assertEqual(audit_ref, f"planning-audit://{files[0].name}")
            payload = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual("sample-factory-planning-audit-v1", payload["schema_version"])
            self.assertEqual("audit-worker", payload["worker_id"])
            self.assertEqual(
                ["atom.ia.document", "atom.ob.decode", "atom.in.apc"],
                [
                    payload["accepted_composition"]["carrier"],
                    *payload["accepted_composition"]["loader_atoms"],
                    *payload["accepted_composition"]["execution_atoms"],
                ],
            )
            self.assertEqual(42, payload["planning_context"]["seed"])
            self.assertEqual(64, len(payload["plan_fingerprint"]))
            self.assertEqual(64, len(payload["combination_fingerprint"]))

    def test_write_failure_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "not-a-directory"
            root.write_text("occupied", encoding="utf-8")
            repository = PlanningAuditRepository(root)

            with self.assertRaises(PlanningAuditError):
                repository.record(
                    self._plan(),
                    _context(),
                    worker_id="audit-worker",
                    approved=True,
                    high_risk_approved=False,
                    workspace_ref="plugin-workspace://audit-run",
                    build_target_ref="build-target://windows-msvc-v143-x64",
                    regression_set_version="audit-v1",
                )


if __name__ == "__main__":
    unittest.main()
