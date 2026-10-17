from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.run_index import RunIndex
from packages.sample_factory.run_models import (
    PlanningStrategy,
    RunEnvelope,
    RunKind,
    RunStatus,
    new_run_id,
    utc_now,
)
from packages.sample_factory.run_repository import RunRepository


class RunIndexTest(unittest.TestCase):
    def test_rebuild_and_query_projection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            repository = RunRepository(runtime)
            envelope = RunEnvelope(
                run_id=new_run_id(),
                run_kind=RunKind.SAMPLE_PRODUCTION,
                planning_strategy=PlanningStrategy.AUTO,
                worker_id="worker-1",
                created_at=utc_now(),
                config_fingerprint="a" * 64,
                request_snapshot={},
            )
            handle = repository.create(envelope)
            repository.finish(
                handle, status=RunStatus.SUCCEEDED, result_status="SUCCESS"
            )
            index = RunIndex(runtime)

            result = index.rebuild(repository)
            rows = index.list(status="SUCCEEDED")

            self.assertEqual(1, result["run_count"])
            self.assertEqual(envelope.run_id, rows[0]["run_id"])
            self.assertEqual("SUCCESS", rows[0]["result_status"])


if __name__ == "__main__":
    unittest.main()
