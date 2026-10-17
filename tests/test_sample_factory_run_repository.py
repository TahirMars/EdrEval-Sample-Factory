from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from packages.sample_factory.run_models import (
    AttemptStatus,
    PlanningStrategy,
    RunEnvelope,
    RunKind,
    RunStatus,
    new_attempt_id,
    new_run_id,
    utc_now,
)
from packages.sample_factory.run_repository import RunRepository


class RunRepositoryTest(unittest.TestCase):
    def _envelope(self) -> RunEnvelope:
        return RunEnvelope(
            run_id=new_run_id(),
            run_kind=RunKind.SAMPLE_PRODUCTION,
            planning_strategy=PlanningStrategy.AUTO,
            worker_id="worker-1",
            created_at=utc_now(),
            config_fingerprint="a" * 64,
            request_snapshot={"profile_id": "win11", "secret_ref": "secret://fixture"},
        )

    def test_creates_dated_run_and_attempt_with_atomic_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repository = RunRepository(Path(tmp) / "runtime")
            envelope = self._envelope()

            run = repository.create(envelope)
            repository.mark_running(run)
            attempt = repository.start_attempt(
                run,
                attempt_id=new_attempt_id(),
                attempt_number=1,
                seed=42,
                workspace_ref="plugin-workspace://test/attempt-1",
            )
            repository.write_attempt_result(attempt, {"status": "SUCCESS"})
            repository.complete_attempt(
                run,
                attempt,
                status=AttemptStatus.SUCCEEDED,
                result_status="SUCCESS",
            )
            state = repository.finish(
                run,
                status=RunStatus.SUCCEEDED,
                result_status="SUCCESS",
            )

            self.assertEqual(
                Path(tmp).resolve()
                / "runtime"
                / "runs"
                / f"{envelope.created_at.year:04d}"
                / f"{envelope.created_at.month:02d}"
                / f"{envelope.created_at.day:02d}"
                / envelope.run_id,
                run.root,
            )
            self.assertTrue((run.root / "run.json").is_file())
            self.assertTrue((attempt.root / "source" / "final-build-input").parent.is_dir())
            self.assertTrue((attempt.root / "result" / "result.json").is_file())
            self.assertEqual(RunStatus.SUCCEEDED, state.status)
            self.assertEqual(1, state.attempt_count)
            self.assertEqual(1, state.completed_attempt_count)
            self.assertFalse(tuple(run.root.rglob("*.part")))
            listed = repository.list_runs()
            self.assertEqual(envelope.run_id, listed[0][0].run_id)
            shown = repository.run_payload(envelope.run_id)
            self.assertEqual(envelope.run_id, shown["run"]["run_id"])
            self.assertEqual(1, len(shown["attempts"]))
            self.assertTrue(repository.reconcile_report()["healthy"])

    def test_events_are_serialized_and_sensitive_values_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repository = RunRepository(Path(tmp) / "runtime")
            run = repository.create(self._envelope())

            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [
                    executor.submit(
                        repository.append_event,
                        run,
                        "test_event",
                        {
                            "index": index,
                            "password": "must-not-appear",
                            "password_ref": "lab-secret://fixture/password",
                        },
                    )
                    for index in range(20)
                ]
                for future in futures:
                    future.result()

            events = [
                json.loads(line)
                for line in (run.root / "events.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]
            self.assertEqual(20, len(events))
            self.assertEqual(set(range(20)), {event["data"]["index"] for event in events})
            self.assertNotIn("must-not-appear", json.dumps(events))
            self.assertTrue(
                all(event["data"]["password"] == "[REDACTED]" for event in events)
            )
            self.assertTrue(
                all(
                    event["data"]["password_ref"] == "lab-secret://fixture/password"
                    for event in events
                )
            )

    def test_failed_state_requires_failure_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repository = RunRepository(Path(tmp) / "runtime")
            run = repository.create(self._envelope())

            with self.assertRaises(ValueError):
                repository.finish(run, status=RunStatus.FAILED)

    def test_lookup_rejects_glob_or_path_injection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repository = RunRepository(Path(tmp) / "runtime")
            run = repository.create(self._envelope())

            with self.assertRaises(ValueError):
                repository.find_run("run-********")
            with self.assertRaises(ValueError):
                repository.find_attempt(run, "attempt-../../escape")


if __name__ == "__main__":
    unittest.main()
