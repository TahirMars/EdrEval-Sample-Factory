from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.run_models import utc_now
from packages.sample_factory.work_queue import FactoryWorkQueue, SampleDemand


class FactoryWorkQueueTest(unittest.TestCase):
    def test_submit_claim_and_fulfill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            queue = FactoryWorkQueue(Path(tmp) / "runtime")
            demand = SampleDemand(
                request_id="demand-12345678",
                requested_at=utc_now(),
                requested_by="online-planner",
                ph_ids=("PH-IN04",),
                profile_id="win11",
                architecture="x64",
                max_stages=2,
                rationale="missing verified bundle for the selected chain",
            )
            with self.assertRaises(PermissionError):
                queue.submit(demand, approved=False)
            self.assertEqual(
                "factory-demand://demand-12345678",
                queue.submit(demand, approved=True),
            )
            claimed = queue.claim(demand.request_id, worker_id="worker-1")
            self.assertEqual("CLAIMED", claimed["status"])
            completed = queue.complete(
                demand.request_id,
                worker_id="worker-1",
                result_refs=("bundle://bundle-12345678",),
            )
            self.assertEqual("FULFILLED", completed["status"])
            self.assertEqual(1, len(queue.list()))

    def test_wrong_worker_cannot_complete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            queue = FactoryWorkQueue(Path(tmp) / "runtime")
            demand = SampleDemand(
                request_id="demand-12345678",
                requested_at=utc_now(),
                requested_by="online-planner",
                ph_ids=("PH-IN04",),
                profile_id="win11",
                architecture="x64",
                rationale="fixture",
            )
            queue.submit(demand, approved=True)
            queue.claim(demand.request_id, worker_id="worker-1")
            with self.assertRaisesRegex(ValueError, "当前 worker"):
                queue.complete(
                    demand.request_id,
                    worker_id="worker-2",
                    result_refs=("artifact://x",),
                )


if __name__ == "__main__":
    unittest.main()
