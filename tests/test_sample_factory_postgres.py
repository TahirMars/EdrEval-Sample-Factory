from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from packages.sample_factory.identity import canonical_parameters, combo_digest
from packages.sample_factory.models import (
    ComboIntent,
    ComboStatus,
    DetectionOutcome,
    FailureTaxonomy,
    LeaseDisposition,
)
from packages.sample_factory.postgres import PostgresComboStateStore
from packages.schemas.enums import ResultClass

NOW = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
PARAMS = canonical_parameters({}, evasion_tier="E2", pointer_mode=None)
PH_IDS = ("PH-IN04",)
DIGEST = combo_digest(PH_IDS, PARAMS)
RECORD_ID = "11111111-1111-4111-8111-111111111111"


class ScriptedDatabase:
    def __init__(self, responses):
        self.responses = list(responses)
        self.sql = []
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0

    def __call__(self):
        return FakeConnection(self)


class FakeConnection:
    def __init__(self, database):
        self.database = database

    def cursor(self):
        return FakeCursor(self.database)

    def commit(self):
        self.database.commits += 1

    def rollback(self):
        self.database.rollbacks += 1

    def close(self):
        self.database.closes += 1


class FakeCursor:
    def __init__(self, database):
        self.database = database
        self.response = None

    def execute(self, sql, params):
        self.database.sql.append((sql, params))
        if not self.database.responses:
            self.response = None
            return
        self.response = self.database.responses.pop(0)
        if isinstance(self.response, Exception):
            raise self.response

    def fetchone(self):
        return self.response

    def close(self):
        pass


def _intent() -> ComboIntent:
    return ComboIntent(
        combo_digest=DIGEST,
        ph_sequence=PH_IDS,
        parameters_canonical=PARAMS,
        profile_id="edr-profile",
    )


def _row(
    status: ComboStatus,
    *,
    taxonomy: FailureTaxonomy | None = None,
    detection: DetectionOutcome | None = None,
):
    success = status is ComboStatus.SUCCESS
    return (
        RECORD_ID,
        DIGEST,
        list(PH_IDS),
        PARAMS,
        "edr-profile",
        {},
        "toolchain" if success else None,
        "a" * 64 if success else None,
        "manifest#sample" if success else None,
        "worker-1",
        status.value,
        None if taxonomy is None else taxonomy.value,
        None if detection is None else detection.model_dump(mode="json"),
        None,
        42,
        NOW,
        NOW,
        NOW + timedelta(minutes=5) if status is ComboStatus.IN_PROGRESS else None,
    )


class PostgresLeaseAdapterTest(unittest.TestCase):
    def test_initialize_and_insert_claim(self) -> None:
        database = ScriptedDatabase([None, (RECORD_ID, "IN_PROGRESS", "worker-1", NOW)])
        store = PostgresComboStateStore(database)
        store.initialize()
        claim = store.claim(_intent(), worker_id="worker-1", ttl=timedelta(minutes=5))
        self.assertEqual(LeaseDisposition.ACQUIRED, claim.disposition)
        self.assertEqual(2, database.commits)
        self.assertIn("CREATE TABLE", database.sql[0][0])

    def test_expired_takeover_busy_and_terminal_claim_paths(self) -> None:
        takeover_db = ScriptedDatabase([None, (RECORD_ID, "IN_PROGRESS", "worker-2", NOW)])
        takeover = PostgresComboStateStore(takeover_db).claim(
            _intent(), worker_id="worker-2", ttl=timedelta(minutes=5)
        )
        self.assertEqual(LeaseDisposition.TAKEN_OVER, takeover.disposition)

        busy_db = ScriptedDatabase([None, None, (RECORD_ID, "IN_PROGRESS", "worker-1", NOW)])
        busy = PostgresComboStateStore(busy_db).claim(
            _intent(), worker_id="worker-2", ttl=timedelta(minutes=5)
        )
        self.assertEqual(LeaseDisposition.BUSY, busy.disposition)

        terminal_db = ScriptedDatabase([None, None, (RECORD_ID, "SUCCESS", "worker-1", None)])
        terminal = PostgresComboStateStore(terminal_db).claim(
            _intent(), worker_id="worker-2", ttl=timedelta(minutes=5)
        )
        self.assertEqual(LeaseDisposition.TERMINAL, terminal.disposition)

    def test_heartbeat_completion_and_get(self) -> None:
        heartbeat_db = ScriptedDatabase([(NOW + timedelta(minutes=5),)])
        expires = PostgresComboStateStore(heartbeat_db).heartbeat(
            RECORD_ID, worker_id="worker-1", ttl=timedelta(minutes=5)
        )
        self.assertEqual(NOW + timedelta(minutes=5), expires)
        with self.assertRaises(ValueError):
            PostgresComboStateStore(ScriptedDatabase([])).heartbeat(
                RECORD_ID, worker_id="", ttl=timedelta(0)
            )

        success_db = ScriptedDatabase([_row(ComboStatus.SUCCESS)])
        success = PostgresComboStateStore(success_db).complete_success(
            RECORD_ID,
            worker_id="worker-1",
            toolchain_fp="toolchain",
            artifact_sha256="a" * 64,
            git_manifest_ref="manifest#sample",
        )
        self.assertEqual(ComboStatus.SUCCESS, success.status)

        failure_db = ScriptedDatabase(
            [_row(ComboStatus.FAILURE, taxonomy=FailureTaxonomy.COMPILE_FAIL)]
        )
        failure = PostgresComboStateStore(failure_db).complete_failure(
            RECORD_ID,
            worker_id="worker-1",
            taxonomy=FailureTaxonomy.COMPILE_FAIL,
        )
        self.assertEqual(FailureTaxonomy.COMPILE_FAIL, failure.failure_taxonomy)

        get_db = ScriptedDatabase([_row(ComboStatus.SUCCESS)])
        self.assertIsNotNone(PostgresComboStateStore(get_db).get(RECORD_ID))

    def test_detection_is_append_once_and_idempotent(self) -> None:
        outcome = DetectionOutcome(
            result_class=ResultClass.DETECTED,
            edr_id="edr-1",
            observed_at=NOW,
        )
        write_db = ScriptedDatabase([_row(ComboStatus.SUCCESS, detection=outcome)])
        written = PostgresComboStateStore(write_db).write_detection(RECORD_ID, outcome)
        self.assertEqual(outcome, written.detection_outcome)

        idempotent_db = ScriptedDatabase([None, _row(ComboStatus.SUCCESS, detection=outcome)])
        same = PostgresComboStateStore(idempotent_db).write_detection(RECORD_ID, outcome)
        self.assertEqual(outcome, same.detection_outcome)

        other = outcome.model_copy(update={"result_class": ResultClass.MISSED_DETECTION})
        conflict_db = ScriptedDatabase([None, _row(ComboStatus.SUCCESS, detection=outcome)])
        with self.assertRaises(ValueError):
            PostgresComboStateStore(conflict_db).write_detection(RECORD_ID, other)

    def test_database_error_rolls_back_and_closes(self) -> None:
        database = ScriptedDatabase([RuntimeError("db down")])
        with self.assertRaises(RuntimeError):
            PostgresComboStateStore(database).initialize()
        self.assertEqual(1, database.rollbacks)
        self.assertEqual(1, database.closes)


if __name__ == "__main__":
    unittest.main()
