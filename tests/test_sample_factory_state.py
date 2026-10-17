from __future__ import annotations

import multiprocessing
import tempfile
import threading
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from packages.sample_factory.errors import LeaseLostError, ManifestError, VerificationError
from packages.sample_factory.identity import canonical_parameters, combo_digest
from packages.sample_factory.manifest import ManifestRepository
from packages.sample_factory.models import (
    ComboIntent,
    ComboStatus,
    DeploymentFingerprint,
    DetectionOutcome,
    EffectObservation,
    FailureTaxonomy,
    LeaseDisposition,
    ProductionProfile,
    RawVerificationReport,
    RegressionManifestEntry,
    SampleRecipe,
    SignalKind,
    SignalLevel,
    TelemetryAssertion,
    TelemetryBundle,
    TelemetryContract,
    TelemetryEvent,
    TriggerMode,
)
from packages.sample_factory.state import InMemoryComboStateStore
from packages.sample_factory.telemetry import FunctionalTruthEvaluator
from packages.schemas.enums import ResultClass
from pydantic import ValidationError

from tests.sample_factory_fixtures import (
    ARTIFACT_SHA,
    IMPLANT_SHA,
    PROFILE_ID,
    atom_specs,
    telemetry_contracts,
)


class MutableClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


class _Waitable(Protocol):
    def wait(self, timeout: float | None = None) -> bool: ...


def _append_manifest_in_process(path: str, entry_json: str, start: _Waitable) -> None:
    start.wait()
    entry = RegressionManifestEntry.model_validate_json(entry_json)
    ManifestRepository(path).append(entry)


def _parameters(tier: str = "E2") -> dict[str, object]:
    return canonical_parameters(
        {
            "atom.ia.document": {"container": "docm"},
            "atom.ob.decode": {"codec": "rc4"},
            "atom.in.apc": {"target": "notepad.exe"},
        },
        evasion_tier=tier,
        pointer_mode=None,
    )


def _intent(tier: str = "E2") -> ComboIntent:
    params = _parameters(tier)
    ph_ids = ("PH-IA01", "PH-OB05", "PH-IN04")
    return ComboIntent(
        combo_digest=combo_digest(ph_ids, params),
        ph_sequence=ph_ids,
        parameters_canonical=params,
        profile_id=PROFILE_ID,
    )


def _recipe() -> SampleRecipe:
    return SampleRecipe(
        recipe_id="sf-test",
        carrier="atom.ia.document",
        loader_atoms=("atom.ob.decode",),
        execution_atoms=("atom.in.apc",),
        implant_sha256=IMPLANT_SHA,
        implant_format="shellcode",
        delivery="motw-stamped(lab)",
        trigger_mode=TriggerMode.LAB_TRIGGER,
        ph_ids=("PH-IA01", "PH-OB05", "PH-IN04"),
        evasion_tier="E2",
    )


def _profile(*, edr: bool = False) -> ProductionProfile:
    return ProductionProfile(
        profile_id=PROFILE_ID,
        security_product_enabled=edr,
        no_edr_control=not edr,
        sensors_ready=True,
    )


def _report(
    *,
    sha256: str = ARTIFACT_SHA,
    baseline: bool = True,
    effects_pass: bool = True,
    blocked: bool = False,
) -> RawVerificationReport:
    events = tuple(
        TelemetryEvent(
            run_id="run-1",
            fields={"event_id": event_id, "atom_id": spec.atom_id},
        )
        for spec, event_id in zip(atom_specs(), (11, 7, 10), strict=True)
    )
    return RawVerificationReport(
        run_id="run-1",
        profile_id=PROFILE_ID,
        artifact_sha256=sha256,
        process_created=True,
        exit_code=0,
        blocked=blocked,
        telemetry=TelemetryBundle(
            run_id="run-1",
            profile_id=PROFILE_ID,
            source_ref="sandbox-report://run-1",
            baseline_collected=baseline,
            events=events,
        ),
        effects=(
            EffectObservation(
                check_id="sacrificial-process-health",
                passed=effects_pass,
                evidence_ref="sandbox-report://run-1#effects",
            ),
        ),
    )


class LeaseStateTest(unittest.TestCase):
    def test_combo_digest_must_match_canonical_identity(self) -> None:
        good = _intent()
        with self.assertRaises(ValidationError):
            ComboIntent(
                combo_digest="f" * 64,
                ph_sequence=good.ph_sequence,
                parameters_canonical=good.parameters_canonical,
                profile_id=good.profile_id,
            )

    def test_claim_busy_exact_expiry_then_takeover_and_fence_zombie(self) -> None:
        clock = MutableClock()
        store = InMemoryComboStateStore(clock=clock)
        ttl = timedelta(minutes=5)
        first = store.claim(_intent(), worker_id="worker-a", ttl=ttl)
        self.assertEqual(LeaseDisposition.ACQUIRED, first.disposition)

        clock.now += ttl
        exact = store.claim(_intent(), worker_id="worker-b", ttl=ttl)
        self.assertEqual(LeaseDisposition.BUSY, exact.disposition)

        clock.now += timedelta(microseconds=1)
        takeover = store.claim(_intent(), worker_id="worker-b", ttl=ttl)
        self.assertEqual(LeaseDisposition.TAKEN_OVER, takeover.disposition)
        self.assertEqual(first.record_id, takeover.record_id)
        with self.assertRaises(LeaseLostError):
            store.complete_failure(
                first.record_id,
                worker_id="worker-a",
                taxonomy=FailureTaxonomy.COMPILE_FAIL,
            )

    def test_only_one_concurrent_worker_acquires_identity(self) -> None:
        store = InMemoryComboStateStore()
        barrier = threading.Barrier(8)
        results = []
        lock = threading.Lock()

        def claim(index: int) -> None:
            barrier.wait()
            result = store.claim(_intent(), worker_id=f"worker-{index}", ttl=timedelta(minutes=5))
            with lock:
                results.append(result)

        threads = [threading.Thread(target=claim, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(1, sum(item.disposition is LeaseDisposition.ACQUIRED for item in results))
        self.assertEqual(1, len({item.record_id for item in results}))

    def test_success_is_terminal_and_detection_writeback_is_five_value(self) -> None:
        store = InMemoryComboStateStore()
        claim = store.claim(_intent(), worker_id="worker-a", ttl=timedelta(minutes=5))
        record = store.complete_success(
            claim.record_id,
            worker_id="worker-a",
            toolchain_fp="clang-cl-pinned",
            artifact_sha256=ARTIFACT_SHA,
            git_manifest_ref="manifest.jsonl#sample",
        )
        self.assertEqual(ComboStatus.SUCCESS, record.status)
        duplicate = store.claim(_intent(), worker_id="worker-b", ttl=timedelta(minutes=5))
        self.assertEqual(LeaseDisposition.TERMINAL, duplicate.disposition)

        updated = store.write_detection(
            claim.record_id,
            DetectionOutcome(
                result_class=ResultClass.MISSED_DETECTION,
                edr_id="edr-a-v1",
                observed_at=datetime.now(UTC),
            ),
        )
        self.assertEqual(ResultClass.MISSED_DETECTION, updated.detection_outcome.result_class)
        same = store.write_detection(claim.record_id, updated.detection_outcome)
        self.assertEqual(updated, same)
        with self.assertRaises(ValueError):
            store.write_detection(
                claim.record_id,
                DetectionOutcome(
                    result_class=ResultClass.DETECTED,
                    edr_id="edr-a-v1",
                    observed_at=datetime.now(UTC),
                ),
            )


class FunctionalTruthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.evaluator = FunctionalTruthEvaluator()

    def test_all_three_truth_layers_pass(self) -> None:
        truth = self.evaluator.evaluate(
            _recipe(),
            atom_specs(),
            telemetry_contracts(),
            _profile(),
            _report(),
            built_sha256=ARTIFACT_SHA,
        )
        self.assertTrue(truth.success)
        self.assertTrue(truth.v1_passed and truth.v2_passed and truth.v3_passed)

    def test_previous_build_artifact_is_rejected(self) -> None:
        with self.assertRaises(VerificationError):
            self.evaluator.evaluate(
                _recipe(),
                atom_specs(),
                telemetry_contracts(),
                _profile(),
                _report(sha256="c" * 64),
                built_sha256=ARTIFACT_SHA,
            )

    def test_loader_effect_failure_does_not_block_intake(self) -> None:
        truth = self.evaluator.evaluate(
            _recipe(),
            atom_specs(),
            telemetry_contracts(),
            _profile(),
            _report(effects_pass=False),
            built_sha256=ARTIFACT_SHA,
        )
        self.assertTrue(truth.success)
        self.assertIsNone(truth.taxonomy)
        self.assertTrue(truth.v1_passed)
        self.assertTrue(truth.v2_passed)
        self.assertFalse(truth.v3_passed)

    def test_missing_required_effects_does_not_block_intake(self) -> None:
        truth = self.evaluator.evaluate(
            _recipe(),
            atom_specs(),
            telemetry_contracts(),
            _profile(),
            _report().model_copy(update={"effects": ()}),
            built_sha256=ARTIFACT_SHA,
        )
        self.assertTrue(truth.success)
        self.assertIsNone(truth.taxonomy)
        self.assertTrue(truth.v2_passed)
        self.assertFalse(truth.v3_passed)

    def test_absence_assertion_needs_negative_control(self) -> None:
        first, *rest = telemetry_contracts()
        absence = TelemetryContract(
            contract_id=first.contract_id,
            atom_id=first.atom_id,
            profile_ids=first.profile_ids,
            source_ref=first.source_ref,
            assertions=(
                TelemetryAssertion(
                    assertion_id="absence",
                    kind=SignalKind.ABSENCE,
                    level=SignalLevel.REQUIRED,
                    match_fields={"event_id": 999, "atom_id": first.atom_id},
                    description="event must be absent",
                ),
            ),
        )
        truth = self.evaluator.evaluate(
            _recipe(),
            atom_specs(),
            (absence, *rest),
            _profile(),
            _report(baseline=False),
            built_sha256=ARTIFACT_SHA,
        )
        self.assertEqual(FailureTaxonomy.TELEMETRY_MISS, truth.taxonomy)

    def test_blocked_requires_declared_security_product_profile(self) -> None:
        with self.assertRaises(VerificationError):
            self.evaluator.evaluate(
                _recipe(),
                atom_specs(),
                telemetry_contracts(),
                _profile(),
                _report(blocked=True),
                built_sha256=ARTIFACT_SHA,
            )
        truth = self.evaluator.evaluate(
            _recipe(),
            atom_specs(),
            telemetry_contracts(),
            _profile(edr=True),
            _report(blocked=True),
            built_sha256=ARTIFACT_SHA,
        )
        self.assertEqual(FailureTaxonomy.SANDBOX_BLOCKED, truth.taxonomy)

    def test_missing_telemetry_contract_is_explicitly_not_applicable(self) -> None:
        specs = tuple(
            spec.model_copy(update={"telemetry_contract_ref": None})
            for spec in atom_specs()
        )

        truth = self.evaluator.evaluate(
            _recipe(),
            specs,
            (),
            _profile(),
            _report(),
            built_sha256=ARTIFACT_SHA,
        )

        self.assertTrue(truth.success)
        self.assertFalse(truth.v2_applicable)
        self.assertFalse(truth.v2_passed)
        self.assertEqual(
            tuple(spec.atom_id for spec in specs if spec.ph_ids),
            truth.missing_contract_atom_ids,
        )
        summary = truth.telemetry_summary()
        self.assertFalse(summary["v2_applicable"])
        self.assertEqual(
            list(truth.missing_contract_atom_ids),
            summary["missing_contract_atom_ids"],
        )


class ManifestRepositoryTest(unittest.TestCase):
    def _entry(self) -> RegressionManifestEntry:
        params = _parameters()
        digest = combo_digest(_recipe().ph_ids, params)
        return RegressionManifestEntry(
            sample_id=f"{digest[:8]}-{ARTIFACT_SHA[:12]}",
            sample_sha256=ARTIFACT_SHA,
            artifact_ref="artifact://samples/test",
            deployment_fp=DeploymentFingerprint(mode=None, note="no pointer"),
            ph_sequence=_recipe().ph_ids,
            attck_ids=("T1566.001", "T1027.013", "T1055.004"),
            parameters_canonical=params,
            profile_id=PROFILE_ID,
            toolchain_fp="clang-cl-pinned",
            telemetry_truth={"v1_passed": True, "v2_passed": True, "v3_passed": True},
            expected_detection={
                "source_ref": "docs/coverage/procedure-host-ttp-coverage-matrix.md",
                "ph_ids": list(_recipe().ph_ids),
            },
            regression_set_version="v1",
        )

    def test_append_is_idempotent_and_conflict_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = ManifestRepository(Path(tmp) / "regression.jsonl")
            ref1 = repo.append(self._entry())
            ref2 = repo.append(self._entry())
            self.assertEqual(ref1, ref2)
            self.assertEqual(1, len(repo.entries()))

            conflict = self._entry().model_copy(update={"profile_id": "different"})
            with self.assertRaises(ManifestError):
                repo.append(conflict)

    def test_concurrent_processes_append_one_idempotent_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "regression.jsonl"
            context = multiprocessing.get_context("spawn")
            start = context.Event()
            entry_json = self._entry().model_dump_json()
            processes = [
                context.Process(
                    target=_append_manifest_in_process,
                    args=(str(path), entry_json, start),
                )
                for _ in range(8)
            ]
            for process in processes:
                process.start()
            start.set()
            try:
                for process in processes:
                    process.join(timeout=15)
                self.assertTrue(all(not process.is_alive() for process in processes))
                self.assertEqual([0] * len(processes), [process.exitcode for process in processes])
                self.assertEqual((self._entry(),), ManifestRepository(path).entries())
            finally:
                for process in processes:
                    if process.is_alive():
                        process.terminate()
                        process.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
