from __future__ import annotations

import unittest

from packages.sample_factory.models import (
    RawVerificationReport,
    SignalKind,
    SignalLevel,
    TelemetryAssertion,
    TelemetryBundle,
    TelemetryContract,
    TelemetryEvent,
)
from packages.sample_factory.telemetry import TelemetryMatcher


PROFILE = "win10-21h2-sysmon15-no-edr"


def _report(*events: TelemetryEvent) -> RawVerificationReport:
    return RawVerificationReport(
        run_id="run-1",
        profile_id=PROFILE,
        artifact_sha256="a" * 64,
        process_created=True,
        exit_code=0,
        timed_out=False,
        crashed=False,
        blocked=False,
        anti_analysis_skipped=False,
        telemetry=TelemetryBundle(
            run_id="run-1",
            profile_id=PROFILE,
            source_ref="vmware-evidence://test",
            baseline_collected=False,
            events=events,
        ),
        effects=(),
    )


def _contract(*assertions: TelemetryAssertion) -> TelemetryContract:
    return TelemetryContract(
        contract_id="telemetry://test/sysmon-v1",
        atom_id="atom.di.whoami",
        profile_ids=(PROFILE,),
        source_ref="test",
        assertions=assertions,
    )


class TelemetryMatcherSemanticTest(unittest.TestCase):
    def test_image_endswith_matches_projected_image_field(self) -> None:
        matcher = TelemetryMatcher()
        report = _report(
            TelemetryEvent(
                run_id="run-1",
                fields={
                    "event_id": 1,
                    "technique": "T1033",
                    "atom_id": "atom.di.whoami",
                    "image": r"C:\Windows\System32\whoami.exe",
                },
            ),
            TelemetryEvent(
                run_id="run-1",
                fields={
                    "event_id": 1,
                    "technique": "T1033",
                    "atom_id": "atom.di.whoami",
                    "image": r"C:\ProgramData\EdrEvalAgent\Runs\x\sample.exe",
                },
            ),
        )
        truths = matcher.match(
            _contract(
                TelemetryAssertion(
                    assertion_id="whoami-eid1",
                    kind=SignalKind.POSITIVE,
                    level=SignalLevel.REQUIRED,
                    match_fields={
                        "event_id": 1,
                        "technique": "T1033",
                        "image_endswith": [r"\whoami.exe"],
                    },
                    description="whoami process create",
                )
            ),
            report,
        )
        self.assertEqual(1, len(truths))
        self.assertTrue(truths[0].passed)
        self.assertEqual(1, truths[0].matched_events)

    def test_source_image_contains_rejects_unrelated_sources(self) -> None:
        matcher = TelemetryMatcher()
        report = _report(
            TelemetryEvent(
                run_id="run-1",
                fields={
                    "event_id": 10,
                    "technique": "T1055",
                    "atom_id": "atom.in.pool_party",
                    "source_image": r"C:\Windows\explorer.exe",
                    "target_image": r"C:\Windows\System32\notepad.exe",
                },
            ),
            TelemetryEvent(
                run_id="run-1",
                fields={
                    "event_id": 10,
                    "technique": "T1055",
                    "atom_id": "atom.in.pool_party",
                    "source_image": r"C:\ProgramData\EdrEvalAgent\Runs\x\sample.exe",
                    "target_image": r"C:\Windows\System32\notepad.exe",
                },
            ),
        )
        truths = matcher.match(
            _contract(
                TelemetryAssertion(
                    assertion_id="pool-eid10",
                    kind=SignalKind.POSITIVE,
                    level=SignalLevel.REQUIRED,
                    match_fields={
                        "event_id": 10,
                        "technique": "T1055",
                        "source_image_contains": ["\\edrevalagent\\"],
                    },
                    description="injection process access",
                )
            ),
            report,
        )
        self.assertTrue(truths[0].passed)
        self.assertEqual(1, truths[0].matched_events)

    def test_legacy_exact_fields_still_match(self) -> None:
        matcher = TelemetryMatcher()
        report = _report(
            TelemetryEvent(
                run_id="run-1",
                fields={"event_id": 13, "technique": "T1548.002", "atom_id": "atom.pe.uac"},
            )
        )
        truths = matcher.match(
            _contract(
                TelemetryAssertion(
                    assertion_id="uac-eid13",
                    kind=SignalKind.POSITIVE,
                    level=SignalLevel.REQUIRED,
                    match_fields={"event_id": 13, "technique": "T1548.002"},
                    description="registry write",
                )
            ),
            report,
        )
        self.assertTrue(truths[0].passed)


if __name__ == "__main__":
    unittest.main()
