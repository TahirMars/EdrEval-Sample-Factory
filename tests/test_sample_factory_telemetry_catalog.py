from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.catalog import CoverageRegistry, CoverageRow
from packages.sample_factory.telemetry_catalog import (
    project_sysmon_telemetry_contract,
    upsert_telemetry_contracts,
)

from tests.sample_factory_fixtures import atom_specs


def _ph_in04_coverage() -> CoverageRegistry:
    return CoverageRegistry(
        {"PH-IN04": ("T1055.004",)},
        rows={
            "PH-IN04": CoverageRow(
                ph_id="PH-IN04",
                attack_ids=("T1055.004",),
                technique="APC Injection",
                data_sources="Sysmon EID1(创建挂起进程) EID10",
                endpoint_visibility="partial",
                audit_prerequisites="需Sysmon",
                detection_layers="behavior",
                matrix_evasion_tier="E2",
                expected_signals="CREATE_SUSPENDED + APC 排队访问组合",
            )
        },
        source_ref="docs/coverage/procedure-host-ttp-coverage-matrix.md#test",
    )


class TelemetryCatalogTest(unittest.TestCase):
    def test_projects_ph_in04_sysmon_eid_cross(self) -> None:
        spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
        spec = spec.model_copy(update={"telemetry_contract_ref": None})
        contract = project_sysmon_telemetry_contract(
            spec, _ph_in04_coverage(), "win11-sysmon15-no-edr"
        )

        self.assertIsNotNone(contract)
        assert contract is not None
        self.assertEqual(
            "telemetry://atom.in.apc/ph-in04/sysmon-eid1-eid10-v1",
            contract.contract_id,
        )
        self.assertEqual(
            (1, 10),
            tuple(item.match_fields["event_id"] for item in contract.assertions),
        )
        self.assertEqual(
            {"T1055.004"},
            {item.match_fields["technique"] for item in contract.assertions},
        )

    def test_atom_without_ph_has_no_contract(self) -> None:
        spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
        spec = spec.model_copy(
            update={
                "ph_ids": (),
                "attck_ids": (),
                "telemetry_contract_ref": None,
                "produces_handoffs": ("handoff://shellcode/v1",),
                "consumes_handoffs": (),
            }
        )
        self.assertIsNone(
            project_sysmon_telemetry_contract(
                spec, _ph_in04_coverage(), "win11-sysmon15-no-edr"
            )
        )

    def test_missing_eid_in_matrix_does_not_invent_contract(self) -> None:
        spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
        spec = spec.model_copy(update={"telemetry_contract_ref": None})
        coverage = CoverageRegistry(
            {"PH-IN04": ("T1055.004",)},
            rows={
                "PH-IN04": CoverageRow(
                    ph_id="PH-IN04",
                    attack_ids=("T1055.004",),
                    technique="APC Injection",
                    data_sources="endpoint",
                    endpoint_visibility="partial",
                    audit_prerequisites="需Sysmon",
                    detection_layers="behavior",
                    matrix_evasion_tier="E2",
                    expected_signals="unspecified",
                )
            },
        )
        self.assertIsNone(
            project_sysmon_telemetry_contract(spec, coverage, "win11-sysmon15-no-edr")
        )

    def test_upsert_merges_by_contract_id(self) -> None:
        spec = next(item for item in atom_specs() if item.atom_id == "atom.in.apc")
        spec = spec.model_copy(update={"telemetry_contract_ref": None})
        contract = project_sysmon_telemetry_contract(
            spec, _ph_in04_coverage(), "win11-sysmon15-no-edr"
        )
        assert contract is not None
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "contracts.json"
            upsert_telemetry_contracts(path, (contract,))
            upsert_telemetry_contracts(path, (contract,))
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(1, len(payload["contracts"]))
            self.assertEqual(contract.contract_id, payload["contracts"][0]["contract_id"])


if __name__ == "__main__":
    unittest.main()
