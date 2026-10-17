from __future__ import annotations

import math
import unittest
from pathlib import Path

from packages.sample_factory.catalog import (
    AtomCatalog,
    CatalogError,
    CoverageRegistry,
    PH_MATRIX_ROW_COUNT,
)
from packages.sample_factory.identity import (
    CanonicalizationError,
    canonical_json,
    canonical_parameters,
    combo_digest,
)
from packages.sample_factory.models import (
    ComboIntent,
    IntegrationState,
    SampleRecipe,
    SignalKind,
    SignalLevel,
    TelemetryAssertion,
    TriggerMode,
)
from pydantic import ValidationError

from tests.sample_factory_fixtures import IMPLANT_SHA, atom_specs, catalog, provenance

ROOT = Path(__file__).resolve().parents[1]


class CoverageRegistryTest(unittest.TestCase):
    def test_loads_authoritative_66_rows_and_multi_attack_mapping(self) -> None:
        registry = CoverageRegistry.from_markdown(
            ROOT / "docs/coverage/procedure-host-ttp-coverage-matrix.md"
        )
        self.assertEqual(PH_MATRIX_ROW_COUNT, len(registry.mapping))
        self.assertEqual(("T1562.001", "T1106"), registry.mapping["PH-BL04"])
        self.assertEqual(("T1543.003",), registry.mapping["PH-PS01"])
        self.assertEqual(("T1569.002",), registry.mapping["PH-EX11"])
        self.assertEqual(("T1547.001",), registry.mapping["PH-PS02"])
        self.assertEqual(("T1053.005",), registry.mapping["PH-PS03"])
        self.assertEqual(("T1033",), registry.mapping["PH-DI01"])
        self.assertEqual(("T1105",), registry.mapping["PH-IT01"])
        self.assertEqual(("T1620",), registry.mapping["PH-IN09"])
        self.assertEqual(("T1027.009",), registry.mapping["PH-OB08"])
        self.assertEqual(("T1140",), registry.mapping["PH-OB09"])
        self.assertEqual(("T1112",), registry.mapping["PH-BL10"])

    def test_unknown_ph_is_rejected(self) -> None:
        with self.assertRaises(CatalogError):
            catalog().coverage.attack_ids_for(("PH-ZZ99",))


class CanonicalIdentityTest(unittest.TestCase):
    def test_mapping_order_and_json_whitespace_do_not_change_digest(self) -> None:
        left = {"z": 1, "nested": {"b": 2, "a": 1}}
        right = {"nested": {"a": 1, "b": 2}, "z": 1}
        self.assertEqual(canonical_json(left), canonical_json(right))
        self.assertEqual(combo_digest(("PH-IA01",), left), combo_digest(("PH-IA01",), right))

    def test_ph_order_and_semantic_string_whitespace_do_change_digest(self) -> None:
        params = {"path": "a b"}
        self.assertNotEqual(
            combo_digest(("PH-IA01", "PH-IN04"), params),
            combo_digest(("PH-IN04", "PH-IA01"), params),
        )
        self.assertNotEqual(
            combo_digest(("PH-IA01",), params),
            combo_digest(("PH-IA01",), {"path": "a  b"}),
        )

    def test_non_finite_and_non_json_values_rejected(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_json({"bad": math.inf})
        with self.assertRaises(CanonicalizationError):
            canonical_json({"bad": {1, 2}})

    def test_production_policy_is_not_part_of_parameters(self) -> None:
        params = canonical_parameters({"atom.x": {"n": 1}}, evasion_tier="E2", pointer_mode=None)
        self.assertNotIn("production_policy", params)
        self.assertEqual("E2", params["evasion_tier"])

    def test_execution_logging_is_a_distinct_build_identity(self) -> None:
        without_logging = canonical_parameters(
            {"atom.x": {"n": 1}},
            evasion_tier="E2",
            pointer_mode=None,
            execution_logging=False,
        )
        with_logging = canonical_parameters(
            {"atom.x": {"n": 1}},
            evasion_tier="E2",
            pointer_mode=None,
            execution_logging=True,
        )

        self.assertFalse(without_logging["execution_logging"])
        self.assertTrue(with_logging["execution_logging"])
        self.assertNotEqual(
            combo_digest(("PH-IA01",), without_logging),
            combo_digest(("PH-IA01",), with_logging),
        )

    def test_legacy_identity_remains_readable_without_digest_rewrite(self) -> None:
        legacy = {
            "atoms": {"atom.x": {"n": 1}},
            "evasion_tier": "E2",
            "pointer_mode": None,
        }

        intent = ComboIntent(
            combo_digest=combo_digest(("PH-IA01",), legacy),
            ph_sequence=("PH-IA01",),
            parameters_canonical=legacy,
            profile_id="legacy-profile",
        )

        self.assertNotIn("execution_logging", intent.parameters_canonical)


class SchemaAndCatalogTest(unittest.TestCase):
    def _recipe(self) -> SampleRecipe:
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

    def test_required_signal_needs_two_independent_fields(self) -> None:
        with self.assertRaises(ValidationError):
            TelemetryAssertion(
                assertion_id="weak",
                kind=SignalKind.POSITIVE,
                level=SignalLevel.REQUIRED,
                match_fields={"event_id": 1},
                description="too weak",
            )

    def test_dispatchable_atom_requires_supply_chain_double_gate(self) -> None:
        spec = atom_specs()[0]
        registry = CoverageRegistry({"PH-IA01": ("T1566.001",)})
        with self.assertRaises(CatalogError):
            AtomCatalog(registry).register(spec)

        reserved = spec.model_copy(
            update={
                "atom_id": "atom.ia.reserved",
                "integration_state": IntegrationState.RESERVED_ATOM,
            }
        )
        AtomCatalog(registry).register(reserved)

    def test_authoritative_attack_mapping_cannot_be_forged(self) -> None:
        spec = atom_specs()[0].model_copy(update={"attck_ids": ("T9999",)})
        with self.assertRaises(CatalogError):
            AtomCatalog(CoverageRegistry({"PH-IA01": ("T1566.001",)})).register(spec, provenance())

    def test_reviewed_pinned_plugin_is_dispatchable_without_telemetry_contract(self) -> None:
        spec = atom_specs()[2].model_copy(update={"telemetry_contract_ref": None})
        atom_catalog = AtomCatalog(CoverageRegistry({"PH-IN04": ("T1055.004",)}))

        atom_catalog.register(spec, provenance())

        self.assertEqual((spec,), atom_catalog.dispatchable_specs())

    def test_recipe_roles_coverage_and_parameter_domains(self) -> None:
        specs = catalog().validate_recipe(
            self._recipe(),
            {
                "atom.ia.document": {"container": "docm"},
                "atom.ob.decode": {"codec": "rc4"},
                "atom.in.apc": {"target": "notepad.exe"},
            },
            profile=_profile(),
            high_risk_approved=False,
        )
        self.assertEqual(self._recipe().atom_ids, tuple(item.atom_id for item in specs))

        with self.assertRaises(CatalogError):
            catalog().validate_recipe(
                self._recipe(),
                {
                    "atom.ia.document": {"container": "pdf"},
                    "atom.ob.decode": {"codec": "rc4"},
                    "atom.in.apc": {"target": "notepad.exe"},
                },
                profile=_profile(),
                high_risk_approved=False,
            )


def _profile():
    from packages.sample_factory.models import ProductionProfile

    return ProductionProfile(
        profile_id="win11-sysmon15-no-edr",
        security_product_enabled=False,
        no_edr_control=True,
        sensors_ready=True,
    )


if __name__ == "__main__":
    unittest.main()
