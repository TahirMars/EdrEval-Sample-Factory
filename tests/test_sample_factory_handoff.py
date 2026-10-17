"""handoff 图闭合与 embed_at_build 物化单测。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.catalog import AtomCatalog, CoverageRegistry
from packages.sample_factory.errors import CatalogError
from packages.sample_factory.handoff import (
    HandoffError,
    apply_embed_materialize,
    handoff_array_symbol,
    handoff_header_path,
    handoff_size_symbol,
    resolve_payload_bytes,
    validate_embedded_handoff_references,
    validate_handoff_closure,
)
from packages.sample_factory.models import (
    AtomRole,
    AtomSpec,
    DeliveryMode,
    GlueMaterializeItem,
    HandoffMaterialize,
    IntegrationState,
    ProductionProfile,
    SafetyProfile,
    SampleRecipe,
    TriggerMode,
)

from tests.sample_factory_fixtures import atom_specs, catalog, provenance


class HandoffGraphTest(unittest.TestCase):
    @staticmethod
    def _materialize_item() -> GlueMaterializeItem:
        return GlueMaterializeItem(
            atom_id="atom.payload.lab_calc",
            handoff_id="handoff://shellcode/v1",
            artifact_ref="payload://x64/msf_calc_x64",
            strategy=HandoffMaterialize.EMBED_AT_BUILD,
        )

    def test_embed_symbols_are_deterministic(self) -> None:
        handoff_id = "handoff://shellcode/v1"
        self.assertEqual("kHandoffShellcodeV1", handoff_array_symbol(handoff_id))
        self.assertEqual("kHandoffShellcodeV1Size", handoff_size_symbol(handoff_id))

    def test_static_gate_accepts_complete_unqualified_identifiers(self) -> None:
        validate_embedded_handoff_references(
            {
                "generated/main.cpp": (
                    '#include "handoff_shellcode_v1.h"\n'
                    "int main() {\n"
                    "  const auto* payload = kHandoffShellcodeV1;\n"
                    "  const auto size = kHandoffShellcodeV1Size;\n"
                    "  return payload != nullptr && size > 0 ? 0 : 1;\n"
                    "}\n"
                )
            },
            (self._materialize_item(),),
        )

    def test_static_gate_rejects_prefixed_identifiers(self) -> None:
        source = (
            '#include "handoff_shellcode_v1.h"\n'
            "auto* payload = handoff_shellcode_v1_kHandoffShellcodeV1;\n"
            "auto size = handoff_shellcode_v1_kHandoffShellcodeV1Size;\n"
        )
        with self.assertRaisesRegex(HandoffError, "缺少完整 C\\+\\+ 标识符"):
            validate_embedded_handoff_references(
                {"generated/main.cpp": source}, (self._materialize_item(),)
            )

    def test_static_gate_rejects_namespace_qualified_identifiers(self) -> None:
        source = (
            '#include "handoff_shellcode_v1.h"\n'
            "auto* payload = handoff_shellcode_v1::kHandoffShellcodeV1;\n"
            "auto size = handoff_shellcode_v1::kHandoffShellcodeV1Size;\n"
        )
        with self.assertRaisesRegex(HandoffError, "不得用 symbol_prefix"):
            validate_embedded_handoff_references(
                {"generated/main.cpp": source}, (self._materialize_item(),)
            )

    def test_static_gate_ignores_identifiers_in_comments_and_strings(self) -> None:
        source = (
            '#include "handoff_shellcode_v1.h"\n'
            "// kHandoffShellcodeV1\n"
            'const char* ignored = "kHandoffShellcodeV1Size";\n'
        )
        with self.assertRaisesRegex(HandoffError, "缺少完整 C\\+\\+ 标识符"):
            validate_embedded_handoff_references(
                {"generated/main.cpp": source}, (self._materialize_item(),)
            )

    def test_closure_accepts_producer_before_consumer(self) -> None:
        _, loader, execution = atom_specs()
        validate_handoff_closure((loader, execution))

    def test_closure_rejects_missing_producer(self) -> None:
        _, _, execution = atom_specs()
        with self.assertRaises(CatalogError):
            validate_handoff_closure((execution,))

    def test_validate_recipe_enforces_closure(self) -> None:
        cat = catalog()
        recipe = SampleRecipe(
            recipe_id="sf-test",
            carrier=None,
            loader_atoms=(),
            execution_atoms=("atom.in.apc",),
            implant_sha256=None,
            implant_format=None,
            delivery=DeliveryMode.MOTW_STAMPED,
            trigger_mode=TriggerMode.LAB_TRIGGER,
            ph_ids=("PH-IN04",),
            evasion_tier="E2",
            pointer_mode=None,
        )
        with self.assertRaises(CatalogError):
            cat.validate_recipe(
                recipe,
                {"atom.in.apc": {"target": "notepad.exe"}},
                ProductionProfile(
                    profile_id="win11-sysmon15-no-edr",
                    security_product_enabled=False,
                    no_edr_control=True,
                    sensors_ready=True,
                ),
                high_risk_approved=False,
            )

    def test_support_payload_atom_without_ph(self) -> None:
        coverage = CoverageRegistry({"PH-IN04": ("T1055.004",)})
        cat = AtomCatalog(coverage)
        payload = AtomSpec(
            atom_id="atom.payload.lab_calc",
            role=AtomRole.LOADER_ATOM,
            integration_state=IntegrationState.PARTIAL,
            ph_ids=(),
            attck_ids=(),
            variant_family="payload_corpus",
            inputs_schema_ref="schema://payload",
            param_domains={},
            output_contract="shellcode",
            produces_handoffs=("handoff://shellcode/v1",),
            materialize=HandoffMaterialize.EMBED_AT_BUILD,
            artifact_ref="payload://x64/msf_calc_x64",
            telemetry_contract_ref=None,
            verification_profile="standard",
            safety_profile=SafetyProfile.MEDIUM,
            trigger_modes=(TriggerMode.LAB_TRIGGER,),
            requires_implant=False,
        )
        cat.register(payload, provenance())
        self.assertIn(payload, cat.dispatchable_specs())

    def test_embed_writes_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload_root = Path(tmp) / "payload" / "x64"
            payload_root.mkdir(parents=True)
            blob = payload_root / "msf_calc_x64.bin"
            blob.write_bytes(b"\x90\x90\xcc")
            workspace = Path(tmp) / "ws"
            workspace.mkdir()
            written = apply_embed_materialize(
                workspace,
                (
                    GlueMaterializeItem(
                        atom_id="atom.payload.lab_calc",
                        handoff_id="handoff://shellcode/v1",
                        artifact_ref="payload://x64/msf_calc_x64",
                        strategy=HandoffMaterialize.EMBED_AT_BUILD,
                    ),
                ),
                payload_root=Path(tmp) / "payload",
            )
            self.assertEqual((handoff_header_path("handoff://shellcode/v1"),), written)
            text = (workspace / written[0]).read_text(encoding="utf-8")
            self.assertIn("0x90", text)
            self.assertIn("0xcc", text)

    def test_resolve_payload_bytes_searches_fallback_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = Path(tmp) / "catalog" / "payloads"
            runtime = Path(tmp) / "runtime" / "payloads" / "x64"
            runtime.mkdir(parents=True)
            (runtime / "msf_calc_x64.bin").write_bytes(b"\x90\xc3")
            data = resolve_payload_bytes(
                "payload://x64/msf_calc_x64",
                payload_root=(catalog, runtime.parent),
            )
            self.assertEqual(b"\x90\xc3", data)

    def test_resolve_payload_bytes_prefers_catalog_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = Path(tmp) / "catalog" / "payloads" / "x64"
            runtime = Path(tmp) / "runtime" / "payloads" / "x64"
            catalog.mkdir(parents=True)
            runtime.mkdir(parents=True)
            (catalog / "msf_calc_x64.bin").write_bytes(b"\x01")
            (runtime / "msf_calc_x64.bin").write_bytes(b"\x02")
            data = resolve_payload_bytes(
                "payload://x64/msf_calc_x64",
                payload_root=(catalog.parent, runtime.parent),
            )
            self.assertEqual(b"\x01", data)


if __name__ == "__main__":
    unittest.main()
