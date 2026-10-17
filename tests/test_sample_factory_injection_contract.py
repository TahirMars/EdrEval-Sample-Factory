from __future__ import annotations

import unittest

from packages.sample_factory.ai_planner import FactoryPlanningAgent
from packages.sample_factory.catalog import AtomCatalog, CatalogError, CoverageRegistry
from packages.sample_factory.errors import PlanningError
from packages.sample_factory.injection_contract import (
    glue_injection_contracts,
    injection_domain_ready,
    validate_injection_glue_source,
    validate_injection_parameters,
)
from packages.sample_factory.models import (
    DeliveryMode,
    FactoryPlanningContext,
    GlueInjectionContract,
    ProductionPolicy,
    SampleRecipe,
    TriggerMode,
)

from tests.sample_factory_fixtures import IMPLANT_SHA, atom_specs, catalog, provenance


def _profile():
    from packages.sample_factory.models import ProductionProfile

    return ProductionProfile(
        profile_id="win11-sysmon15-no-edr",
        security_product_enabled=False,
        no_edr_control=True,
        sensors_ready=True,
    )


def _injection_spec(**updates):
    spec = atom_specs()[2]
    return spec.model_copy(update=updates)


class InjectionContractTest(unittest.TestCase):
    def test_pid_only_domain_is_not_schedulable(self) -> None:
        spec = _injection_spec(param_domains={"target_pid": ("0",)})
        self.assertFalse(injection_domain_ready(spec))
        with self.assertRaises(CatalogError) as ctx:
            validate_injection_parameters(spec, {"target_pid": "0"})
        self.assertIn("自注入", str(ctx.exception))

    def test_sacrificial_image_is_required_even_if_pid_sentinel_in_domain(self) -> None:
        spec = _injection_spec(
            param_domains={
                "target_pid": ("0",),
                "target_image": (r"C:\Windows\System32\notepad.exe",),
            }
        )
        self.assertTrue(injection_domain_ready(spec))
        with self.assertRaises(CatalogError):
            validate_injection_parameters(spec, {"target_pid": "0"})
        validate_injection_parameters(
            spec,
            {
                "target_pid": "0",
                "target_image": r"C:\Windows\System32\notepad.exe",
            },
        )

    def test_catalog_rejects_self_inject_pid_zero(self) -> None:
        spec = _injection_spec(param_domains={"target_pid": ("0",)})
        coverage = CoverageRegistry({"PH-IN04": ("T1055.004",)})
        atom_catalog = AtomCatalog(coverage)
        atom_catalog.register(spec, provenance())
        recipe = SampleRecipe(
            recipe_id="sf-self-inject",
            ph_ids=("PH-IN04",),
            execution_atoms=("atom.in.apc",),
            delivery="preset(no-MotW)",
            trigger_mode=TriggerMode.LAB_TRIGGER,
            evasion_tier="E0",
        )
        with self.assertRaises(CatalogError) as ctx:
            atom_catalog.validate_recipe(
                recipe,
                {"atom.in.apc": {"target_pid": "0"}},
                _profile(),
                high_risk_approved=False,
            )
        self.assertIn("牺牲进程", str(ctx.exception))

    def test_planner_excludes_pid_zero_injection_from_inventory(self) -> None:
        spec = _injection_spec(param_domains={"target_pid": ("0",)})
        atom_catalog = AtomCatalog(CoverageRegistry({"PH-IN04": ("T1055.004",)}))
        atom_catalog.register(spec, provenance())

        class _MustNotCall:
            def complete(self, messages: list[dict[str, str]]) -> str:
                raise AssertionError(f"planner should not query LLM: {messages!r}")

        with self.assertRaises(PlanningError) as ctx:
            FactoryPlanningAgent(_MustNotCall(), atom_catalog).plan(
                FactoryPlanningContext(
                    candidate_ph_ids=("PH-IN04",),
                    required_ph_ids=("PH-IN04",),
                    production_policy=ProductionPolicy.BASELINE,
                    profile=_profile(),
                    delivery=DeliveryMode.PRESET_NO_MOTW,
                    trigger_mode=TriggerMode.LAB_TRIGGER,
                    seed=1,
                )
            )
        self.assertIn("可调度", str(ctx.exception))

    def test_valid_target_image_recipe_still_passes(self) -> None:
        catalog().validate_recipe(
            SampleRecipe(
                recipe_id="sf-ok",
                ph_ids=("PH-IA01", "PH-OB05", "PH-IN04"),
                carrier="atom.ia.document",
                loader_atoms=("atom.ob.decode",),
                execution_atoms=("atom.in.apc",),
                implant_sha256=IMPLANT_SHA,
                implant_format="shellcode",
                delivery="motw-stamped(lab)",
                trigger_mode=TriggerMode.LAB_TRIGGER,
                evasion_tier="E0",
            ),
            {
                "atom.ia.document": {"container": "docm"},
                "atom.ob.decode": {"codec": "rc4"},
                "atom.in.apc": {"target": "notepad.exe"},
            },
            _profile(),
            high_risk_approved=False,
        )

    def test_glue_rejects_current_process_self_inject(self) -> None:
        contracts = (
            GlueInjectionContract(
                atom_id="atom.in.apc",
                sacrificial_image=r"C:\Windows\System32\notepad.exe",
            ),
        )
        with self.assertRaises(PlanningError) as ctx:
            validate_injection_glue_source(
                {
                    "generated/main.cpp": (
                        "const DWORD pid = GetCurrentProcessId();\n"
                        "RemoteThreadInjectExecute(pid, buf, size);\n"
                    )
                },
                contracts,
            )
        self.assertIn("GetCurrentProcessId", str(ctx.exception))

    def test_glue_requires_sacrificial_process_and_wait(self) -> None:
        contracts = glue_injection_contracts(
            (atom_specs()[2],),
            {"atom.in.apc": {"target": "notepad.exe"}},
        )
        validate_injection_glue_source(
            {
                "generated/main.cpp": """
STARTUPINFOW si{};
PROCESS_INFORMATION pi{};
CreateProcessW(L"notepad.exe", nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
RemoteThreadInjectExecute(pi.dwProcessId, buf, size);
WaitForSingleObject(pi.hThread, 5000);
"""
            },
            contracts,
        )

    def test_non_injection_atoms_are_unchanged(self) -> None:
        loader = atom_specs()[1]
        self.assertTrue(injection_domain_ready(loader))
        validate_injection_parameters(loader, {"codec": "rc4"})


if __name__ == "__main__":
    unittest.main()
