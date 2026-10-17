from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.catalog import CoverageRegistry
from packages.sample_factory.models import AtomRole, SafetyProfile
from packages.sample_factory.plugin_models import (
    PluginDecompositionPlan,
    PluginOperation,
    PluginRequest,
    PortContract,
    TechniqueIntent,
)
from packages.sample_factory.plugin_seed import (
    SeedPluginAuthoringBackend,
    variant_family_for_plugin,
)


class SeedPluginAuthoringTest(unittest.TestCase):
    def test_variant_family_follows_atom_prefix_not_injection_default(self) -> None:
        cases = (
            ("atom.payload.msf_calc_x64", AtomRole.LOADER_ATOM, (), "payload"),
            ("atom.in.apc_early_bird", AtomRole.EXECUTION_ATOM, ("PH-IN04",), "injection"),
            ("atom.di.whoami", AtomRole.EXECUTION_ATOM, ("PH-DI01",), "discovery"),
            ("atom.ex.powershell", AtomRole.EXECUTION_ATOM, ("PH-EX01",), "execution"),
            ("atom.ob.decode_runtime", AtomRole.EXECUTION_ATOM, ("PH-OB09",), "obfuscation"),
            ("atom.bl.modify_registry", AtomRole.EXECUTION_ATOM, ("PH-BL10",), "blind"),
            ("atom.ps.registry_run_hkcu", AtomRole.EXECUTION_ATOM, ("PH-PS02",), "persistence"),
            ("atom.pe.uacme_cmluautil", AtomRole.EXECUTION_ATOM, ("PH-PE01",), "privesc"),
            ("atom.it.copy_tool", AtomRole.EXECUTION_ATOM, ("PH-IT01",), "tool_transfer"),
        )
        for plugin_id, role, ph_ids, expected in cases:
            with self.subTest(plugin_id=plugin_id):
                self.assertEqual(
                    expected,
                    variant_family_for_plugin(plugin_id, role=role, ph_ids=ph_ids),
                )

    def test_copies_candidate_source_and_attaches_atom_spec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = Path(tmp) / "catalog"
            seed = catalog / "plugins" / "candidate" / "atom.payload.msf_calc_x64"
            (seed / "src").mkdir(parents=True)
            (seed / "src" / "MsfCalcX64.h").write_text(
                '#pragma once\n#include <cstddef>\nextern "C" int '
                "EdrEvalTtp_MsfCalcX64_Execute(const char*, char*, std::size_t);\n",
                encoding="utf-8",
            )
            (seed / "src" / "MsfCalcX64.cpp").write_text(
                '#include "MsfCalcX64.h"\n#include "handoff_shellcode_v1.h"\n',
                encoding="utf-8",
            )
            dest = Path(tmp) / "runtime" / "final-source"
            request = PluginRequest(
                request_id="plugin-request-msf-calc-x64-0001",
                operation=PluginOperation.CREATE,
                implementation_name="MsfCalcX64",
                seed_source_ref="plugin-seed://atom.payload.msf_calc_x64",
                intent=TechniqueIntent(
                    intent_id="intent-msf-calc-x64-0001",
                    role=AtomRole.LOADER_ATOM,
                    provided_capabilities=("cap.payload.shellcode",),
                    input_ports=(
                        PortContract(
                            port_id="port.request",
                            value_type="json",
                            semantic="empty json smoke",
                            required=False,
                        ),
                    ),
                    output_ports=(
                        PortContract(
                            port_id="port.payload",
                            value_type="byte[]",
                            semantic="shellcode",
                            architecture="x64",
                        ),
                    ),
                    produces_handoffs=("handoff://shellcode/v1",),
                    artifact_ref="payload://x64/msf_calc_x64",
                    architecture="x64",
                    safety_profile=SafetyProfile.LOW,
                    source_refs=("plugin-seed://atom.payload.msf_calc_x64",),
                ),
                build_target_ref="build-target://initial/windows-msvc-v143-x64-plugin",
                profile_id="win11-sysmon15-no-edr",
            )
            source = SeedPluginAuthoringBackend(catalog, lambda _run_id: dest).author(
                request, plugin_run_id="plugin-run-12345678"
            )
            self.assertEqual("atom.payload.msf_calc_x64", source.plugin_id)
            self.assertIsNotNone(source.atom_spec)
            assert source.atom_spec is not None
            self.assertEqual(("handoff://shellcode/v1",), source.atom_spec.produces_handoffs)
            self.assertEqual("payload://x64/msf_calc_x64", source.atom_spec.artifact_ref)
            self.assertEqual((), source.atom_spec.attck_ids)
            self.assertTrue((dest / "src" / "MsfCalcX64.cpp").is_file())

    def test_checked_in_joint_plan_closes_payload_to_early_apc(self) -> None:
        plan = PluginDecompositionPlan.model_validate_json(
            Path("deployment/factory-plugin-joint-plan.json").read_bytes()
        )
        self.assertEqual("plugin-plan-msf-calc-early-apc-0001", plan.plan_id)
        self.assertEqual(2, len(plan.requests))
        producer, consumer = plan.requests
        self.assertEqual("plugin-seed://atom.payload.msf_calc_x64", producer.seed_source_ref)
        self.assertEqual(("cap.payload.shellcode",), producer.intent.provided_capabilities)
        self.assertEqual(("cap.payload.shellcode",), consumer.intent.required_capabilities)
        self.assertEqual(("PH-IN04",), consumer.intent.ph_ids)
        self.assertEqual("payload://x64/msf_calc_x64", producer.intent.artifact_ref)

    def test_execution_seed_copies_attck_ids_from_coverage_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = Path(tmp) / "catalog"
            seed = catalog / "plugins" / "candidate" / "atom.in.apc_early_bird"
            (seed / "src").mkdir(parents=True)
            (seed / "src" / "EarlyApcInjection.h").write_text(
                '#pragma once\n#include <cstddef>\nextern "C" int '
                "EdrEvalTtp_EarlyApcInjection_Execute(const char*, char*, std::size_t);\n",
                encoding="utf-8",
            )
            (seed / "src" / "EarlyApcInjection.cpp").write_text(
                '#include "EarlyApcInjection.h"\n',
                encoding="utf-8",
            )
            dest = Path(tmp) / "runtime" / "final-source"
            request = PluginRequest(
                request_id="plugin-request-early-apc-0001",
                operation=PluginOperation.CREATE,
                implementation_name="EarlyApcInjection",
                seed_source_ref="plugin-seed://atom.in.apc_early_bird",
                intent=TechniqueIntent(
                    intent_id="intent-early-apc-0001",
                    ph_ids=("PH-IN04",),
                    role=AtomRole.EXECUTION_ATOM,
                    required_capabilities=("cap.payload.shellcode",),
                    provided_capabilities=("cap.process.injection",),
                    input_ports=(
                        PortContract(
                            port_id="port.payload",
                            value_type="byte[]",
                            semantic="shellcode",
                            architecture="x64",
                        ),
                    ),
                    consumes_handoffs=("handoff://shellcode/v1",),
                    architecture="x64",
                    safety_profile=SafetyProfile.LOW,
                    source_refs=("plugin-seed://atom.in.apc_early_bird",),
                ),
                build_target_ref="build-target://initial/windows-msvc-v143-x64-plugin",
                harness_ref="plugin-harness://execution/windows-x64/v1",
                profile_id="win11-sysmon15-no-edr",
            )
            coverage = CoverageRegistry({"PH-IN04": ("T1055.004",)})
            source = SeedPluginAuthoringBackend(
                catalog,
                lambda _run_id: dest,
                coverage=coverage,
            ).author(request, plugin_run_id="plugin-run-12345678")
            assert source.atom_spec is not None
            self.assertEqual(("PH-IN04",), source.atom_spec.ph_ids)
            self.assertEqual(("T1055.004",), source.atom_spec.attck_ids)

    def test_execution_seed_without_coverage_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = Path(tmp) / "catalog"
            seed = catalog / "plugins" / "candidate" / "atom.in.apc_early_bird"
            (seed / "src").mkdir(parents=True)
            (seed / "src" / "EarlyApcInjection.h").write_text(
                '#pragma once\n#include <cstddef>\nextern "C" int '
                "EdrEvalTtp_EarlyApcInjection_Execute(const char*, char*, std::size_t);\n",
                encoding="utf-8",
            )
            (seed / "src" / "EarlyApcInjection.cpp").write_text(
                '#include "EarlyApcInjection.h"\n',
                encoding="utf-8",
            )
            dest = Path(tmp) / "runtime" / "final-source"
            request = PluginRequest(
                request_id="plugin-request-early-apc-0001",
                operation=PluginOperation.CREATE,
                implementation_name="EarlyApcInjection",
                seed_source_ref="plugin-seed://atom.in.apc_early_bird",
                intent=TechniqueIntent(
                    intent_id="intent-early-apc-0001",
                    ph_ids=("PH-IN04",),
                    role=AtomRole.EXECUTION_ATOM,
                    required_capabilities=("cap.payload.shellcode",),
                    provided_capabilities=("cap.process.injection",),
                    input_ports=(
                        PortContract(
                            port_id="port.payload",
                            value_type="byte[]",
                            semantic="shellcode",
                            architecture="x64",
                        ),
                    ),
                    consumes_handoffs=("handoff://shellcode/v1",),
                    architecture="x64",
                    safety_profile=SafetyProfile.LOW,
                    source_refs=("plugin-seed://atom.in.apc_early_bird",),
                ),
                build_target_ref="build-target://initial/windows-msvc-v143-x64-plugin",
                profile_id="win11-sysmon15-no-edr",
            )
            with self.assertRaisesRegex(ValueError, "覆盖矩阵"):
                SeedPluginAuthoringBackend(catalog, lambda _run_id: dest).author(
                    request, plugin_run_id="plugin-run-12345678"
                )


if __name__ == "__main__":
    unittest.main()
