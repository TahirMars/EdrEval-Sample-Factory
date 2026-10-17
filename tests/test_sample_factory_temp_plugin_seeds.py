from __future__ import annotations

import json
import unittest
from pathlib import Path

from packages.sample_factory.catalog import CoverageRegistry
from packages.sample_factory.plugin_contract import validate_candidate_source_snapshot
from packages.sample_factory.plugin_models import PluginDecompositionPlan, PluginRequest
from packages.sample_factory.plugin_seed import _atom_spec_from_request
from packages.sample_factory.telemetry_catalog import project_sysmon_telemetry_contract

_REPO = Path(__file__).resolve().parents[1]
_REQUESTS = _REPO / "deployment" / "plugin-seeds" / "requests"
_PLANS = _REPO / "deployment" / "plugin-seeds" / "plans"
_FACTORY_CONFIG = _REPO / "deployment" / "factory-config.json"
_COVERAGE = _REPO / "docs" / "coverage" / "procedure-host-ttp-coverage-matrix.md"


def _catalog_root() -> Path | None:
    if not _FACTORY_CONFIG.is_file():
        return None
    raw = json.loads(_FACTORY_CONFIG.read_text(encoding="utf-8"))
    root = Path(raw["catalog_root"])
    return root if root.is_dir() else None


class ConvertedTempPluginSeedTest(unittest.TestCase):
    def test_seed_requests_parse_and_keep_producer_consumer_edges(self) -> None:
        requests = {
            path.stem: PluginRequest.model_validate_json(path.read_bytes())
            for path in sorted(_REQUESTS.glob("*.json"))
        }
        self.assertIn("atom.in.thread_hijack", requests)
        self.assertEqual(("PH-IN01",), requests["atom.in.create_remote_thread"].intent.ph_ids)
        self.assertEqual(("PH-IN02",), requests["atom.in.process_hollowing"].intent.ph_ids)
        self.assertEqual(("PH-IN05",), requests["atom.in.ewm_injection"].intent.ph_ids)
        self.assertEqual(("PH-IN06",), requests["atom.in.process_doppelgang"].intent.ph_ids)
        self.assertEqual(("PH-IN07",), requests["atom.in.process_herpaderp"].intent.ph_ids)
        self.assertEqual(("PH-IN03",), requests["atom.in.thread_hijack"].intent.ph_ids)
        self.assertEqual(
            ("handoff://shellcode/v1",),
            requests["atom.in.thread_hijack"].intent.consumes_handoffs,
        )
        self.assertEqual(
            ("cap.payload.shellcode",),
            requests["atom.in.thread_hijack"].intent.required_capabilities,
        )
        self.assertEqual(
            ("handoff://shellcode/encrypted/v1",),
            requests["atom.payload.msf_calc_x64_sf033"].intent.produces_handoffs,
        )
        self.assertEqual(
            ("handoff://shellcode/v1",),
            requests["atom.ld.rc4_systemfunction033"].intent.produces_handoffs,
        )
        self.assertEqual((), requests["atom.ld.get_from_disk"].intent.ph_ids)
        self.assertEqual((), requests["atom.ld.get_from_param"].intent.ph_ids)
        self.assertEqual(("PH-PS01",), requests["atom.ps.create_service_winapi"].intent.ph_ids)
        self.assertEqual(("PH-PS01",), requests["atom.ps.create_service_rpc"].intent.ph_ids)
        self.assertEqual(("PH-PS01",), requests["atom.ps.create_service_named_pipe"].intent.ph_ids)
        self.assertEqual(("PH-EX11",), requests["atom.ps.start_service_winapi"].intent.ph_ids)
        self.assertEqual(("PH-EX02",), requests["atom.ex.create_process_cmd"].intent.ph_ids)
        self.assertEqual(("PH-BL07",), requests["atom.bl.timestomp"].intent.ph_ids)
        self.assertEqual(("PH-BL08",), requests["atom.bl.delete_using_stream"].intent.ph_ids)
        self.assertEqual(("PH-OB05",), requests["atom.ob.drop_ciphertext"].intent.ph_ids)
        self.assertEqual(("PH-PS03",), requests["atom.ps.create_scheduled_task_com"].intent.ph_ids)
        self.assertEqual(("PH-PS03",), requests["atom.ps.start_scheduled_task_com"].intent.ph_ids)
        self.assertEqual(("PH-EX01",), requests["atom.ex.powershell"].intent.ph_ids)
        self.assertEqual(("PH-PS02",), requests["atom.ps.registry_run_hkcu"].intent.ph_ids)
        self.assertEqual(("PH-DI01",), requests["atom.di.whoami"].intent.ph_ids)
        self.assertEqual(("PH-IT01",), requests["atom.it.copy_tool"].intent.ph_ids)
        self.assertEqual(("PH-OB08",), requests["atom.ob.extract_embedded"].intent.ph_ids)
        self.assertEqual(("PH-OB09",), requests["atom.ob.decode_runtime"].intent.ph_ids)
        self.assertEqual(("PH-BL10",), requests["atom.bl.modify_registry"].intent.ph_ids)
        self.assertEqual(
            ("cap.scheduled_task.created",),
            requests["atom.ps.create_scheduled_task_com"].intent.provided_capabilities,
        )
        self.assertEqual(
            ("cap.scheduled_task.created",),
            requests["atom.ps.start_scheduled_task_com"].intent.required_capabilities,
        )
        self.assertEqual(
            ("handoff://scheduled-task/name/v1",),
            requests["atom.ps.create_scheduled_task_com"].intent.produces_handoffs,
        )
        self.assertEqual(
            ("handoff://scheduled-task/name/v1",),
            requests["atom.ps.start_scheduled_task_com"].intent.consumes_handoffs,
        )
        self.assertEqual((), requests["atom.pe.request_elevation_uac"].intent.ph_ids)
        self.assertEqual((), requests["atom.pe.enable_token_privilege"].intent.ph_ids)
        self.assertEqual(("PH-PE01",), requests["atom.pe.uacme_cmluautil"].intent.ph_ids)
        self.assertEqual(("PH-PE02",), requests["atom.pe.token_impersonation_theft"].intent.ph_ids)
        self.assertEqual(
            ("cap.process.elevated",),
            requests["atom.ps.create_service_winapi"].intent.required_capabilities,
        )
        self.assertEqual(
            ("cap.process.elevated",),
            requests["atom.ps.create_service_rpc"].intent.required_capabilities,
        )
        self.assertEqual(
            ("cap.process.elevated",),
            requests["atom.ps.create_service_named_pipe"].intent.required_capabilities,
        )
        self.assertEqual(
            (),
            requests["atom.ex.ppid_spoof"].intent.required_capabilities,
        )
        self.assertEqual(
            (),
            requests["atom.ex.ppid_spoof"].intent.consumes_handoffs,
        )
        self.assertEqual(
            ("cap.token.privilege",),
            requests["atom.pe.token_impersonation_theft"].intent.required_capabilities,
        )
        self.assertEqual(
            ("cap.process.elevated",),
            requests["atom.pe.uacme_cmluautil"].intent.provided_capabilities,
        )
        self.assertEqual(
            ("cap.process.uac_consent",),
            requests["atom.pe.request_elevation_uac"].intent.provided_capabilities,
        )
        self.assertEqual(
            ("handoff://service/name/v1",),
            requests["atom.ps.create_service_winapi"].intent.produces_handoffs,
        )
        self.assertEqual(
            ("cap.service.created",),
            requests["atom.ps.start_service_winapi"].intent.required_capabilities,
        )
        self.assertEqual(
            ("handoff://service/name/v1",),
            requests["atom.ps.start_service_winapi"].intent.consumes_handoffs,
        )
        self.assertEqual(
            ("handoff://process/uac_consent/v1",),
            requests["atom.pe.request_elevation_uac"].intent.produces_handoffs,
        )
        self.assertEqual(
            ("cap.process.elevated",),
            requests["atom.pe.enable_token_privilege"].intent.required_capabilities,
        )
        self.assertIsNone(requests["atom.in.thread_hijack"].harness_ref)
        self.assertIsNone(requests["atom.ps.create_service_rpc"].harness_ref)
        self.assertEqual(
            {"win10-21h2-sysmon15-no-edr"},
            {item.profile_id for item in requests.values()},
        )

    def test_joint_plans_close_declared_capabilities(self) -> None:
        for path in sorted(_PLANS.glob("*.json")):
            plan = PluginDecompositionPlan.model_validate_json(path.read_bytes())
            by_id = {item.request_id: item for item in plan.requests}
            for dependency in plan.dependencies:
                producer = by_id[dependency.producer_request_id]
                consumer = by_id[dependency.consumer_request_id]
                self.assertIn(
                    dependency.capability,
                    producer.intent.provided_capabilities,
                    msg=path.name,
                )
                self.assertIn(
                    dependency.capability,
                    consumer.intent.required_capabilities,
                    msg=path.name,
                )
            self.assertEqual(
                {"win10-21h2-sysmon15-no-edr"},
                {item.profile_id for item in plan.requests},
                msg=path.name,
            )

    def test_ph_rows_project_matrix_telemetry(self) -> None:
        coverage = CoverageRegistry.from_markdown(_COVERAGE)
        requests = [
            PluginRequest.model_validate_json(path.read_bytes())
            for path in sorted(_REQUESTS.glob("*.json"))
        ]
        expected = {
            "atom.in.create_remote_thread": (8,),
            "atom.in.ewm_injection": (10,),
            "atom.in.process_hollowing": (25,),
            "atom.in.process_doppelgang": (25,),
            "atom.in.process_herpaderp": (25,),
            "atom.in.thread_hijack": (10,),
            "atom.in.pool_party": (10,),
            "atom.ex.callback_exec": (1,),
            "atom.ex.ppid_spoof": (1,),
            "atom.ex.seclogon_spoof": (1,),
            "atom.pe.token_impersonation_theft": (10,),
            "atom.ps.create_service_winapi": (13,),
            "atom.ps.create_service_rpc": (13,),
            "atom.ps.create_service_named_pipe": (13,),
            "atom.ps.start_service_winapi": (1,),
            "atom.ex.create_process_cmd": (1,),
            "atom.bl.timestomp": (2,),
            "atom.bl.delete_using_stream": (26,),
            "atom.ob.drop_ciphertext": (11,),
        }
        for request in requests:
            atom_id = request.seed_plugin_id
            if atom_id not in expected:
                continue
            spec = _atom_spec_from_request(atom_id, request, coverage)
            contract = project_sysmon_telemetry_contract(
                spec, coverage, "win10-21h2-sysmon15-no-edr"
            )
            self.assertIsNotNone(contract, atom_id)
            assert contract is not None
            event_ids = tuple(
                int(item.match_fields["event_id"])
                for item in contract.assertions
                if item.level.value == "required"
            )
            self.assertEqual(expected[atom_id], event_ids, atom_id)

    def test_candidate_sources_match_abi_contract(self) -> None:
        catalog = _catalog_root()
        if catalog is None:
            self.skipTest("factory catalog_root is not mounted")
        coverage = CoverageRegistry.from_markdown(_COVERAGE)
        for path in sorted(_REQUESTS.glob("*.json")):
            request = PluginRequest.model_validate_json(path.read_bytes())
            atom_id = request.seed_plugin_id
            if atom_id is None:
                continue
            seed = catalog / "plugins" / "candidate" / atom_id
            if not seed.is_dir():
                seed = catalog / "plugins" / "dispatchable" / atom_id
            if atom_id == "atom.payload.msf_calc_x64":
                continue
            self.assertTrue(seed.is_dir(), atom_id)
            snapshot = {
                item.relative_to(seed).as_posix(): item.read_text(encoding="utf-8")
                for item in seed.rglob("*")
                if item.is_file() and item.suffix.lower() in {".h", ".cpp", ".vcxproj"}
            }
            validate_candidate_source_snapshot(snapshot, request.implementation_name)
            self.assertIn(
                f"EdrEvalTtp_{request.implementation_name}_Execute",
                snapshot[f"src/{request.implementation_name}.h"],
            )
            if request.intent.ph_ids:
                self.assertEqual(
                    coverage.attack_ids_for(request.intent.ph_ids),
                    _atom_spec_from_request(atom_id, request, coverage).attck_ids,
                )
            cpp = snapshot[f"src/{request.implementation_name}.cpp"]
            windows = cpp.find("#include <windows.h>")
            toolhelp = cpp.find("#include <tlhelp32.h>")
            if toolhelp >= 0:
                self.assertGreaterEqual(windows, 0, atom_id)
                self.assertLess(windows, toolhelp, atom_id)

    def test_callback_exec_catches_payload_seh_exitfunk(self) -> None:
        catalog = _catalog_root()
        if catalog is None:
            self.skipTest("factory catalog_root is not mounted")
        cpp = (
            catalog
            / "plugins"
            / "candidate"
            / "atom.ex.callback_exec"
            / "src"
            / "CallbackExec.cpp"
        ).read_text(encoding="utf-8")
        invoke = cpp.index("InvokeEnumWindowsCallback")
        try_pos = cpp.index("__try", invoke)
        enum_pos = cpp.index("EnumWindows", try_pos)
        except_pos = cpp.index("EXCEPTION_EXECUTE_HANDLER", enum_pos)
        self.assertLess(try_pos, enum_pos)
        self.assertLess(enum_pos, except_pos)

    def test_seclogon_defaults_to_cmd_not_store_alias(self) -> None:
        request = PluginRequest.model_validate_json(
            (_REQUESTS / "atom.ex.seclogon_spoof.json").read_bytes()
        )
        images = request.intent.parameter_domains["target_image"]
        self.assertEqual("cmd.exe", images[0])
        self.assertIn("cmd.exe", images)
        self.assertGreaterEqual(len(images), 3)
        self.assertLessEqual(len(images), 10)
        catalog = _catalog_root()
        if catalog is None:
            self.skipTest("factory catalog_root is not mounted")
        cpp = (
            catalog
            / "plugins"
            / "candidate"
            / "atom.ex.seclogon_spoof"
            / "src"
            / "SeclogonSpoofing.cpp"
        ).read_text(encoding="utf-8")
        self.assertIn('target_image = "cmd.exe"', cpp)
        self.assertNotIn('target_image = "notepad.exe"', cpp)

    def test_uacme_fodhelper_relaunches_harness_not_com_hang(self) -> None:
        catalog = _catalog_root()
        if catalog is None:
            self.skipTest("factory catalog_root is not mounted")
        cpp = (
            catalog
            / "plugins"
            / "candidate"
            / "atom.pe.uacme_cmluautil"
            / "src"
            / "UacmeCMLuaUtil.cpp"
        ).read_text(encoding="utf-8")
        self.assertIn("fodhelper.exe", cpp)
        self.assertIn("ms-settings", cpp)
        self.assertIn("ShellExecuteExW", cpp)
        self.assertIn("GetModuleFileNameW", cpp)
        self.assertIn("kElevatedWaitMs", cpp)
        self.assertIn("edreval-elevated-done", cpp)
        self.assertIn("delegated_to_elevated_process", cpp)
        self.assertNotIn("CreateProcessW", cpp)
        self.assertNotIn("CoGetObject", cpp)
        self.assertNotIn("ICMLuaUtil", cpp)
        self.assertNotIn("edreval-ph-pe01", cpp)

    def test_start_service_accepts_marker_binary_timeout(self) -> None:
        catalog = _catalog_root()
        if catalog is None:
            self.skipTest("factory catalog_root is not mounted")
        cpp = (
            catalog
            / "plugins"
            / "candidate"
            / "atom.ps.start_service_winapi"
            / "src"
            / "StartServiceByWinApi.cpp"
        ).read_text(encoding="utf-8")
        self.assertIn("ERROR_SERVICE_REQUEST_TIMEOUT", cpp)
        self.assertIn("StartServiceA", cpp)

    def test_expandable_parameter_domains_have_three_to_ten_values(self) -> None:
        hardcoded = {
            "atom.ex.create_process_cmd": ("target_image",),
            "atom.in.ewm_injection": ("target_image",),
        }
        for path in sorted(_REQUESTS.glob("*.json")):
            request = PluginRequest.model_validate_json(path.read_bytes())
            skip = hardcoded.get(path.stem, ())
            for key, values in request.intent.parameter_domains.items():
                if key in skip:
                    self.assertEqual(1, len(values), path.stem)
                    continue
                self.assertGreaterEqual(len(values), 3, f"{path.stem}.{key}")
                self.assertLessEqual(len(values), 10, f"{path.stem}.{key}")

    def test_plan_parameter_domains_match_request_seeds(self) -> None:
        requests = {
            PluginRequest.model_validate_json(path.read_bytes()).request_id: path
            for path in _REQUESTS.glob("*.json")
        }
        for path in sorted(_PLANS.glob("*.json")):
            plan = PluginDecompositionPlan.model_validate_json(path.read_bytes())
            for request in plan.requests:
                seed = PluginRequest.model_validate_json(requests[request.request_id].read_bytes())
                self.assertEqual(
                    seed.intent.parameter_domains,
                    request.intent.parameter_domains,
                    f"{path.name}:{request.request_id}",
                )


if __name__ == "__main__":
    unittest.main()
