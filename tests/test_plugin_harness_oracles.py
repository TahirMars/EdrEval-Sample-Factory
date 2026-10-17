from __future__ import annotations

import unittest

from packages.sample_factory.catalog import CoverageRegistry
from packages.sample_factory.plugin_harness_oracles import (
    matrix_sysmon_event_ids,
    related_sysmon_image_suffixes,
    related_sysmon_path_prefixes,
    resolve_harness_ph_ids,
    sysmon_event_matches,
    variant_sysmon_matchers,
)


class PluginHarnessOraclesTest(unittest.TestCase):
    def test_empty_request_falls_back_to_create_service_atom(self) -> None:
        class _Intent:
            ph_ids = ()

        class _Request:
            intent = _Intent()
            seed_plugin_id = "atom.ps.create_service_winapi"

        class _Spec:
            atom_id = "atom.ps.create_service_winapi"
            ph_ids = ()

        self.assertEqual(("PH-PS01",), resolve_harness_ph_ids(_Request(), _Spec()))

    def test_callback_matcher_rejects_harness_image(self) -> None:
        matcher = variant_sysmon_matchers("atom.ex.callback_exec")[0]
        self.assertTrue(
            sysmon_event_matches(
                {
                    "event_id": 1,
                    "data": {"Image": r"C:\Windows\System32\calc.exe"},
                },
                matcher,
            )
        )
        self.assertFalse(
            sysmon_event_matches(
                {
                    "event_id": 1,
                    "data": {
                        "Image": r"C:\ProgramData\EdrEvalAgent\Runs\x\CallbackExecHarness.exe"
                    },
                },
                matcher,
            )
        )

    def test_seclogon_requires_cmd_eid1_not_harness(self) -> None:
        matcher = variant_sysmon_matchers("atom.ex.seclogon_spoof")[0]
        self.assertEqual(1, matcher.event_id)
        self.assertEqual((), matcher.parent_image_endswith)
        self.assertTrue(
            sysmon_event_matches(
                {
                    "event_id": 1,
                    "data": {
                        "Image": r"C:\Windows\System32\cmd.exe",
                        "ParentImage": r"C:\Windows\explorer.exe",
                    },
                },
                matcher,
            )
        )
        self.assertFalse(
            sysmon_event_matches(
                {
                    "event_id": 1,
                    "data": {
                        "Image": (
                            r"C:\ProgramData\EdrEvalAgent\Runs\x\SeclogonSpoofingHarness.exe"
                        ),
                    },
                },
                matcher,
            )
        )

    def test_related_image_suffixes_keep_spoofed_children_not_parents(self) -> None:
        self.assertEqual(
            (r"\cmd.exe",),
            related_sysmon_image_suffixes(("atom.ex.seclogon_spoof",)),
        )
        self.assertEqual(
            (r"\notepad.exe",),
            related_sysmon_image_suffixes(("atom.ex.ppid_spoof",)),
        )
        self.assertEqual((), related_sysmon_image_suffixes(("atom.pe.uac_sxsconsent",)))
        self.assertNotIn(r"\svchost.exe", related_sysmon_image_suffixes(("atom.ex.seclogon_spoof",)))
        self.assertNotIn(r"\winlogon.exe", related_sysmon_image_suffixes(("atom.pe.token_impersonation_theft",)))
        self.assertEqual(
            (r"\cmd.exe",),
            related_sysmon_image_suffixes(("atom.ps.start_scheduled_task_com",)),
        )
        self.assertNotIn(
            r"\svchost.exe",
            related_sysmon_image_suffixes(("atom.ps.start_scheduled_task_com",)),
        )
        self.assertEqual((), related_sysmon_image_suffixes(("atom.ps.create_scheduled_task_com",)))
        self.assertEqual(
            (),
            related_sysmon_image_suffixes(("atom.pe.uacme_cmluautil",)),
        )
        self.assertNotIn(
            r"\dllhost.exe",
            related_sysmon_image_suffixes(("atom.pe.uacme_cmluautil",)),
        )
        self.assertNotIn(
            r"\fodhelper.exe",
            related_sysmon_image_suffixes(("atom.pe.uacme_cmluautil",)),
        )
        self.assertEqual(
            (r"\cmd.exe",),
            related_sysmon_image_suffixes(("atom.ps.start_service_winapi",)),
        )
        self.assertNotIn(
            r"\services.exe",
            related_sysmon_image_suffixes(("atom.ps.start_service_winapi",)),
        )

    def test_ps03_collects_taskcache_prefixes_not_svchost_image(self) -> None:
        prefixes = related_sysmon_path_prefixes(("atom.ps.create_scheduled_task_com",))
        self.assertIn(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
            prefixes,
        )
        self.assertIn(r"C:\Windows\System32\Tasks", prefixes)
        self.assertEqual(
            prefixes,
            related_sysmon_path_prefixes(("atom.ps.start_scheduled_task_com",)),
        )
        self.assertEqual((), related_sysmon_path_prefixes(("atom.ex.seclogon_spoof",)))
        prefixes_ps01 = related_sysmon_path_prefixes(("atom.ps.create_service_winapi",))
        self.assertIn(r"HKLM\SYSTEM\CurrentControlSet\Services", prefixes_ps01)
        self.assertEqual(
            prefixes_ps01,
            related_sysmon_path_prefixes(("atom.ps.create_service_rpc",)),
        )
        self.assertEqual(
            prefixes_ps01,
            related_sysmon_path_prefixes(("atom.ps.create_service_named_pipe",)),
        )

    def test_create_scheduled_task_requires_taskcache_eid13_not_bam(self) -> None:
        matcher = variant_sysmon_matchers("atom.ps.create_scheduled_task_com")[0]
        self.assertEqual(13, matcher.event_id)
        self.assertTrue(
            sysmon_event_matches(
                {
                    "event_id": 13,
                    "data": {
                        "Image": r"C:\Windows\System32\svchost.exe",
                        "TargetObject": (
                            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                            r"\Schedule\TaskCache\Tree\EdrEvalFactoryT1053005"
                        ),
                    },
                },
                matcher,
            )
        )
        self.assertFalse(
            sysmon_event_matches(
                {
                    "event_id": 13,
                    "data": {
                        "Image": r"C:\Windows\System32\svchost.exe",
                        "TargetObject": (
                            r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State"
                            r"\UserSettings\S-1-5-21-1\C:\ProgramData\EdrEvalAgent"
                            r"\Runs\x\CreateScheduledTaskComHarness.exe"
                        ),
                    },
                },
                matcher,
            )
        )

    def test_start_scheduled_task_requires_cmd_from_taskeng(self) -> None:
        matcher = variant_sysmon_matchers("atom.ps.start_scheduled_task_com")[0]
        self.assertEqual(1, matcher.event_id)
        self.assertTrue(
            sysmon_event_matches(
                {
                    "event_id": 1,
                    "data": {
                        "Image": r"C:\Windows\System32\cmd.exe",
                        "ParentImage": r"C:\Windows\System32\taskeng.exe",
                        "CommandLine": r'cmd.exe /c echo edreval-t1053-005',
                    },
                },
                matcher,
            )
        )
        self.assertFalse(
            sysmon_event_matches(
                {
                    "event_id": 1,
                    "data": {
                        "Image": r"C:\Windows\System32\cmd.exe",
                        "ParentImage": r"C:\Windows\System32\taskeng.exe",
                        "CommandLine": r"cmd.exe /c echo unrelated",
                    },
                },
                matcher,
            )
        )

    def test_create_remote_thread_requires_eid8_to_notepad(self) -> None:
        matcher = variant_sysmon_matchers("atom.in.create_remote_thread")[0]
        self.assertEqual(8, matcher.event_id)
        self.assertTrue(
            sysmon_event_matches(
                {
                    "event_id": 8,
                    "data": {
                        "SourceImage": r"C:\ProgramData\EdrEvalAgent\Runs\x\CreateRemoteThreadInjectionHarness.exe",
                        "TargetImage": r"C:\Windows\System32\notepad.exe",
                    },
                },
                matcher,
            )
        )
        self.assertFalse(
            sysmon_event_matches(
                {
                    "event_id": 8,
                    "data": {
                        "SourceImage": r"C:\ProgramData\EdrEvalAgent\Runs\x\CreateRemoteThreadInjectionHarness.exe",
                        "TargetImage": r"C:\Windows\System32\cmd.exe",
                    },
                },
                matcher,
            )
        )

    def test_token_impersonation_requires_eid10_to_winlogon(self) -> None:
        matcher = variant_sysmon_matchers("atom.pe.token_impersonation_theft")[0]
        self.assertEqual(10, matcher.event_id)
        self.assertTrue(
            sysmon_event_matches(
                {
                    "event_id": 10,
                    "data": {
                        "SourceImage": r"C:\ProgramData\EdrEvalAgent\Runs\x\TokenImpersonationTheftHarness.exe",
                        "TargetImage": r"C:\Windows\System32\winlogon.exe",
                    },
                },
                matcher,
            )
        )
        self.assertFalse(
            sysmon_event_matches(
                {
                    "event_id": 10,
                    "data": {
                        "SourceImage": r"C:\ProgramData\EdrEvalAgent\Runs\x\TokenImpersonationTheftHarness.exe",
                        "TargetImage": r"C:\Windows\System32\explorer.exe",
                    },
                },
                matcher,
            )
        )

    def test_create_process_cmd_requires_marker_command_line(self) -> None:
        matcher = variant_sysmon_matchers("atom.ex.create_process_cmd")[0]
        self.assertEqual(1, matcher.event_id)
        self.assertTrue(
            sysmon_event_matches(
                {
                    "event_id": 1,
                    "data": {
                        "Image": r"C:\Windows\System32\cmd.exe",
                        "CommandLine": r'"C:\Windows\System32\cmd.exe" /c echo edreval-ph-ex02',
                    },
                },
                matcher,
            )
        )
        self.assertFalse(
            sysmon_event_matches(
                {
                    "event_id": 1,
                    "data": {
                        "Image": r"C:\Windows\System32\cmd.exe",
                        "CommandLine": r"C:\Windows\System32\cmd.exe",
                    },
                },
                matcher,
            )
        )

    def test_timestomp_requires_eid2_on_marker_file(self) -> None:
        matcher = variant_sysmon_matchers("atom.bl.timestomp")[0]
        self.assertEqual(2, matcher.event_id)
        self.assertTrue(
            sysmon_event_matches(
                {
                    "event_id": 2,
                    "data": {
                        "TargetFilename": r"C:\Users\lab\AppData\Local\Temp\edreval-bl07-timestomp.bin",
                    },
                },
                matcher,
            )
        )
        self.assertFalse(
            sysmon_event_matches(
                {
                    "event_id": 2,
                    "data": {
                        "TargetFilename": r"C:\Users\lab\AppData\Local\Temp\other.bin",
                    },
                },
                matcher,
            )
        )

    def test_drop_ciphertext_requires_eid11_on_cipher_file(self) -> None:
        matcher = variant_sysmon_matchers("atom.ob.drop_ciphertext")[0]
        self.assertEqual(11, matcher.event_id)
        self.assertTrue(
            sysmon_event_matches(
                {
                    "event_id": 11,
                    "data": {
                        "TargetFilename": r"C:\Users\lab\AppData\Local\Temp\edreval-ob05-cipher.bin",
                    },
                },
                matcher,
            )
        )
        self.assertFalse(
            sysmon_event_matches(
                {
                    "event_id": 11,
                    "data": {
                        "TargetFilename": r"C:\Users\lab\AppData\Local\Temp\edreval-factory-payload.bin",
                    },
                },
                matcher,
            )
        )

    def test_bl08_matrix_slash_eids_include_file_delete_detected(self) -> None:
        from pathlib import Path

        coverage = CoverageRegistry.from_markdown(
            Path("docs/coverage/procedure-host-ttp-coverage-matrix.md")
        )
        self.assertEqual((1, 23, 26), matrix_sysmon_event_ids(coverage, ("PH-BL08",)))

    def test_ewm_requires_eid10_to_explorer(self) -> None:
        matcher = variant_sysmon_matchers("atom.in.ewm_injection")[0]
        self.assertEqual(10, matcher.event_id)
        self.assertTrue(
            sysmon_event_matches(
                {
                    "event_id": 10,
                    "data": {
                        "SourceImage": r"C:\ProgramData\EdrEvalAgent\Runs\x\EwmInjectionHarness.exe",
                        "TargetImage": r"C:\Windows\explorer.exe",
                    },
                },
                matcher,
            )
        )
        self.assertFalse(
            sysmon_event_matches(
                {
                    "event_id": 10,
                    "data": {
                        "SourceImage": r"C:\ProgramData\EdrEvalAgent\Runs\x\EwmInjectionHarness.exe",
                        "TargetImage": r"C:\Windows\System32\notepad.exe",
                    },
                },
                matcher,
            )
        )

    def test_hollowing_requires_eid25_on_notepad(self) -> None:
        matcher = variant_sysmon_matchers("atom.in.process_hollowing")[0]
        self.assertEqual(25, matcher.event_id)
        self.assertTrue(
            sysmon_event_matches(
                {
                    "event_id": 25,
                    "data": {"Image": r"C:\Windows\System32\notepad.exe"},
                },
                matcher,
            )
        )
        self.assertFalse(
            sysmon_event_matches(
                {
                    "event_id": 25,
                    "data": {"Image": r"C:\Windows\System32\cmd.exe"},
                },
                matcher,
            )
        )

    def test_delete_stream_requires_eid26_on_marker_file(self) -> None:
        matcher = variant_sysmon_matchers("atom.bl.delete_using_stream")[0]
        self.assertEqual(26, matcher.event_id)
        self.assertTrue(
            sysmon_event_matches(
                {
                    "event_id": 26,
                    "data": {
                        "TargetFilename": r"C:\Users\lab\AppData\Local\Temp\edreval-bl08-delete.bin",
                    },
                },
                matcher,
            )
        )
        self.assertFalse(
            sysmon_event_matches(
                {
                    "event_id": 26,
                    "data": {
                        "TargetFilename": r"C:\Users\lab\AppData\Local\Temp\other.bin",
                    },
                },
                matcher,
            )
        )


if __name__ == "__main__":
    unittest.main()
