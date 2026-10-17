from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "configure_factory_validation_vm.ps1"
CONNECTION_TEST_SCRIPT = ROOT / "scripts" / "test_factory_validation_vm_connection.ps1"
GUEST_DRIVER_SCRIPT = ROOT / "scripts" / "run_factory_vm_guest.ps1"
SNAPSHOT_TEST_SCRIPT = ROOT / "scripts" / "test_factory_vmware_snapshot.ps1"


class FactoryValidationVmScriptTest(unittest.TestCase):
    source: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_requires_elevation_and_explicit_management_host(self) -> None:
        self.assertIn("#Requires -RunAsAdministrator", self.source)
        self.assertRegex(
            self.source,
            r"\[Parameter\(Mandatory = \$true\)\]\s+"
            r"\[System\.Net\.IPAddress\]\$ManagementHostIp",
        )
        self.assertIn('ExpectedVmIp = "192.168.131.139"', self.source)
        self.assertIn("Windows (10|11)", self.source)

    def test_exposes_only_restricted_winrm_https(self) -> None:
        self.assertIn("Remove-WinRmHttpSurface", self.source)
        self.assertIn("Service\\AllowUnencrypted -Value $false", self.source)
        self.assertIn("Service\\Auth\\Basic -Value $false", self.source)
        self.assertIn("-LocalPort 5986", self.source)
        self.assertIn("-RemoteAddress $ManagementHostIpText", self.source)
        self.assertNotIn("0.0.0.0/0", self.source)

    def test_does_not_claim_nat_is_isolated_or_snapshot_verified(self) -> None:
        self.assertIn('declared_mode = "nat"', self.source)
        self.assertIn("isolated = $false", self.source)
        self.assertIn("snapshot_rollback_verified = $false", self.source)
        self.assertIn("rollback_capable = $false", self.source)

    def test_no_edr_declaration_is_explicit_and_does_not_disable_products(self) -> None:
        self.assertIn("[switch]$DeclareNoCommercialEdr", self.source)
        self.assertIn("declared_no_edr = [bool]$DeclareNoCommercialEdr", self.source)
        self.assertIn("operator-asserted-no-commercial-edr", self.source)
        self.assertNotIn("Disable-MpPreference", self.source)

    def test_runner_is_filtered_local_admin_with_limited_interactive_worker(self) -> None:
        self.assertIn('Get-LocalGroup -SID "S-1-5-32-573"', self.source)
        self.assertIn("Add-LocalGroupMember -Group $eventLogReadersGroup", self.source)
        self.assertIn('Get-LocalGroup -SID "S-1-5-32-544"', self.source)
        self.assertIn("Add-LocalGroupMember -Group $adminsGroup", self.source)
        self.assertIn("runner_local_admin = $true", self.source)
        self.assertIn('execution_integrity = "medium"', self.source)
        self.assertIn('interactive_worker_run_level = "Limited"', self.source)
        self.assertIn('execution_session = "interactive_console"', self.source)
        self.assertIn("EdrEvalInteractiveWorker", self.source)
        self.assertIn('-Name "AutoAdminLogon"', self.source)
        self.assertIn("LogonType Interactive", self.source)
        self.assertIn("RunLevel Limited", self.source)
        self.assertNotIn("EnableLUA", self.source)
        self.assertIn("factory-vmware-interactive-launch-v1", self.source)
        self.assertIn("refusing to start Harness", self.source)
        self.assertIn('`$resultPath + ".tmp"', self.source)
        self.assertIn("Move-Item -LiteralPath `$tmpPath -Destination `$resultPath -Force", self.source)

    def test_does_not_weaken_security_or_clear_system_event_logs(self) -> None:
        forbidden = (
            "Set-MpPreference",
            "Disable-WindowsOptionalFeature",
            "Clear-EventLog",
            "wevtutil cl",
            "AllowUnencrypted -Value $true",
            "Auth\\Basic -Value $true",
        )
        for token in forbidden:
            self.assertNotIn(token, self.source)

    def test_password_is_prompted_as_secure_string(self) -> None:
        self.assertIn("Read-Host", self.source)
        self.assertIn("-AsSecureString", self.source)
        self.assertNotRegex(self.source, r"(?i)password\s*=\s*['\"][^'\"]+['\"]")


class FactoryValidationVmConnectionScriptTest(unittest.TestCase):
    source: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = CONNECTION_TEST_SCRIPT.read_text(encoding="utf-8")

    def test_requires_profile_certificate_and_uses_expected_vm_defaults(self) -> None:
        self.assertRegex(
            self.source,
            r"\[Parameter\(Mandatory = \$true\)\]\s+"
            r"\[ValidateScript\([^\n]+\)\]\s+\[string\]\$CertificatePath",
        )
        self.assertIn("$ProfilePath", self.source)
        self.assertIn('VmIp = "192.168.131.139"', self.source)
        self.assertIn('VmDnsName = "new-dev.edreval.lab"', self.source)
        self.assertIn("Windows (10|11)", self.source)

    def test_host_mutation_requires_explicit_switch(self) -> None:
        self.assertIn("[switch]$ConfigureHostTrust", self.source)
        self.assertIn("if ($ConfigureHostTrust)", self.source)
        self.assertIn("Test-IsAdministrator", self.source)
        self.assertIn("Import-VerifiedCertificate", self.source)
        self.assertIn("Add-HostMappingIfMissing", self.source)

    def test_checks_tcp_winrm_and_round_trip_hashes(self) -> None:
        self.assertIn("Test-NetConnection", self.source)
        self.assertIn("-Port 5986", self.source)
        self.assertIn("Test-WSMan", self.source)
        self.assertIn("New-PSSession", self.source)
        self.assertIn("-ToSession $Session", self.source)
        self.assertIn("-FromSession $Session", self.source)
        self.assertIn("Get-FileHash", self.source)
        self.assertIn("all_hashes_match = $true", self.source)

    def test_uploads_part_then_renames_and_cleans_only_unique_probe(self) -> None:
        self.assertIn('"connectivity-$ProbeId"', self.source)
        self.assertIn('"probe.txt.part"', self.source)
        self.assertIn("Move-Item -LiteralPath $PartPath", self.source)
        self.assertIn("Remove-Item -LiteralPath $Path", self.source)
        self.assertNotIn("Remove-Item $RemoteRunsRoot", self.source)

    def test_does_not_use_insecure_winrm_bypasses_or_literal_passwords(self) -> None:
        forbidden = (
            "SkipCACheck",
            "SkipCNCheck",
            "TrustedHosts=*",
            "AllowUnencrypted",
            "Authentication Basic",
        )
        for token in forbidden:
            self.assertNotIn(token, self.source)
        self.assertNotRegex(self.source, r"(?i)password\s*=\s*['\"][^'\"]+['\"]")


class FactoryVmGuestDriverScriptTest(unittest.TestCase):
    source: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = GUEST_DRIVER_SCRIPT.read_text(encoding="utf-8")

    def test_password_uses_stdin_and_winrm_https(self) -> None:
        self.assertIn("[Console]::In.ReadToEnd()", self.source)
        self.assertIn("UseSSL = $true", self.source)
        self.assertIn('Authentication = "Negotiate"', self.source)
        self.assertIn('Get-Service -Name "WinRM"', self.source)
        self.assertIn("while ($null -eq $Session", self.source)
        self.assertIn("-OpenTimeout 20000", self.source)
        self.assertIn('ErrorAction = "Stop"', self.source)
        self.assertIn("Format-WinRmOpenError", self.source)
        self.assertIn("$openFailure", self.source)
        self.assertNotIn("$lastError", self.source)
        self.assertNotIn("Authentication Basic", self.source)
        self.assertNotIn("SkipCACheck", self.source)
        self.assertNotIn("SkipCNCheck", self.source)

    def test_upload_is_hash_checked_before_interactive_zero_argument_execution(self) -> None:
        self.assertIn('"$($Request.guest_artifact_name).part"', self.source)
        self.assertIn("Copy-FileToGuest", self.source)
        self.assertIn("[System.IO.FileMode]::Append", self.source)
        self.assertIn(".write-probe-", self.source)
        self.assertNotIn("Copy-Item @copyToParams", self.source)
        self.assertNotIn("Copy-Item @copyFromParams", self.source)
        self.assertNotIn("-ToSession $Session", self.source)
        self.assertNotIn("-FromSession $Session", self.source)
        self.assertIn("Copy-FileFromGuest", self.source)
        self.assertIn("Convert-ToWin32ExtendedPath", self.source)
        self.assertIn("WriteAllBytes($extendedLocal, $bytes)", self.source)
        self.assertIn("Get-FileHash", self.source)
        self.assertIn("Move-Item -LiteralPath $PartPath", self.source)
        self.assertIn("Wait-InteractiveWorker", self.source)
        self.assertIn("interactive-worker", self.source)
        self.assertIn("SessionId -gt 0", self.source)
        self.assertIn("Start-ScheduledTask -TaskName $taskName", self.source)
        self.assertIn("EdrEvalInteractiveWorker", self.source)
        self.assertIn("launch-request.json", self.source)
        self.assertIn("factory-vmware-interactive-launch-v1", self.source)
        self.assertIn("session_id", self.source)
        self.assertIn("Session 0 WinRM cannot host UAC", self.source)
        self.assertIn("Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop", self.source)
        self.assertIn("Partial JSON while the worker flushes the result file.", self.source)
        self.assertIn('factory-vmware-interactive-launch-result-v1', self.source)
        self.assertNotIn("WindowStyle Hidden", self.source)
        self.assertNotRegex(
            self.source,
            r"Start-Process[^\r\n]*-ArgumentList",
        )

    def test_collects_logs_and_sysmon_but_cleans_only_run_directory(self) -> None:
        self.assertIn('"sample-logs"', self.source)
        self.assertIn("Get-WinEvent", self.source)
        self.assertIn("$_.ToXml()", self.source)
        self.assertIn("Convert-SysmonXmlData", self.source)
        self.assertIn("Test-RelatedSysmonData", self.source)
        self.assertIn("Remove-Item -LiteralPath $Path", self.source)
        self.assertNotIn("Remove-Item -LiteralPath $Request.remote_logs_root", self.source)

    def test_sysmon_collection_follows_process_tree_not_event_id_allowlist(self) -> None:
        self.assertIn("-Oldest", self.source)
        self.assertIn("Convert-ToWinEventFilterTime", self.source)
        self.assertIn("ToLocalTime()", self.source)
        self.assertIn("[DateTimeKind]::Unspecified", self.source)
        self.assertIn("EndTime = $ended", self.source)
        self.assertIn("New-RelatedSysmonIdentity", self.source)
        self.assertIn("Add-RelatedSysmonProcess", self.source)
        self.assertIn("related_path_prefixes", self.source)
        self.assertIn("related_image_suffixes", self.source)
        self.assertIn("ImageSuffixes", self.source)
        self.assertIn('ProcessId$', self.source)
        self.assertIn("CommandLine$", self.source)
        self.assertIn("TargetObject|TargetFilename", self.source)
        self.assertIn(r'(?i)^(Image|TargetImage)$', self.source)
        self.assertIn(".EndsWith($suffix)", self.source)
        self.assertIn("data = $data", self.source)
        self.assertNotIn("SysmonCollectorEventIds", self.source)
        self.assertNotIn("Id = @($EventIds)", self.source)
        get_win_event = self.source.index("Get-WinEvent -FilterHashtable $filter")
        tree_expand = self.source.index("Add-RelatedSysmonProcess", get_win_event)
        cap = self.source.index("Select-Object -First $MaxEvents", get_win_event)
        self.assertLess(tree_expand, cap)
        self.assertNotRegex(
            self.source[get_win_event:cap],
            r"return \$true",
        )


class FactoryVmwareSnapshotScriptTest(unittest.TestCase):
    source: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SNAPSHOT_TEST_SCRIPT.read_text(encoding="utf-8")

    def test_is_explicitly_destructive_and_runs_two_cycles(self) -> None:
        self.assertIn("#Requires -RunAsAdministrator", self.source)
        self.assertIn("SupportsShouldProcess = $true", self.source)
        self.assertIn('ConfirmImpact = "High"', self.source)
        self.assertIn("foreach ($cycle in 1..2)", self.source)

    def test_proves_marker_disappears_and_leaves_vm_reverted(self) -> None:
        self.assertIn('"snapshot-proof-$MarkerId.txt"', self.source)
        self.assertIn("if ($markerExists)", self.source)
        self.assertIn("Stop-And-Revert", self.source)
        self.assertIn("snapshot_rollback_verified = $true", self.source)
        self.assertIn("rollback_capable = $true", self.source)

    def test_vm_password_is_prompted_and_not_persisted(self) -> None:
        self.assertIn("-AsSecureString", self.source)
        self.assertIn("ZeroFreeBSTR", self.source)
        self.assertIn('Replace($script:VmPassword, "[REDACTED]")', self.source)
        self.assertNotRegex(self.source, r"(?i)password\s*=\s*['\"][^'\"]+['\"]")


class FactorySysmonOverlayTest(unittest.TestCase):
    overlay: Path
    source: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.overlay = ROOT / "scripts" / "sysmon-factory-overlay.xml"
        cls.source = cls.overlay.read_text(encoding="utf-8")

    def test_is_complete_config_and_enables_matrix_sysmon_channels(self) -> None:
        from xml.etree import ElementTree as ET

        root = ET.parse(self.overlay).getroot()
        self.assertEqual("Sysmon", root.tag)
        filtering = root.find("EventFiltering")
        self.assertIsNotNone(filtering)
        names = {child.tag for group in filtering for child in group}
        for required in (
            "ProcessCreate",
            "ProcessAccess",
            "ImageLoad",
            "CreateRemoteThread",
            "ProcessTampering",
            "FileCreate",
            "FileCreateStreamHash",
            "FileDeleteDetected",
            "FileCreateTime",
        ):
            self.assertIn(required, names)
        self.assertIn("C:\\ProgramData\\EdrEvalAgent", self.source)
        self.assertIn("C:\\Windows\\System32\\Tasks", self.source)
        self.assertIn("\\Schedule\\TaskCache", self.source)
        self.assertIn('ProcessAccess onmatch="include"', self.source)
        self.assertIn('ImageLoad onmatch="include"', self.source)
        self.assertIn('ProcessTampering onmatch="exclude"', self.source)
        self.assertNotIn("SkipCACheck", self.source)
        self.assertIn("Sysmon64.exe -c", self.source)
        # CreateRemoteThread's StartModule is kernel32 even for shellcode IN01.
        self.assertNotIn(
            'StartModule condition="is">C:\\Windows\\system32\\kernel32.dll',
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
