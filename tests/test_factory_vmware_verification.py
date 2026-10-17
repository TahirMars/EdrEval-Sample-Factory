from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.config.resolver import SecretResolver
from packages.factory_host.vmware_verification import (
    GuestExecutionResult,
    VmrunController,
    VmwareVerificationBackend,
    VmwareVerificationSettings,
    _validate_sample_log_evidence,
    windows_client_caption_supported,
)
from packages.sample_factory.errors import VerificationError
from packages.sample_factory.models import (
    BuiltSample,
    DeliveryMode,
    FactoryPlanningContext,
    ProductionPolicy,
    ProductionProfile,
    SampleRecipe,
    TriggerMode,
)
from packages.sample_factory.telemetry import FunctionalTruthEvaluator
from pydantic import ValidationError


class _ArtifactResolver:
    def __init__(self, path: Path) -> None:
        self.path = path

    def resolve_artifact(self, artifact_ref: str) -> Path:
        if artifact_ref != "build-artifact://vmware-test":
            raise KeyError(artifact_ref)
        return self.path


class _VmrunRunner:
    def __init__(
        self,
        *,
        snapshots: tuple[str, ...] = ("new_dev",),
        fail_final_revert: bool = False,
    ) -> None:
        self.snapshots = snapshots
        self.fail_final_revert = fail_final_revert
        self.calls: list[list[str]] = []
        self._reverts = 0

    def run(self, argv: list[str], *, timeout: float | None = None) -> tuple[int, str]:
        del timeout
        self.calls.append(list(argv))
        if len(argv) >= 6 and argv[3] == "-vp":
            command = argv[5]
            secret = argv[4]
        else:
            command = argv[3]
            secret = ""
        if command == "listSnapshots":
            return 0, "Total snapshots: 1\n" + "\n".join(self.snapshots)
        if command == "revertToSnapshot":
            self._reverts += 1
            if self.fail_final_revert and self._reverts >= 2:
                return 1, f"failed with secret {secret}"
        return 0, "ok"


class _GuestRunner:
    def __init__(self, *, log_success: bool = True) -> None:
        self.log_success = log_success
        self.calls: list[tuple[list[str], str]] = []

    def run(
        self,
        argv: list[str],
        *,
        stdin_text: str,
        timeout: float | None = None,
    ) -> tuple[int, str]:
        del timeout
        self.calls.append((list(argv), stdin_text))
        request_path = Path(argv[argv.index("-RequestPath") + 1])
        request = json.loads(request_path.read_text(encoding="utf-8"))
        evidence_dir = Path(request["evidence_dir"])
        log_dir = evidence_dir / "sample-logs"
        log_dir.mkdir(parents=True)
        remote_path = r"C:\ProgramData\EdrEvalAgent\Runs\run-1\\" + request["guest_artifact_name"]
        log_name = f"{request['recipe_id']}-sample-run.jsonl"
        log_path = log_dir / log_name
        events = [
            {
                "schema_version": "edreval-sample-log-v1",
                "event": "sample_start",
                "sample_id": request["recipe_id"],
                "recipe_id": request["recipe_id"],
                "run_id": "sample-run",
                "trigger_mode": "lab_trigger",
                "process_id": 1234,
                "host_name": "WIN11",
                "image_path": remote_path,
                "execution_logging": True,
                "ph_ids": request["expected_ph_ids"],
                "atom_ids": request["expected_atom_ids"],
            },
            {
                "schema_version": "edreval-sample-log-v1",
                "event": "ttp_start",
                "sample_id": request["recipe_id"],
                "run_id": "sample-run",
                "ph_id": "PH-PE01",
                "atom_id": "atom.pe.uac_sxsconsent",
                "stage": "execute",
            },
            {
                "schema_version": "edreval-sample-log-v1",
                "event": "ttp_result",
                "sample_id": request["recipe_id"],
                "run_id": "sample-run",
                "ph_id": "PH-PE01",
                "atom_id": "atom.pe.uac_sxsconsent",
                "stage": "execute",
                "success": self.log_success,
                "result_code": 0,
                "win32_error": 0,
            },
            {
                "schema_version": "edreval-sample-log-v1",
                "event": "sample_result",
                "sample_id": request["recipe_id"],
                "run_id": "sample-run",
                "success": self.log_success,
                "result_code": 0,
            },
        ]
        log_path.write_text(
            "\n".join(json.dumps(item) for item in events) + "\n",
            encoding="utf-8",
        )
        result = {
            "schema_version": "factory-vmware-guest-result-v1",
            "run_id": "vm-run-1",
            "process_created": True,
            "process_id": 1234,
            "exit_code": 0,
            "timed_out": False,
            "error": None,
            "remote_artifact_path": remote_path,
            "remote_artifact_sha256": request["artifact_sha256"],
            "started_at_utc": "2026-09-03T00:00:00Z",
            "finished_at_utc": "2026-09-03T00:00:01Z",
            "sample_log_paths": [f"sample-logs/{log_name}"],
            "sysmon_events": [
                {
                    "event_id": 13,
                    "record_id": 99,
                    "timestamp_utc": "2026-09-03T00:00:00.500Z",
                    "data": {"ProcessId": "1234"},
                }
            ],
        }
        Path(request["result_path"]).write_text(json.dumps(result), encoding="utf-8")
        return 0, "guest result written"


def _recipe() -> SampleRecipe:
    return SampleRecipe(
        recipe_id="sf-vmware-test",
        execution_atoms=("atom.pe.uac_sxsconsent",),
        delivery=DeliveryMode.MOTW_STAMPED,
        trigger_mode=TriggerMode.LAB_TRIGGER,
        ph_ids=("PH-PE01",),
        evasion_tier="E1",
        execution_logging=True,
    )


def _vmrun_command(argv: list[str]) -> str:
    if len(argv) >= 6 and argv[3] == "-vp":
        return argv[5]
    return argv[3]


def _context(
    *,
    no_edr: bool = True,
    high_risk: bool = False,
    rollback_capable: bool = True,
    profile_id: str = "win11-sysmon15-no-edr",
) -> FactoryPlanningContext:
    return FactoryPlanningContext(
        candidate_ph_ids=("PH-PE01",),
        required_ph_ids=("PH-PE01",),
        production_policy=ProductionPolicy.BASELINE,
        profile=ProductionProfile(
            profile_id=profile_id,
            security_product_enabled=False,
            high_risk_enabled=high_risk,
            isolated=False,
            rollback_capable=rollback_capable,
            no_edr_control=no_edr,
            sensors_ready=True,
        ),
        delivery=DeliveryMode.MOTW_STAMPED,
        trigger_mode=TriggerMode.LAB_TRIGGER,
        seed=42,
    )


class VmwareVerificationTest(unittest.TestCase):
    def _fixture(
        self,
        root: Path,
        *,
        declared_no_edr: bool = True,
        allow_nat: bool = True,
        vmrun_runner: _VmrunRunner | None = None,
        guest_runner: _GuestRunner | None = None,
        caption: str = "Microsoft Windows 11 Pro",
        encrypted: bool = True,
        profile_id: str = "win11-sysmon15-no-edr",
    ) -> tuple[VmwareVerificationBackend, BuiltSample, _VmrunRunner, _GuestRunner]:
        files = {
            "vmrun.exe": b"fake",
            "guest.ps1": b"# fake",
            "winrm.cer": b"fake-public-certificate",
        }
        for name, content in files.items():
            (root / name).write_bytes(content)
        artifact_path = root / "sample.exe"
        artifact_path.write_bytes(b"compiled-sample")
        artifact_sha = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        profile = {
            "schema_version": "edreval-factory-vm-bootstrap-v1",
            "host_name": "WIN11",
            "vm_dns_name": "new-dev.edreval.lab",
            "os": {
                "caption": caption,
                "architecture": "64-bit",
            },
            "network": {
                "declared_mode": "nat",
                "vm_ip": "192.168.131.139",
                "isolated": False,
            },
            "management": {
                "runner_user": "edreval_runner",
                "winrm_https_port": 5986,
                "allow_unencrypted": False,
                "basic_auth": False,
                "certificate": {"thumbprint": "A" * 40},
            },
            "services": {},
            "security_product": {"declared_no_edr": declared_no_edr},
            "directories": {
                "runs": r"C:\ProgramData\EdrEvalAgent\Runs",
                "sample_logs": r"C:\ProgramData\EdrEvalAgent\SampleLogs",
            },
            "readiness": {
                "guest_management_ready": True,
                "vmware_tools_ready": True,
                "sensors_ready": True,
            },
        }
        profile_path = root / "profile.json"
        profile_path.write_text(json.dumps(profile), encoding="utf-8")
        vmx_path = root / "sample.vmx"
        vmx_path.write_text("fake", encoding="utf-8")
        contracts_path = root / "contracts.json"
        contracts_path.write_text(
            json.dumps(
                {
                    "contracts": [
                        {
                            "atom_id": "atom.pe.uac_sxsconsent",
                            "assertions": [
                                {
                                    "kind": "positive",
                                    "match_fields": {
                                        "event_id": 13,
                                        "technique": "T1548.002",
                                    },
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        secret_root = root / "secrets"
        (secret_root / "vmware").mkdir(parents=True)
        (secret_root / "winrm").mkdir(parents=True)
        (secret_root / "vmware" / "vm-password").write_text("synthetic-vm-secret", encoding="utf-8")
        (secret_root / "winrm" / "guest-password").write_text(
            "synthetic-guest-secret", encoding="utf-8"
        )
        runtime_root = root / "runtime"
        (
            runtime_root
            / "runs"
            / "2026"
            / "09"
            / "04"
            / "run-12345678"
            / "attempts"
            / "0001-attempt-12345678"
            / "verification"
        ).mkdir(parents=True)
        settings = VmwareVerificationSettings(
            schema_version="factory-vmware-verification-v2",
            profile_id=profile_id,
            vmrun_path=root / "vmrun.exe",
            vmx_path=vmx_path,
            snapshot_name="new_dev",
            vm_encryption_password_ref=(
                "lab-secret://vmware/vm-password" if encrypted else None
            ),
            vm_profile_path=profile_path,
            winrm_certificate_path=root / "winrm.cer",
            guest_password_ref="lab-secret://winrm/guest-password",
            runtime_root=runtime_root,
            allow_nat=allow_nat,
            startup_timeout_s=1,
            poll_interval_s=0.01,
        )
        hypervisor = vmrun_runner or _VmrunRunner()
        guest = guest_runner or _GuestRunner()
        backend = VmwareVerificationBackend(
            settings,
            secrets=SecretResolver(secret_root),
            artifact_resolver=_ArtifactResolver(artifact_path),
            telemetry_contracts_path=contracts_path,
            driver_path=root / "guest.ps1",
            vmrun_runner=hypervisor,
            guest_runner=guest,
        )
        backend._assert_host_winrm_client = lambda: None  # type: ignore[method-assign]
        artifact = BuiltSample(
            artifact_ref="build-artifact://vmware-test",
            artifact_sha256=artifact_sha,
            source_digest="a" * 64,
            toolchain_fp="msvc-test@pinned",
            build_id="build-vmware-test",
            factory_run_id="run-12345678",
            factory_attempt_id="attempt-12345678",
        )
        return backend, artifact, hypervisor, guest

    def test_collect_reverts_runs_collects_and_reverts_again(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, artifact, vmrun, guest = self._fixture(Path(tmp))
            with patch.object(backend, "_wait_for_tcp"):
                report = backend.collect(artifact, _recipe(), _context())

            commands = [_vmrun_command(call) for call in vmrun.calls]
            self.assertEqual(
                [
                    "listSnapshots",
                    "stop",
                    "revertToSnapshot",
                    "start",
                    "stop",
                    "revertToSnapshot",
                ],
                commands,
            )
            self.assertTrue(report.process_created)
            self.assertEqual(0, report.exit_code)
            self.assertEqual("T1548.002", report.telemetry.events[0].fields["technique"])
            self.assertIn("image", report.telemetry.events[0].fields)
            self.assertIn("source_image", report.telemetry.events[0].fields)
            self.assertFalse(report.telemetry.baseline_collected)
            self.assertEqual("synthetic-guest-secret", guest.calls[0][1])
            self.assertNotIn(
                "synthetic-guest-secret",
                " ".join(guest.calls[0][0]),
            )
            summaries = list((Path(tmp) / "runtime").rglob("sample-log-summary.json"))
            self.assertEqual(1, len(summaries))
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            self.assertTrue(summary["self_report_only"])

            truth = FunctionalTruthEvaluator().evaluate(
                _recipe(),
                (_uac_atom_spec(),),
                (),
                _context().profile,
                report,
                built_sha256=artifact.artifact_sha256,
            )
            self.assertTrue(truth.success)
            self.assertTrue(truth.v1_passed)
            self.assertFalse(truth.v3_passed)

    def test_plugin_artifact_reuses_snapshot_channel_without_sample_run_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, artifact, vmrun, guest = self._fixture(Path(tmp))
            evidence = Path(tmp) / "runtime" / "plugin-runs" / "plugin-run-12345678" / "verification" / "vm"
            with patch.object(backend, "_wait_for_tcp"):
                result, evidence_path = backend.execute_plugin_artifact(
                    artifact_path=Path(tmp) / "sample.exe",
                    artifact_sha256=artifact.artifact_sha256,
                    recipe=_recipe().model_copy(update={"execution_logging": False}),
                    context=_context(),
                    evidence_dir=evidence,
                    guest_artifact_name="EarlyApcInjectionHarness.exe",
                )

            self.assertTrue(result.process_created)
            self.assertEqual(evidence.resolve(), evidence_path)
            request_path = evidence / "guest-request.json"
            request = json.loads(request_path.read_text(encoding="utf-8"))
            self.assertEqual("EarlyApcInjectionHarness.exe", request["guest_artifact_name"])
            self.assertEqual(
                [
                    r"C:\ProgramData\EdrEvalAgent\Runs",
                    r"C:\ProgramData\EdrEvalAgent\SampleLogs",
                ],
                request["related_path_prefixes"],
            )
            self.assertEqual([], request["related_image_suffixes"])
            self.assertNotIn("sysmon_event_ids", request)
            self.assertEqual("synthetic-guest-secret", guest.calls[0][1])
            self.assertEqual(
                ["listSnapshots", "stop", "revertToSnapshot", "start", "stop", "revertToSnapshot"],
                [_vmrun_command(call) for call in vmrun.calls],
            )

    def test_plugin_guest_request_keeps_seclogon_cmd_image_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, artifact, _, _ = self._fixture(Path(tmp))
            evidence = (
                Path(tmp)
                / "runtime"
                / "plugin-runs"
                / "plugin-run-seclogon"
                / "verification"
                / "vm"
            )
            recipe = _recipe().model_copy(
                update={
                    "execution_atoms": ("atom.ex.seclogon_spoof",),
                    "ph_ids": ("PH-PE05",),
                    "execution_logging": False,
                }
            )
            with patch.object(backend, "_wait_for_tcp"):
                backend.execute_plugin_artifact(
                    artifact_path=Path(tmp) / "sample.exe",
                    artifact_sha256=artifact.artifact_sha256,
                    recipe=recipe,
                    context=_context(),
                    evidence_dir=evidence,
                    guest_artifact_name="SeclogonSpoofingHarness.exe",
                )

            request = json.loads((evidence / "guest-request.json").read_text(encoding="utf-8"))
            self.assertEqual([r"\cmd.exe"], request["related_image_suffixes"])

    def test_plugin_guest_request_keeps_ps03_taskcache_path_prefixes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, artifact, _, _ = self._fixture(Path(tmp))
            evidence = (
                Path(tmp)
                / "runtime"
                / "plugin-runs"
                / "plugin-run-ps03"
                / "verification"
                / "vm"
            )
            recipe = _recipe().model_copy(
                update={
                    "execution_atoms": ("atom.ps.create_scheduled_task_com",),
                    "ph_ids": ("PH-PS03",),
                    "execution_logging": False,
                }
            )
            with patch.object(backend, "_wait_for_tcp"):
                backend.execute_plugin_artifact(
                    artifact_path=Path(tmp) / "sample.exe",
                    artifact_sha256=artifact.artifact_sha256,
                    recipe=recipe,
                    context=_context(),
                    evidence_dir=evidence,
                    guest_artifact_name="CreateScheduledTaskComHarness.exe",
                )

            request = json.loads((evidence / "guest-request.json").read_text(encoding="utf-8"))
            self.assertEqual(
                [
                    r"C:\ProgramData\EdrEvalAgent\Runs",
                    r"C:\ProgramData\EdrEvalAgent\SampleLogs",
                    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
                    r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
                    r"C:\Windows\System32\Tasks",
                ],
                request["related_path_prefixes"],
            )
            self.assertEqual([], request["related_image_suffixes"])

    def test_collect_uses_factory_run_and_attempt_identity_for_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, artifact, _, _ = self._fixture(Path(tmp))
            artifact = artifact.model_copy(
                update={
                    "factory_run_id": "run-12345678",
                    "factory_attempt_id": "attempt-12345678",
                }
            )
            with patch.object(backend, "_wait_for_tcp"):
                report = backend.collect(artifact, _recipe(), _context())

            evidence_root = (
                Path(tmp)
                / "runtime"
                / "runs"
                / "2026"
                / "09"
                / "04"
                / "run-12345678"
                / "attempts"
                / "0001-attempt-12345678"
                / "verification"
            )
            verification_dirs = list(evidence_root.glob("verification-*"))
            self.assertEqual(1, len(verification_dirs))
            self.assertRegex(verification_dirs[0].name, r"^verification-[0-9a-f]{12}$")
            self.assertTrue(
                report.telemetry.source_ref.startswith(
                    "vmware-evidence://runs/2026/09/04/run-12345678/attempts/"
                    "0001-attempt-12345678/verification/verification-"
                )
            )

    def test_collect_rejects_artifact_without_factory_run_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, artifact, _, _ = self._fixture(Path(tmp))
            artifact = artifact.model_copy(
                update={"factory_run_id": None, "factory_attempt_id": None}
            )

            with self.assertRaisesRegex(VerificationError, "factory_run_id"):
                backend.collect(artifact, _recipe(), _context())

    def test_snapshot_missing_rejected_before_power_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = _VmrunRunner(snapshots=("other",))
            backend, artifact, _, _ = self._fixture(Path(tmp), vmrun_runner=runner)
            with self.assertRaisesRegex(VerificationError, "快照不存在"):
                backend.collect(artifact, _recipe(), _context())
            self.assertEqual(
                ["listSnapshots", "stop", "revertToSnapshot"],
                [_vmrun_command(call) for call in runner.calls],
            )

    def test_nat_requires_explicit_allowance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, artifact, runner, _ = self._fixture(Path(tmp), allow_nat=False)
            with self.assertRaisesRegex(VerificationError, "未显式 allow_nat"):
                backend.collect(artifact, _recipe(), _context())
            self.assertEqual([], runner.calls)

    def test_no_edr_profile_requires_operator_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, artifact, runner, _ = self._fixture(Path(tmp), declared_no_edr=False)
            with self.assertRaisesRegex(VerificationError, "显式 no-commercial-EDR"):
                backend.collect(artifact, _recipe(), _context())
            self.assertEqual([], runner.calls)

    def test_run_profile_must_explicitly_enable_snapshot_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, artifact, runner, _ = self._fixture(Path(tmp))
            with self.assertRaisesRegex(VerificationError, "rollback_capable=true"):
                backend.collect(
                    artifact,
                    _recipe(),
                    _context(rollback_capable=False),
                )
            self.assertEqual([], runner.calls)

    def test_tcp_wait_connects_to_expected_ipv4_and_requires_matching_tls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, _, _, _ = self._fixture(Path(tmp))
            connected: list[tuple[str, int]] = []

            class _Sock:
                def __enter__(self):
                    return self

                def __exit__(self, *args: object) -> None:
                    return None

            class _Tls:
                def __enter__(self):
                    return self

                def __exit__(self, *args: object) -> None:
                    return None

            class _Context:
                hostname = ""
                cadata = ""

                def load_verify_locations(
                    self,
                    *,
                    cafile: str | None = None,
                    capath: str | None = None,
                    cadata: str | bytes | None = None,
                ) -> None:
                    del cafile, capath
                    self.cadata = cadata or ""

                def wrap_socket(self, sock: object, *, server_hostname: str) -> _Tls:
                    del sock
                    self.hostname = server_hostname
                    return _Tls()

            context = _Context()
            cert_path = Path(tmp) / "winrm-server.cer"
            cert_path.write_bytes(b"\x30\x82\x03\x48" + b"\x00" * 8)
            pem = (
                "-----BEGIN CERTIFICATE-----\n"
                "MIIB\n"
                "-----END CERTIFICATE-----\n"
            )
            with (
                patch(
                    "packages.factory_host.vmware_verification.socket.getaddrinfo",
                    return_value=[
                        (2, 1, 6, "", ("192.168.131.139", 5986)),
                    ],
                ),
                patch(
                    "packages.factory_host.vmware_verification.socket.create_connection",
                    side_effect=lambda address, timeout=None: connected.append(address) or _Sock(),
                ),
                patch(
                    "packages.factory_host.vmware_verification.ssl.SSLContext",
                    return_value=context,
                ),
                patch(
                    "packages.factory_host.vmware_verification.ssl.DER_cert_to_PEM_cert",
                    return_value=pem,
                ),
            ):
                backend._wait_for_tcp(
                    "new-dev.edreval.lab",
                    5986,
                    expected_ip="192.168.131.139",
                    certificate_path=cert_path,
                )
            self.assertEqual([("192.168.131.139", 5986)], connected)
            self.assertEqual("new-dev.edreval.lab", context.hostname)
            self.assertEqual(pem, context.cadata)

    def test_winrm_certificate_loader_accepts_der_and_pem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pem = (
                "-----BEGIN CERTIFICATE-----\n"
                "MIIB\n"
                "-----END CERTIFICATE-----\n"
            )
            pem_path = Path(tmp) / "winrm.pem"
            pem_path.write_bytes(pem.encode("ascii"))
            self.assertEqual(pem, VmwareVerificationBackend._winrm_certificate_cadata(pem_path))

            der_path = Path(tmp) / "winrm.cer"
            der_path.write_bytes(b"\x30\x82\x03\x48" + b"\x00" * 8)
            with patch(
                "packages.factory_host.vmware_verification.ssl.DER_cert_to_PEM_cert",
                return_value=pem,
            ) as convert:
                self.assertEqual(
                    pem, VmwareVerificationBackend._winrm_certificate_cadata(der_path)
                )
            convert.assert_called_once()

    def test_host_winrm_client_must_be_running(self) -> None:
        class _Completed:
            def __init__(self, stdout: bytes, returncode: int = 0) -> None:
                self.stdout = stdout
                self.stderr = b""
                self.returncode = returncode

        with patch(
            "packages.factory_host.vmware_verification.subprocess.run",
            return_value=_Completed(b"STATE              : 1  STOPPED\n"),
        ):
            with self.assertRaisesRegex(VerificationError, "宿主机 WinRM 服务未运行"):
                VmwareVerificationBackend._assert_host_winrm_client()
        with patch(
            "packages.factory_host.vmware_verification.subprocess.run",
            return_value=_Completed(b"STATE              : 4  RUNNING\n"),
        ):
            VmwareVerificationBackend._assert_host_winrm_client()

    def test_tcp_wait_rejects_dns_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, _, _, _ = self._fixture(Path(tmp))
            with (
                patch(
                    "packages.factory_host.vmware_verification.socket.getaddrinfo",
                    return_value=[
                        (
                            2,
                            1,
                            6,
                            "",
                            ("192.168.131.140", 5986),
                        )
                    ],
                ),
                self.assertRaisesRegex(VerificationError, "DNS 身份漂移"),
            ):
                backend._wait_for_tcp(
                    "new-dev.edreval.lab",
                    5986,
                    expected_ip="192.168.131.139",
                )

    def test_cleanup_failure_marks_vm_dirty_and_redacts_vm_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = _VmrunRunner(fail_final_revert=True)
            backend, artifact, _, _ = self._fixture(Path(tmp), vmrun_runner=runner)
            with (
                patch.object(backend, "_wait_for_tcp"),
                self.assertRaisesRegex(VerificationError, "实例必须视为 dirty") as ctx,
            ):
                backend.collect(artifact, _recipe(), _context())
            self.assertNotIn("synthetic-vm-secret", str(ctx.exception))
            self.assertIn("[REDACTED]", str(ctx.exception))

    def test_failed_sample_self_report_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, artifact, _, _ = self._fixture(
                Path(tmp), guest_runner=_GuestRunner(log_success=False)
            )
            with (
                patch.object(backend, "_wait_for_tcp"),
                self.assertRaisesRegex(VerificationError, "TTP 自报失败"),
            ):
                backend.collect(artifact, _recipe(), _context())

    def test_settings_reject_plaintext_or_reused_credential(self) -> None:
        with self.assertRaises(ValidationError):
            VmwareVerificationSettings(
                schema_version="factory-vmware-verification-v2",
                profile_id="profile",
                vmrun_path=Path("vmrun"),
                vmx_path=Path("vmx"),
                snapshot_name="new_dev",
                vm_encryption_password_ref="plaintext",
                vm_profile_path=Path("profile"),
                winrm_certificate_path=Path("cert"),
                guest_password_ref="lab-secret://winrm/password",
                runtime_root=Path("runtime"),
            )

    def test_settings_allow_unencrypted_vm(self) -> None:
        settings = VmwareVerificationSettings(
            schema_version="factory-vmware-verification-v2",
            profile_id="win10-21h2-sysmon15-no-edr",
            vmrun_path=Path("vmrun"),
            vmx_path=Path("vmx"),
            snapshot_name="new_dev_win10",
            vm_encryption_password_ref=None,
            vm_profile_path=Path("profile"),
            winrm_certificate_path=Path("cert"),
            guest_password_ref="lab-secret://winrm/new-dev-win10-runner-password",
            runtime_root=Path("runtime"),
        )
        self.assertIsNone(settings.vm_encryption_password_ref)

    def test_windows_client_captions_accept_10_and_11_only(self) -> None:
        self.assertTrue(windows_client_caption_supported("Microsoft Windows 10 专业版"))
        self.assertTrue(windows_client_caption_supported("Microsoft Windows 11 Pro"))
        self.assertFalse(windows_client_caption_supported("Microsoft Windows 7 Professional"))
        self.assertFalse(windows_client_caption_supported("Microsoft Windows Server 2022"))

    def test_collect_accepts_windows_10_caption(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, artifact, _, _ = self._fixture(
                Path(tmp),
                caption="Microsoft Windows 10 专业版",
            )
            with patch.object(backend, "_wait_for_tcp"):
                report = backend.collect(artifact, _recipe(), _context())
            self.assertTrue(report.process_created)

    def test_collect_rejects_unsupported_windows_caption(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, artifact, _, _ = self._fixture(
                Path(tmp),
                caption="Microsoft Windows 7 Professional",
            )
            with self.assertRaisesRegex(VerificationError, "不是 Windows 10/11"):
                backend.collect(artifact, _recipe(), _context())

    def test_unencrypted_vmrun_omits_vp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend, artifact, vmrun, _ = self._fixture(Path(tmp), encrypted=False)
            with patch.object(backend, "_wait_for_tcp"):
                backend.collect(artifact, _recipe(), _context())
            self.assertGreater(len(vmrun.calls), 0)
            for call in vmrun.calls:
                self.assertNotIn("-vp", call)
                self.assertEqual("ws", call[2])
            self.assertEqual(
                [
                    "listSnapshots",
                    "stop",
                    "revertToSnapshot",
                    "start",
                    "stop",
                    "revertToSnapshot",
                ],
                [_vmrun_command(call) for call in vmrun.calls],
            )

    def test_checked_in_win10_verification_config_is_unencrypted(self) -> None:
        settings = VmwareVerificationSettings.load(
            Path("deployment/factory-vmware-verification-win10.json")
        )
        self.assertEqual("win10-21h2-sysmon15-no-edr", settings.profile_id)
        self.assertEqual("new_dev_win10", settings.snapshot_name)
        self.assertIsNone(settings.vm_encryption_password_ref)
        self.assertEqual(
            Path(r"E:\Win10_21H2\Win10_21H2.vmx"),
            settings.vmx_path,
        )
        self.assertEqual(
            "lab-secret://winrm/new-dev-win10-runner-password",
            settings.guest_password_ref,
        )

    def test_guest_result_rejects_session_zero(self) -> None:
        with self.assertRaisesRegex(ValidationError, "交互桌面会话"):
            GuestExecutionResult(
                schema_version="factory-vmware-guest-result-v1",
                run_id="vm-run-1",
                process_created=True,
                process_id=1234,
                session_id=0,
                exit_code=0,
                remote_artifact_path=r"C:\ProgramData\EdrEvalAgent\Runs\x\harness.exe",
                remote_artifact_sha256="a" * 64,
                started_at_utc="2026-09-09T00:00:00Z",
                finished_at_utc="2026-09-09T00:00:01Z",
            )

    def test_vmrun_error_redacts_encryption_password(self) -> None:
        class FailingRunner:
            def run(self, argv: list[str], *, timeout: float | None = None) -> tuple[int, str]:
                del timeout
                return 1, f"failure echoed {argv[4]}"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = VmwareVerificationSettings(
                schema_version="factory-vmware-verification-v2",
                profile_id="profile",
                vmrun_path=root / "vmrun.exe",
                vmx_path=root / "vm.vmx",
                snapshot_name="new_dev",
                vm_encryption_password_ref="lab-secret://vmware/password",
                vm_profile_path=root / "profile.json",
                winrm_certificate_path=root / "cert.cer",
                guest_password_ref="lab-secret://winrm/password",
                runtime_root=root / "runtime",
            )
            controller = VmrunController(settings, runner=FailingRunner())
            with self.assertRaises(VerificationError) as ctx:
                controller.list_snapshots("synthetic-secret")
            self.assertNotIn("synthetic-secret", str(ctx.exception))
            self.assertIn("[REDACTED]", str(ctx.exception))

    def test_vmrun_power_idempotency_accepts_localized_status(self) -> None:
        class LocalizedRunner:
            def run(self, argv: list[str], *, timeout: float | None = None) -> tuple[int, str]:
                del timeout
                if argv[5] == "stop":
                    return 1, "错误：虚拟机未启动"
                return 1, "错误：虚拟机已启动"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = VmwareVerificationSettings(
                schema_version="factory-vmware-verification-v2",
                profile_id="profile",
                vmrun_path=root / "vmrun.exe",
                vmx_path=root / "vm.vmx",
                snapshot_name="new_dev",
                vm_encryption_password_ref="lab-secret://vmware/password",
                vm_profile_path=root / "profile.json",
                winrm_certificate_path=root / "cert.cer",
                guest_password_ref="lab-secret://winrm/password",
                runtime_root=root / "runtime",
            )
            controller = VmrunController(settings, runner=LocalizedRunner())
            controller.stop_hard("synthetic-secret")
            controller.start("synthetic-secret")

    def test_sample_log_evidence_accepts_elevated_child_covering_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp)
            log_dir = evidence / "sample-logs"
            log_dir.mkdir()
            remote = r"C:\ProgramData\EdrEvalAgent\Runs\run-1\PluginValidationHarness.exe"
            recipe = _recipe()
            parent = {
                "schema_version": "edreval-sample-log-v1",
                "event": "sample_start",
                "sample_id": recipe.recipe_id,
                "recipe_id": recipe.recipe_id,
                "run_id": "parent-1",
                "image_path": remote,
                "ph_ids": list(recipe.ph_ids),
                "atom_ids": list(recipe.atom_ids),
            }
            (log_dir / "parent.jsonl").write_text(
                "\n".join(
                    json.dumps(item)
                    for item in (
                        parent,
                        {
                            "schema_version": "edreval-sample-log-v1",
                            "event": "sample_result",
                            "sample_id": recipe.recipe_id,
                            "run_id": "parent-1",
                            "success": True,
                            "result_code": 0,
                        },
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            child_events = [
                {
                    **parent,
                    "run_id": "child-2",
                },
                {
                    "schema_version": "edreval-sample-log-v1",
                    "event": "ttp_start",
                    "sample_id": recipe.recipe_id,
                    "run_id": "child-2",
                    "ph_id": "PH-PE01",
                    "atom_id": "atom.pe.uac_sxsconsent",
                    "stage": "execute",
                },
                {
                    "schema_version": "edreval-sample-log-v1",
                    "event": "ttp_result",
                    "sample_id": recipe.recipe_id,
                    "run_id": "child-2",
                    "ph_id": "PH-PE01",
                    "atom_id": "atom.pe.uac_sxsconsent",
                    "stage": "execute",
                    "success": True,
                    "result_code": 0,
                    "win32_error": 0,
                },
                {
                    "schema_version": "edreval-sample-log-v1",
                    "event": "sample_result",
                    "sample_id": recipe.recipe_id,
                    "run_id": "child-2",
                    "success": True,
                    "result_code": 0,
                },
            ]
            (log_dir / "child.jsonl").write_text(
                "\n".join(json.dumps(item) for item in child_events) + "\n",
                encoding="utf-8",
            )
            summary = _validate_sample_log_evidence(
                evidence,
                ("sample-logs/parent.jsonl", "sample-logs/child.jsonl"),
                recipe,
                remote_artifact_path=remote,
                process_exit_code=0,
            )
            self.assertEqual("child-2", summary["run_id"])
            self.assertEqual(2, summary["candidate_count"])
            nonzero = _validate_sample_log_evidence(
                evidence,
                ("sample-logs/parent.jsonl", "sample-logs/child.jsonl"),
                recipe,
                remote_artifact_path=remote,
                process_exit_code=1,
            )
            self.assertEqual("child-2", nonzero["run_id"])
            self.assertTrue(nonzero["elevated_child_covered_nonzero_parent_exit"])
            with self.assertRaises(VerificationError):
                _validate_sample_log_evidence(
                    evidence,
                    (),
                    recipe,
                    remote_artifact_path=remote,
                    process_exit_code=0,
                )


def _uac_atom_spec():
    from packages.sample_factory.models import (
        AtomRole,
        AtomSpec,
        IntegrationState,
        SafetyProfile,
    )

    return AtomSpec(
        atom_id="atom.pe.uac_sxsconsent",
        role=AtomRole.EXECUTION_ATOM,
        integration_state=IntegrationState.IMPLEMENTED,
        ph_ids=("PH-PE01",),
        attck_ids=("T1548.002",),
        variant_family="privesc",
        inputs_schema_ref="schema://uac",
        output_contract="exe",
        verification_profile="standard",
        safety_profile=SafetyProfile.LOW,
        trigger_modes=(TriggerMode.LAB_TRIGGER,),
        requires_implant=False,
        telemetry_contract_ref=None,
    )


if __name__ == "__main__":
    unittest.main()
