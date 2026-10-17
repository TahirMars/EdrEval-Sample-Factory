"""VMware Workstation single-VM verification backend.

The hypervisor and guest channel are separate. vmrun owns snapshot and power
operations. A fixed PowerShell driver owns WinRM HTTPS transfer and evidence
collection; Harness execution is delegated to an interactive console worker
(Session > 0, filtered local administrator, medium integrity). Secrets never
enter events or diagnostics.
"""

from __future__ import annotations

import errno
import hashlib
import importlib
import ipaddress
import json
import locale
import os
import re
import socket
import ssl
import subprocess
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from os import open as open_descriptor
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from packages.config.resolver import SecretResolver
from packages.config.secrets_env import SecretsEnv
from packages.labmgr.process import ProcessRunner
from packages.sample_factory.errors import VerificationError
from packages.sample_factory.plugin_harness_oracles import (
    related_sysmon_image_suffixes,
    related_sysmon_path_prefixes,
)
from packages.sample_factory.models import (
    BuiltSample,
    FactoryPlanningContext,
    RawVerificationReport,
    SampleRecipe,
    TelemetryBundle,
    TelemetryEvent,
)

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SECRET_REF_RE = re.compile(r"^lab-secret://[a-z0-9][a-z0-9-]*/[A-Za-z0-9_][A-Za-z0-9._-]*$")


def windows_client_caption_supported(caption: str) -> bool:
    """Factory validation guests are 64-bit Windows 10 or Windows 11 clients."""
    folded = caption.casefold()
    return "windows 10" in folded or "windows 11" in folded


_PROFILE_SCHEMA = "edreval-factory-vm-bootstrap-v1"
_SYS_MON_LOG = "Microsoft-Windows-Sysmon/Operational"


class ArtifactResolver(Protocol):
    def resolve_artifact(self, artifact_ref: str) -> Path: ...


class SecretStdinRunner(Protocol):
    def run(
        self,
        argv: list[str],
        *,
        stdin_text: str,
        timeout: float | None = None,
    ) -> tuple[int, str]: ...


class SubprocessSecretStdinRunner:
    """Run a fixed command with a secret on stdin, never in argv."""

    def run(
        self,
        argv: list[str],
        *,
        stdin_text: str,
        timeout: float | None = None,
    ) -> tuple[int, str]:
        proc = subprocess.run(
            argv,
            input=stdin_text.encode("utf-8"),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        output = (proc.stdout + b"\n" + proc.stderr).decode("utf-8", errors="replace")
        return proc.returncode, output


class VmrunSubprocessRunner:
    """Decode localized vmrun output with the host's active Windows code page."""

    def run(self, argv: list[str], *, timeout: float | None = None) -> tuple[int, str]:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        encoding = locale.getpreferredencoding(False)
        output = (proc.stdout + b"\n" + proc.stderr).decode(encoding, errors="replace")
        return proc.returncode, output


class VmwareVerificationSettings(BaseModel):
    """Non-secret configuration for one VMware Workstation verification VM."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["factory-vmware-verification-v2"]
    profile_id: str = Field(min_length=1)
    vmrun_path: Path
    vmx_path: Path
    snapshot_name: str = Field(min_length=1)
    vm_encryption_password_ref: str | None = None
    vm_profile_path: Path
    winrm_certificate_path: Path
    guest_password_ref: str
    runtime_root: Path
    guest_artifact_name: str = "sample.exe"
    allow_nat: bool = False
    startup_timeout_s: float = Field(default=180.0, gt=0, le=1800)
    execution_timeout_s: float = Field(default=120.0, gt=0, le=3600)
    settle_timeout_s: float = Field(default=3.0, ge=0, le=60)
    lock_timeout_s: float = Field(default=30.0, gt=0, le=600)
    poll_interval_s: float = Field(default=2.0, gt=0, le=30)
    max_sysmon_events: int = Field(default=512, ge=1, le=10000)

    @field_validator("snapshot_name", "guest_artifact_name")
    @classmethod
    def _safe_names(cls, value: str) -> str:
        if not _SAFE_NAME_RE.fullmatch(value):
            raise ValueError("snapshot_name/guest_artifact_name 含非法字符")
        return value

    @field_validator("guest_password_ref")
    @classmethod
    def _guest_secret_ref(cls, value: str) -> str:
        if not _SECRET_REF_RE.fullmatch(value):
            raise ValueError("VM 凭据必须使用 lab-secret://<type>/<name> 引用")
        return value

    @field_validator("vm_encryption_password_ref")
    @classmethod
    def _optional_encryption_secret_ref(cls, value: str | None) -> str | None:
        if value is None or value.strip() == "":
            return None
        if not _SECRET_REF_RE.fullmatch(value):
            raise ValueError("VM 凭据必须使用 lab-secret://<type>/<name> 引用")
        return value

    @model_validator(mode="after")
    def _settings_invariants(self) -> VmwareVerificationSettings:
        if self.vm_encryption_password_ref == self.guest_password_ref:
            raise ValueError("VM 加密口令与 guest 登录口令必须使用不同 secret 引用")
        if self.guest_artifact_name.lower().endswith(".part"):
            raise ValueError("guest_artifact_name 不得使用 .part 后缀")
        return self

    @classmethod
    def load(cls, path: str | Path) -> VmwareVerificationSettings:
        source = Path(path).resolve()
        if not source.is_file():
            raise VerificationError(f"VMware 验证配置不存在：{source}")
        try:
            value = json.loads(source.read_text(encoding="utf-8"))
            settings = cls.model_validate(value)
        except Exception as exc:
            raise VerificationError(f"VMware 验证配置非法：{source}: {exc}") from exc
        base = source.parent
        fields = (
            "vmrun_path",
            "vmx_path",
            "vm_profile_path",
            "winrm_certificate_path",
            "runtime_root",
        )
        updates = {
            field: (value if value.is_absolute() else base / value).resolve()
            for field in fields
            if (value := getattr(settings, field)) is not None
        }
        return settings.model_copy(update=updates)


class VmProfile(BaseModel):
    """Subset of the guest bootstrap report required by the verifier."""

    model_config = ConfigDict(extra="allow", frozen=True)

    schema_version: str
    host_name: str = Field(min_length=1)
    vm_dns_name: str = Field(min_length=1)
    os: dict[str, Any]
    network: dict[str, Any]
    management: dict[str, Any]
    services: dict[str, Any]
    security_product: dict[str, Any]
    directories: dict[str, Any]
    readiness: dict[str, Any]

    @classmethod
    def load(cls, path: Path) -> VmProfile:
        if not path.is_file():
            raise VerificationError(f"VM profile 不存在：{path}")
        try:
            value = json.loads(path.read_bytes().decode("utf-8-sig"))
            profile = cls.model_validate(value)
        except Exception as exc:
            raise VerificationError(f"VM profile 非法：{path}: {exc}") from exc
        if profile.schema_version != _PROFILE_SCHEMA:
            raise VerificationError(f"不支持的 VM profile schema：{profile.schema_version}")
        return profile


class GuestExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["factory-vmware-guest-result-v1"]
    run_id: str = Field(min_length=1)
    process_created: bool
    process_id: int | None = None
    session_id: int | None = None
    exit_code: int | None = None
    timed_out: bool = False
    error: str | None = None
    remote_artifact_path: str = Field(min_length=1)
    remote_artifact_sha256: str
    started_at_utc: str
    finished_at_utc: str
    sample_log_paths: tuple[str, ...] = ()
    sysmon_events: tuple[dict[str, Any], ...] = ()

    @field_validator("remote_artifact_sha256")
    @classmethod
    def _sha256(cls, value: str) -> str:
        normalized = value.lower()
        if not _SHA256_RE.fullmatch(normalized):
            raise ValueError("remote_artifact_sha256 必须是 SHA-256")
        return normalized

    @model_validator(mode="after")
    def _process_shape(self) -> GuestExecutionResult:
        if self.process_created and self.process_id is None:
            raise ValueError("process_created=true 时 process_id 必填")
        if self.timed_out and not self.process_created:
            raise ValueError("timed_out 只能用于已创建进程")
        if self.session_id is not None and self.session_id <= 0:
            raise ValueError("session_id 必须是交互桌面会话")
        return self


class VmrunController:
    """Fixed vmrun command adapter with secret-redacted diagnostics."""

    def __init__(
        self,
        settings: VmwareVerificationSettings,
        *,
        runner: ProcessRunner | None = None,
    ) -> None:
        self._settings = settings
        self._runner = runner or VmrunSubprocessRunner()

    def list_snapshots(self, password: str | None) -> tuple[str, ...]:
        output = self._require_success(
            password, "listSnapshots", str(self._settings.vmx_path), "showTree"
        )
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return tuple(line for line in lines if not line.lower().startswith("total snapshots:"))

    def assert_snapshot(self, password: str | None) -> None:
        snapshots = self.list_snapshots(password)
        if self._settings.snapshot_name not in snapshots:
            raise VerificationError(
                f"VMware 快照不存在：{self._settings.snapshot_name}；已发现 {len(snapshots)} 个快照"
            )

    def stop_hard(self, password: str | None) -> None:
        rc, output = self._invoke(password, "stop", str(self._settings.vmx_path), "hard")
        folded = output.casefold()
        already_stopped = any(
            marker in folded for marker in ("not powered on", "未启动", "未打开电源")
        )
        if rc == 0 or already_stopped:
            return
        raise VerificationError(f"VMware stop 失败：{self._safe_output(output, password)}")

    def revert(
        self,
        password: str | None,
        *,
        attempts: int = 6,
        delay_s: float = 2.0,
    ) -> None:
        """Revert to the configured baseline snapshot.

        VMware Workstation often reports a transient \"file in use\" right after
        ``stop hard`` while vmdk/vmx handles are still releasing; retry instead of
        marking the lab VM permanently dirty.
        """
        if attempts < 1:
            raise ValueError("revert attempts 必须 >= 1")
        last_output = ""
        for attempt in range(1, attempts + 1):
            rc, output = self._invoke(
                password,
                "revertToSnapshot",
                str(self._settings.vmx_path),
                self._settings.snapshot_name,
            )
            if rc == 0:
                # Memory-inclusive snapshots can fail restore after a crashed
                # mks/vmx; keep disk baseline and cold-boot instead.
                self._discard_saved_checkpoint_state()
                return
            last_output = output
            if not self._is_transient_file_in_use(output) or attempt >= attempts:
                break
            # Re-assert power-off before the next revert attempt.
            self.stop_hard(password)
            time.sleep(delay_s)
        raise VerificationError(
            f"VMware revertToSnapshot 失败：{self._safe_output(last_output, password)}"
        )

    def _discard_saved_checkpoint_state(self) -> None:
        vmx_path = self._settings.vmx_path
        if not vmx_path.is_file():
            return
        original = vmx_path.read_text(encoding="utf-8", errors="surrogateescape")
        kept: list[str] = []
        removed = 0
        for line in original.splitlines(keepends=True):
            if line.lstrip().startswith("checkpoint.vmState"):
                removed += 1
                continue
            kept.append(line)
        if removed == 0:
            return
        vmx_path.write_text("".join(kept), encoding="utf-8", errors="surrogateescape")

    @staticmethod
    def _is_transient_file_in_use(output: str) -> bool:
        folded = output.casefold()
        markers = (
            "file is in use",
            "file in use",
            "being used by another process",
            "正在使用",
        )
        return any(marker in folded or marker in output for marker in markers)

    def start(self, password: str | None) -> None:
        rc, output = self._invoke(password, "start", str(self._settings.vmx_path), "nogui")
        folded = output.casefold()
        already_started = any(
            marker in folded for marker in ("already powered on", "已启动", "已打开电源")
        )
        if rc == 0 or already_started:
            return
        raise VerificationError(f"VMware start 失败：{self._safe_output(output, password)}")

    def _require_success(self, password: str | None, *command: str) -> str:
        rc, output = self._invoke(password, *command)
        if rc != 0:
            raise VerificationError(
                f"VMware {command[0]} 失败：{self._safe_output(output, password)}"
            )
        return output

    def _invoke(self, password: str | None, *command: str) -> tuple[int, str]:
        argv = [str(self._settings.vmrun_path), "-T", "ws"]
        if password:
            argv.extend(["-vp", password])
        argv.extend(command)
        return self._runner.run(argv, timeout=self._settings.startup_timeout_s)

    @staticmethod
    def _safe_output(output: str, password: str | None) -> str:
        sanitized = output.replace(password, "[REDACTED]") if password else output
        return sanitized.strip()[-1000:]


class PowerShellGuestChannel:
    """Fixed WinRM driver; guest password crosses the boundary on stdin."""

    def __init__(
        self,
        settings: VmwareVerificationSettings,
        *,
        driver_path: Path,
        runner: SecretStdinRunner | None = None,
    ) -> None:
        self._settings = settings
        self.driver_path = driver_path.resolve()
        self._runner = runner or SubprocessSecretStdinRunner()

    def execute(
        self,
        *,
        password: str,
        artifact_path: Path,
        artifact_sha256: str,
        recipe: SampleRecipe,
        evidence_dir: Path,
        guest_artifact_name: str | None = None,
    ) -> GuestExecutionResult:
        profile = VmProfile.load(self._settings.vm_profile_path)
        request_path = evidence_dir / "guest-request.json"
        result_path = evidence_dir / "guest-result.json"
        request = {
            "schema_version": "factory-vmware-guest-request-v1",
            "vm_dns_name": profile.vm_dns_name,
            "vm_profile_path": str(self._settings.vm_profile_path),
            "winrm_certificate_path": str(self._settings.winrm_certificate_path),
            "runner_user": self._required_profile_value(profile.management, "runner_user"),
            "local_artifact_path": str(artifact_path),
            "artifact_sha256": artifact_sha256,
            "guest_artifact_name": guest_artifact_name or self._settings.guest_artifact_name,
            "remote_runs_root": self._required_profile_value(profile.directories, "runs"),
            "remote_logs_root": self._required_profile_value(profile.directories, "sample_logs"),
            "recipe_id": recipe.recipe_id,
            "expected_ph_ids": list(recipe.ph_ids),
            "expected_atom_ids": list(recipe.atom_ids),
            "execution_logging": recipe.execution_logging,
            "execution_timeout_s": self._settings.execution_timeout_s,
            "settle_timeout_s": self._settings.settle_timeout_s,
            "winrm_open_timeout_s": self._settings.startup_timeout_s,
            "max_sysmon_events": self._settings.max_sysmon_events,
            "related_path_prefixes": list(
                _related_path_prefixes(profile.directories, recipe.atom_ids)
            ),
            "related_image_suffixes": list(related_sysmon_image_suffixes(recipe.atom_ids)),
            "sysmon_log_name": _SYS_MON_LOG,
            "evidence_dir": str(evidence_dir),
            "result_path": str(result_path),
        }
        request_path.write_text(
            json.dumps(request, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        argv = [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "RemoteSigned",
            "-File",
            str(self.driver_path),
            "-RequestPath",
            str(request_path),
        ]
        timeout = (
            self._settings.startup_timeout_s
            + self._settings.execution_timeout_s
            + self._settings.settle_timeout_s
            + 60
        )
        rc, output = self._runner.run(argv, stdin_text=password, timeout=timeout)
        if rc != 0:
            raise VerificationError(
                "WinRM guest driver 失败：" + VmrunController._safe_output(output, password)
            )
        if not result_path.is_file():
            raise VerificationError("WinRM guest driver 未产生结构化结果")
        try:
            return GuestExecutionResult.model_validate_json(
                result_path.read_bytes().decode("utf-8-sig")
            )
        except Exception as exc:
            raise VerificationError(f"WinRM guest result 非法：{exc}") from exc

    @staticmethod
    def _required_profile_value(values: dict[str, Any], key: str) -> str:
        value = str(values.get(key, "")).strip()
        if not value:
            raise VerificationError(f"VM profile 缺少 {key}")
        return value


def _directory_prefixes(directories: dict[str, Any]) -> tuple[str, ...]:
    prefixes: list[str] = []
    seen: set[str] = set()
    for value in directories.values():
        if not isinstance(value, str):
            continue
        normalized = value.replace("/", "\\").strip().rstrip("\\")
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        prefixes.append(normalized)
    return tuple(prefixes)


def _related_path_prefixes(
    directories: dict[str, Any],
    atom_ids: tuple[str, ...] | list[str],
) -> tuple[str, ...]:
    prefixes = list(_directory_prefixes(directories))
    seen = {item.casefold() for item in prefixes}
    for item in related_sysmon_path_prefixes(atom_ids):
        key = item.casefold()
        if key in seen:
            continue
        seen.add(key)
        prefixes.append(item)
    return tuple(prefixes)


class VmwareVerificationBackend:
    """Single-VM snapshot verification with fail-closed evidence semantics."""

    def __init__(
        self,
        settings: VmwareVerificationSettings,
        *,
        secrets: SecretResolver,
        artifact_resolver: ArtifactResolver,
        telemetry_contracts_path: Path | None,
        driver_path: Path,
        vmrun_runner: ProcessRunner | None = None,
        guest_runner: SecretStdinRunner | None = None,
    ) -> None:
        self._settings = settings
        self._secrets = secrets
        self._artifact_resolver = artifact_resolver
        self._telemetry_contracts_path = (
            None if telemetry_contracts_path is None else telemetry_contracts_path.resolve()
        )
        self._controller = VmrunController(settings, runner=vmrun_runner)
        self._guest = PowerShellGuestChannel(
            settings,
            driver_path=driver_path,
            runner=guest_runner,
        )
        self._repo_root = Path(__file__).resolve().parents[2]
        self._validate_static_paths()

    @classmethod
    def from_config(
        cls,
        config_path: str | Path,
        *,
        secrets_env_path: str | Path,
        artifact_resolver: ArtifactResolver,
        telemetry_contracts_path: str | Path | None,
        driver_path: str | Path | None = None,
    ) -> VmwareVerificationBackend:
        settings = VmwareVerificationSettings.load(config_path)
        secrets_env = SecretsEnv.load(secrets_env_path)
        secret_resolver = SecretResolver(secrets_env.secret_store_dir)
        default_driver = (
            Path(__file__).resolve().parents[2] / "scripts" / "run_factory_vm_guest.ps1"
        )
        return cls(
            settings,
            secrets=secret_resolver,
            artifact_resolver=artifact_resolver,
            telemetry_contracts_path=(
                None if telemetry_contracts_path is None else Path(telemetry_contracts_path)
            ),
            driver_path=Path(driver_path) if driver_path is not None else default_driver,
        )

    @property
    def runtime_root(self) -> Path:
        return self._settings.runtime_root

    def preflight(self, context: FactoryPlanningContext) -> dict[str, object]:
        profile = self._validate_profile(context)
        self._assert_host_winrm_client()
        vm_password = self._optional_encryption_password()
        self._resolve_secret(self._settings.guest_password_ref, "VM guest 登录口令")
        self._controller.assert_snapshot(vm_password)
        return {
            "ready": True,
            "profile_id": self._settings.profile_id,
            "vm_dns_name": profile.vm_dns_name,
            "snapshot_name": self._settings.snapshot_name,
            "network_mode": profile.network.get("declared_mode"),
            "isolated": bool(profile.network.get("isolated", False)),
            "winrm_https_port": self._required_winrm_port(profile),
            "runtime_root": self._settings.runtime_root.as_posix(),
        }

    def collect(
        self,
        artifact: BuiltSample,
        recipe: SampleRecipe,
        context: FactoryPlanningContext,
    ) -> RawVerificationReport:
        profile = self._validate_profile(context)
        artifact_path = self._artifact_resolver.resolve_artifact(artifact.artifact_ref).resolve()
        if not artifact_path.is_file():
            raise VerificationError("本轮构建产物不存在，拒绝 VM 投递")
        if _sha256_file(artifact_path) != artifact.artifact_sha256:
            raise VerificationError("VM 投递前产物 SHA-256 与构建回执不一致")

        vm_password = self._optional_encryption_password()
        guest_password = self._resolve_secret(
            self._settings.guest_password_ref, "VM guest 登录口令"
        )
        self._assert_host_winrm_client()
        if artifact.factory_run_id is None or artifact.factory_attempt_id is None:
            raise VerificationError("VM 验证产物缺少 factory_run_id/factory_attempt_id")
        attempt_root = self._resolve_attempt_root(
            artifact.factory_run_id, artifact.factory_attempt_id
        )
        evidence_dir = (
            attempt_root / "verification" / f"verification-{uuid4().hex[:12]}"
        ).resolve()
        if not evidence_dir.is_relative_to(attempt_root):
            raise VerificationError("VM evidence 路径越界")
        evidence_dir.mkdir(parents=True, mode=0o700)

        result: GuestExecutionResult | None = None
        operation_error: Exception | None = None
        cleanup_error: Exception | None = None
        lock_path = self._settings.runtime_root / "locks" / "factory-vmware.lock"
        with _exclusive_file_lock(lock_path, timeout_s=self._settings.lock_timeout_s):
            try:
                self._controller.assert_snapshot(vm_password)
                self._controller.stop_hard(vm_password)
                self._controller.revert(vm_password)
                self._controller.start(vm_password)
                self._wait_for_tcp(
                    profile.vm_dns_name,
                    self._required_winrm_port(profile),
                    expected_ip=str(profile.network["vm_ip"]),
                    certificate_path=self._settings.winrm_certificate_path,
                )
                result = self._guest.execute(
                    password=guest_password,
                    artifact_path=artifact_path,
                    artifact_sha256=artifact.artifact_sha256,
                    recipe=recipe,
                    evidence_dir=evidence_dir,
                )
            except Exception as exc:
                operation_error = exc
            finally:
                try:
                    self._controller.stop_hard(vm_password)
                    self._controller.revert(vm_password)
                except Exception as exc:
                    cleanup_error = exc

        if cleanup_error is not None:
            raise VerificationError(
                f"VM 验证后无法恢复基线快照，实例必须视为 dirty：{cleanup_error}"
            ) from cleanup_error
        if operation_error is not None:
            if isinstance(operation_error, VerificationError):
                raise operation_error
            raise VerificationError(f"VM 验证基础设施失败：{operation_error}") from operation_error
        if result is None:  # pragma: no cover - guarded by invariants above
            raise VerificationError("VM 验证未返回结果")
        if result.remote_artifact_sha256 != artifact.artifact_sha256:
            raise VerificationError("VM 内样本 SHA-256 与本轮构建产物不一致")

        report_exit_code = result.exit_code
        if recipe.execution_logging:
            summary = _validate_sample_log_evidence(
                evidence_dir,
                result.sample_log_paths,
                recipe,
                remote_artifact_path=result.remote_artifact_path,
                process_exit_code=result.exit_code,
            )
            (evidence_dir / "sample-log-summary.json").write_text(
                json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            # UACME parent may time out waiting for elevated-done while the child
            # already covered every PH; treat functional exit as success for truth.
            if summary.get("sample_self_report_succeeded"):
                report_exit_code = 0

        telemetry = self._project_sysmon_events(
            result.sysmon_events,
            recipe,
            run_id=result.run_id,
            evidence_dir=evidence_dir,
        )
        evidence_relative = evidence_dir.relative_to(self._settings.runtime_root).as_posix()
        return RawVerificationReport(
            run_id=result.run_id,
            profile_id=context.profile.profile_id,
            artifact_sha256=artifact.artifact_sha256,
            process_created=result.process_created,
            exit_code=report_exit_code,
            timed_out=result.timed_out,
            crashed=False,
            blocked=False,
            anti_analysis_skipped=False,
            telemetry=TelemetryBundle(
                run_id=result.run_id,
                profile_id=context.profile.profile_id,
                source_ref=f"vmware-evidence://{evidence_relative}",
                baseline_collected=False,
                events=telemetry,
            ),
            effects=(),
        )

    def execute_plugin_artifact(
        self,
        *,
        artifact_path: Path,
        artifact_sha256: str,
        recipe: SampleRecipe,
        context: FactoryPlanningContext,
        evidence_dir: Path,
        guest_artifact_name: str,
    ) -> tuple[GuestExecutionResult, Path]:
        """Execute a linked Plugin Harness EXE through this VM backend.

        Plugin validation uses the same snapshot, WinRM HTTPS management path,
        NAT policy, Sysmon collection, and cleanup path as sample verification.
        The Harness EXE itself is started by the guest interactive desktop
        worker (filtered local administrator, medium integrity, Session > 0),
        not by WinRM Session 0.  Evidence
        stays under the plugin run instead of manufacturing a sample factory
        ``run/attempt`` identity.
        """
        profile = self._validate_profile(context)
        artifact = artifact_path.resolve()
        if not artifact.is_file():
            raise VerificationError("Plugin Harness 链接产物不存在，拒绝 VM 投递")
        if _sha256_file(artifact) != artifact_sha256:
            raise VerificationError("Plugin Harness EXE SHA-256 与链接回执不一致")
        root = evidence_dir.resolve()
        runtime_root = self._settings.runtime_root.resolve()
        if not root.is_relative_to(runtime_root):
            raise VerificationError("Plugin Harness evidence 路径必须位于 runtime_root")
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", guest_artifact_name)
            or not guest_artifact_name.lower().endswith(".exe")
        ):
            raise VerificationError("Plugin Harness guest_artifact_name 含非法字符")
        if artifact.suffix.lower() != ".exe":
            raise VerificationError("Plugin Harness 投递产物必须是最终链接的 .exe")
        root.mkdir(parents=True, mode=0o700, exist_ok=False)
        vm_password = self._optional_encryption_password()
        guest_password = self._resolve_secret(
            self._settings.guest_password_ref, "VM guest 登录口令"
        )
        lock_path = runtime_root / "locks" / "factory-vmware.lock"
        result: GuestExecutionResult | None = None
        operation_error: Exception | None = None
        cleanup_error: Exception | None = None
        self._assert_host_winrm_client()
        with _exclusive_file_lock(lock_path, timeout_s=self._settings.lock_timeout_s):
            try:
                self._controller.assert_snapshot(vm_password)
                self._controller.stop_hard(vm_password)
                self._controller.revert(vm_password)
                self._controller.start(vm_password)
                self._wait_for_tcp(
                    profile.vm_dns_name,
                    self._required_winrm_port(profile),
                    expected_ip=str(profile.network["vm_ip"]),
                    certificate_path=self._settings.winrm_certificate_path,
                )
                result = self._guest.execute(
                    password=guest_password,
                    artifact_path=artifact,
                    artifact_sha256=artifact_sha256,
                    recipe=recipe,
                    evidence_dir=root,
                    guest_artifact_name=guest_artifact_name,
                )
            except Exception as exc:
                operation_error = exc
            finally:
                try:
                    self._controller.stop_hard(vm_password)
                    self._controller.revert(vm_password)
                except Exception as exc:
                    cleanup_error = exc
        if cleanup_error is not None:
            raise VerificationError(
                f"VM Plugin Harness 验证后无法恢复基线快照，实例必须视为 dirty：{cleanup_error}"
            ) from cleanup_error
        if operation_error is not None:
            if isinstance(operation_error, VerificationError):
                raise operation_error
            raise VerificationError(f"VM Plugin Harness 基础设施失败：{operation_error}") from operation_error
        if result is None:  # pragma: no cover - guarded by the operation invariant
            raise VerificationError("VM Plugin Harness 未返回结果")
        if result.remote_artifact_sha256 != artifact_sha256:
            raise VerificationError("VM 内 Harness EXE SHA-256 与链接产物不一致")
        if not result.process_created or result.error:
            detail = result.error or "process_created=false"
            raise VerificationError(f"VM 未能创建 Harness 进程：{detail}")
        if recipe.execution_logging:
            summary = _validate_sample_log_evidence(
                root,
                result.sample_log_paths,
                recipe,
                remote_artifact_path=result.remote_artifact_path,
                process_exit_code=result.exit_code,
            )
            (root / "sample-log-summary.json").write_text(
                json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        return result, root

    def _validate_static_paths(self) -> None:
        required_files = tuple(
            path
            for path in (
                self._settings.vmrun_path,
                self._settings.vmx_path,
                self._settings.vm_profile_path,
                self._settings.winrm_certificate_path,
                self._guest.driver_path,
                self._telemetry_contracts_path,
            )
            if path is not None
        )
        missing = [str(path) for path in required_files if not path.is_file()]
        if missing:
            raise VerificationError("VMware 验证所需文件缺失：" + ", ".join(missing))
        runtime_root = self._settings.runtime_root.resolve()
        if runtime_root.is_relative_to(self._repo_root):
            raise VerificationError("VM runtime 目录不得位于 EdrEvalAgent 代码仓")

    def _resolve_attempt_root(self, run_id: str, attempt_id: str) -> Path:
        if not re.fullmatch(r"run-[a-z0-9-]{8,79}", run_id) or not re.fullmatch(
            r"attempt-[a-z0-9-]{8,79}", attempt_id
        ):
            raise VerificationError("VM 验证 run_id/attempt_id 非法")
        matches = tuple(
            self._settings.runtime_root.glob(
                f"runs/*/*/*/{run_id}/attempts/*-{attempt_id}"
            )
        )
        if len(matches) != 1:
            raise VerificationError(
                f"VM 验证无法解析唯一运行包 attempt：{run_id}/{attempt_id}"
            )
        attempt_root = matches[0].resolve()
        if not attempt_root.is_relative_to(self._settings.runtime_root.resolve()):
            raise VerificationError("VM attempt 路径越界")
        return attempt_root

    def _validate_profile(self, context: FactoryPlanningContext) -> VmProfile:
        profile = VmProfile.load(self._settings.vm_profile_path)
        if context.profile.profile_id != self._settings.profile_id:
            raise VerificationError("运行 profile_id 与 VMware 验证配置不一致")
        if not windows_client_caption_supported(str(profile.os.get("caption", ""))):
            raise VerificationError("VM profile 不是 Windows 10/11")
        if "64" not in str(profile.os.get("architecture", "")):
            raise VerificationError("VM profile 不是 64 位")
        mode = str(profile.network.get("declared_mode", "")).casefold()
        isolated = bool(profile.network.get("isolated", False))
        if mode == "nat" and not self._settings.allow_nat:
            raise VerificationError("VM 使用 NAT，但验证配置未显式 allow_nat")
        if context.profile.isolated != isolated:
            raise VerificationError("运行 isolated 声明与 VM profile 不一致")
        if not context.profile.rollback_capable:
            raise VerificationError("运行 profile 尚未声明 rollback_capable=true")
        if context.profile.high_risk_enabled and not isolated:
            raise VerificationError("高风险样本不得在非隔离 NAT profile 验证")
        if not bool(profile.readiness.get("guest_management_ready", False)):
            raise VerificationError("VM profile 的 guest management 未就绪")
        if not bool(profile.readiness.get("vmware_tools_ready", False)):
            raise VerificationError("VMware Tools 未就绪")
        if context.profile.sensors_ready and not bool(
            profile.readiness.get("sensors_ready", False)
        ):
            raise VerificationError("运行声明 sensors_ready，但 VM profile 传感器未就绪")
        if context.profile.no_edr_control and not bool(
            profile.security_product.get("declared_no_edr", False)
        ):
            raise VerificationError("no-EDR profile 缺少操作员显式 no-commercial-EDR 声明")
        if context.profile.security_product_enabled and bool(
            profile.security_product.get("declared_no_edr", False)
        ):
            raise VerificationError("EDR profile 与 VM 的 no-commercial-EDR 声明冲突")
        if bool(profile.management.get("allow_unencrypted", True)):
            raise VerificationError("VM profile 不得允许未加密 WinRM")
        if bool(profile.management.get("basic_auth", True)):
            raise VerificationError("VM profile 不得启用 WinRM Basic")
        try:
            ipaddress.ip_address(str(profile.network["vm_ip"]))
        except (KeyError, ValueError) as exc:
            raise VerificationError("VM profile 缺少合法 network.vm_ip") from exc
        self._required_winrm_port(profile)
        return profile

    @staticmethod
    def _required_winrm_port(profile: VmProfile) -> int:
        port = profile.management.get("winrm_https_port")
        if not isinstance(port, int) or isinstance(port, bool) or port != 5986:
            raise VerificationError("VM profile WinRM HTTPS 端口必须为 5986")
        return port

    @staticmethod
    def _assert_host_winrm_client() -> None:
        completed = subprocess.run(
            ["sc.exe", "query", "WinRM"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        encoding = locale.getpreferredencoding(False)
        output = (completed.stdout + completed.stderr).decode(encoding, errors="replace")
        if completed.returncode != 0 or not re.search(
            r"STATE\s*:\s*4\b", output, re.IGNORECASE
        ):
            raise VerificationError(
                "宿主机 WinRM 服务未运行。New-PSSession 依赖本机 WinRM 客户端堆栈；"
                "请用管理员 PowerShell 执行 Start-Service WinRM。"
                "不要运行 winrm quickconfig（会打开 HTTP 5985）。"
            )

    def _optional_encryption_password(self) -> str | None:
        if self._settings.vm_encryption_password_ref is None:
            return None
        return self._resolve_secret(
            self._settings.vm_encryption_password_ref, "VMware VM 加密口令"
        )

    def _resolve_secret(self, ref: str, label: str) -> str:
        value = self._secrets.resolve(ref)
        if not value or "\r" in value or "\n" in value:
            raise VerificationError(f"{label} 为空或含换行；secret 文件必须保存精确单行值")
        return value

    def _wait_for_tcp(
        self,
        host: str,
        port: int,
        *,
        expected_ip: str,
        certificate_path: Path | None = None,
    ) -> None:
        deadline = time.monotonic() + self._settings.startup_timeout_s
        last_error = ""
        tls_context: ssl.SSLContext | None = None
        if certificate_path is not None:
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls_context.check_hostname = True
            tls_context.verify_mode = ssl.CERT_REQUIRED
            tls_context.load_verify_locations(
                cadata=self._winrm_certificate_cadata(certificate_path)
            )
        while time.monotonic() < deadline:
            try:
                addresses = {
                    item[4][0]
                    for item in socket.getaddrinfo(
                        host, port, family=socket.AF_INET, type=socket.SOCK_STREAM
                    )
                }
                if expected_ip not in addresses:
                    raise VerificationError(
                        f"VM DNS 身份漂移：{host} -> {sorted(addresses)}，期望 {expected_ip}"
                    )
                with socket.create_connection((expected_ip, port), timeout=3) as sock:
                    if tls_context is None:
                        return
                    with tls_context.wrap_socket(sock, server_hostname=host):
                        return
            except VerificationError:
                raise
            except (OSError, ssl.SSLError) as exc:
                last_error = str(exc)
                time.sleep(self._settings.poll_interval_s)
        kind = "HTTPS TLS" if tls_context is not None else "HTTPS"
        raise VerificationError(f"VM WinRM {kind} 未在时限内就绪：{host}:{port}: {last_error}")

    @staticmethod
    def _winrm_certificate_cadata(certificate_path: Path) -> str:
        if not certificate_path.is_file():
            raise VerificationError(f"WinRM 证书不存在：{certificate_path}")
        raw = certificate_path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        if not raw:
            raise VerificationError(f"WinRM 证书为空：{certificate_path}")
        if b"-----BEGIN CERTIFICATE-----" in raw:
            try:
                return raw.decode("ascii")
            except UnicodeDecodeError as exc:
                raise VerificationError(
                    f"WinRM PEM 证书不是 ASCII：{certificate_path}"
                ) from exc
        try:
            return ssl.DER_cert_to_PEM_cert(raw)
        except ssl.SSLError as exc:
            raise VerificationError(
                f"WinRM 证书无法解析为 X.509（需要 DER 或 PEM）：{certificate_path}: {exc}"
            ) from exc

    def _project_sysmon_events(
        self,
        raw_events: tuple[dict[str, Any], ...],
        recipe: SampleRecipe,
        *,
        run_id: str,
        evidence_dir: Path,
    ) -> tuple[TelemetryEvent, ...]:
        if self._telemetry_contracts_path is None:
            raise VerificationError("样本验证缺少 telemetry_contracts_path")
        expectations = _telemetry_expectations(self._telemetry_contracts_path, recipe.atom_ids)
        image_by_pid = _sysmon_image_by_process_id(raw_events)
        projected: list[TelemetryEvent] = []
        for raw in raw_events:
            event_id = raw.get("event_id")
            if not isinstance(event_id, int) or isinstance(event_id, bool):
                continue
            data = raw.get("data")
            fields_data = data if isinstance(data, dict) else {}
            image = str(fields_data.get("Image") or "")
            # ProcessTampering (EID25) often reports "<unknown process>" after the
            # image is replaced; recover the original Image from EID1 by ProcessId.
            if event_id == 25 and (
                not image or image.casefold() in {"<unknown process>", "unknown"}
            ):
                pid = _sysmon_process_id(fields_data)
                if pid is not None and pid in image_by_pid:
                    image = image_by_pid[pid]
            for atom_id, technique in expectations.get(event_id, ()):
                projected.append(
                    TelemetryEvent(
                        run_id=run_id,
                        fields={
                            "event_id": event_id,
                            "technique": technique,
                            "atom_id": atom_id,
                            "record_id": raw.get("record_id"),
                            "timestamp_utc": raw.get("timestamp_utc"),
                            # 供 TelemetryMatcher 的 *_endswith / *_contains 语义算子使用
                            "image": image,
                            "parent_image": str(fields_data.get("ParentImage") or ""),
                            "source_image": str(fields_data.get("SourceImage") or ""),
                            "target_image": str(fields_data.get("TargetImage") or ""),
                            "target_object": str(fields_data.get("TargetObject") or ""),
                            "target_filename": str(fields_data.get("TargetFilename") or ""),
                            "command_line": str(fields_data.get("CommandLine") or ""),
                        },
                    )
                )
        (evidence_dir / "telemetry-projection.json").write_text(
            json.dumps(
                [item.model_dump(mode="json") for item in projected],
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return tuple(projected)


def create_vmware_verification_backend(
    *,
    config_path: str | Path,
    secrets_env_path: str | Path,
    artifact_resolver: ArtifactResolver,
    telemetry_contracts_path: str | Path,
) -> VmwareVerificationBackend:
    return VmwareVerificationBackend.from_config(
        config_path,
        secrets_env_path=secrets_env_path,
        artifact_resolver=artifact_resolver,
        telemetry_contracts_path=telemetry_contracts_path,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sysmon_process_id(fields_data: Mapping[str, Any]) -> int | None:
    raw = fields_data.get("ProcessId")
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw > 0 else None
    if isinstance(raw, str) and raw.strip().isdigit():
        value = int(raw.strip())
        return value if value > 0 else None
    return None


def _sysmon_image_by_process_id(
    raw_events: tuple[dict[str, Any], ...],
) -> dict[int, str]:
    """Map ProcessId → Image from process-create (EID1) events."""
    images: dict[int, str] = {}
    for raw in raw_events:
        if raw.get("event_id") != 1:
            continue
        data = raw.get("data")
        if not isinstance(data, dict):
            continue
        pid = _sysmon_process_id(data)
        image = str(data.get("Image") or "").strip()
        if pid is None or not image or image.casefold() in {"<unknown process>", "unknown"}:
            continue
        images.setdefault(pid, image)
    return images


def _telemetry_expectations(
    path: Path, atom_ids: tuple[str, ...]
) -> dict[int, tuple[tuple[str, str], ...]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        values = raw["contracts"] if isinstance(raw, dict) else raw
        if not isinstance(values, list):
            raise TypeError("contracts 必须是数组")
    except Exception as exc:
        raise VerificationError(f"遥测合同无法读取：{path}: {exc}") from exc
    selected = set(atom_ids)
    result: dict[int, list[tuple[str, str]]] = {}
    for contract in values:
        if not isinstance(contract, dict) or contract.get("atom_id") not in selected:
            continue
        atom_id = str(contract["atom_id"])
        assertions = contract.get("assertions")
        if not isinstance(assertions, list):
            raise VerificationError(f"{atom_id} 遥测合同 assertions 非法")
        for assertion in assertions:
            if not isinstance(assertion, dict) or assertion.get("kind") != "positive":
                continue
            match = assertion.get("match_fields")
            if not isinstance(match, dict):
                continue
            event_id, technique = match.get("event_id"), match.get("technique")
            if (
                isinstance(event_id, int)
                and not isinstance(event_id, bool)
                and isinstance(technique, str)
                and technique
            ):
                result.setdefault(event_id, []).append((atom_id, technique))
    return {key: tuple(values) for key, values in result.items()}


def _decode_sample_log_text(raw: bytes) -> str:
    """Sample logs are UTF-8; Win32 FormatMessage may inject ACP (gb18030) bytes."""
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _validate_one_sample_log_file(
    path: Path,
    recipe: SampleRecipe,
    *,
    remote_artifact_path: str,
) -> dict[str, object]:
    items: list[dict[str, Any]] = []
    for line_number, line in enumerate(_decode_sample_log_text(path.read_bytes()).splitlines(), start=1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise VerificationError(f"SampleLogs 第 {line_number} 行不是合法 JSON") from exc
        if not isinstance(value, dict):
            raise VerificationError(f"SampleLogs 第 {line_number} 行必须是对象")
        if value.get("schema_version") != "edreval-sample-log-v1":
            raise VerificationError(f"SampleLogs 第 {line_number} 行 schema 不支持")
        items.append(value)
    if len(items) < 2 or items[0].get("event") != "sample_start":
        raise VerificationError("SampleLogs 缺少首行 sample_start")
    if items[-1].get("event") != "sample_result":
        raise VerificationError("SampleLogs 缺少末行 sample_result")
    run_ids = {str(item.get("run_id", "")) for item in items}
    if len(run_ids) != 1 or "" in run_ids:
        raise VerificationError("SampleLogs run_id 不唯一或为空")
    start = items[0]
    if start.get("recipe_id") != recipe.recipe_id or start.get("sample_id") != recipe.recipe_id:
        raise VerificationError("SampleLogs recipe/sample 身份与本轮 Recipe 不一致")
    if tuple(start.get("ph_ids") or ()) != recipe.ph_ids:
        raise VerificationError("SampleLogs 声明的 PH 序列与本轮 Recipe 不一致")
    if tuple(start.get("atom_ids") or ()) != recipe.atom_ids:
        raise VerificationError("SampleLogs 声明的 atom 序列与本轮 Recipe 不一致")
    if str(start.get("image_path", "")).casefold() != remote_artifact_path.casefold():
        raise VerificationError("SampleLogs image_path 与本轮 VM 投递路径不一致")

    open_events: dict[tuple[str, str, str], int] = {}
    successful_ph: set[str] = set()
    for index, item in enumerate(items[1:-1], start=1):
        event = item.get("event")
        ph_id = str(item.get("ph_id", ""))
        atom_id = str(item.get("atom_id", ""))
        stage = str(item.get("stage", ""))
        key = (ph_id, atom_id, stage)
        if event == "ttp_start":
            # No-PH capability atoms (e.g. enable_token_privilege) may log empty ph_id.
            if not atom_id or not stage or key in open_events:
                raise VerificationError("SampleLogs ttp_start 身份为空或重复")
            open_events[key] = index
        elif event == "ttp_result":
            if key not in open_events:
                raise VerificationError("SampleLogs ttp_result 缺少对应 ttp_start")
            del open_events[key]
            if item.get("success") is not True:
                raise VerificationError(f"SampleLogs TTP 自报失败：{ph_id or '-'}/{atom_id}")
            if item.get("result_code") != 0 or item.get("win32_error") != 0:
                raise VerificationError(f"SampleLogs TTP 返回码非零：{ph_id or '-'}/{atom_id}")
            if ph_id:
                successful_ph.add(ph_id)
        else:
            raise VerificationError(f"SampleLogs 包含未知事件：{event!r}")
    if open_events:
        raise VerificationError("SampleLogs 存在未闭合的 ttp_start")
    if not set(recipe.ph_ids).issubset(successful_ph):
        missing = sorted(set(recipe.ph_ids) - successful_ph)
        raise VerificationError(f"SampleLogs 未覆盖全部 PH：{missing}")
    final = items[-1]
    if final.get("success") is not True or final.get("result_code") != 0:
        raise VerificationError("SampleLogs sample_result 自报失败")
    return {
        "schema_version": "edreval-sample-log-validation-v1",
        "self_report_only": True,
        "run_id": next(iter(run_ids)),
        "recipe_id": recipe.recipe_id,
        "ph_ids": list(recipe.ph_ids),
        "atom_ids": list(recipe.atom_ids),
        "event_count": len(items),
        "source_relative": path.name,
        "all_ttp_self_reports_succeeded": True,
        "sample_self_report_succeeded": True,
    }


def _validate_sample_log_evidence(
    evidence_dir: Path,
    relative_paths: tuple[str, ...],
    recipe: SampleRecipe,
    *,
    remote_artifact_path: str,
    process_exit_code: int | None,
) -> dict[str, object]:
    # UACME fodhelper self-relaunch writes one JSONL per process (parent + elevated
    # child). Keep every file; PH coverage may live only in the child log when the
    # parent returns early with delegated_to_elevated_process=true.
    # Parent may exit non-zero if the elevated-done event is missed while the child
    # already completed all TTPs — accept covering child logs in that case.
    if not relative_paths:
        raise VerificationError("execution_logging=true 时缺少 SampleLogs JSONL")
    if len(relative_paths) > 8:
        raise VerificationError(
            f"execution_logging=true 时 SampleLogs JSONL 过多：{len(relative_paths)}"
        )
    failures: list[str] = []
    for relative_text in relative_paths:
        relative = Path(relative_text)
        if relative.is_absolute() or ".." in relative.parts or relative.suffix.lower() != ".jsonl":
            failures.append(f"{relative_text}: 证据引用越界或后缀非法")
            continue
        path = (evidence_dir / relative).resolve()
        if not path.is_relative_to(evidence_dir.resolve()) or not path.is_file():
            failures.append(f"{relative_text}: 证据文件不存在")
            continue
        try:
            summary = _validate_one_sample_log_file(
                path,
                recipe,
                remote_artifact_path=remote_artifact_path,
            )
        except VerificationError as exc:
            failures.append(f"{relative_text}: {exc}")
            continue
        summary["candidate_count"] = len(relative_paths)
        summary["parent_exit_code"] = process_exit_code
        if process_exit_code is not None and process_exit_code != 0:
            summary["elevated_child_covered_nonzero_parent_exit"] = True
        return summary
    detail = "；".join(failures) if failures else "无可用候选"
    if process_exit_code is not None and process_exit_code != 0:
        detail = f"父进程退出码={process_exit_code}；{detail}"
    raise VerificationError(
        f"execution_logging=true 时没有一份 SampleLogs 覆盖全部 PH：{detail}"
    )


@contextmanager
def _exclusive_file_lock(path: Path, *, timeout_s: float) -> Iterator[None]:
    """Hold one byte of a shared file so crashes do not leave a stale lease."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR
    if os.name == "nt":
        flags |= os.O_BINARY
    descriptor = open_descriptor(path, flags, 0o600)
    acquired = False
    deadline = time.monotonic() + timeout_s
    try:
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        while not acquired:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                else:
                    _flock(descriptor, "LOCK_EX", nonblocking=True)
                acquired = True
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                    raise
                if time.monotonic() >= deadline:
                    raise VerificationError("等待单 VM 验证锁超时") from exc
                time.sleep(0.1)
        yield
    finally:
        if acquired:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                _flock(descriptor, "LOCK_UN")
        os.close(descriptor)


def _flock(descriptor: int, operation: str, *, nonblocking: bool = False) -> None:
    fcntl = importlib.import_module("fcntl")
    value = getattr(fcntl, operation)
    if nonblocking:
        value |= fcntl.LOCK_NB
    fcntl.flock(descriptor, value)


__all__ = [
    "ArtifactResolver",
    "GuestExecutionResult",
    "PowerShellGuestChannel",
    "SecretStdinRunner",
    "SubprocessSecretStdinRunner",
    "VmProfile",
    "VmrunController",
    "VmrunSubprocessRunner",
    "VmwareVerificationBackend",
    "VmwareVerificationSettings",
    "windows_client_caption_supported",
    "create_vmware_verification_backend",
]
