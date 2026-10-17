"""Variant-specific Plugin Harness Sysmon oracles.

PH coverage-matrix rows are variant groups.  Projecting every listed EID as a
required assertion makes ``behavior_valid`` depend on sibling techniques that
a given implementation never performs (for example IN08 EID7 module stomping
on same-process EnumWindows callback execution).

This catalog is the A-side Harness gate: each required matcher must be a
subset of the bound PH row, or an explicit functional payload signal when
the matrix row has no Sysmon that this variant can emit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from packages.sample_factory.catalog import CoverageRegistry
from packages.sample_factory.errors import VerificationError

_SYSMON_EID_RE = re.compile(r"EID\s*(\d+(?:\s*/\s*\d+)*)", re.IGNORECASE)
_HARNESS_NOISE = ("harness.exe", "wsmprovhost.exe")


@dataclass(frozen=True)
class HarnessSysmonMatcher:
    """One required Sysmon event, optionally bound to Image/Parent/Target fields."""

    event_id: int
    functional: bool = False
    image_endswith: tuple[str, ...] = ()
    image_not_contains: tuple[str, ...] = ()
    parent_image_endswith: tuple[str, ...] = ()
    source_image_contains: tuple[str, ...] = ()
    target_image_endswith: tuple[str, ...] = ()
    target_object_contains: tuple[str, ...] = ()
    target_filename_contains: tuple[str, ...] = ()
    command_line_contains: tuple[str, ...] = ()


@dataclass(frozen=True)
class AtomHarnessOracle:
    ph_ids: tuple[str, ...]
    required: tuple[HarnessSysmonMatcher, ...]


# Keys are AtomSpec.atom_id / plugin-seed:// suffix.
ATOM_HARNESS_ORACLES: dict[str, AtomHarnessOracle] = {
    "atom.ex.callback_exec": AtomHarnessOracle(
        ph_ids=("PH-IN08",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                functional=True,
                image_endswith=("\\calc.exe", "\\calculator.exe", "\\calculatorapp.exe"),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.in.pool_party": AtomHarnessOracle(
        ph_ids=("PH-IN08",),
        required=(
            HarnessSysmonMatcher(
                event_id=10,
                source_image_contains=("\\edrevalagent\\",),
            ),
        ),
    ),
    "atom.in.create_remote_thread": AtomHarnessOracle(
        ph_ids=("PH-IN01",),
        required=(
            HarnessSysmonMatcher(
                event_id=8,
                source_image_contains=("\\edrevalagent\\",),
                target_image_endswith=("\\notepad.exe",),
            ),
        ),
    ),
    "atom.in.thread_hijack": AtomHarnessOracle(
        ph_ids=("PH-IN03",),
        required=(
            HarnessSysmonMatcher(
                event_id=10,
                source_image_contains=("\\edrevalagent\\",),
            ),
        ),
    ),
    "atom.in.apc_early_bird": AtomHarnessOracle(
        ph_ids=("PH-IN04",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\notepad.exe",),
                image_not_contains=_HARNESS_NOISE,
            ),
            HarnessSysmonMatcher(
                event_id=10,
                source_image_contains=("\\edrevalagent\\",),
            ),
        ),
    ),
    "atom.pe.token_impersonation_theft": AtomHarnessOracle(
        ph_ids=("PH-PE02",),
        required=(
            HarnessSysmonMatcher(
                event_id=10,
                source_image_contains=("\\edrevalagent\\",),
                target_image_endswith=("\\winlogon.exe",),
            ),
        ),
    ),
    "atom.ex.ppid_spoof": AtomHarnessOracle(
        ph_ids=("PH-PE05",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\notepad.exe",),
                parent_image_endswith=("\\explorer.exe",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.ex.seclogon_spoof": AtomHarnessOracle(
        ph_ids=("PH-PE05",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\cmd.exe",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.ps.create_service_winapi": AtomHarnessOracle(
        ph_ids=("PH-PS01",),
        required=(
            HarnessSysmonMatcher(
                event_id=13,
                target_object_contains=("\\services\\",),
            ),
        ),
    ),
    "atom.ps.create_service_rpc": AtomHarnessOracle(
        ph_ids=("PH-PS01",),
        required=(
            HarnessSysmonMatcher(
                event_id=13,
                target_object_contains=("\\services\\",),
            ),
        ),
    ),
    "atom.ps.create_service_named_pipe": AtomHarnessOracle(
        ph_ids=("PH-PS01",),
        required=(
            HarnessSysmonMatcher(
                event_id=13,
                target_object_contains=("\\services\\",),
            ),
        ),
    ),
    "atom.ps.start_service_winapi": AtomHarnessOracle(
        ph_ids=("PH-EX11",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\cmd.exe",),
                parent_image_endswith=("\\services.exe",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.ex.create_process_cmd": AtomHarnessOracle(
        ph_ids=("PH-EX02",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\cmd.exe",),
                command_line_contains=("edreval-ph-ex02",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.bl.timestomp": AtomHarnessOracle(
        ph_ids=("PH-BL07",),
        required=(
            HarnessSysmonMatcher(
                event_id=2,
                target_filename_contains=("edreval-bl07-timestomp",),
            ),
        ),
    ),
    "atom.ob.drop_ciphertext": AtomHarnessOracle(
        ph_ids=("PH-OB05",),
        required=(
            HarnessSysmonMatcher(
                event_id=11,
                target_filename_contains=("edreval-ob05-cipher",),
            ),
        ),
    ),
    "atom.ps.create_scheduled_task_com": AtomHarnessOracle(
        ph_ids=("PH-PS03",),
        required=(
            HarnessSysmonMatcher(
                event_id=13,
                target_object_contains=("\\Schedule\\TaskCache",),
            ),
        ),
    ),
    "atom.pe.uacme_cmluautil": AtomHarnessOracle(
        ph_ids=("PH-PE01",),
        required=(
            HarnessSysmonMatcher(
                event_id=13,
                target_object_contains=("\\ms-settings\\Shell\\Open\\command",),
            ),
        ),
    ),
    "atom.ps.start_scheduled_task_com": AtomHarnessOracle(
        ph_ids=("PH-PS03",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\cmd.exe",),
                parent_image_endswith=("\\taskeng.exe", "\\svchost.exe"),
                command_line_contains=("edreval-t1053-005",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.in.ewm_injection": AtomHarnessOracle(
        ph_ids=("PH-IN05",),
        required=(
            HarnessSysmonMatcher(
                event_id=10,
                source_image_contains=("\\edrevalagent\\",),
                target_image_endswith=("\\explorer.exe",),
            ),
        ),
    ),
    "atom.in.process_hollowing": AtomHarnessOracle(
        ph_ids=("PH-IN02",),
        required=(
            HarnessSysmonMatcher(
                event_id=25,
                image_endswith=("\\notepad.exe",),
            ),
        ),
    ),
    "atom.in.process_doppelgang": AtomHarnessOracle(
        ph_ids=("PH-IN06",),
        required=(
            HarnessSysmonMatcher(
                event_id=25,
                image_endswith=("\\edreval-in06-doppel.exe",),
            ),
        ),
    ),
    "atom.in.process_herpaderp": AtomHarnessOracle(
        ph_ids=("PH-IN07",),
        required=(
            HarnessSysmonMatcher(
                event_id=25,
                image_endswith=("\\edreval-in07-herpaderp.exe",),
            ),
        ),
    ),
    "atom.bl.delete_using_stream": AtomHarnessOracle(
        ph_ids=("PH-BL08",),
        required=(
            HarnessSysmonMatcher(
                event_id=26,
                target_filename_contains=("edreval-bl08-delete",),
            ),
        ),
    ),
    "atom.ex.powershell": AtomHarnessOracle(
        ph_ids=("PH-EX01",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\powershell.exe",),
                command_line_contains=("edreval-ph-ex01",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.ex.vbs_wscript": AtomHarnessOracle(
        ph_ids=("PH-EX03",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\wscript.exe",),
                command_line_contains=("edreval-ex03",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.ex.jscript_wscript": AtomHarnessOracle(
        ph_ids=("PH-EX04",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\wscript.exe",),
                command_line_contains=("edreval-ex04",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.ex.mshta_inline": AtomHarnessOracle(
        ph_ids=("PH-EX05",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\mshta.exe",),
                command_line_contains=("edreval-ph-ex05",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.ex.regsvr32_scrobj": AtomHarnessOracle(
        ph_ids=("PH-EX06",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\regsvr32.exe",),
                command_line_contains=("edreval-ex06.sct",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.ex.rundll32_shell": AtomHarnessOracle(
        ph_ids=("PH-EX07",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\rundll32.exe",),
                command_line_contains=("edreval-ph-ex07",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.ex.msbuild_inline": AtomHarnessOracle(
        ph_ids=("PH-EX08",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\msbuild.exe",),
                command_line_contains=("edreval-ex08",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.ex.installutil": AtomHarnessOracle(
        ph_ids=("PH-EX09",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\installutil.exe",),
                command_line_contains=("edreval-ex09",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.ex.com_mmc20": AtomHarnessOracle(
        ph_ids=("PH-EX10",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\cmd.exe",),
                command_line_contains=("edreval-ex10-mmc",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.ex.com_shellwindows": AtomHarnessOracle(
        ph_ids=("PH-EX10",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\cmd.exe",),
                command_line_contains=("edreval-ex10-sw",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.ps.registry_run_hkcu": AtomHarnessOracle(
        ph_ids=("PH-PS02",),
        required=(
            HarnessSysmonMatcher(
                event_id=13,
                target_object_contains=("EdrEvalPs02",),
            ),
        ),
    ),
    "atom.di.whoami": AtomHarnessOracle(
        ph_ids=("PH-DI01",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\whoami.exe",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.di.systeminfo": AtomHarnessOracle(
        ph_ids=("PH-DI02",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\systeminfo.exe",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.di.tasklist": AtomHarnessOracle(
        ph_ids=("PH-DI03",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\tasklist.exe",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.di.dir": AtomHarnessOracle(
        ph_ids=("PH-DI04",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\where.exe",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.di.ipconfig": AtomHarnessOracle(
        ph_ids=("PH-DI05",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\ipconfig.exe",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.di.netstat": AtomHarnessOracle(
        ph_ids=("PH-DI06",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\netstat.exe",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.di.sc_query": AtomHarnessOracle(
        ph_ids=("PH-DI07",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\sc.exe",),
                command_line_contains=("query",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.di.net_localgroup": AtomHarnessOracle(
        ph_ids=("PH-DI08",),
        required=(
            HarnessSysmonMatcher(
                event_id=1,
                image_endswith=("\\net.exe",),
                command_line_contains=("localgroup",),
                image_not_contains=_HARNESS_NOISE,
            ),
        ),
    ),
    "atom.it.copy_tool": AtomHarnessOracle(
        ph_ids=("PH-IT01",),
        required=(
            HarnessSysmonMatcher(
                event_id=11,
                target_filename_contains=("edreval-ph-it01-copied",),
            ),
        ),
    ),
    "atom.ob.extract_embedded": AtomHarnessOracle(
        ph_ids=("PH-OB08",),
        required=(
            HarnessSysmonMatcher(
                event_id=11,
                target_filename_contains=("edreval-ob08-embedded",),
            ),
        ),
    ),
    "atom.ob.decode_runtime": AtomHarnessOracle(
        ph_ids=("PH-OB09",),
        required=(
            HarnessSysmonMatcher(
                event_id=11,
                target_filename_contains=("edreval-ob09-decoded",),
            ),
        ),
    ),
    "atom.bl.modify_registry": AtomHarnessOracle(
        ph_ids=("PH-BL10",),
        required=(
            HarnessSysmonMatcher(
                event_id=13,
                target_object_contains=("\\Software\\EdrEvalFactory",),
            ),
        ),
    ),
}


def _event_ids_from_data_sources(text: str) -> tuple[int, ...]:
    """Parse ``EID25`` and slash groups such as ``EID23/26`` from a matrix data-source cell."""
    event_ids: list[int] = []
    for match in _SYSMON_EID_RE.findall(text or ""):
        for part in str(match).split("/"):
            event_id = int(part.strip())
            if event_id not in event_ids:
                event_ids.append(event_id)
    return tuple(event_ids)


def matrix_sysmon_event_ids(
    coverage: CoverageRegistry,
    ph_ids: tuple[str, ...],
) -> tuple[int, ...]:
    """Unique Sysmon EID numbers listed on the bound PH coverage-matrix rows."""
    event_ids: list[int] = []
    for ph_id in ph_ids:
        row = coverage.rows.get(ph_id)
        if row is None:
            raise VerificationError(f"Harness PH 不在覆盖矩阵：{ph_id}")
        found = _event_ids_from_data_sources(row.data_sources)
        if not found:
            raise VerificationError(f"矩阵行缺少可投影 Sysmon EID：{ph_id}")
        for event_id in found:
            if event_id not in event_ids:
                event_ids.append(event_id)
    if not event_ids:
        raise VerificationError(f"矩阵投影未给出 Sysmon event_id：{list(ph_ids)}")
    return tuple(event_ids)


def resolve_harness_ph_ids(request: object | None, atom_spec: object | None) -> tuple[str, ...]:
    """Prefer request/atom PH; fall back to the variant catalog for older runs."""
    intent = getattr(request, "intent", None)
    request_ph = tuple(getattr(intent, "ph_ids", ()) or ())
    if request_ph:
        return request_ph
    spec_ph = tuple(getattr(atom_spec, "ph_ids", ()) or ())
    if spec_ph:
        return spec_ph
    atom_id = getattr(atom_spec, "atom_id", None) or getattr(request, "seed_plugin_id", None)
    variant = ATOM_HARNESS_ORACLES.get(str(atom_id or ""))
    if variant is not None:
        return variant.ph_ids
    return ()


def variant_sysmon_matchers(atom_id: str | None) -> tuple[HarnessSysmonMatcher, ...]:
    variant = ATOM_HARNESS_ORACLES.get(atom_id or "")
    if variant is None:
        return ()
    return variant.required


def related_sysmon_image_suffixes(atom_ids: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Image suffixes the guest collector must keep even when the parent tree is spoofed.

    Seclogon / PPID spoof create EID1 under svchost/explorer, so a Harness-PID
    walk never sees ``cmd.exe`` / ``notepad.exe``. Collection still stays
    bounded: only oracle ``image_endswith`` values, not parent images such as
    ``svchost.exe``.
    """
    suffixes: list[str] = []
    seen: set[str] = set()
    for atom_id in atom_ids:
        for matcher in variant_sysmon_matchers(atom_id):
            for item in matcher.image_endswith:
                normalized = str(item).strip().replace("/", "\\").casefold()
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)
                suffixes.append(normalized)
    return tuple(suffixes)


# Task Scheduler writes TaskCache (EID13) and Tasks XML (EID11) from svchost,
# outside the Harness PID tree. Keep these prefixes atom-scoped; never add a
# blanket ``\\svchost.exe`` image suffix (that would vacuum seclogon parents).
_PS03_TASK_PATH_PREFIXES: tuple[str, ...] = (
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
    r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
    r"C:\Windows\System32\Tasks",
)
_PS01_SERVICE_PATH_PREFIXES: tuple[str, ...] = (
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SYSTEM\ControlSet001\Services",
    r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services",
)
_RELATED_PATH_PREFIXES_BY_ATOM: dict[str, tuple[str, ...]] = {
    "atom.ps.create_scheduled_task_com": _PS03_TASK_PATH_PREFIXES,
    "atom.ps.start_scheduled_task_com": _PS03_TASK_PATH_PREFIXES,
    "atom.ps.create_service_winapi": _PS01_SERVICE_PATH_PREFIXES,
    "atom.ps.create_service_rpc": _PS01_SERVICE_PATH_PREFIXES,
    "atom.ps.create_service_named_pipe": _PS01_SERVICE_PATH_PREFIXES,
}


def related_sysmon_path_prefixes(atom_ids: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Registry/file prefixes the guest collector must keep beyond lab directories.

    ``ITaskFolder::RegisterTask`` EID13/EID11 are emitted by the Schedule
    service, so a Harness-PID walk never sees TaskCache. Collection stays
    bounded to these explicit prefixes.
    """
    prefixes: list[str] = []
    seen: set[str] = set()
    for atom_id in atom_ids:
        for item in _RELATED_PATH_PREFIXES_BY_ATOM.get(atom_id, ()):
            normalized = str(item).strip().replace("/", "\\").rstrip("\\")
            key = normalized.casefold()
            if not normalized or key in seen:
                continue
            seen.add(key)
            prefixes.append(normalized)
    return tuple(prefixes)


def required_sysmon_assertion_ids(
    ph_ids: tuple[str, ...],
    coverage: CoverageRegistry,
    atom_id: str | None,
) -> tuple[str, ...]:
    """Process-adjacent Sysmon assertion ids that must pass for behavior_valid."""
    matrix_ids = set(matrix_sysmon_event_ids(coverage, ph_ids))
    matchers = variant_sysmon_matchers(atom_id)
    if not matchers:
        return tuple(f"sysmon.event_id.{event_id}" for event_id in matrix_sysmon_event_ids(coverage, ph_ids))
    tokens: list[str] = []
    for matcher in matchers:
        if not matcher.functional and matcher.event_id not in matrix_ids:
            raise VerificationError(
                f"{atom_id} 变体 oracle EID{matcher.event_id} 不在矩阵行 {list(ph_ids)} 的数据源内"
            )
        token = f"sysmon.event_id.{matcher.event_id}"
        if token not in tokens:
            tokens.append(token)
    return tuple(tokens)


def sysmon_image_by_process_id(events: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> dict[int, str]:
    """Map ProcessId → Image from process-create (EID1) events."""
    images: dict[int, str] = {}
    for event in events:
        if event.get("event_id") != 1:
            continue
        data = event.get("data")
        if not isinstance(data, dict):
            continue
        pid = _sysmon_process_id(data)
        image = str(data.get("Image") or "").strip()
        if pid is None or not image or image.casefold() in {"<unknown process>", "unknown"}:
            continue
        images.setdefault(pid, image)
    return images


def project_sysmon_event_for_oracle(
    event: dict[str, Any],
    *,
    image_by_pid: dict[int, str] | None = None,
) -> dict[str, Any]:
    """Recover EID25 Image from EID1 when Sysmon reports ``<unknown process>``."""
    if event.get("event_id") != 25:
        return event
    data = event.get("data")
    if not isinstance(data, dict):
        return event
    image = str(data.get("Image") or "").strip()
    if image and image.casefold() not in {"<unknown process>", "unknown"}:
        return event
    if image_by_pid is None:
        return event
    pid = _sysmon_process_id(data)
    if pid is None or pid not in image_by_pid:
        return event
    projected = dict(event)
    projected_data = dict(data)
    projected_data["Image"] = image_by_pid[pid]
    projected["data"] = projected_data
    return projected


def _sysmon_process_id(fields: dict[str, Any]) -> int | None:
    raw = fields.get("ProcessId")
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw > 0 else None
    if isinstance(raw, str):
        text = raw.strip()
        if text.isdigit():
            value = int(text)
            return value if value > 0 else None
    return None


def sysmon_event_matches(event: dict[str, Any], matcher: HarnessSysmonMatcher) -> bool:
    event_id = event.get("event_id")
    if event_id != matcher.event_id:
        return False
    data = event.get("data")
    fields = data if isinstance(data, dict) else {}
    image = str(fields.get("Image") or "")
    parent = str(fields.get("ParentImage") or "")
    source = str(fields.get("SourceImage") or "")
    target_image = str(fields.get("TargetImage") or "")
    target_object = str(fields.get("TargetObject") or "")
    target_filename = str(fields.get("TargetFilename") or "")
    command_line = str(fields.get("CommandLine") or "")
    if matcher.image_endswith and not _endswith_any(image, matcher.image_endswith):
        return False
    if matcher.image_not_contains and _contains_any(image, matcher.image_not_contains):
        return False
    if matcher.parent_image_endswith and not _endswith_any(parent, matcher.parent_image_endswith):
        return False
    if matcher.source_image_contains and not _contains_any(source, matcher.source_image_contains):
        return False
    if matcher.target_image_endswith and not _endswith_any(target_image, matcher.target_image_endswith):
        return False
    if matcher.target_object_contains and not _contains_any(target_object, matcher.target_object_contains):
        return False
    if matcher.target_filename_contains and not _contains_any(
        target_filename, matcher.target_filename_contains
    ):
        return False
    if matcher.command_line_contains and not _contains_any(
        command_line, matcher.command_line_contains
    ):
        return False
    return True


def _endswith_any(value: str, suffixes: tuple[str, ...]) -> bool:
    lowered = value.casefold()
    return any(lowered.endswith(item.casefold()) for item in suffixes)


def _contains_any(value: str, needles: tuple[str, ...]) -> bool:
    lowered = value.casefold()
    return any(item.casefold() in lowered for item in needles)


__all__ = [
    "ATOM_HARNESS_ORACLES",
    "AtomHarnessOracle",
    "HarnessSysmonMatcher",
    "matrix_sysmon_event_ids",
    "related_sysmon_image_suffixes",
    "required_sysmon_assertion_ids",
    "resolve_harness_ph_ids",
    "project_sysmon_event_for_oracle",
    "sysmon_event_matches",
    "sysmon_image_by_process_id",
    "variant_sysmon_matchers",
]
