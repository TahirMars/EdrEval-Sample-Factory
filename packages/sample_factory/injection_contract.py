"""注入类原子的牺牲进程合同。

规划期允许 ``target_pid=0`` 仅表示「运行时解析」，不得表示自注入。
glue 必须 CreateProcess 独立牺牲进程，并把真实 PID 交给注入 API。
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from packages.sample_factory.errors import CatalogError, PlanningError
from packages.sample_factory.models import AtomSpec, GlueInjectionContract

INJECTION_FAMILY = "injection"
_IMAGE_KEYS = ("target_image", "target")
_PID_KEYS = frozenset({"target_pid", "pid", "process_id"})
_PID_SENTINEL_TEXTS = frozenset(
    {
        "0",
        "",
        "self",
        "current",
        "current_process",
        "getcurrentprocessid",
    }
)


def is_injection_spec(spec: AtomSpec) -> bool:
    return spec.variant_family.lower() == INJECTION_FAMILY


def is_pid_sentinel(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == 0
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit() and int(stripped) == 0:
            return True
        return stripped.lower() in _PID_SENTINEL_TEXTS
    return False


def looks_like_image(value: object) -> bool:
    if not isinstance(value, str):
        return False
    name = value.replace("/", "\\").rsplit("\\", 1)[-1].strip()
    return name.lower().endswith(".exe") and len(name) > 4


def sacrificial_image(parameters: Mapping[str, Any]) -> str | None:
    for key in _IMAGE_KEYS:
        value = parameters.get(key)
        if looks_like_image(value):
            return str(value)
    return None


def injection_domain_ready(spec: AtomSpec) -> bool:
    """injection 族必须声明可用牺牲进程映像；仅 target_pid=0 不可调度。"""
    if not is_injection_spec(spec):
        return True
    return any(
        key in spec.param_domains and all(looks_like_image(item) for item in spec.param_domains[key])
        for key in _IMAGE_KEYS
    )


def validate_injection_parameters(spec: AtomSpec, supplied: Mapping[str, Any]) -> None:
    if not is_injection_spec(spec):
        return
    if not injection_domain_ready(spec):
        raise CatalogError(
            f"{spec.atom_id} 是 injection 族，但 param_domains 未声明 target_image/target "
            "牺牲进程映像；target_pid=0 不能表示自注入"
        )
    image = sacrificial_image(supplied)
    sentinel_pids = [
        f"{key}={supplied[key]!r}"
        for key in _PID_KEYS
        if key in supplied and is_pid_sentinel(supplied[key])
    ]
    if image is None:
        detail = f"；同时给出了哨兵 PID {sentinel_pids}" if sentinel_pids else ""
        raise CatalogError(
            f"{spec.atom_id} 禁止 target_pid=0/当前进程自注入，必须选择独立牺牲进程映像"
            f"（target_image 或 target）{detail}"
        )


def glue_injection_contracts(
    specs: tuple[AtomSpec, ...],
    atom_parameters: Mapping[str, Mapping[str, Any]],
) -> tuple[GlueInjectionContract, ...]:
    contracts: list[GlueInjectionContract] = []
    for spec in specs:
        if not is_injection_spec(spec):
            continue
        validate_injection_parameters(spec, atom_parameters.get(spec.atom_id, {}))
        image = sacrificial_image(atom_parameters.get(spec.atom_id, {}))
        if image is None:
            raise CatalogError(f"{spec.atom_id} 缺少牺牲进程映像")
        contracts.append(
            GlueInjectionContract(atom_id=spec.atom_id, sacrificial_image=image)
        )
    return tuple(contracts)


def injection_glue_requirements(contracts: tuple[GlueInjectionContract, ...]) -> tuple[str, ...]:
    if not contracts:
        return ()
    images = ", ".join(
        f"{item.atom_id}={item.sacrificial_image}" for item in contracts
    )
    self_hosting = {
        item.atom_id
        for item in contracts
        if item.atom_id in _SELF_HOSTING_INJECTION_ATOMS
    }
    if self_hosting == {item.atom_id for item in contracts}:
        return (
            "下列 injection 原子自行 CreateProcess 牺牲进程并完成注入："
            f"{', '.join(sorted(self_hosting))}。"
            "glue 只调用其 Execute（可把 target_image 钉进 request JSON），"
            "禁止再 SpawnSacrificial / CreateProcess 第二个牺牲进程，"
            "也禁止对无关 PID WaitForSingleObject 空等。"
            f"映像仍须与 param_domains 一致：{images}。",
        )
    return (
        "injection 族必须 CreateProcess/CreateProcessW 启动独立牺牲进程，"
        f"把 PROCESS_INFORMATION.dwProcessId 传给注入 API；禁止 GetCurrentProcessId 自注入。"
        f"牺牲进程映像必须编译期钉死：{images}。"
        "注入后必须 WaitForSingleObject 等待远程线程或牺牲进程，"
        "不得把 CreateRemoteThread 返回成功且立即 CloseHandle 当成 TTP 已发生。"
        + (
            f" 例外（自行建牺牲进程，勿再 Spawn）：{', '.join(sorted(self_hosting))}。"
            if self_hosting
            else ""
        ),
    )


_SELF_HOSTING_INJECTION_ATOMS = frozenset(
    {
        "atom.in.process_hollowing",
        "atom.in.process_doppelgang",
        "atom.in.process_herpaderp",
    }
)


def cpp_image_needles(image: str) -> tuple[str, ...]:
    needles = [image]
    if "\\" in image:
        needles.append(image.replace("\\", "\\\\"))
        needles.append(image.replace("\\", "/"))
    basename = image.replace("/", "\\").rsplit("\\", 1)[-1]
    if basename and basename not in needles:
        needles.append(basename)
    return tuple(dict.fromkeys(needles))


def validate_injection_glue_source(
    files: Mapping[str, str],
    contracts: tuple[GlueInjectionContract, ...],
) -> None:
    if not contracts:
        return
    main = files.get("generated/main.cpp")
    if main is None:
        raise PlanningError("injection glue 必须生成 generated/main.cpp")
    if "GetCurrentProcessId" in main:
        raise PlanningError(
            "injection glue 禁止 GetCurrentProcessId：那是当前进程自注入，"
            "不能证明跨进程 TTP，也不会稳定产生 Sysmon EID8"
        )
    lowered = main.lower()
    self_hosting = tuple(
        item for item in contracts if item.atom_id in _SELF_HOSTING_INJECTION_ATOMS
    )
    external = tuple(
        item for item in contracts if item.atom_id not in _SELF_HOSTING_INJECTION_ATOMS
    )
    if external:
        if "createprocess" not in lowered:
            raise PlanningError(
                "injection glue 必须 CreateProcess 启动独立牺牲进程，再对其 PID 注入"
            )
        if "waitforsingleobject" not in lowered:
            raise PlanningError(
                "injection glue 必须 WaitForSingleObject 等待远程线程或牺牲进程；"
                "立即 CloseHandle 不能证明注入效果"
            )
    for contract in contracts:
        if not any(needle in main for needle in cpp_image_needles(contract.sacrificial_image)):
            raise PlanningError(
                f"{contract.atom_id} glue 未钉死牺牲进程映像 {contract.sacrificial_image}"
            )
    if self_hosting and not external:
        # Self-hosting atoms already CreateProcess inside Execute; a second glue
        # SpawnSacrificial only creates an unrelated notepad and burns the wait.
        if "spawnsacrificial" in lowered:
            raise PlanningError(
                "process_hollowing 等自行建牺牲进程的原子禁止 glue 再 SpawnSacrificial"
            )


__all__ = [
    "INJECTION_FAMILY",
    "cpp_image_needles",
    "glue_injection_contracts",
    "injection_domain_ready",
    "injection_glue_requirements",
    "is_injection_spec",
    "is_pid_sentinel",
    "looks_like_image",
    "sacrificial_image",
    "validate_injection_glue_source",
    "validate_injection_parameters",
]
