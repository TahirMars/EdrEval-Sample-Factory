"""样本工厂单测共享的纯控制面 fixture。"""

from __future__ import annotations

from datetime import UTC, datetime

from packages.sample_factory.catalog import AtomCatalog, CoverageRegistry
from packages.sample_factory.models import (
    AtomRole,
    AtomSpec,
    IntegrationState,
    PluginProvenance,
    SafetyProfile,
    SignalKind,
    SignalLevel,
    TelemetryAssertion,
    TelemetryContract,
    TriggerMode,
)

PROFILE_ID = "win11-sysmon15-no-edr"
IMPLANT_SHA = "a" * 64
ARTIFACT_SHA = "b" * 64


def provenance() -> PluginProvenance:
    return PluginProvenance(
        repository_ref="plugin://approved/atoms",
        source_revision="c" * 40,
        source_refs=("https://example.invalid/research",),
        audit_passed=True,
        pinned=True,
        reviewed_by="reviewer-1",
        reviewed_at=datetime(2026, 8, 31, tzinfo=UTC),
    )


def atom_specs() -> tuple[AtomSpec, ...]:
    common = {
        "integration_state": IntegrationState.IMPLEMENTED,
        "env_prerequisites": ("windows-11",),
        "toolchain_ref": "toolchain://clang-cl-pinned",
        "verification_profile": "standard",
        "compat_hints": (),
        "safety_profile": SafetyProfile.LOW,
        "trigger_modes": (TriggerMode.LAB_TRIGGER,),
        "tool_ref": "plugin://approved/atoms",
    }
    carrier = AtomSpec(
        atom_id="atom.ia.document",
        role=AtomRole.CARRIER,
        ph_ids=("PH-IA01",),
        attck_ids=("T1566.001",),
        variant_family="delivery",
        provided_capabilities=("cap.delivery.document",),
        inputs_schema_ref="schema://ia-document",
        param_domains={"container": ("docm", "lnk")},
        output_contract="document",
        handoff_contract="handoff://document-to-loader",
        c2_pointer_schema=None,
        telemetry_contract_ref="telemetry://ia-document",
        requires_implant=False,
        **common,
    )
    loader = AtomSpec(
        atom_id="atom.ob.decode",
        role=AtomRole.LOADER_ATOM,
        ph_ids=("PH-OB05",),
        attck_ids=("T1027.013",),
        variant_family="obfuscation",
        required_capabilities=("cap.delivery.document",),
        provided_capabilities=("cap.payload.shellcode",),
        inputs_schema_ref="schema://decode",
        param_domains={"codec": ("rc4", "xor")},
        output_contract="shellcode",
        handoff_contract="handoff://shellcode/v1",
        produces_handoffs=("handoff://shellcode/v1",),
        consumes_handoffs=(),
        c2_pointer_schema=None,
        telemetry_contract_ref="telemetry://decode",
        requires_implant=True,
        **common,
    )
    execution = AtomSpec(
        atom_id="atom.in.apc",
        role=AtomRole.EXECUTION_ATOM,
        ph_ids=("PH-IN04",),
        attck_ids=("T1055.004",),
        variant_family="injection",
        required_capabilities=("cap.payload.shellcode",),
        provided_capabilities=("cap.process.injection",),
        inputs_schema_ref="schema://apc",
        param_domains={"target": ("notepad.exe", "werfault.exe")},
        output_contract="exe",
        handoff_contract="handoff://shellcode/v1",
        produces_handoffs=(),
        consumes_handoffs=("handoff://shellcode/v1",),
        c2_pointer_schema=None,
        telemetry_contract_ref="telemetry://apc",
        requires_implant=False,
        **common,
    )
    return carrier, loader, execution


def catalog() -> AtomCatalog:
    result = AtomCatalog(
        CoverageRegistry(
            {
                "PH-IA01": ("T1566.001",),
                "PH-OB05": ("T1027.013",),
                "PH-IN04": ("T1055.004",),
            }
        )
    )
    for spec in atom_specs():
        result.register(spec, provenance())
    return result


def telemetry_contracts() -> tuple[TelemetryContract, ...]:
    result = []
    for spec, event_id in zip(atom_specs(), (11, 7, 10), strict=True):
        result.append(
            TelemetryContract(
                contract_id=spec.telemetry_contract_ref,
                atom_id=spec.atom_id,
                profile_ids=(PROFILE_ID,),
                source_ref=f"contract-source://{spec.atom_id}",
                assertions=(
                    TelemetryAssertion(
                        assertion_id=f"{spec.atom_id}.positive",
                        kind=SignalKind.POSITIVE,
                        level=SignalLevel.REQUIRED,
                        match_fields={"event_id": event_id, "atom_id": spec.atom_id},
                        description="independent event and atom correlation",
                    ),
                ),
            )
        )
    return tuple(result)
