"""独立的 V1/V2/V3 功能真值裁判。"""

from __future__ import annotations

from dataclasses import dataclass

from packages.sample_factory.errors import VerificationError
from packages.sample_factory.models import (
    AtomRole,
    AtomSpec,
    FailureTaxonomy,
    ProductionProfile,
    RawVerificationReport,
    SampleRecipe,
    SignalKind,
    SignalLevel,
    TelemetryAssertion,
    TelemetryContract,
)


@dataclass(frozen=True)
class AssertionTruth:
    assertion_id: str
    kind: SignalKind
    level: SignalLevel
    passed: bool
    matched_events: int


@dataclass(frozen=True)
class FunctionalTruth:
    success: bool
    taxonomy: FailureTaxonomy | None
    v1_passed: bool
    v2_passed: bool
    v3_passed: bool
    assertions: tuple[AssertionTruth, ...] = ()
    v2_applicable: bool = True
    missing_contract_atom_ids: tuple[str, ...] = ()

    def telemetry_summary(self) -> dict[str, object]:
        return {
            "v1_passed": self.v1_passed,
            "v2_passed": self.v2_passed,
            "v2_applicable": self.v2_applicable,
            "v3_passed": self.v3_passed,
            "missing_contract_atom_ids": list(self.missing_contract_atom_ids),
            "assertions": [
                {
                    "assertion_id": item.assertion_id,
                    "kind": item.kind.value,
                    "level": item.level.value,
                    "passed": item.passed,
                    "matched_events": item.matched_events,
                }
                for item in self.assertions
            ],
        }


# 与 plugin_harness_oracles / Sysmon 投影字段对齐的语义算子。
# 值是 list/tuple 时按「任一」匹配；其余键仍走精确相等。
_SEMANTIC_MATCH_OPS: dict[str, tuple[str, str]] = {
    "image_endswith": ("image", "endswith"),
    "parent_image_endswith": ("parent_image", "endswith"),
    "source_image_contains": ("source_image", "contains"),
    "target_image_endswith": ("target_image", "endswith"),
    "target_object_contains": ("target_object", "contains"),
    "target_filename_contains": ("target_filename", "contains"),
    "command_line_contains": ("command_line", "contains"),
    "image_not_contains": ("image", "not_contains"),
}


class TelemetryMatcher:
    """对 marker/run_id 隔离后的结构化事件做合取匹配。

    普通字段精确相等；``*_endswith`` / ``*_contains`` 对投影出的 Image 等字段做
    与 Harness oracle 相同的后缀/子串语义，避免合同里的算子键被当成字面量字段。
    """

    def match(
        self,
        contract: TelemetryContract,
        report: RawVerificationReport,
    ) -> tuple[AssertionTruth, ...]:
        if report.profile_id not in contract.profile_ids:
            raise VerificationError(
                f"遥测合同 {contract.contract_id} 不适用于 profile={report.profile_id}"
            )
        if report.telemetry.profile_id != report.profile_id:
            raise VerificationError("遥测包 profile_id 与验证报告不一致")
        if report.telemetry.run_id != report.run_id:
            raise VerificationError("遥测包 run_id 与验证水印不一致")
        events = [event for event in report.telemetry.events if event.run_id == report.run_id]
        truths: list[AssertionTruth] = []
        for assertion in contract.assertions:
            matched = sum(self._matches(assertion, event.fields) for event in events)
            passed = matched > 0 if assertion.kind is SignalKind.POSITIVE else matched == 0
            truths.append(
                AssertionTruth(
                    assertion_id=assertion.assertion_id,
                    kind=assertion.kind,
                    level=assertion.level,
                    passed=passed,
                    matched_events=matched,
                )
            )
        return tuple(truths)

    @classmethod
    def _matches(cls, assertion: TelemetryAssertion, fields: dict[str, object]) -> bool:
        for key, expected in assertion.match_fields.items():
            op = _SEMANTIC_MATCH_OPS.get(key)
            if op is None:
                if fields.get(key) != expected:
                    return False
                continue
            field_name, mode = op
            haystack = str(fields.get(field_name) or "")
            needles = expected if isinstance(expected, (list, tuple)) else (expected,)
            texts = tuple(str(item) for item in needles if item is not None and str(item))
            if not texts:
                return False
            if mode == "endswith":
                if not cls._endswith_any(haystack, texts):
                    return False
            elif mode == "contains":
                if not cls._contains_any(haystack, texts):
                    return False
            elif mode == "not_contains":
                if cls._contains_any(haystack, texts):
                    return False
            else:  # pragma: no cover - closed operator set
                raise VerificationError(f"未知遥测匹配算子：{mode}")
        return True

    @staticmethod
    def _endswith_any(value: str, suffixes: tuple[str, ...]) -> bool:
        lowered = value.casefold()
        return any(lowered.endswith(item.casefold()) for item in suffixes)

    @staticmethod
    def _contains_any(value: str, needles: tuple[str, ...]) -> bool:
        lowered = value.casefold()
        return any(item.casefold() in lowered for item in needles)


class FunctionalTruthEvaluator:
    """生成者之外的确定性裁判。A 侧入库只要求 V1+V2；V3 写入摘要但不挡 SUCCESS。EDR 告警不参与 SUCCESS。"""

    def __init__(self, matcher: TelemetryMatcher | None = None) -> None:
        self._matcher = matcher or TelemetryMatcher()

    @staticmethod
    def validate_contract_bindings(
        recipe: SampleRecipe,
        specs: tuple[AtomSpec, ...],
        contracts: tuple[TelemetryContract, ...],
    ) -> None:
        if tuple(spec.atom_id for spec in specs) != recipe.atom_ids:
            raise VerificationError("验证 AtomSpec 顺序与 Recipe 不一致")
        by_ref = {contract.contract_id: contract for contract in contracts}
        if len(by_ref) != len(contracts):
            raise VerificationError("遥测合同 ID 重复")
        for spec in specs:
            if not spec.ph_ids:
                continue
            contract_ref = spec.telemetry_contract_ref
            if contract_ref is None:
                continue
            contract = by_ref.get(contract_ref)
            if contract is None or contract.atom_id != spec.atom_id:
                raise VerificationError(f"{spec.atom_id} 缺匹配的遥测合同")

    def evaluate(
        self,
        recipe: SampleRecipe,
        specs: tuple[AtomSpec, ...],
        contracts: tuple[TelemetryContract, ...],
        profile: ProductionProfile,
        report: RawVerificationReport,
        *,
        built_sha256: str,
    ) -> FunctionalTruth:
        self._validate_evidence_identity(recipe, specs, contracts, profile, report, built_sha256)
        missing_contract_atom_ids = tuple(
            spec.atom_id
            for spec in specs
            if spec.ph_ids and spec.telemetry_contract_ref is None
        )
        v2_applicable = not missing_contract_atom_ids

        if report.timed_out:
            return self._failure(
                FailureTaxonomy.TIMEOUT,
                v2_applicable=v2_applicable,
                missing_contract_atom_ids=missing_contract_atom_ids,
            )
        if report.blocked:
            if not profile.security_product_enabled:
                raise VerificationError("no-EDR/无防护 profile 出现 blocked，环境配置语义不完整")
            return self._failure(
                FailureTaxonomy.SANDBOX_BLOCKED,
                v2_applicable=v2_applicable,
                missing_contract_atom_ids=missing_contract_atom_ids,
            )
        if report.anti_analysis_skipped:
            if not any(spec.verification_profile == "anti-analysis-ack" for spec in specs):
                raise VerificationError("未声明 anti-analysis-ack 的插件报告了反分析跳过")
            return self._failure(
                FailureTaxonomy.ANTI_ANALYSIS_SKIP,
                v2_applicable=v2_applicable,
                missing_contract_atom_ids=missing_contract_atom_ids,
            )
        if (
            not report.process_created
            or report.crashed
            or (report.exit_code is not None and report.exit_code != 0)
        ):
            return self._failure(
                FailureTaxonomy.RUNTIME_CRASH,
                v2_applicable=v2_applicable,
                missing_contract_atom_ids=missing_contract_atom_ids,
            )

        assertions = tuple(
            truth for contract in contracts for truth in self._matcher.match(contract, report)
        )
        has_absence = any(item.kind is SignalKind.ABSENCE for item in assertions)
        required_ok = all(item.passed for item in assertions if item.level is SignalLevel.REQUIRED)
        if (has_absence and not report.telemetry.baseline_collected) or not required_ok:
            return FunctionalTruth(
                success=False,
                taxonomy=FailureTaxonomy.TELEMETRY_MISS,
                v1_passed=True,
                v2_passed=False,
                v3_passed=False,
                assertions=assertions,
                v2_applicable=v2_applicable,
                missing_contract_atom_ids=missing_contract_atom_ids,
            )

        v3_required = bool(recipe.implant_sha256) or any(
            spec.role is AtomRole.LOADER_ATOM
            or spec.variant_family.lower() in {"injection", "privesc", "privilege_escalation"}
            for spec in specs
        )
        required_effects = [item for item in report.effects if item.required]
        v3_passed = (not v3_required) or (
            bool(required_effects) and all(item.passed for item in required_effects)
        )
        # V3 remains in the telemetry summary, but A-side intake only requires V1+V2.
        # Glue template promotion still keys off v3_passed.
        return FunctionalTruth(
            success=True,
            taxonomy=None,
            v1_passed=True,
            v2_passed=v2_applicable,
            v3_passed=v3_passed,
            assertions=assertions,
            v2_applicable=v2_applicable,
            missing_contract_atom_ids=missing_contract_atom_ids,
        )

    @staticmethod
    def _validate_evidence_identity(
        recipe: SampleRecipe,
        specs: tuple[AtomSpec, ...],
        contracts: tuple[TelemetryContract, ...],
        profile: ProductionProfile,
        report: RawVerificationReport,
        built_sha256: str,
    ) -> None:
        FunctionalTruthEvaluator.validate_contract_bindings(recipe, specs, contracts)
        if report.artifact_sha256 != built_sha256:
            raise VerificationError("验证样本 sha256 不是本轮构建产物，拒绝上一轮二进制冒充")
        if report.profile_id != profile.profile_id:
            raise VerificationError("验证报告 profile_id 与生产意图不一致")

    @staticmethod
    def _failure(
        taxonomy: FailureTaxonomy,
        *,
        v2_applicable: bool = True,
        missing_contract_atom_ids: tuple[str, ...] = (),
    ) -> FunctionalTruth:
        return FunctionalTruth(
            success=False,
            taxonomy=taxonomy,
            v1_passed=False,
            v2_passed=False,
            v3_passed=False,
            v2_applicable=v2_applicable,
            missing_contract_atom_ids=missing_contract_atom_ids,
        )


__all__ = [
    "AssertionTruth",
    "FunctionalTruth",
    "FunctionalTruthEvaluator",
    "TelemetryMatcher",
]
