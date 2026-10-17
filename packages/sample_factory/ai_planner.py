"""离线工厂 LLM：通过 Function Calling 从已登记 AtomSpec 选择组合与参数。

模型只能调用 submit_planned_composition。控制面随后重建 SampleRecipe，并再次经过
AtomCatalog 的状态、PH、参数域、trigger、implant 与高危门禁；提示词不是安全边界。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol, cast

from packages.llm.provider import (
    LLMCompletion,
    LLMMessage,
    LLMTimeoutError,
    LLMTool,
    LLMToolChoice,
)
from packages.sample_factory.agent_events import (
    AgentActivitySink,
    emit_activity,
    safe_activity_text,
)
from packages.sample_factory.capability import capability_paths
from packages.sample_factory.catalog import AtomCatalog
from packages.sample_factory.errors import PlanningError
from packages.sample_factory.experience import (
    ExperienceSearchQuery,
    ExperienceSearchResult,
    HybridExperienceRetriever,
    KnowledgeMaturity,
    select_planning_strategy,
)
from packages.sample_factory.identity import canonical_json, canonical_parameters, combo_digest
from packages.sample_factory.injection_contract import injection_domain_ready
from packages.sample_factory.models import (
    AtomRole,
    AtomSpec,
    FactoryPlanningContext,
    PlannedComposition,
    ProductionPolicy,
    SafetyProfile,
    SampleRecipe,
    TriggerMode,
)
from packages.sample_factory.run_models import PlanningStrategy


class CompletionClient(Protocol):
    """与 OpenAICompatClient 的原生 Function Calling 接口兼容。"""

    def complete_tool_with_metadata(
        self,
        messages: list[LLMMessage],
        tools: list[LLMTool],
        *,
        tool_choice: LLMToolChoice = "required",
    ) -> LLMCompletion: ...


@dataclass(frozen=True)
class PlannedRecipe:
    recipe: SampleRecipe
    composition: PlannedComposition
    atom_parameters: dict[str, dict[str, object]]
    rationale: str
    plan_fingerprint: str
    combination_fingerprint: str
    audit_ref: str | None = None
    planning_strategy: PlanningStrategy = PlanningStrategy.AUTO
    experience_refs: tuple[str, ...] = ()
    experience_set_version: str | None = None
    learning_snapshot_ref: str | None = None


def _system_prompt() -> str:
    return (
        "You must call submit_planned_composition exactly once; do not put the plan in message content."
        "你是 EdrEval 离线样本工厂的组合规划器。只从用户消息中的插件目录选择，"
        "严禁输出命令、源码、路径、二进制或 schema 外字段。"
        "ph_ids 是有序主键，ATT&CK ID 不是主键；不得选择 reserved/planned/gap 插件。"
        "production_policy 只影响采样，不能把商业 EDR 零检出当成功条件。"
        "若某原子声明 consumes_handoffs，必须在同一次计划的 loader_atoms/前面原子中"
        "选择 produces 相同 handoff id 的生产者；不得假设 argv 会提供载荷。"
        "字段映射必须严格服从 user.selection_contract：carrier 只能是 carrier_atom_ids 中的"
        "atom_id 或 null，绝不能填写 exe/document 等 output_contract；loader_atoms 只能选"
        "loader_atom_ids；execution_atoms 只能选 execution_atom_ids；同一 atom_id 只能出现一次。"
        "某槽 allowed 为空时必须分别输出 null 或空数组。atom_parameters 必须恰好为所有已选"
        "atom_id 提供对象，无参数原子也必须显式写空对象 {}。"
        "已选原子每个 param_domains 键都必须给值，且只能从 plugins[].param_domains 同名枚举取；"
        "禁止发明域外值。"
        "injection 族必须从 param_domains 选择 target_image 或 target 牺牲进程映像；"
        "禁止 target_pid=0 或当前进程自注入。"
        "user.excluded_combinations 是本批次已经接受的组合；换合法 atom_parameters 即新组合，"
        "新输出必须在角色槽、PH 序列、atom 参数、evasion_tier 或 pointer_mode 上至少一项不同，不得重复。"
        "已占用某 atom 图时，优先从 user.parameter_diversity.prefer_unused_values 换未用过的"
        "target_image/target/parent_image/source_image/service_name/binary_path/privilege_name/"
        "task_name/value_name/dest_name/query_style/command_style/lane_tag，"
        "不必每次换整条 atom 链；某键 exhausted_keys 后再换其它键或换 execution atom。"
        "多样性目标：本批次需要大量互不重复样本；在能力闭合前提下优先产出符合攻击链逻辑的"
        "多原子组合，而不是反复提交同一单原子。参考 user.attack_chain_templates："
        "常见合法顺序是 IT→OB→EX→IN、EX→PE、EX→PS、EX→DI、EX→BL、OB→EX、PE→PS；"
        "ph_ids 必须按该因果顺序排列，且与所选 atom 的 ph_ids 并集一致。"
        "同一模板下用参数分叉铺开样本；模板内参数将尽后再换模板或换 execution atom。"
        "单原子仅在该 PH 尚无多原子闭合路径、或 capability_paths 为空时使用。"
        "explore 时轮换不同 PH 族前缀（EX/IN/PS/DI/PE/OB/IT/BL），避免连续多轮只覆盖同一族。"
        "rationale 用一句话写清攻击链意图（例如：投递落盘后解码再 LOLBin 执行并注入牺牲进程）。"
        "user.experience_context 是控制面检索并经过硬过滤的历史证据，只能作为组合先验；"
        "不得修改其中的成熟度、成功率或证据引用。"
        "planning_strategy=explore 时在合同闭合前提下换 execution atom 或换参数；"
        "mutate 只做一到两个局部变化并优先换参数；exploit 时必须复用稳定序列。"
    )


_KILL_CHAIN_FAMILY_ORDER: tuple[str, ...] = (
    "IA",
    "IT",
    "OB",
    "EX",
    "IN",
    "PE",
    "PS",
    "DI",
    "BL",
)


def _ph_family(ph_id: str) -> str:
    """PH-EX01 → EX；PH-IA01 → IA。"""
    _, _, body = ph_id.partition("-")
    if not body:
        return ph_id
    return "".join(ch for ch in body if ch.isalpha())


def _attack_chain_templates(specs: list[AtomSpec]) -> list[dict[str, object]]:
    """给 Planner 的攻击链模板提示：只引用候选目录中真实存在的 PH 族前缀。"""
    present = {_ph_family(ph_id) for spec in specs for ph_id in spec.ph_ids}
    ordered = [family for family in _KILL_CHAIN_FAMILY_ORDER if family in present]
    catalog: tuple[tuple[str, tuple[str, ...], str], ...] = (
        ("drop-decode-execute-inject", ("IT", "OB", "EX", "IN"), "落盘→解码→执行→注入"),
        ("carrier-decode-inject", ("IA", "OB", "IN"), "载体投递→解码→注入"),
        ("execute-inject", ("EX", "IN"), "主机执行后注入牺牲进程"),
        ("decode-inject", ("OB", "IN"), "解码后注入"),
        ("execute-privilege", ("EX", "PE"), "执行后提权/令牌操作"),
        ("execute-persist", ("EX", "PS"), "执行后持久化"),
        ("execute-discover", ("EX", "DI"), "执行后主机发现"),
        ("execute-bypass", ("EX", "BL"), "执行后防御规避（注册表等）"),
        ("decode-execute", ("OB", "EX"), "运行时解码后执行"),
        ("privilege-persist", ("PE", "PS"), "提权后持久化"),
        ("tool-execute", ("IT", "EX"), "工具落盘后执行"),
        ("inject-only", ("IN",), "独立注入变体（靠 target_image 分叉）"),
        ("execute-only", ("EX",), "独立执行变体（靠 lane_tag/command_style 等分叉）"),
        ("discover-only", ("DI",), "独立发现变体（靠 query_style 分叉）"),
        ("persist-only", ("PS",), "独立持久化变体"),
    )
    templates: list[dict[str, object]] = []
    seen: set[tuple[str, ...]] = set()
    for template_id, sequence, intent in catalog:
        if any(family not in present for family in sequence):
            continue
        key = tuple(sequence)
        if key in seen:
            continue
        seen.add(key)
        templates.append(
            {
                "template_id": template_id,
                "family_sequence": list(sequence),
                "intent": intent,
                "rule": "选 atom 使其 ph 并集覆盖该族序列，且 ph_ids 按因果顺序输出",
            }
        )
    # 候选族按杀伤链顺序的连续子序列，补全静态表未覆盖的合法路径。
    for length in (4, 3, 2):
        if len(ordered) < length:
            continue
        for start in range(0, len(ordered) - length + 1):
            sequence = tuple(ordered[start : start + length])
            if sequence in seen:
                continue
            seen.add(sequence)
            templates.append(
                {
                    "template_id": "chain-" + "-".join(item.lower() for item in sequence),
                    "family_sequence": list(sequence),
                    "intent": "→".join(sequence),
                    "rule": "选 atom 使其 ph 并集覆盖该族序列，且 ph_ids 按因果顺序输出",
                }
            )
    return templates


def _param_value_key(value: object) -> str:
    return value if isinstance(value, str) else canonical_json(value)


def _parameter_diversity_hints(
    specs: list[AtomSpec],
    excluded_compositions: tuple[PlannedComposition, ...],
) -> list[dict[str, object]]:
    """各原子尚未被 excluded 组合用过的 param_domains 值，供 Planner 做参数分叉。"""
    used: dict[str, dict[str, set[str]]] = {}
    for composition in excluded_compositions:
        for atom_id, params in composition.atom_parameters.items():
            atom_used = used.setdefault(atom_id, {})
            for key, value in params.items():
                atom_used.setdefault(key, set()).add(_param_value_key(value))
    hints: list[dict[str, object]] = []
    for spec in specs:
        if not spec.param_domains:
            continue
        atom_used = used.get(spec.atom_id, {})
        unused: dict[str, list[object]] = {}
        exhausted: list[str] = []
        for key, domain in spec.param_domains.items():
            taken = atom_used.get(key, set())
            remaining = [item for item in domain if _param_value_key(item) not in taken]
            unused[key] = remaining
            if domain and not remaining:
                exhausted.append(key)
        hints.append(
            {
                "atom_id": spec.atom_id,
                "prefer_unused_values": unused,
                "exhausted_keys": exhausted,
            }
        )
    return hints


_PLANNED_COMPOSITION_TOOL = LLMTool(
    name="submit_planned_composition",
    description="Submit one governed sample-factory composition for validation by the control plane.",
    parameters=cast(dict[str, object], PlannedComposition.model_json_schema()),
)
_PLANNED_COMPOSITION_CHOICE: LLMToolChoice = {
    "type": "function",
    "function": {"name": _PLANNED_COMPOSITION_TOOL.name},
}


def _planner_output_summary(completion: LLMCompletion) -> str:
    if not completion.tool_calls:
        return "模型未调用规划工具" + _completion_diagnostics(completion)
    value = completion.tool_calls[0].arguments
    ph_ids = value.get("ph_ids")
    carrier = value.get("carrier")
    loaders = value.get("loader_atoms")
    executions = value.get("execution_atoms")
    parameters = value.get("atom_parameters")
    parameter_atoms = sorted(parameters) if isinstance(parameters, dict) else []
    return safe_activity_text(
        "选择 "
        f"PH={ph_ids}; carrier={carrier}; loaders={loaders}; executions={executions}; "
        f"parameter_atoms={parameter_atoms}; evasion={value.get('evasion_tier')}; "
        f"rationale={value.get('rationale', '')}"
        + _completion_diagnostics(completion)
    )


def _completion_diagnostics(completion: LLMCompletion) -> str:
    values = {
        "finish_reason": completion.finish_reason,
        "prompt_tokens": completion.prompt_tokens,
        "completion_tokens": completion.completion_tokens,
        "reasoning_tokens": completion.reasoning_tokens,
        "reasoning_chars": completion.reasoning_content_chars,
    }
    rendered = ", ".join(
        f"{key}={value}" for key, value in values.items() if value is not None
    )
    return "" if not rendered else f"; provider=[{rendered}]"


class FactoryPlanningAgent:
    """带严格解析、目录复核和有限反馈重试的离线选件 Agent。"""

    def __init__(
        self,
        client: CompletionClient,
        catalog: AtomCatalog,
        *,
        retry_limit: int = 2,
        max_tokens: int | None = None,
        sink: AgentActivitySink | None = None,
        planning_strategy: PlanningStrategy = PlanningStrategy.AUTO,
        experience_retriever: HybridExperienceRetriever | None = None,
    ) -> None:
        if retry_limit < 1:
            raise ValueError("retry_limit 必须至少为 1")
        self._client = _with_max_tokens(client, max_tokens)
        self._catalog = catalog
        self._retry_limit = retry_limit
        self._sink = sink
        self._planning_strategy = planning_strategy
        self._experience_retriever = experience_retriever

    def plan(
        self,
        context: FactoryPlanningContext,
        *,
        high_risk_approved: bool = False,
        excluded_compositions: tuple[PlannedComposition, ...] = (),
    ) -> PlannedRecipe:
        if context.trigger_mode is TriggerMode.SESSION_REPLAY:
            raise PlanningError("离线样本生产不得使用 session_replay 首发路径")
        planning_strategy = self._effective_strategy(context)
        experience_result = self._retrieve_experience(context, planning_strategy)

        inventory = []
        candidate_specs = []
        # 仅纳入候选 PH 上的原子；无 PH 的 payload/loader 只按下方 handoff 闭包按需补入，
        # 避免 explore 把无关 msf_calc 塞进 UAC/服务等非注入链导致 RUNTIME_CRASH。
        for spec in self._catalog.dispatchable_specs():
            if context.trigger_mode not in spec.trigger_modes:
                continue
            if spec.safety_profile is SafetyProfile.HIGH_RISK and not high_risk_approved:
                continue
            if not spec.ph_ids:
                continue
            if not set(spec.ph_ids).intersection(context.candidate_ph_ids):
                continue
            if not injection_domain_ready(spec):
                continue
            candidate_specs.append(spec)

        needed_handoffs = {
            handoff
            for spec in candidate_specs
            for handoff in spec.consumes_handoffs
        }
        # 按需闭包：只补「当前缺口 handoff」的无 PH 生产者，并继续消化其 consumes。
        changed = True
        while changed:
            changed = False
            for spec in self._catalog.dispatchable_specs():
                if spec in candidate_specs:
                    continue
                if (
                    not spec.ph_ids
                    and spec.produces_handoffs
                    and needed_handoffs.intersection(spec.produces_handoffs)
                    and context.trigger_mode in spec.trigger_modes
                    and not (
                        spec.safety_profile is SafetyProfile.HIGH_RISK
                        and not high_risk_approved
                    )
                    and injection_domain_ready(spec)
                ):
                    candidate_specs.append(spec)
                    before = len(needed_handoffs)
                    needed_handoffs.update(spec.consumes_handoffs)
                    changed = True
                    if len(needed_handoffs) != before:
                        changed = True

        role_order = {
            AtomRole.CARRIER: 0,
            AtomRole.LOADER_ATOM: 1,
            AtomRole.EXECUTION_ATOM: 2,
        }
        candidate_specs.sort(key=lambda spec: (role_order[spec.role], spec.atom_id))
        if planning_strategy is PlanningStrategy.EXPLOIT:
            assert experience_result is not None
            allowed = {
                atom_id
                for candidate in experience_result.candidates
                for atom_id in candidate.experience.atom_ids
            }
            candidate_specs = [spec for spec in candidate_specs if spec.atom_id in allowed]

        for spec in candidate_specs:
            inventory.append(
                {
                    "atom_id": spec.atom_id,
                    "role": spec.role.value,
                    "ph_ids": list(spec.ph_ids),
                    "param_domains": spec.param_domains,
                    "output_contract": spec.output_contract,
                    "handoff_contract": spec.handoff_contract,
                    "produces_handoffs": list(spec.produces_handoffs),
                    "consumes_handoffs": list(spec.consumes_handoffs),
                    "materialize": spec.materialize.value,
                    "artifact_ref": spec.artifact_ref,
                    "c2_pointer_schema": spec.c2_pointer_schema,
                    "env_prerequisites": spec.env_prerequisites,
                    "compat_hints": spec.compat_hints,
                    "requires_implant": spec.requires_implant,
                    "safety_profile": spec.safety_profile.value,
                }
            )
        if not inventory:
            raise PlanningError("候选 PH 范围内没有已审计、已钉扎且可调度的 AtomSpec")

        payload = {
            "candidate_ph_ids": context.candidate_ph_ids,
            "required_ph_ids": context.required_ph_ids,
            "production_policy": context.production_policy.value,
            "allowed_evasion_tiers": self._allowed_tiers(context.production_policy),
            "profile": {
                "profile_id": context.profile.profile_id,
                "high_risk_enabled": context.profile.high_risk_enabled,
                "security_product_enabled": context.profile.security_product_enabled,
            },
            "delivery": context.delivery.value,
            "trigger_mode": context.trigger_mode.value,
            "implant_format": context.implant_format,
            "seed": context.seed,
            "failure_priors": [item.model_dump(mode="json") for item in context.failure_priors],
            "excluded_combinations": [
                item.model_dump(mode="json") for item in excluded_compositions
            ],
            "parameter_diversity": _parameter_diversity_hints(
                candidate_specs, excluded_compositions
            ),
            "attack_chain_templates": _attack_chain_templates(candidate_specs),
            "selection_contract": self._selection_contract(candidate_specs),
            "plugins": inventory,
            "capability_paths": capability_paths(
                candidate_specs, max_depth=5, limit=64
            ),
            "planning_strategy": planning_strategy.value,
            "experience_context": self._experience_payload(experience_result),
        }
        base_messages: list[LLMMessage] = [
            {"role": "system", "content": _system_prompt()},
            {"role": "user", "content": canonical_json(payload)},
        ]
        messages = list(base_messages)
        errors: list[str] = []
        excluded_fingerprints = {
            self._combination_fingerprint(item) for item in excluded_compositions
        }
        for _attempt in range(self._retry_limit):
            try:
                completion = _complete_tool_with_metadata(
                    self._client,
                    messages,
                    [_PLANNED_COMPOSITION_TOOL],
                    tool_choice=_PLANNED_COMPOSITION_CHOICE,
                )
            except (LLMTimeoutError, TimeoutError) as exc:
                error = safe_activity_text(str(exc) or "LLM 请求超时")
                errors.append(error)
                emit_activity(
                    self._sink,
                    "sample_factory_planner_feedback",
                    {
                        "agent": "planner",
                        "turn": _attempt + 1,
                        "content": error,
                        "reason": "timeout",
                    },
                )
                if _attempt + 1 < self._retry_limit:
                    messages = base_messages + [
                        {
                            "role": "user",
                            "content": (
                                "上一次模型请求超时。请直接调用规划工具并提交完整参数。"
                            ),
                        }
                    ]
                continue
            emit_activity(
                self._sink,
                "sample_factory_planner_model_output",
                {
                    "agent": "planner",
                    "turn": _attempt + 1,
                    "content": _planner_output_summary(completion),
                },
            )
            try:
                if len(completion.tool_calls) != 1:
                    raise PlanningError(
                        "模型必须调用一次 submit_planned_composition"
                        + _completion_diagnostics(completion)
                    )
                call = completion.tool_calls[0]
                composition = self._parse(call.arguments)
                self._validate_composition_roles(composition, candidate_specs)
                result = self._validate_and_project(
                    composition,
                    context,
                    high_risk_approved=high_risk_approved,
                    excluded_fingerprints=excluded_fingerprints,
                    experience_result=experience_result,
                    planning_strategy=planning_strategy,
                )
                return result
            except Exception as exc:
                error = self._short_error(exc)
                errors.append(error)
                emit_activity(
                    self._sink,
                    "sample_factory_planner_feedback",
                    {
                        "agent": "planner",
                        "turn": _attempt + 1,
                        "content": safe_activity_text(error),
                    },
                )
                messages = list(base_messages)
                feedback = (
                    f"参数未通过控制面门禁：{error}。请修正后重新调用工具；"
                    "严格服从 selection_contract，不要把 output_contract 当作 atom_id，"
                    "也不要跨角色重复 atom_id。"
                    "atom_parameters 必须从 plugins[].param_domains 取值；"
                    "换未用过的合法参数即可避开 excluded_combinations。"
                )
                if len(completion.tool_calls) == 1:
                    call = completion.tool_calls[0]
                    messages.extend([
                        call.assistant_message(content=completion.content),
                        call.result_message({"ok": False, "error": feedback}),
                    ])
                else:
                    messages.append({"role": "user", "content": feedback})
        raise PlanningError(
            f"工厂 LLM 连续 {self._retry_limit} 次未返回有效计划：" + " | ".join(errors)
        )

    @staticmethod
    def _parse(arguments: dict[str, object]) -> PlannedComposition:
        try:
            return PlannedComposition.model_validate(arguments)
        except Exception as exc:
            raise PlanningError(f"模型工具参数违反 PlannedComposition schema：{exc}") from exc

    @staticmethod
    def _selection_contract(specs: list[AtomSpec]) -> dict[str, object]:
        by_role = {
            role: [spec.atom_id for spec in specs if spec.role is role]
            for role in AtomRole
        }
        return {
            "carrier_atom_ids": by_role[AtomRole.CARRIER],
            "loader_atom_ids": by_role[AtomRole.LOADER_ATOM],
            "execution_atom_ids": by_role[AtomRole.EXECUTION_ATOM],
            "empty_slot_values": {"carrier": None, "loader_atoms": [], "execution_atoms": []},
            "atom_id_may_appear_in_only_one_role": True,
            "atom_parameters_keys": "exactly all selected atom_ids; use {} for no parameters",
            "atom_parameters_values_must_be_in_param_domains": True,
            "changing_atom_parameters_creates_new_combination": True,
            "prefer_unused_param_values_before_changing_atom_graph": True,
            "prefer_attack_chain_templates_when_capability_closes": True,
            "diversify_across_ph_families": True,
            "single_atom_only_when_no_multi_atom_path": True,
        }

    @staticmethod
    def _validate_composition_roles(
        composition: PlannedComposition,
        specs: list[AtomSpec],
    ) -> None:
        by_id = {spec.atom_id: spec for spec in specs}
        slots = {
            "carrier": (() if composition.carrier is None else (composition.carrier,)),
            "loader_atoms": composition.loader_atoms,
            "execution_atoms": composition.execution_atoms,
        }
        selected = tuple(atom_id for values in slots.values() for atom_id in values)
        duplicates = sorted({atom_id for atom_id in selected if selected.count(atom_id) > 1})
        if duplicates:
            raise PlanningError(
                "同一 atom_id 不得跨角色重复；重复项=" + ",".join(duplicates)
            )

        expected_roles = {
            "carrier": AtomRole.CARRIER,
            "loader_atoms": AtomRole.LOADER_ATOM,
            "execution_atoms": AtomRole.EXECUTION_ATOM,
        }
        for slot, atom_ids in slots.items():
            allowed = sorted(
                spec.atom_id for spec in specs if spec.role is expected_roles[slot]
            )
            invalid = [
                atom_id
                for atom_id in atom_ids
                if atom_id not in by_id or by_id[atom_id].role is not expected_roles[slot]
            ]
            if invalid:
                empty_hint = "null" if slot == "carrier" else "[]"
                raise PlanningError(
                    f"{slot} 只允许 atom_id={allowed}；实得={invalid}；"
                    f"若 allowed 为空必须使用 {empty_hint}，output_contract 不是 atom_id"
                )

        parameter_ids = set(composition.atom_parameters)
        selected_ids = set(selected)
        if parameter_ids != selected_ids:
            raise PlanningError(
                "atom_parameters 键必须与所选 atom_id 完全一致；"
                f"缺少={sorted(selected_ids - parameter_ids)}；"
                f"多余={sorted(parameter_ids - selected_ids)}；无参数原子也要写 {{}}"
            )

    def _validate_and_project(
        self,
        composition: PlannedComposition,
        context: FactoryPlanningContext,
        *,
        high_risk_approved: bool,
        excluded_fingerprints: set[str] | None = None,
        experience_result: ExperienceSearchResult | None = None,
        planning_strategy: PlanningStrategy = PlanningStrategy.AUTO,
    ) -> PlannedRecipe:
        if not set(composition.ph_ids).issubset(context.candidate_ph_ids):
            raise PlanningError("模型选择了 candidate_ph_ids 外的 PH 行")
        if not set(context.required_ph_ids).issubset(composition.ph_ids):
            raise PlanningError("模型遗漏 required_ph_ids")
        if composition.evasion_tier not in self._allowed_tiers(context.production_policy):
            raise PlanningError("evasion_tier 不符合 production_policy 采样档")

        parameters = canonical_parameters(
            composition.atom_parameters,
            evasion_tier=composition.evasion_tier,
            pointer_mode=(
                None if composition.pointer_mode is None else composition.pointer_mode.value
            ),
        )
        digest = combo_digest(composition.ph_ids, parameters)
        recipe = SampleRecipe(
            recipe_id=f"sf-{digest[:16]}",
            carrier=composition.carrier,
            loader_atoms=composition.loader_atoms,
            execution_atoms=composition.execution_atoms,
            implant_sha256=context.implant_sha256,
            implant_format=context.implant_format,
            delivery=context.delivery,
            trigger_mode=context.trigger_mode,
            ph_ids=composition.ph_ids,
            evasion_tier=composition.evasion_tier,
            pointer_mode=composition.pointer_mode,
        )
        self._catalog.validate_recipe(
            recipe,
            composition.atom_parameters,
            context.profile,
            high_risk_approved=high_risk_approved,
        )
        fingerprint = self._composition_fingerprint(
            composition,
            planning_strategy=planning_strategy,
            learning_snapshot_ref=(
                None
                if experience_result is None
                else experience_result.learning_snapshot_ref
            ),
        )
        combination_fingerprint = self._combination_fingerprint(composition)
        if combination_fingerprint in (excluded_fingerprints or set()):
            raise PlanningError("模型重复了本批次已接受组合；必须改变 atom 选择或合法参数")
        self._validate_strategy(composition, experience_result, planning_strategy)
        return PlannedRecipe(
            recipe=recipe,
            composition=composition,
            atom_parameters={
                key: dict(value) for key, value in composition.atom_parameters.items()
            },
            rationale=composition.rationale,
            plan_fingerprint=fingerprint,
            combination_fingerprint=combination_fingerprint,
            planning_strategy=planning_strategy,
            experience_refs=(
                ()
                if experience_result is None
                else tuple(
                    f"experience://{item.experience.experience_id}/v{item.experience.version}"
                    for item in experience_result.candidates
                )
            ),
            experience_set_version=(
                None
                if experience_result is None
                else experience_result.experience_set_version
            ),
            learning_snapshot_ref=(
                None
                if experience_result is None
                else experience_result.learning_snapshot_ref
            ),
        )

    def _retrieve_experience(
        self,
        context: FactoryPlanningContext,
        planning_strategy: PlanningStrategy,
    ) -> ExperienceSearchResult | None:
        if self._experience_retriever is None:
            if self._planning_strategy is PlanningStrategy.AUTO:
                return None
            raise PlanningError("规划策略必须配置 ExperienceRetriever")
        minimum = {
            PlanningStrategy.EXPLOIT: KnowledgeMaturity.REPLAY_STABLE,
            PlanningStrategy.MUTATE: KnowledgeMaturity.BEHAVIOR_VALID,
            PlanningStrategy.EXPLORE: KnowledgeMaturity.HYPOTHESIS,
        }[planning_strategy]
        result = self._experience_retriever.search(
            ExperienceSearchQuery(
                strategy=planning_strategy,
                ph_ids=context.required_ph_ids,
                profile_id=context.profile.profile_id,
                architecture=context.architecture,
                minimum_maturity=minimum,
                semantic_query=(
                    "TTP composition "
                    + " ".join(context.required_ph_ids or context.candidate_ph_ids)
                ),
            )
        )
        if planning_strategy is not PlanningStrategy.EXPLORE and not result.candidates:
            raise PlanningError(
                f"planning_strategy={planning_strategy.value} 没有符合硬约束的经验"
            )
        return result

    def _effective_strategy(
        self, context: FactoryPlanningContext
    ) -> PlanningStrategy:
        if self._planning_strategy is not PlanningStrategy.AUTO:
            return self._planning_strategy
        if self._experience_retriever is None:
            return PlanningStrategy.EXPLORE
        return select_planning_strategy(
            self._experience_retriever,
            seed=context.seed,
            ph_ids=context.required_ph_ids,
            profile_id=context.profile.profile_id,
            architecture=context.architecture,
        )

    @staticmethod
    def _experience_payload(
        result: ExperienceSearchResult | None,
    ) -> dict[str, object] | None:
        if result is None:
            return None
        return {
            "experience_set_version": result.experience_set_version,
            "learning_snapshot_ref": result.learning_snapshot_ref,
            "candidates": [
                {
                    "experience_ref": (
                        f"experience://{item.experience.experience_id}/"
                        f"v{item.experience.version}"
                    ),
                    "maturity": item.experience.maturity.value,
                    "ph_sequence": item.experience.ph_sequence,
                    "atom_ids": item.experience.atom_ids,
                    "atom_parameters": item.experience.atom_parameters,
                    "success_count": item.experience.success_count,
                    "failure_count": item.experience.failure_count,
                    "score": item.final_score,
                    "evidence_refs": item.experience.evidence_refs,
                }
                for item in result.candidates
            ],
        }

    def _validate_strategy(
        self,
        composition: PlannedComposition,
        result: ExperienceSearchResult | None,
        planning_strategy: PlanningStrategy,
    ) -> None:
        if planning_strategy is PlanningStrategy.EXPLORE:
            return
        if result is None or not result.candidates:
            raise PlanningError("当前规划策略缺少经验基线")
        selected = (
            (() if composition.carrier is None else (composition.carrier,))
            + composition.loader_atoms
            + composition.execution_atoms
        )
        sequences = [item.experience.atom_ids for item in result.candidates]
        if planning_strategy is PlanningStrategy.EXPLOIT:
            if selected not in sequences:
                raise PlanningError("exploit 必须复用检索到的稳定 Atom 序列")
            return
        distances = [len(set(selected).symmetric_difference(sequence)) for sequence in sequences]
        if not distances or min(distances) > 2:
            raise PlanningError("mutate 必须是成功链路的一到两个局部节点变化")

    @staticmethod
    def _composition_fingerprint(
        composition: PlannedComposition,
        *,
        planning_strategy: PlanningStrategy = PlanningStrategy.AUTO,
        learning_snapshot_ref: str | None = None,
    ) -> str:
        return hashlib.sha256(
            canonical_json(
                {
                    "composition": composition.model_dump(mode="json"),
                    "planning_strategy": planning_strategy.value,
                    "learning_snapshot_ref": learning_snapshot_ref,
                }
            ).encode()
        ).hexdigest()

    @staticmethod
    def _combination_fingerprint(composition: PlannedComposition) -> str:
        payload = composition.model_dump(mode="json")
        payload.pop("rationale", None)
        return hashlib.sha256(canonical_json(payload).encode()).hexdigest()

    @staticmethod
    def _allowed_tiers(policy: ProductionPolicy) -> tuple[str, ...]:
        if policy is ProductionPolicy.BASELINE:
            return ("E0", "E1", "E2")
        return ("E3", "E4")

    @staticmethod
    def _short_error(exc: Exception, *, limit: int = 500) -> str:
        text = str(exc).replace("\n", " ").strip()
        return text if len(text) <= limit else text[:limit] + "..."


__all__ = ["CompletionClient", "FactoryPlanningAgent", "PlannedRecipe"]


def _with_max_tokens(client: CompletionClient, max_tokens: int | None) -> CompletionClient:
    if max_tokens is None:
        return client
    if max_tokens <= 0:
        raise ValueError("max_tokens 必须为正整数")
    copier = getattr(client, "with_max_tokens", None)
    if copier is None:
        raise TypeError("CompletionClient 不支持分角色 max_tokens；请注入带该能力的 client")
    return cast(CompletionClient, copier(max_tokens))


def _complete_tool_with_metadata(
    client: CompletionClient,
    messages: list[LLMMessage],
    tools: list[LLMTool],
    *,
    tool_choice: LLMToolChoice,
) -> LLMCompletion:
    result = client.complete_tool_with_metadata(
        messages,
        tools,
        tool_choice=tool_choice,
    )
    if not isinstance(result, LLMCompletion):
        raise TypeError("complete_tool_with_metadata 必须返回 LLMCompletion")
    return result
