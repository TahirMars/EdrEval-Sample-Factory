"""Textual operations view for one sample-factory production run."""

from __future__ import annotations

import json
import re
import unicodedata
import webbrowser
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import Click
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    Select,
    SelectionList,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)
from textual.widgets.selection_list import Selection
from textual.worker import Worker, WorkerState

from packages.factory_host.plugin_harness_vmware import VmwarePluginHarnessConfig
from packages.sample_factory.catalog import CoverageRegistry, PH_MATRIX_ROW_COUNT
from packages.sample_factory.technique_board import (
    collect_factory_plugin_board_rows,
    render_covered_board_text,
    write_published_attck_board,
)
from packages.sample_factory.cli import (
    FactoryInputs,
    cleanup_plugin_runs,
    continue_plugin_intake,
    describe_plugin_run_choice,
    execute_plugin_authoring_request,
    execute_plugin_decomposition,
    execute_plugin_run_validation,
    execute_production,
    list_plugin_inventory,
    list_produced_samples,
    load_inputs,
    plugin_run_short_id,
    preflight,
    promote_plugin,
    result_payload,
    review_plugin_run,
    start_plugin_intake,
    transfer_produced_samples,
)
from packages.sample_factory.plugin_run_select import select_canonical_plugin_runs
from packages.sample_factory.errors import ProductionStopped
from packages.sample_factory.models import PluginProvenance
from packages.sample_factory.pipeline import ProductionStopToken
from packages.sample_factory.plugin_intake import (
    PluginIntakeSession,
    PluginIntakeStatus,
)
from packages.sample_factory.plugin_models import PluginDecompositionPlan, PluginRequest

_PHASES = {
    "sample_factory_planning_started": (1, "AI 组合规划"),
    "sample_factory_plan_ready": (2, "计划已通过门禁"),
    "sample_factory_claim": (3, "组合租约"),
    "sample_factory_glue_started": (4, "AI 代码生成"),
    "sample_factory_glue_ready": (4, "AI 代码已生成"),
    "sample_factory_compile_attempt": (5, "受控编译"),
    "sample_factory_compile_failed": (5, "编译失败（将自动修复重试）"),
    "sample_factory_glue_repair": (4, "AI 代码修复重试"),
    "sample_factory_verification_started": (6, "三重验证"),
    "sample_factory_verification_finished": (6, "验证完成"),
    "sample_factory_publish_started": (7, "发布回归集"),
    "sample_factory_success": (8, "生产完成"),
    "sample_factory_failure": (8, "生产失败"),
    "sample_factory_batch_started": (0, "批量生产启动"),
    "sample_factory_batch_attempt_started": (1, "批量样本规划"),
    "sample_factory_batch_attempt_finished": (0, "批量尝试完成"),
    "sample_factory_batch_finished": (8, "批量生产结束"),
    "sample_factory_stop_acknowledged": (0, "安全停止"),
    "sample_factory_planner_model_output": (1, "Planner 模型回合"),
    "sample_factory_planner_feedback": (1, "Planner 门禁反馈"),
    "sample_factory_coding_session": (4, "Coding Agent 会话"),
    "sample_factory_coding_model_output": (4, "Coding Agent 模型回合"),
    "sample_factory_coding_tool_result": (4, "Coding Agent 工具结果"),
    "sample_factory_coding_feedback": (4, "Coding Agent 门禁反馈"),
    "sample_factory_plugin_authoring_started": (1, "插件源码生成"),
    "sample_factory_plugin_coding_session": (1, "插件 Coding Agent 会话"),
    "sample_factory_plugin_coding_model_output": (1, "插件 Coding Agent 模型回合"),
    "sample_factory_plugin_coding_tool_result": (1, "插件 Coding Agent 工具结果"),
    "sample_factory_plugin_coding_feedback": (1, "插件 Coding Agent 门禁反馈"),
    "sample_factory_plugin_source_ready": (2, "插件源码就绪"),
    "sample_factory_plugin_compile_attempt": (3, "插件受控编译"),
    "sample_factory_plugin_compile_failed": (3, "插件编译失败（将自动修复重试）"),
    "sample_factory_plugin_coding_repair_session": (2, "插件 Coding Agent 修复会话"),
    "sample_factory_plugin_source_repaired": (2, "插件修复源码就绪"),
    "sample_factory_plugin_compile_valid": (3, "插件编译通过"),
    "sample_factory_plugin_compile_only": (3, "插件编译完成（待行为验证）"),
    "sample_factory_plugin_plan_node_finished": (4, "插件分解节点完成"),
    "sample_factory_plugin_behavior_valid": (4, "插件行为验证通过"),
    "sample_factory_plugin_authoring_failed": (4, "插件生成失败"),
    "sample_factory_plugin_validation_started": (1, "独立 Harness 验证"),
    "sample_factory_plugin_validation_finished": (2, "Harness 验证通过"),
    "sample_factory_plugin_validation_failed": (2, "Harness 验证失败"),
    "sample_factory_plugin_validation_skipped": (2, "无 PH 已跳过"),
    "sample_factory_plugin_dependency_link_valid": (2, "依赖闭包 Harness 通过"),
    "sample_factory_plugin_reviewed": (3, "已进入 reviewed"),
    "sample_factory_plugin_promoted": (3, "已进入 dispatchable"),
}

_EVENT_TITLES = {
    "preflight_ready": "预检通过",
    "production_start_requested": "已批准启动",
    "production_result": "生产结果",
    "sample_factory_planning_started": "开始规划",
    "sample_factory_plan_ready": "计划就绪",
    "sample_factory_claim": "租约结果",
    "sample_factory_glue_started": "开始 AI 代码生成",
    "sample_factory_glue_ready": "AI 代码已生成",
    "sample_factory_compile_attempt": "编译尝试",
    "sample_factory_compile_failed": "编译失败",
    "sample_factory_glue_repair": "AI 代码修复",
    "sample_factory_verification_started": "开始验证",
    "sample_factory_verification_finished": "验证结束",
    "sample_factory_publish_started": "开始发布",
    "sample_factory_success": "生产成功",
    "sample_factory_failure": "生产失败",
    "sample_factory_batch_started": "批量生产启动",
    "sample_factory_batch_attempt_started": "批量尝试启动",
    "sample_factory_batch_attempt_finished": "批量尝试结束",
    "sample_factory_batch_finished": "批量生产结束",
    "production_stop_requested": "已请求停止",
    "production_stopped": "生产已停止",
    "sample_factory_stop_acknowledged": "停止信号已确认",
    "sample_factory_planner_model_output": "Planner 模型输出",
    "sample_factory_planner_feedback": "Planner 门禁反馈",
    "sample_factory_coding_session": "Coding Agent 会话",
    "sample_factory_coding_model_output": "Coding Agent 模型输出",
    "sample_factory_coding_tool_result": "Coding Agent 工具结果",
    "sample_factory_coding_feedback": "Coding Agent 门禁反馈",
    "sample_factory_plugin_authoring_started": "插件生成启动",
    "sample_factory_plugin_coding_session": "插件 Coding Agent 会话",
    "sample_factory_plugin_coding_model_output": "插件 Coding Agent 模型输出",
    "sample_factory_plugin_coding_tool_result": "插件 Coding Agent 工具结果",
    "sample_factory_plugin_coding_feedback": "插件 Coding Agent 门禁反馈",
    "sample_factory_plugin_source_ready": "插件源码就绪",
    "sample_factory_plugin_compile_attempt": "插件编译尝试",
    "sample_factory_plugin_compile_failed": "插件编译失败",
    "sample_factory_plugin_coding_repair_session": "插件 Coding Agent 修复会话",
    "sample_factory_plugin_source_repaired": "插件修复源码就绪",
    "sample_factory_plugin_compile_valid": "插件编译通过",
    "sample_factory_plugin_compile_only": "插件编译完成（待行为验证）",
    "sample_factory_plugin_plan_node_finished": "插件分解节点完成",
    "sample_factory_plugin_behavior_valid": "插件行为验证通过",
    "sample_factory_plugin_authoring_failed": "插件生成失败",
    "sample_factory_plugin_validation_started": "独立 Harness 验证启动",
    "sample_factory_plugin_validation_finished": "Harness 验证通过",
    "sample_factory_plugin_validation_failed": "Harness 验证失败",
    "sample_factory_plugin_validation_skipped": "无 PH，已跳过 Harness",
    "sample_factory_plugin_dependency_link_valid": "依赖闭包 Harness 通过",
    "sample_factory_plugin_reviewed": "插件已 review",
    "sample_factory_plugin_promoted": "插件已 promote",
}

_AGENT_ACTIVITY_EVENTS = frozenset(
    {
        "sample_factory_planner_model_output",
        "sample_factory_planner_feedback",
        "sample_factory_coding_session",
        "sample_factory_coding_model_output",
        "sample_factory_coding_tool_result",
        "sample_factory_coding_feedback",
        "sample_factory_plugin_coding_session",
        "sample_factory_plugin_coding_repair_session",
        "sample_factory_plugin_coding_model_output",
        "sample_factory_plugin_coding_tool_result",
        "sample_factory_plugin_coding_feedback",
    }
)


def _capability_text(value: object) -> str:
    if isinstance(value, list) and value:
        return ",".join(str(item) for item in value)
    return "-"


def _selection_list_prompt(text: str) -> str:
    """Keep literal [id] prefixes visible; SelectionList otherwise treats them as Rich tags."""
    return text.replace("\\", "\\\\").replace("[", r"\[")


PLUGIN_VERIFY_QUEUE_LABELS = {
    "validate": "待验证",
    "review": "待review",
    "promote": "待promote",
    "done": "已入库",
    "other": "其他",
}
PLUGIN_VERIFY_QUEUE_ORDER = {
    "validate": 0,
    "review": 1,
    "promote": 2,
    "other": 3,
    "done": 4,
}


def plugin_verify_queue(item: Mapping[str, object]) -> str:
    catalog = str(item.get("catalog_status") or "").strip()
    lifecycle = str(item.get("lifecycle_status") or item.get("status") or "").strip()
    if catalog == "dispatchable":
        return "done"
    if catalog == "reviewed":
        return "promote"
    if lifecycle == "behavior_valid":
        return "review"
    if lifecycle in {"compile_valid", "atom_valid", "contract_valid"}:
        return "validate"
    return "other"


def plugin_verify_queue_label(item: Mapping[str, object]) -> str:
    return PLUGIN_VERIFY_QUEUE_LABELS[plugin_verify_queue(item)]


def plugin_verify_matches_queue(item: Mapping[str, object], scope: str) -> bool:
    queue = plugin_verify_queue(item)
    if scope in {"", "all"}:
        return True
    if scope in {"work", "pending"}:
        return queue in {"validate", "review"}
    return queue == scope


def plugin_verify_catalog_summary(
    runs: Sequence[Mapping[str, object]],
    catalog: Mapping[str, object] | None = None,
    *,
    hidden: int = 0,
) -> str:
    counts = {key: 0 for key in PLUGIN_VERIFY_QUEUE_LABELS}
    for item in runs:
        queue = plugin_verify_queue(item)
        counts[queue] = counts.get(queue, 0) + 1
    catalog = catalog or {}
    hidden_note = f" · 隐藏历史 {hidden}" if hidden else ""
    return (
        f"待验证 {counts['validate']} · 待review {counts['review']} · "
        f"待promote {counts['promote']} · 已入库 {counts['done']}"
        f"{hidden_note} · catalog reviewed="
        f"{len(catalog.get('reviewed') or [])} dispatchable="
        f"{len(catalog.get('dispatchable') or [])}"
    )


def plugin_verify_option_prompt(item: Mapping[str, object]) -> str:
    plugin_run_id = str(item.get("plugin_run_id") or "")
    short = plugin_run_short_id(plugin_run_id) if plugin_run_id else "--------"
    name = str(item.get("implementation_name") or "-")
    lifecycle = str(item.get("lifecycle_status") or item.get("status") or "-")
    queue = plugin_verify_queue_label(item)
    catalog = str(item.get("catalog_status") or "").strip()
    catalog_bit = f" · catalog={catalog}" if catalog else ""
    ph_ids = item.get("ph_ids") if isinstance(item.get("ph_ids"), list) else []
    provided = _capability_text(item.get("provided_capabilities"))
    required = _capability_text(item.get("required_capabilities"))
    superseded = item.get("superseded_runs")
    history = (
        f" · 历史 {superseded}"
        if isinstance(superseded, int) and superseded > 0
        else ""
    )
    return (
        f"{queue} [{short}] {name} · {lifecycle}{catalog_bit} · "
        f"provide={provided} · need={required} · PH={ph_ids or '-'}{history}"
    )


def plugin_run_matches_filter(item: Mapping[str, object], query: str) -> bool:
    needle = query.strip().lower()
    if not needle:
        return True
    plugin_run_id = str(item.get("plugin_run_id") or "")
    haystacks = [
        plugin_run_id,
        plugin_run_short_id(plugin_run_id) if plugin_run_id else "",
        str(item.get("implementation_name") or ""),
        str(item.get("plugin_id") or ""),
        str(item.get("lifecycle_status") or ""),
        str(item.get("catalog_status") or ""),
        plugin_verify_queue(item),
        plugin_verify_queue_label(item),
        _capability_text(item.get("provided_capabilities")),
        _capability_text(item.get("required_capabilities")),
        ",".join(str(ph) for ph in item.get("ph_ids"))
        if isinstance(item.get("ph_ids"), list)
        else "",
    ]
    return any(needle in text.lower() for text in haystacks)


def produced_sample_is_published(item: Mapping[str, object]) -> bool:
    return str(item.get("export_status") or "") == "published"


def produced_sample_status_label(item: Mapping[str, object]) -> str:
    return "已发布" if produced_sample_is_published(item) else "未发布"


def produced_sample_option_prompt(item: Mapping[str, object]) -> str:
    sample_id = str(item.get("sample_id") or "-")
    ph_ids = item.get("ph_sequence") if isinstance(item.get("ph_sequence"), list) else []
    atom_ids = item.get("atom_ids") if isinstance(item.get("atom_ids"), list) else []
    status = produced_sample_status_label(item)
    return (
        f"{status}  [{sample_id}] PH={ph_ids or '-'} · atoms={atom_ids or '-'} "
    )


def produced_sample_matches_scope(item: Mapping[str, object], scope: str) -> bool:
    published = produced_sample_is_published(item)
    if scope == "published":
        return published
    if scope == "unpublished":
        return not published
    return True


def produced_sample_matches_filter(item: Mapping[str, object], query: str) -> bool:
    needle = query.strip().lower()
    if not needle:
        return True
    haystacks = [
        str(item.get("sample_id") or ""),
        str(item.get("sample_sha256") or ""),
        str(item.get("profile_id") or ""),
        str(item.get("export_status") or ""),
        produced_sample_status_label(item),
        str(item.get("export_ref") or ""),
        ",".join(str(ph) for ph in item.get("ph_sequence"))
        if isinstance(item.get("ph_sequence"), list)
        else "",
        ",".join(str(atom) for atom in item.get("atom_ids"))
        if isinstance(item.get("atom_ids"), list)
        else "",
    ]
    return any(needle in text.lower() for text in haystacks)


_TECHNIQUE_BOARD_EMPTY = (
    "尚无已发布样本。请先在「样本发布」将 SUCCESS 样本转到 runtime/exports/published。"
)


@dataclass(frozen=True)
class CoverageCountBar:
    """One ATT&CK or PH row in the published-sample coverage board."""

    key: str
    label: str
    sample_count: int
    sample_ids: tuple[str, ...]
    extra: tuple[str, ...] = ()


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item).strip() for item in value if str(item).strip())


def attck_labels_from_coverage(coverage: CoverageRegistry) -> dict[str, str]:
    """First matrix technique name per ATT&CK ID; never invent names."""
    labels: dict[str, str] = {}
    for row in coverage.rows.values():
        name = row.technique.strip()
        if not name:
            continue
        for attack_id in row.attack_ids:
            if attack_id not in labels:
                labels[attack_id] = name
    return labels


def ph_labels_from_coverage(coverage: CoverageRegistry) -> dict[str, str]:
    """PH-row technique names from the Procedure/Host coverage matrix."""
    return {
        ph_id: row.technique.strip()
        for ph_id, row in coverage.rows.items()
        if row.technique.strip()
    }


def _coverage_count_bars(
    samples: Sequence[Mapping[str, object]],
    *,
    key_field: str,
    extra_field: str,
    labels: Mapping[str, str] | None = None,
) -> tuple[CoverageCountBar, ...]:
    buckets: dict[str, dict[str, list[str]]] = {}
    for item in samples:
        if not produced_sample_is_published(item):
            continue
        sample_id = str(item.get("sample_id") or "").strip()
        if not sample_id:
            continue
        keys = _string_tuple(item.get(key_field))
        extras = _string_tuple(item.get(extra_field))
        for key in keys:
            bucket = buckets.setdefault(key, {"sample_ids": [], "extra": []})
            if sample_id not in bucket["sample_ids"]:
                bucket["sample_ids"].append(sample_id)
            for extra in extras:
                if extra not in bucket["extra"]:
                    bucket["extra"].append(extra)
    bars = [
        CoverageCountBar(
            key=key,
            label=str(labels.get(key) or "").strip() if labels else "",
            sample_count=len(bucket["sample_ids"]),
            sample_ids=tuple(bucket["sample_ids"]),
            extra=tuple(bucket["extra"]),
        )
        for key, bucket in buckets.items()
    ]
    bars.sort(key=lambda row: (-row.sample_count, row.key))
    return tuple(bars)


def published_attck_coverage(
    samples: Sequence[Mapping[str, object]],
    *,
    labels: Mapping[str, str] | None = None,
) -> tuple[CoverageCountBar, ...]:
    """Count unique published samples per ATT&CK ID."""
    return _coverage_count_bars(
        samples,
        key_field="attck_ids",
        extra_field="ph_sequence",
        labels=labels,
    )


def published_ph_coverage(
    samples: Sequence[Mapping[str, object]],
    *,
    labels: Mapping[str, str] | None = None,
) -> tuple[CoverageCountBar, ...]:
    """Count unique published samples per PH id."""
    return _coverage_count_bars(
        samples,
        key_field="ph_sequence",
        extra_field="attck_ids",
        labels=labels,
    )


def published_coverage_summary(
    samples: Sequence[Mapping[str, object]],
) -> tuple[int, int, int]:
    """Return published sample count, unique ATT&CK count, unique PH count."""
    published = [
        item
        for item in samples
        if produced_sample_is_published(item) and str(item.get("sample_id") or "").strip()
    ]
    attck_ids: set[str] = set()
    ph_ids: set[str] = set()
    for item in published:
        attck_ids.update(_string_tuple(item.get("attck_ids")))
        ph_ids.update(_string_tuple(item.get("ph_sequence")))
    return len(published), len(attck_ids), len(ph_ids)


def _char_display_width(char: str) -> int:
    """CJK and fullwidth glyphs occupy two terminal columns."""
    kind = unicodedata.east_asian_width(char)
    if kind in {"W", "F", "A"}:
        return 2
    return 1


def _display_width(text: str) -> int:
    return sum(_char_display_width(char) for char in text)


def _fit_display(text: str, width: int, *, ellipsis: str = "…") -> str:
    """Truncate and pad by terminal columns so later glyphs cannot overlap."""
    if width <= 0:
        return ""
    current = _display_width(text)
    if current <= width:
        return text + (" " * (width - current))
    ellipsis_width = _display_width(ellipsis)
    budget = width - ellipsis_width if ellipsis_width < width else width
    fitted: list[str] = []
    used = 0
    for char in text:
        char_width = _char_display_width(char)
        if used + char_width > budget:
            break
        fitted.append(char)
        used += char_width
    if ellipsis_width < width:
        fitted.append(ellipsis)
        used += ellipsis_width
    return "".join(fitted) + (" " * (width - used))


def render_coverage_bars(
    rows: Sequence[CoverageCountBar],
    *,
    bar_width: int = 20,
    key_width: int = 11,
    label_width: int = 22,
    empty_message: str = _TECHNIQUE_BOARD_EMPTY,
) -> str:
    """Render a Unicode horizontal bar chart of sample counts."""
    if not rows:
        return empty_message
    max_count = max(row.sample_count for row in rows)
    lines: list[str] = []
    for row in rows:
        filled = 0 if max_count <= 0 else round(bar_width * row.sample_count / max_count)
        filled = min(bar_width, max(0, filled))
        if row.sample_count > 0 and filled == 0:
            filled = 1
        bar = "█" * filled + "░" * (bar_width - filled)
        name = _fit_display(row.label, label_width)
        lines.append(f"{row.key:<{key_width}} {name} {bar}  {row.sample_count}")
    return "\n".join(lines)


def render_coverage_detail(
    attck_bars: Sequence[CoverageCountBar],
    *,
    empty_message: str = _TECHNIQUE_BOARD_EMPTY,
) -> str:
    """List published sample IDs under each covered ATT&CK technique."""
    if not attck_bars:
        return empty_message
    lines = ["ATT&CK 样本明细（仅已发布）", ""]
    for bar in attck_bars:
        title = bar.key if not bar.label else f"{bar.key}  {bar.label}"
        lines.append(f"{title}  · {bar.sample_count}")
        if bar.extra:
            lines.append("  PH: " + ", ".join(bar.extra))
        for sample_id in bar.sample_ids:
            lines.append(f"  - {sample_id}")
        lines.append("")
    return "\n".join(lines).rstrip()


class _FixedHeader(Header):
    """保留 Header / 命令面板图标；阻止父类 Header._on_click 切换 -tall。"""

    def _on_click(self, event: Click) -> None:  # type: ignore[override]
        # Textual 会沿 MRO 调用所有 _on_click；prevent_default 拦住 Header 的 tall 切换
        event.prevent_default()


class SampleFactoryTui(App[int]):
    TITLE = "EdrEval 样本工厂"
    SUB_TITLE = "AI 驱动生产流水线"
    # 主题只走 Textual 默认：Ctrl+P / 标题栏图标 / 页脚命令面板 → Theme
    theme = "textual-dark"
    # 关闭整屏划选高亮，避免点击拖拽时大块反色像换肤；事件区 TextArea 仍可本地选中
    ALLOW_SELECT = False
    BINDINGS = [
        ("q", "quit", "退出"),
        ("ctrl+s", "start_production", "启动生产"),
        ("ctrl+x", "stop_production", "停止生产"),
        ("ctrl+shift+c", "copy_events", "复制事件"),
    ]
    CSS = """
    #body {
        height: 1fr;
        padding: 1 2;
    }
    #factory-tabs {
        height: 1fr;
    }
    #run-info {
        height: auto;
        padding: 0 1 1 1;
        color: $text-muted;
    }
    #controls {
        height: 3;
        align-vertical: middle;
    }
    #controls Checkbox {
        width: auto;
        margin-right: 3;
    }
    #start, #stop, #copy-events {
        min-width: 12;
        margin-right: 1;
    }
    /* compact 控件仍可能有 hover/active 底色跳变；钉成与常态一致 */
    #controls Checkbox,
    #controls Checkbox:hover,
    #controls Checkbox:focus,
    #controls Checkbox.-active {
        background: $surface !important;
        border: none !important;
        tint: transparent !important;
    }
    #controls Button,
    #controls Button:hover,
    #controls Button:focus,
    #controls Button.-active {
        background: $surface !important;
        color: $foreground !important;
        border: none !important;
        tint: transparent !important;
        text-style: none !important;
    }
    #controls Button.-primary,
    #controls Button.-primary:hover,
    #controls Button.-primary:focus,
    #controls Button.-primary.-active {
        background: $primary !important;
        color: $foreground !important;
        border: none !important;
        tint: transparent !important;
    }
    #controls Button.-error,
    #controls Button.-error:hover,
    #controls Button.-error:focus,
    #controls Button.-error.-active {
        background: $error !important;
        color: $foreground !important;
        border: none !important;
        tint: transparent !important;
        text-style: none !important;
    }
    #progress {
        margin: 1 0;
    }
    #work-area {
        height: 1fr;
    }
    #summary-pane {
        width: 34;
        min-width: 28;
        border-right: solid $border;
        padding: 1 2 0 0;
    }
    #event-pane {
        width: 1fr;
        padding-left: 2;
    }
    .pane-title {
        height: 1;
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }
    .field-label {
        height: 1;
        color: $text-muted;
        margin-top: 1;
    }
    .field-value {
        height: auto;
    }
    #status {
        color: $warning;
        text-style: bold;
    }
    #events {
        height: 1fr;
        border: solid $border;
        padding: 0 1;
        background: $surface;
    }
    #events:focus {
        border: solid $border;
        background: $surface;
    }
    #events .text-area--cursor-line {
        background: transparent;
    }
    #plugin-layout {
        height: 1fr;
    }
    #plugin-input-pane {
        width: 43;
        min-width: 36;
        border-right: solid $border;
        padding-right: 2;
    }
    #plugin-output-pane {
        width: 1fr;
        padding-left: 2;
    }
    #plugin-description {
        height: 7;
        border: solid $border;
    }
    #plugin-urls {
        height: 4;
        border: solid $border;
    }
    #plugin-harness {
        height: 3;
    }
    #plugin-intake-controls, #plugin-author-controls, #plugin-dialogue-controls {
        height: 3;
        align-vertical: middle;
    }
    #plugin-intake-controls Button,
    #plugin-author-controls Button,
    #plugin-dialogue-controls Button {
        min-width: 12;
        margin-right: 1;
    }
    #plugin-approve {
        width: auto;
        margin-right: 2;
    }
    #plugin-message {
        width: 1fr;
    }
    #plugin-conversation {
        height: 7;
        border: solid $border;
    }
    #plugin-request-preview {
        height: 12;
        border: solid $border;
    }
    #plugin-events {
        height: 1fr;
        border: solid $border;
    }
    #plugin-progress {
        margin: 1 0 0 0;
    }
    #plugin-verify-body {
        height: 1fr;
    }
    #plugin-verify-layout {
        height: 1fr;
    }
    #plugin-verify-list-pane {
        width: 58;
        min-width: 42;
        border-right: solid $border;
        padding-right: 2;
    }
    #plugin-verify-detail-pane {
        width: 1fr;
        padding-left: 2;
    }
    #plugin-verify-list {
        height: 1fr;
        min-height: 6;
        border: solid $border;
    }
    #plugin-verify-filter-row {
        height: auto;
        align-vertical: middle;
        margin: 0 0 1 0;
    }
    #plugin-verify-queue {
        width: 22;
        margin: 0 1 0 0;
    }
    #plugin-verify-filter-row Input {
        width: 1fr;
        margin: 0;
    }
    #plugin-verify-controls, #plugin-verify-cleanup-controls,
    #plugin-verify-review-controls, #plugin-verify-promote-controls {
        height: 3;
        align-vertical: middle;
    }
    #plugin-verify-actions {
        height: auto;
        dock: bottom;
        padding-top: 1;
        border-top: solid $border;
    }
    #plugin-verify-controls Button,
    #plugin-verify-cleanup-controls Button,
    #plugin-verify-review-controls Button,
    #plugin-verify-promote-controls Button {
        min-width: 10;
        margin-right: 1;
    }
    #plugin-verify-validate-approve,
    #plugin-verify-cleanup-approve,
    #plugin-verify-review-approve,
    #plugin-verify-promote-approve,
    #plugin-verify-audit,
    #plugin-verify-pinned {
        width: auto;
        margin-right: 2;
    }
    #plugin-verify-identity-row {
        height: 3;
    }
    #plugin-verify-reviewed-by, #plugin-verify-repository, #plugin-verify-revision {
        height: 3;
        width: 1fr;
        margin-right: 1;
    }
    #plugin-verify-source-refs {
        height: 3;
        border: solid $border;
    }
    #plugin-verify-catalog, #plugin-verify-selection {
        height: auto;
        max-height: 3;
        color: $text-muted;
    }
    #plugin-verify-detail {
        height: 1fr;
        min-height: 8;
        border: solid $border;
    }
    #plugin-verify-events {
        height: 1fr;
        min-height: 6;
        border: solid $border;
    }
    #plugin-verify-progress {
        margin: 1 0 0 0;
    }
    #sample-publish-body {
        height: 1fr;
    }
    #sample-publish-layout {
        height: 1fr;
    }
    #sample-publish-list-pane {
        width: 58;
        min-width: 42;
        border-right: solid $border;
        padding-right: 2;
    }
    #sample-publish-detail-pane {
        width: 1fr;
        padding-left: 2;
    }
    #sample-publish-list {
        height: 1fr;
        min-height: 6;
        border: solid $border;
    }
    #sample-publish-filter {
        margin: 0 0 1 0;
    }
    #sample-publish-scope {
        width: 18;
        margin: 0 1 1 0;
    }
    #sample-publish-filter-row {
        height: auto;
        align-vertical: middle;
        margin: 0 0 1 0;
    }
    #sample-publish-filter-row Input {
        width: 1fr;
        margin: 0;
    }
    #sample-publish-controls {
        height: 3;
        align-vertical: middle;
    }
    #sample-publish-controls Button {
        min-width: 10;
        margin-right: 1;
    }
    #sample-publish-select-visible {
        min-width: 12;
    }
    #sample-publish-approve {
        width: auto;
        margin-right: 2;
    }
    #sample-publish-selection, #sample-publish-catalog {
        height: auto;
        color: $text-muted;
    }
    #sample-publish-detail {
        height: 12;
        border: solid $border;
    }
    #sample-publish-events {
        height: 1fr;
        border: solid $border;
    }
    #technique-board-body {
        height: 1fr;
    }
    #technique-board-header {
        height: 3;
        align-vertical: middle;
    }
    #technique-board-summary {
        width: 1fr;
        color: $text-muted;
        height: auto;
    }
    #technique-board-header Button {
        min-width: 10;
        margin-left: 1;
    }
    #technique-board-detail {
        height: 1fr;
        border: solid $border;
        padding: 0 1;
        background: $surface;
    }
    #technique-board-detail:focus {
        border: solid $border;
        background: $surface;
    }
    #technique-board-detail .text-area--cursor-line {
        background: transparent;
    }
    """

    def __init__(self, config_path: str | Path, run_path: str | Path) -> None:
        super().__init__()
        self._config_path = Path(config_path)
        self._run_path = Path(run_path)
        self._inputs: FactoryInputs | None = None
        self._preflight_ready = False
        self._production_active = False
        self._stop_token: ProductionStopToken | None = None
        self._exit_code = 0
        self._event_lines: list[str] = []
        self._plugin_intake: PluginIntakeSession | None = None
        self._plugin_active = False
        self._plugin_event_lines: list[str] = []
        self._plugin_verify_event_lines: list[str] = []
        self._plugin_verify_runs: list[dict[str, object]] = []
        self._produced_samples: list[dict[str, object]] = []
        self._publish_event_lines: list[str] = []
        self._publish_active = False
        self._technique_board_copy_lines: list[str] = []
        self._technique_board_html_path: Path | None = None

    def compose(self) -> ComposeResult:
        yield _FixedHeader(show_clock=False)
        with Vertical(id="body"):
            yield Static(
                f"配置  {self._config_path}\n请求  {self._run_path}",
                id="run-info",
            )
            with TabbedContent(id="factory-tabs"):
                with TabPane("插件生成", id="plugin-tab"), Horizontal(id="plugin-layout"):
                    with Vertical(id="plugin-input-pane"):
                        yield Label("插件需求", classes="pane-title")
                        yield TextArea(
                            id="plugin-description",
                            soft_wrap=True,
                            show_line_numbers=False,
                            compact=True,
                        )
                        yield Label("参考网页（每行一个，可选）", classes="field-label")
                        yield TextArea(
                            id="plugin-urls",
                            soft_wrap=False,
                            show_line_numbers=False,
                            compact=True,
                        )
                        yield Label("Canonical Harness", classes="field-label")
                        yield Input(
                            placeholder="留空则由模型按 TTP 意图选择，后续验证时再绑定",
                            id="plugin-harness",
                        )
                        with Horizontal(id="plugin-intake-controls"):
                            yield Button(
                                "解析需求",
                                id="plugin-intake-start",
                                variant="primary",
                                compact=True,
                            )
                            yield Button(
                                "清空草案",
                                id="plugin-intake-reset",
                                compact=True,
                            )
                        yield Label("补充要求", classes="field-label")
                        with Horizontal(id="plugin-dialogue-controls"):
                            yield Input(id="plugin-message")
                            yield Button(
                                "发送",
                                id="plugin-message-send",
                                disabled=True,
                                compact=True,
                            )
                        yield TextArea(
                            id="plugin-conversation",
                            read_only=True,
                            soft_wrap=True,
                            show_line_numbers=False,
                            compact=True,
                        )
                        with Horizontal(id="plugin-author-controls"):
                            yield Checkbox("人工审批", id="plugin-approve", compact=True)
                            yield Button(
                                "审批并生成",
                                id="plugin-author-start",
                                variant="primary",
                                disabled=True,
                                compact=True,
                            )
                    with Vertical(id="plugin-output-pane"):
                        yield Label("PluginRequest 预览", classes="pane-title")
                        yield TextArea(
                            id="plugin-request-preview",
                            read_only=True,
                            soft_wrap=False,
                            show_line_numbers=True,
                            compact=True,
                        )
                        yield ProgressBar(total=4, show_eta=False, id="plugin-progress")
                        yield Label("插件运行事件", classes="field-label")
                        yield TextArea(
                            id="plugin-events",
                            read_only=True,
                            soft_wrap=True,
                            show_line_numbers=False,
                            compact=True,
                        )
                with TabPane("插件验证", id="plugin-verify-tab"):
                    with Vertical(id="plugin-verify-body"):
                        with Horizontal(id="plugin-verify-layout"):
                            with VerticalScroll(id="plugin-verify-list-pane"):
                                yield Label("已有插件运行", classes="pane-title")
                                yield Static(
                                    "空格勾选。行首队列：待验证=编译成功可跑 Harness；"
                                    "待review=behavior_valid 可入库；待promote=reviewed 可晋升；"
                                    "已入库=dispatchable。默认只列出待验证+待review。",
                                    id="plugin-verify-selection",
                                )
                                with Horizontal(id="plugin-verify-filter-row"):
                                    yield Select[str](
                                        (
                                            ("待验证+待review", "work"),
                                            ("待验证", "validate"),
                                            ("待review", "review"),
                                            ("待promote", "promote"),
                                            ("已入库", "done"),
                                            ("全部", "all"),
                                        ),
                                        value="work",
                                        prompt="队列",
                                        allow_blank=False,
                                        compact=True,
                                        id="plugin-verify-queue",
                                    )
                                    yield Input(
                                        placeholder="过滤：名称 / 短ID / plugin_id / PH / capability",
                                        id="plugin-verify-filter",
                                    )
                                yield SelectionList[str](id="plugin-verify-list")
                                with Horizontal(id="plugin-verify-controls"):
                                    yield Button(
                                        "刷新列表",
                                        id="plugin-verify-refresh",
                                        compact=True,
                                    )
                                    yield Checkbox(
                                        "审批验证",
                                        id="plugin-verify-validate-approve",
                                        compact=True,
                                    )
                                    yield Button(
                                        "运行 Harness",
                                        id="plugin-verify-validate",
                                        variant="primary",
                                        disabled=True,
                                        compact=True,
                                    )
                                with Horizontal(id="plugin-verify-cleanup-controls"):
                                    yield Checkbox(
                                        "审批清理",
                                        id="plugin-verify-cleanup-approve",
                                        compact=True,
                                    )
                                    yield Button(
                                        "清理失败/重复",
                                        id="plugin-verify-cleanup",
                                        variant="warning",
                                        disabled=True,
                                        compact=True,
                                    )
                                yield Label("人工 Review 供应链", classes="field-label")
                                with Horizontal(id="plugin-verify-identity-row"):
                                    yield Input(
                                        placeholder="reviewed_by",
                                        id="plugin-verify-reviewed-by",
                                    )
                                    yield Input(
                                        placeholder="plugin://reviewed/<plugin_id>，可留空",
                                        id="plugin-verify-repository",
                                    )
                                yield Input(
                                    placeholder="source_revision（留空则用 source_digest）",
                                    id="plugin-verify-revision",
                                )
                                yield Label(
                                    "source_refs（每行一个 https/http/doi）",
                                    classes="field-label",
                                )
                                yield TextArea(
                                    id="plugin-verify-source-refs",
                                    soft_wrap=False,
                                    show_line_numbers=False,
                                    compact=True,
                                )
                            with Vertical(id="plugin-verify-detail-pane"):
                                yield Label("Catalog 队列摘要", classes="pane-title")
                                yield Static(
                                    "candidate=[] reviewed=[] dispatchable=[]",
                                    id="plugin-verify-catalog",
                                )
                                yield Label("选中插件详情", classes="field-label")
                                yield TextArea(
                                    id="plugin-verify-detail",
                                    read_only=True,
                                    soft_wrap=False,
                                    show_line_numbers=False,
                                    compact=True,
                                )
                                yield ProgressBar(
                                    total=3, show_eta=False, id="plugin-verify-progress"
                                )
                                yield Label("验证 / review 事件", classes="field-label")
                                yield TextArea(
                                    id="plugin-verify-events",
                                    read_only=True,
                                    soft_wrap=True,
                                    show_line_numbers=False,
                                    compact=True,
                                )
                        with Vertical(id="plugin-verify-actions"):
                            with Horizontal(id="plugin-verify-review-controls"):
                                yield Checkbox(
                                    "审计通过", id="plugin-verify-audit", compact=True
                                )
                                yield Checkbox(
                                    "锁定此版本", id="plugin-verify-pinned", compact=True
                                )
                                yield Checkbox(
                                    "审批 Review",
                                    id="plugin-verify-review-approve",
                                    compact=True,
                                )
                                yield Button(
                                    "Review 入仓",
                                    id="plugin-verify-review",
                                    disabled=True,
                                    compact=True,
                                )
                            with Horizontal(id="plugin-verify-promote-controls"):
                                yield Checkbox(
                                    "审批 Promote",
                                    id="plugin-verify-promote-approve",
                                    compact=True,
                                )
                                yield Button(
                                    "Promote 可调度",
                                    id="plugin-verify-promote",
                                    variant="primary",
                                    disabled=True,
                                    compact=True,
                                )
                with TabPane("样本生产", id="production-tab"):
                    with Horizontal(id="controls"):
                        yield Checkbox("人工审批", id="approve", compact=True)
                        yield Checkbox("高危独立审批", id="high-risk", compact=True)
                        yield Checkbox("输出样本执行日志", id="execution-logging", compact=True)
                        yield Button(
                            "启动生产",
                            id="start",
                            variant="primary",
                            disabled=True,
                            compact=True,
                        )
                        yield Button(
                            "停止生产",
                            id="stop",
                            variant="error",
                            disabled=True,
                            compact=True,
                        )
                        yield Button("复制事件", id="copy-events", variant="default", compact=True)
                    yield ProgressBar(total=8, show_eta=False, id="progress")
                    with Horizontal(id="work-area"):
                        with Vertical(id="summary-pane"):
                            yield Label("运行状态", classes="pane-title")
                            yield Static("预检中", id="status", classes="field-value")
                            yield Label("阶段", classes="field-label")
                            yield Static("配置预检", id="phase", classes="field-value")
                            yield Label("Recipe", classes="field-label")
                            yield Static("-", id="recipe", classes="field-value")
                            yield Label("PH 序列", classes="field-label")
                            yield Static("-", id="ph-ids", classes="field-value")
                            yield Label("原子", classes="field-label")
                            yield Static("-", id="atom-ids", classes="field-value")
                            yield Label("产物", classes="field-label")
                            yield Static("-", id="artifact", classes="field-value")
                        with Vertical(id="event-pane"):
                            yield Label(
                                "审计事件（可选择复制 / Ctrl+Shift+C）", classes="pane-title"
                            )
                            yield TextArea(
                                id="events",
                                read_only=True,
                                soft_wrap=True,
                                show_line_numbers=False,
                                show_cursor=False,
                                tab_behavior="indent",
                                compact=True,
                                highlight_cursor_line=False,
                            )
                with TabPane("样本发布", id="sample-publish-tab"):
                    with Vertical(id="sample-publish-body"):
                        with Horizontal(id="sample-publish-layout"):
                            with VerticalScroll(id="sample-publish-list-pane"):
                                yield Label("已生产样本", classes="pane-title")
                                yield Static(
                                    "默认只显示未发布。过滤 PH/atom 后可「勾选可见」。"
                                    "已发布=已转到 exports/published（含 telemetry 证据）。",
                                    id="sample-publish-selection",
                                )
                                with Horizontal(id="sample-publish-filter-row"):
                                    yield Select[str](
                                        (
                                            ("未发布", "unpublished"),
                                            ("已发布", "published"),
                                            ("全部", "all"),
                                        ),
                                        value="unpublished",
                                        prompt="范围",
                                        allow_blank=False,
                                        compact=True,
                                        id="sample-publish-scope",
                                    )
                                    yield Input(
                                        placeholder="过滤：sample_id / PH / atom / sha256",
                                        id="sample-publish-filter",
                                    )
                                yield SelectionList[str](id="sample-publish-list")
                                with Horizontal(id="sample-publish-controls"):
                                    yield Button(
                                        "刷新列表",
                                        id="sample-publish-refresh",
                                        compact=True,
                                    )
                                    yield Button(
                                        "勾选可见",
                                        id="sample-publish-select-visible",
                                        compact=True,
                                    )
                                    yield Checkbox(
                                        "审批发布",
                                        id="sample-publish-approve",
                                        compact=True,
                                    )
                                    yield Button(
                                        "发布转到",
                                        id="sample-publish-transfer",
                                        variant="primary",
                                        disabled=True,
                                        compact=True,
                                    )
                            with Vertical(id="sample-publish-detail-pane"):
                                yield Label("发布包", classes="pane-title")
                                yield Static(
                                    "未发布=0 已发布=0 · 可见=0",
                                    id="sample-publish-catalog",
                                )
                                yield Label("选中样本详情", classes="field-label")
                                yield TextArea(
                                    id="sample-publish-detail",
                                    read_only=True,
                                    soft_wrap=False,
                                    show_line_numbers=False,
                                    compact=True,
                                )
                                yield Label("发布事件", classes="field-label")
                                yield TextArea(
                                    id="sample-publish-events",
                                    read_only=True,
                                    soft_wrap=True,
                                    show_line_numbers=False,
                                    compact=True,
                                )
                with TabPane("技术看板", id="technique-board-tab"):
                    with Vertical(id="technique-board-body"):
                        with Horizontal(id="technique-board-header"):
                            yield Static(
                                "已发布样本=0 · 覆盖 ATT&CK=0 · 覆盖 PH=0",
                                id="technique-board-summary",
                            )
                            yield Button(
                                "刷新看板",
                                id="technique-board-refresh",
                                compact=True,
                            )
                            yield Button(
                                "导出 HTML",
                                id="technique-board-export",
                                variant="primary",
                                compact=True,
                            )
                            yield Button(
                                "浏览器打开",
                                id="technique-board-open",
                                compact=True,
                            )
                        yield Label(
                            "ATT&CK 图在浏览器中查看（AEL 热力图/Gap/攻击链/靶场 + 适合覆盖按已发布样本着色 + 明细表 PH 行 + 插件状态）",
                            classes="field-label",
                        )
                        yield TextArea(
                            id="technique-board-detail",
                            read_only=True,
                            soft_wrap=True,
                            show_line_numbers=False,
                            show_cursor=False,
                            highlight_cursor_line=False,
                            compact=True,
                        )
        yield Footer()

    def on_mount(self) -> None:
        events = self.query_one("#events", TextArea)
        events.cursor_blink = False
        self.query_one("#plugin-conversation", TextArea).cursor_blink = False
        self.query_one("#plugin-request-preview", TextArea).cursor_blink = False
        self.query_one("#plugin-events", TextArea).cursor_blink = False
        self.query_one("#plugin-verify-detail", TextArea).cursor_blink = False
        self.query_one("#plugin-verify-events", TextArea).cursor_blink = False
        self.query_one("#sample-publish-detail", TextArea).cursor_blink = False
        self.query_one("#sample-publish-events", TextArea).cursor_blink = False
        self.query_one("#technique-board-detail", TextArea).cursor_blink = False
        self._configure_plugin_harness()
        self._update_plugin_buttons()
        self._update_verify_buttons()
        self._refresh_plugin_verify_list()
        self._refresh_publish_list()
        self._run_preflight()

    def _configure_plugin_harness(self) -> None:
        """Bind the plugin page to the operator-configured canonical Harness."""
        try:
            inputs = load_inputs(self._config_path, self._run_path)
            config_path = inputs.config.plugin_harness_config
            if config_path is None:
                return
            harness = VmwarePluginHarnessConfig.load(config_path)
        except Exception as exc:
            self._append_plugin_line(
                f"[Harness 配置不可用] {type(exc).__name__}: {exc}"
            )
            return
        widget = self.query_one("#plugin-harness", Input)
        widget.value = harness.spec.harness_ref
        widget.read_only = True
        self._append_plugin_line(
            f"[Harness 已配置] {harness.spec.harness_ref} · {harness.profile.profile_id}"
        )

    async def action_quit(self) -> None:
        if self._production_active or self._plugin_active or self._publish_active:
            self.query_one("#status", Static).update("生产中，退出已拒绝")
            self._log_line("请先停止生产；当前样本会在安全边界收口后结束。")
            return
        self.exit(result=self._exit_code)

    def action_start_production(self) -> None:
        self._try_start_production()

    def action_stop_production(self) -> None:
        self._try_stop_production()

    def action_copy_events(self) -> None:
        self._copy_events_to_clipboard()

    @on(Button.Pressed, "#copy-events")
    def _copy_pressed(self) -> None:
        self._copy_events_to_clipboard()

    @on(Button.Pressed, "#plugin-intake-start")
    def _plugin_intake_start_pressed(self) -> None:
        self._try_start_plugin_intake()

    @on(Button.Pressed, "#plugin-intake-reset")
    def _plugin_intake_reset_pressed(self) -> None:
        if self._plugin_active:
            self.notify("插件流程运行中，不能清空草案", severity="warning")
            return
        self._plugin_intake = None
        self.query_one("#plugin-approve", Checkbox).value = False
        self.query_one("#plugin-description", TextArea).load_text("")
        self.query_one("#plugin-urls", TextArea).load_text("")
        self.query_one("#plugin-message", Input).value = ""
        self.query_one("#plugin-conversation", TextArea).load_text("")
        self.query_one("#plugin-request-preview", TextArea).load_text("")
        self.query_one("#plugin-events", TextArea).load_text("")
        self.query_one("#plugin-progress", ProgressBar).update(progress=0)
        self._plugin_event_lines.clear()
        self._set_plugin_intake_fields_disabled(False)
        self._update_plugin_buttons()
        self._update_start_button()

    @on(Button.Pressed, "#plugin-message-send")
    def _plugin_message_pressed(self) -> None:
        self._try_continue_plugin_intake()

    @on(Input.Submitted, "#plugin-message")
    def _plugin_message_submitted(self) -> None:
        self._try_continue_plugin_intake()

    @on(Checkbox.Changed, "#plugin-approve")
    def _plugin_approval_changed(self) -> None:
        self._update_plugin_buttons()

    @on(Button.Pressed, "#plugin-author-start")
    def _plugin_author_start_pressed(self) -> None:
        self._try_start_plugin_authoring()

    @on(Button.Pressed, "#plugin-verify-refresh")
    def _plugin_verify_refresh_pressed(self) -> None:
        self._refresh_plugin_verify_list()

    @on(Button.Pressed, "#plugin-verify-cleanup")
    def _plugin_verify_cleanup_pressed(self) -> None:
        self._try_start_plugin_cleanup()

    @on(Button.Pressed, "#plugin-verify-validate")
    def _plugin_verify_validate_pressed(self) -> None:
        self._try_start_plugin_validation()

    @on(Button.Pressed, "#plugin-verify-review")
    def _plugin_verify_review_pressed(self) -> None:
        self._try_start_plugin_review()

    @on(Button.Pressed, "#plugin-verify-promote")
    def _plugin_verify_promote_pressed(self) -> None:
        self._try_start_plugin_promote()

    @on(Checkbox.Changed, "#plugin-verify-cleanup-approve")
    @on(Checkbox.Changed, "#plugin-verify-validate-approve")
    @on(Checkbox.Changed, "#plugin-verify-review-approve")
    @on(Checkbox.Changed, "#plugin-verify-promote-approve")
    @on(Checkbox.Changed, "#plugin-verify-audit")
    @on(Checkbox.Changed, "#plugin-verify-pinned")
    def _plugin_verify_approval_changed(self) -> None:
        self._update_verify_buttons()

    @on(SelectionList.SelectedChanged, "#plugin-verify-list")
    def _plugin_verify_selection_changed(self) -> None:
        self._render_plugin_verify_detail()
        self._update_verify_buttons()

    @on(Input.Changed, "#plugin-verify-filter")
    def _plugin_verify_filter_changed(self) -> None:
        self._render_plugin_verify_options()

    @on(Select.Changed, "#plugin-verify-queue")
    def _plugin_verify_queue_changed(self) -> None:
        self._render_plugin_verify_options()

    @on(Button.Pressed, "#sample-publish-refresh")
    def _sample_publish_refresh_pressed(self) -> None:
        self._refresh_publish_list()

    @on(Button.Pressed, "#technique-board-refresh")
    def _technique_board_refresh_pressed(self) -> None:
        self._refresh_publish_list()

    @on(Button.Pressed, "#technique-board-export")
    def _technique_board_export_pressed(self) -> None:
        self._export_technique_board(open_browser=False)

    @on(Button.Pressed, "#technique-board-open")
    def _technique_board_open_pressed(self) -> None:
        self._export_technique_board(open_browser=True)

    @on(Button.Pressed, "#sample-publish-select-visible")
    def _sample_publish_select_visible_pressed(self) -> None:
        self._select_visible_unpublished()

    @on(Button.Pressed, "#sample-publish-transfer")
    def _sample_publish_transfer_pressed(self) -> None:
        self._try_start_sample_transfer()

    @on(Checkbox.Changed, "#sample-publish-approve")
    def _sample_publish_approval_changed(self) -> None:
        self._update_publish_buttons()

    @on(SelectionList.SelectedChanged, "#sample-publish-list")
    def _sample_publish_selection_changed(self) -> None:
        self._render_publish_detail()
        self._update_publish_buttons()

    @on(Input.Changed, "#sample-publish-filter")
    def _sample_publish_filter_changed(self) -> None:
        self._render_publish_options()
        self._update_publish_counts()
        self._update_publish_buttons()

    @on(Select.Changed, "#sample-publish-scope")
    def _sample_publish_scope_changed(self) -> None:
        self._render_publish_options()
        self._update_publish_counts()
        self._update_publish_buttons()

    def _copy_events_to_clipboard(self) -> None:
        lines = self._selected_event_lines()
        text = "\n".join(lines).strip()
        if not text:
            self.notify("暂无事件可复制", severity="warning")
            return
        self.copy_to_clipboard(text)
        try:
            active_tab = self.query_one("#factory-tabs", TabbedContent).active
        except Exception:  # pragma: no cover - only reachable before compose
            active_tab = "plugin-tab"
        if active_tab == "technique-board-tab":
            self.notify(f"已复制技术看板 {len(lines)} 行到剪贴板")
            return
        self.notify(f"已复制 {len(lines)} 行事件到剪贴板")

    def _selected_event_lines(self) -> list[str]:
        """Copy the event stream belonging to the currently visible factory mode."""
        try:
            active_tab = self.query_one("#factory-tabs", TabbedContent).active
        except Exception:  # pragma: no cover - only reachable before compose
            active_tab = "plugin-tab"
        if active_tab == "plugin-tab":
            return self._plugin_event_lines
        if active_tab == "plugin-verify-tab":
            return self._plugin_verify_event_lines
        if active_tab == "sample-publish-tab":
            return self._publish_event_lines
        if active_tab == "technique-board-tab":
            return self._technique_board_copy_lines
        return self._event_lines

    def _try_start_plugin_intake(self) -> None:
        if self._production_active:
            self._append_plugin_line("样本生产运行中，不能同时启动插件流程")
            return
        if self._plugin_active:
            self._append_plugin_line("插件流程仍在运行")
            return
        if self._publish_active:
            self._append_plugin_line("样本发布运行中，不能同时启动插件流程")
            return
        description = self.query_one("#plugin-description", TextArea).text.strip()
        if not description:
            self.notify("请先填写插件需求描述", severity="warning")
            return
        harness_value = self.query_one("#plugin-harness", Input).value.strip()
        harness_ref = harness_value or None
        if harness_ref is not None and not harness_ref.startswith("plugin-harness://"):
            self.notify("Canonical Harness 必须是 plugin-harness:// 引用", severity="error")
            return
        source_urls = tuple(
            line.strip()
            for line in self.query_one("#plugin-urls", TextArea).text.splitlines()
            if line.strip()
        )
        self._plugin_active = True
        self._set_plugin_intake_fields_disabled(True)
        self._update_plugin_buttons()
        self._update_start_button()
        self._append_plugin_conversation(f"你: {description}")
        self._append_plugin_line("[需求解析] 正在固化来源并生成结构化 PluginRequest")
        self._run_plugin_intake(description, source_urls, harness_ref)

    @work(thread=True, exclusive=True, group="plugin-intake", exit_on_error=False)
    def _run_plugin_intake(
        self,
        description: str,
        source_urls: tuple[str, ...],
        harness_ref: str,
    ) -> None:
        try:
            session = start_plugin_intake(
                self._config_path,
                self._run_path,
                description=description,
                source_urls=source_urls,
                harness_ref=harness_ref,
            )
        except Exception as exc:
            self.call_from_thread(self._plugin_operation_failed, "需求解析", exc, True)
            return
        self.call_from_thread(self._plugin_intake_ready, session)

    def _try_continue_plugin_intake(self) -> None:
        if self._production_active:
            self._append_plugin_line("样本生产运行中，不能修改插件草案")
            return
        if self._plugin_active or self._plugin_intake is None:
            self.notify("请先完成一次需求解析", severity="warning")
            return
        if self._publish_active:
            self._append_plugin_line("样本发布运行中，不能修改插件草案")
            return
        message = self.query_one("#plugin-message", Input).value.strip()
        if not message:
            self.notify("补充要求不能为空", severity="warning")
            return
        self._plugin_active = True
        self._update_plugin_buttons()
        self._update_start_button()
        self._append_plugin_conversation(f"你: {message}")
        self.query_one("#plugin-message", Input).value = ""
        self._run_plugin_intake_continue(self._plugin_intake.session_id, message)

    @work(thread=True, exclusive=True, group="plugin-intake", exit_on_error=False)
    def _run_plugin_intake_continue(self, session_id: str, message: str) -> None:
        try:
            session = continue_plugin_intake(
                self._config_path,
                session_id=session_id,
                user_message=message,
            )
        except Exception as exc:
            self.call_from_thread(self._plugin_operation_failed, "对话修订", exc, False)
            return
        self.call_from_thread(self._plugin_intake_ready, session)

    def _plugin_intake_ready(self, session: PluginIntakeSession) -> None:
        self._plugin_intake = session
        self._plugin_active = False
        self._append_plugin_conversation(f"Intake Agent: {session.decision.message}")
        request = session.decision.request
        plan = session.decision.decomposition
        preview_model = plan if plan is not None else request
        preview = ""
        if preview_model is not None:
            preview = json.dumps(
                preview_model.model_dump(mode="json"), ensure_ascii=False, indent=2
            )
        self.query_one("#plugin-request-preview", TextArea).load_text(preview)
        if session.decision.status is PluginIntakeStatus.READY:
            self._append_plugin_line(
                f"[合同就绪] {session.session_id}；请核对右侧请求后进行人工审批"
            )
        else:
            self._append_plugin_line("[需要补充] 请在下方输入框回答，然后发送")
        self._update_plugin_buttons()
        self._update_start_button()

    def _try_start_plugin_authoring(self) -> None:
        session = self._plugin_intake
        request = None if session is None else session.decision.request
        plan = None if session is None else session.decision.decomposition
        if self._production_active:
            self._append_plugin_line("样本生产运行中，不能同时启动插件生成")
            return
        if self._plugin_active:
            self._append_plugin_line("插件流程仍在运行")
            return
        if self._publish_active:
            self._append_plugin_line("样本发布运行中，不能同时启动插件生成")
            return
        if (request is None and plan is None) or session is None:
            self.notify("PluginRequest/分解计划尚未就绪", severity="warning")
            return
        if not self.query_one("#plugin-approve", Checkbox).value:
            self.notify("请先勾选插件人工审批", severity="warning")
            return
        self._plugin_active = True
        self._update_plugin_buttons()
        self._update_start_button()
        self.query_one("#plugin-progress", ProgressBar).update(progress=0)
        if plan is not None:
            self._append_plugin_line(
                f"[审批启动] {plan.plan_id} · {len(plan.requests)} 个插件 · "
                f"{len(plan.dependencies)} 条依赖"
            )
            self._run_plugin_authoring(plan)
        else:
            assert request is not None
            self._append_plugin_line(f"[审批启动] {request.request_id}")
            self._run_plugin_authoring(request)

    @work(thread=True, exclusive=True, group="plugin-author", exit_on_error=False)
    def _run_plugin_authoring(self, request: PluginRequest | PluginDecompositionPlan) -> None:
        def sink(event: tuple[str, dict[str, object]]) -> None:
            self.call_from_thread(self._render_plugin_event, event)

        try:
            if isinstance(request, PluginDecompositionPlan):
                results = execute_plugin_decomposition(
                    self._config_path, request, approved=True, sink=sink
                )
            else:
                results = (
                    execute_plugin_authoring_request(
                        self._config_path,
                        request,
                        approved=True,
                        sink=sink,
                    ),
                )
        except Exception as exc:
            self.call_from_thread(self._plugin_operation_failed, "插件生成", exc, False)
            return
        self.call_from_thread(
            self._plugin_authoring_finished,
            [result.model_dump(mode="json") for result in results],
        )

    def _plugin_authoring_finished(self, results: list[dict[str, object]]) -> None:
        self._plugin_active = False
        statuses = [str(result.get("status")) for result in results]
        compile_only = [
            result for result in results if str(result.get("status")) == "compile_valid"
        ]
        self.query_one("#plugin-progress", ProgressBar).update(
            progress=3 if compile_only else 4
        )
        self._append_plugin_line(f"[生成完成] {len(results)} 个插件：{', '.join(statuses)}")
        if compile_only:
            reasons = {str(result.get("compile_only_reason") or "unknown") for result in compile_only}
            harness_ref = self.query_one("#plugin-harness", Input).value.strip()
            if "atom_spec_governance_pending" in reasons:
                harness_status = (
                    f"Harness 已配置（{harness_ref}）"
                    if harness_ref
                    else "Canonical Harness 尚未配置"
                )
                self._append_plugin_line(
                    f"候选已完成受控编译；{harness_status}，但 AtomSpec 治理尚未完成，"
                    "因此尚未执行行为验证，不能声明 behavior_valid 或晋升。"
                )
            elif "independent_harness_not_configured" in reasons:
                self._append_plugin_line(
                    "候选已完成受控编译；未配置独立 Harness，"
                    "不能声明 behavior_valid 或晋升。请到「插件验证」页绑定 Harness。"
                )
            else:
                self._append_plugin_line(
                    "候选已完成受控编译，但本次未执行独立 Harness；"
                    "请到「插件验证」页单独跑 Plugin Harness，再 review / promote。"
                )
        else:
            self._append_plugin_line("候选达到 behavior_valid；仍需到「插件验证」页独立 review 和 promote")
        self.query_one("#plugin-approve", Checkbox).value = False
        self._update_plugin_buttons()
        self._update_start_button()
        self._refresh_plugin_verify_list()

    def _plugin_operation_failed(self, stage: str, exc: Exception, unlock_intake: bool) -> None:
        self._plugin_active = False
        self._exit_code = 1
        self._append_plugin_line(f"[{stage}失败] {type(exc).__name__}: {exc}")
        if unlock_intake and self._plugin_intake is None:
            self._set_plugin_intake_fields_disabled(False)
        self._update_plugin_buttons()
        self._update_start_button()

    def _render_plugin_event(self, event: tuple[str, dict[str, object]]) -> None:
        kind, data = event
        progress, phase = _PHASES.get(kind, (0, kind))
        if progress:
            self.query_one("#plugin-progress", ProgressBar).update(progress=progress)
        title = _EVENT_TITLES.get(kind, phase)
        self._append_plugin_line(f"[{title}]")
        for key in sorted(data):
            value = data[key]
            rendered = (
                json.dumps(value, ensure_ascii=False)
                if isinstance(value, (dict, list))
                else str(value)
            )
            self._append_plugin_line(f"  - {key}: {rendered}")

    def _append_plugin_line(self, text: str) -> None:
        self._plugin_event_lines.append(text)
        area = self.query_one("#plugin-events", TextArea)
        area.load_text((area.text + "\n" if area.text else "") + text)
        area.scroll_end(animate=False)

    def _append_plugin_conversation(self, text: str) -> None:
        area = self.query_one("#plugin-conversation", TextArea)
        area.load_text((area.text + "\n" if area.text else "") + text)
        area.scroll_end(animate=False)

    def _plugin_verify_selected_ids(self) -> tuple[str, ...]:
        widget = self.query_one("#plugin-verify-list", SelectionList)
        return tuple(str(item) for item in widget.selected)

    def _plugin_verify_selected_runs(self) -> list[dict[str, object]]:
        selected = set(self._plugin_verify_selected_ids())
        return [item for item in self._plugin_verify_runs if str(item.get("plugin_run_id")) in selected]

    def _refresh_plugin_verify_list(self) -> None:
        try:
            inventory = list_plugin_inventory(self._config_path)
        except Exception as exc:
            self._append_plugin_verify_line(
                f"[刷新失败] {type(exc).__name__}: {exc}"
            )
            return
        runs = list(inventory.get("runs") or [])
        catalog = inventory.get("catalog") if isinstance(inventory.get("catalog"), dict) else {}
        canonical = select_canonical_plugin_runs(
            [item for item in runs if isinstance(item, dict)]
        )
        hidden = max(0, len(runs) - len(canonical))
        self._plugin_verify_runs = list(canonical)
        self._render_plugin_verify_options()
        self.query_one("#plugin-verify-catalog", Static).update(
            plugin_verify_catalog_summary(canonical, catalog, hidden=hidden)
        )
        if not self._plugin_verify_runs:
            self.query_one("#plugin-verify-detail", TextArea).load_text(
                "暂无 plugin run。请先在「插件生成」页产出 compile_valid 候选。"
            )
        self._render_plugin_verify_detail()
        self._update_verify_buttons()

    def _plugin_verify_queue_scope(self) -> str:
        try:
            value = self.query_one("#plugin-verify-queue", Select).value
        except Exception:  # pragma: no cover - compose 前不会走到
            return "work"
        if value in {"work", "pending", "validate", "review", "promote", "done", "all"}:
            return str(value)
        return "work"

    def _render_plugin_verify_options(self) -> None:
        widget = self.query_one("#plugin-verify-list", SelectionList)
        selected = {str(item) for item in widget.selected}
        try:
            query = self.query_one("#plugin-verify-filter", Input).value
        except Exception:  # pragma: no cover - compose 前不会走到
            query = ""
        scope = self._plugin_verify_queue_scope()
        widget.clear_options()
        ordered = sorted(
            self._plugin_verify_runs,
            key=lambda row: (
                PLUGIN_VERIFY_QUEUE_ORDER.get(plugin_verify_queue(row), 9),
                str(row.get("implementation_name") or ""),
                str(row.get("plugin_id") or ""),
            ),
        )
        for item in ordered:
            plugin_run_id = str(item.get("plugin_run_id") or "")
            if not plugin_run_id:
                continue
            if plugin_run_id not in selected and (
                not plugin_verify_matches_queue(item, scope)
                or not plugin_run_matches_filter(item, query)
            ):
                continue
            widget.add_option(
                Selection(
                    _selection_list_prompt(plugin_verify_option_prompt(item)),
                    plugin_run_id,
                    plugin_run_id in selected,
                )
            )

    def _render_plugin_verify_detail(self) -> None:
        selected = self._plugin_verify_selected_runs()
        if not selected:
            text = (
                "未勾选插件。空格键勾选；左上角队列可只看待验证或待review。"
                "待验证=compile_valid，可跑 Harness；待review=behavior_valid，可入库。"
                "请勾选带 PH 的 TTP；payload 与 loader 无 PH，不能单独跑 Harness，"
                "可只勾 consumer，唯一 producer 会自动带上。"
            )
        else:
            lines = ["已选："]
            for item in selected:
                plugin_run_id = str(item.get("plugin_run_id") or "")
                lines.append(
                    "- "
                    + describe_plugin_run_choice(
                        plugin_run_id,
                        implementation_name=str(item.get("implementation_name") or "-"),
                        plugin_id=(
                            None
                            if item.get("plugin_id") in {None, ""}
                            else str(item.get("plugin_id"))
                        ),
                    )
                    + f" · {plugin_verify_queue_label(item)}"
                    + f" · {item.get('lifecycle_status') or '-'}"
                    + f" · catalog={item.get('catalog_status') or '-'}"
                    + f" · provide={_capability_text(item.get('provided_capabilities'))}"
                    + f" · need={_capability_text(item.get('required_capabilities'))}"
                    + f" · PH={item.get('ph_ids') or '-'}"
                )
            lines.append("")
            lines.append(json.dumps(selected, ensure_ascii=False, indent=2))
            text = "\n".join(lines)
        self.query_one("#plugin-verify-detail", TextArea).load_text(text)

    def _update_verify_buttons(self) -> None:
        busy = self._production_active or self._plugin_active or self._publish_active
        selected = self._plugin_verify_selected_runs()
        cleanup_approved = self.query_one("#plugin-verify-cleanup-approve", Checkbox).value
        validate_approved = self.query_one("#plugin-verify-validate-approve", Checkbox).value
        review_approved = self.query_one("#plugin-verify-review-approve", Checkbox).value
        promote_approved = self.query_one("#plugin-verify-promote-approve", Checkbox).value
        reviewable = [
            item
            for item in selected
            if item.get("lifecycle_status") == "behavior_valid"
            and item.get("catalog_status") not in {"reviewed", "dispatchable"}
        ]
        promotable = [item for item in selected if item.get("catalog_status") == "reviewed"]
        self.query_one("#plugin-verify-refresh", Button).disabled = busy
        self.query_one("#plugin-verify-queue", Select).disabled = busy
        self.query_one("#plugin-verify-filter", Input).disabled = busy
        self.query_one("#plugin-verify-cleanup-approve", Checkbox).disabled = busy
        self.query_one("#plugin-verify-validate-approve", Checkbox).disabled = busy
        self.query_one("#plugin-verify-review-approve", Checkbox).disabled = busy
        self.query_one("#plugin-verify-promote-approve", Checkbox).disabled = busy
        self.query_one("#plugin-verify-cleanup", Button).disabled = busy or not cleanup_approved
        self.query_one("#plugin-verify-validate", Button).disabled = (
            busy or not selected or not validate_approved
        )
        self.query_one("#plugin-verify-review", Button).disabled = (
            busy or not reviewable or not review_approved
        )
        self.query_one("#plugin-verify-promote", Button).disabled = (
            busy or not promotable or not promote_approved
        )

    def _try_start_plugin_cleanup(self) -> None:
        if self._production_active:
            self._append_plugin_verify_line("样本生产运行中，不能同时清理插件运行包")
            return
        if self._plugin_active:
            self._append_plugin_verify_line("插件流程仍在运行")
            return
        if self._publish_active:
            self._append_plugin_verify_line("样本发布运行中，不能同时清理插件运行包")
            return
        if not self.query_one("#plugin-verify-cleanup-approve", Checkbox).value:
            self.notify("请先勾选清理人工审批", severity="warning")
            return
        self._plugin_active = True
        self._update_plugin_buttons()
        self._update_start_button()
        self._append_plugin_verify_line(
            "[审批清理] 删除 FAILED 终态，以及已被更新 behavior_valid 取代的旧 plugin-run"
        )
        self._run_plugin_cleanup()

    @work(thread=True, exclusive=True, group="plugin-verify", exit_on_error=False)
    def _run_plugin_cleanup(self) -> None:
        try:
            result = cleanup_plugin_runs(self._config_path, approved=True)
        except Exception as exc:
            self.call_from_thread(self._plugin_verify_failed, "插件运行包清理", exc)
            return
        self.call_from_thread(
            self._plugin_cleanup_finished,
            result,
            deleted=int(result.get("deleted_count") or 0) > 0,
        )

    def _plugin_cleanup_finished(
        self, payload: Mapping[str, object], *, deleted: bool
    ) -> None:
        self._plugin_active = False
        if deleted:
            deleted_count = int(payload.get("deleted_count") or 0)
            retained_count = int(payload.get("retained_count") or 0)
            self._append_plugin_verify_line(
                f"[清理完成] 删除 {deleted_count} 个失败/重复包，保留 {retained_count} 个"
            )
            for item in payload.get("deleted_runs") or ():
                if not isinstance(item, Mapping):
                    continue
                self._append_plugin_verify_line(
                    f"  - {item.get('plugin_run_id')} "
                    f"[{item.get('implementation_name') or '-'}] "
                    f"{item.get('reason') or ''}"
                )
        else:
            self._append_plugin_verify_line(
                f"[清理跳过] 没有可删候选（保留 {payload.get('retained_count') or 0} 个）"
            )
        self.query_one("#plugin-verify-cleanup-approve", Checkbox).value = False
        self._refresh_plugin_verify_list()
        self._update_plugin_buttons()
        self._update_start_button()

    def _try_start_plugin_validation(self) -> None:
        selected = self._plugin_verify_selected_ids()
        if self._production_active:
            self._append_plugin_verify_line("样本生产运行中，不能同时启动插件验证")
            return
        if self._plugin_active:
            self._append_plugin_verify_line("插件流程仍在运行")
            return
        if self._publish_active:
            self._append_plugin_verify_line("样本发布运行中，不能同时启动插件验证")
            return
        if not selected:
            self.notify("请先勾选要验证的插件运行", severity="warning")
            return
        if not self.query_one("#plugin-verify-validate-approve", Checkbox).value:
            self.notify("请先勾选验证人工审批", severity="warning")
            return
        self._plugin_active = True
        self._update_plugin_buttons()
        self._update_start_button()
        self.query_one("#plugin-verify-progress", ProgressBar).update(progress=0)
        self._append_plugin_verify_line(f"[审批启动 Harness] {', '.join(selected)}")
        self._run_plugin_validation(selected)

    @work(thread=True, exclusive=True, group="plugin-verify", exit_on_error=False)
    def _run_plugin_validation(self, plugin_run_ids: tuple[str, ...]) -> None:
        def sink(event: tuple[str, dict[str, object]]) -> None:
            self.call_from_thread(self._render_plugin_verify_event, event)

        try:
            results = execute_plugin_run_validation(
                self._config_path,
                plugin_run_ids,
                approved=True,
                sink=sink,
            )
        except Exception as exc:
            self.call_from_thread(self._plugin_verify_failed, "Harness 验证", exc)
            return
        self.call_from_thread(
            self._plugin_validation_finished,
            [result.model_dump(mode="json") for result in results],
        )

    def _plugin_validation_finished(self, results: list[dict[str, object]]) -> None:
        self._plugin_active = False
        statuses = [str(item.get("status")) for item in results]
        self.query_one("#plugin-verify-progress", ProgressBar).update(progress=2)
        self._append_plugin_verify_line(
            f"[Harness 完成] {len(results)} 个插件：{', '.join(statuses)}"
        )
        if all(status == "behavior_valid" for status in statuses):
            self._append_plugin_verify_line(
                "已达到 behavior_valid。请核对源码与证据后，单独勾选「审批 Review」写入 reviewed。"
            )
        self.query_one("#plugin-verify-validate-approve", Checkbox).value = False
        self._refresh_plugin_verify_list()
        self._update_plugin_buttons()
        self._update_start_button()

    def _plugin_verify_provenance(self, plugin_id: str, source_digest: str | None) -> PluginProvenance:
        reviewed_by = self.query_one("#plugin-verify-reviewed-by", Input).value.strip()
        repository_ref = self.query_one("#plugin-verify-repository", Input).value.strip()
        source_revision = self.query_one("#plugin-verify-revision", Input).value.strip()
        source_refs = tuple(
            line.strip()
            for line in self.query_one("#plugin-verify-source-refs", TextArea).text.splitlines()
            if line.strip()
        )
        if not reviewed_by:
            raise ValueError("reviewed_by 不能为空")
        if not repository_ref:
            repository_ref = f"plugin://reviewed/{plugin_id}"
        if not source_revision:
            if not source_digest:
                raise ValueError("缺少 source_revision，且所选插件没有 source_digest")
            source_revision = source_digest
        if not source_refs:
            raise ValueError("source_refs 至少需要一行可追溯 URL/DOI")
        return PluginProvenance(
            repository_ref=repository_ref,
            source_revision=source_revision,
            source_refs=source_refs,
            audit_passed=self.query_one("#plugin-verify-audit", Checkbox).value,
            pinned=self.query_one("#plugin-verify-pinned", Checkbox).value,
            reviewed_by=reviewed_by,
            reviewed_at=datetime.now(UTC),
        )

    def _try_start_plugin_review(self) -> None:
        selected = self._plugin_verify_selected_ids()
        if self._production_active or self._plugin_active or self._publish_active:
            self._append_plugin_verify_line("有任务运行中，不能 review")
            return
        if not selected:
            self.notify("请先勾选 behavior_valid 插件", severity="warning")
            return
        if not self.query_one("#plugin-verify-review-approve", Checkbox).value:
            self.notify("请先勾选 Review 人工审批", severity="warning")
            return
        try:
            provenances = []
            for item in self._plugin_verify_selected_runs():
                if item.get("lifecycle_status") != "behavior_valid":
                    continue
                plugin_id = str(item.get("plugin_id") or "")
                if not plugin_id:
                    raise ValueError(f"{item.get('plugin_run_id')} 缺少 plugin_id")
                digest = item.get("source_digest")
                source_digest = digest if isinstance(digest, str) else None
                provenances.append(
                    (
                        str(item.get("plugin_run_id")),
                        self._plugin_verify_provenance(plugin_id, source_digest),
                    )
                )
            if not provenances:
                raise ValueError("没有 behavior_valid 插件可 review")
        except Exception as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        self._plugin_active = True
        self._update_plugin_buttons()
        self._update_start_button()
        self._append_plugin_verify_line(f"[审批 Review] {', '.join(selected)}")
        self._run_plugin_review(tuple(provenances))

    @work(thread=True, exclusive=True, group="plugin-verify", exit_on_error=False)
    def _run_plugin_review(
        self, items: tuple[tuple[str, PluginProvenance], ...]
    ) -> None:
        reviewed: list[dict[str, object]] = []
        try:
            for plugin_run_id, provenance in items:
                try:
                    path = review_plugin_run(
                        self._config_path,
                        plugin_run_id,
                        provenance,
                        approved=True,
                    )
                except Exception as exc:
                    raise ValueError(f"{plugin_run_id}: {exc}") from exc
                reviewed.append(
                    {"plugin_run_id": plugin_run_id, "reviewed_path": path.as_posix()}
                )
        except Exception as exc:
            self.call_from_thread(self._plugin_verify_failed, "Review", exc)
            return
        self.call_from_thread(self._plugin_review_finished, reviewed)

    def _plugin_review_finished(self, reviewed: list[dict[str, object]]) -> None:
        self._plugin_active = False
        self.query_one("#plugin-verify-progress", ProgressBar).update(progress=3)
        for item in reviewed:
            self._append_plugin_verify_line(
                f"[Review 完成] {item['plugin_run_id']} → {item['reviewed_path']}"
            )
        self._append_plugin_verify_line(
            "reviewed 不是可调度状态。请再单独勾选「审批 Promote」写入 dispatchable，样本生产才能选中这些原子。"
        )
        self.query_one("#plugin-verify-review-approve", Checkbox).value = False
        self._refresh_plugin_verify_list()
        self._update_plugin_buttons()
        self._update_start_button()

    def _try_start_plugin_promote(self) -> None:
        selected = self._plugin_verify_selected_runs()
        if self._production_active or self._plugin_active or self._publish_active:
            self._append_plugin_verify_line("有任务运行中，不能 promote")
            return
        plugin_ids = []
        for item in selected:
            if item.get("catalog_status") != "reviewed":
                continue
            plugin_id = str(item.get("plugin_id") or "")
            if not plugin_id:
                self.notify(f"{item.get('plugin_run_id')} 缺少 plugin_id", severity="error")
                return
            plugin_ids.append(plugin_id)
        plugin_ids = list(dict.fromkeys(plugin_ids))
        if not plugin_ids:
            self.notify("请先勾选已 review 的插件", severity="warning")
            return
        if not self.query_one("#plugin-verify-promote-approve", Checkbox).value:
            self.notify("请先勾选 Promote 人工审批（与 Review 必须分开）", severity="warning")
            return
        self._plugin_active = True
        self._update_plugin_buttons()
        self._update_start_button()
        self._append_plugin_verify_line(f"[审批 Promote] {', '.join(plugin_ids)}")
        self._run_plugin_promote(tuple(plugin_ids))

    @work(thread=True, exclusive=True, group="plugin-verify", exit_on_error=False)
    def _run_plugin_promote(self, plugin_ids: tuple[str, ...]) -> None:
        promoted: list[dict[str, object]] = []
        try:
            for plugin_id in plugin_ids:
                path = promote_plugin(self._config_path, plugin_id, approved=True)
                promoted.append(
                    {"plugin_id": plugin_id, "dispatchable_path": path.as_posix()}
                )
                self.call_from_thread(
                    self._render_plugin_verify_event,
                    (
                        "sample_factory_plugin_promoted",
                        {
                            "plugin_id": plugin_id,
                            "dispatchable_path": path.as_posix(),
                        },
                    ),
                )
        except Exception as exc:
            self.call_from_thread(self._plugin_verify_failed, "Promote", exc)
            return
        self.call_from_thread(self._plugin_promote_finished, promoted)

    def _plugin_promote_finished(self, promoted: list[dict[str, object]]) -> None:
        self._plugin_active = False
        self.query_one("#plugin-verify-progress", ProgressBar).update(progress=3)
        for item in promoted:
            self._append_plugin_verify_line(
                f"[Promote 完成] {item['plugin_id']} → {item['dispatchable_path']}"
            )
        self._append_plugin_verify_line(
            "插件已进入 dispatchable。样本生产页预检会读取这些原子；若预检先前失败，请重启 TUI。"
        )
        self.query_one("#plugin-verify-promote-approve", Checkbox).value = False
        self._refresh_plugin_verify_list()
        self._update_plugin_buttons()
        self._update_start_button()

    def _plugin_verify_failed(self, stage: str, exc: Exception) -> None:
        self._plugin_active = False
        self._exit_code = 1
        self._append_plugin_verify_line(f"[{stage}失败] {type(exc).__name__}: {exc}")
        self._update_plugin_buttons()
        self._update_start_button()

    def _render_plugin_verify_event(self, event: tuple[str, dict[str, object]]) -> None:
        kind, data = event
        progress, phase = _PHASES.get(kind, (0, kind))
        if progress:
            self.query_one("#plugin-verify-progress", ProgressBar).update(progress=progress)
        title = _EVENT_TITLES.get(kind, phase)
        self._append_plugin_verify_line(f"[{title}]")
        for key in sorted(data):
            value = data[key]
            rendered = (
                json.dumps(value, ensure_ascii=False)
                if isinstance(value, (dict, list))
                else str(value)
            )
            self._append_plugin_verify_line(f"  - {key}: {rendered}")

    def _append_plugin_verify_line(self, text: str) -> None:
        self._plugin_verify_event_lines.append(text)
        area = self.query_one("#plugin-verify-events", TextArea)
        area.load_text((area.text + "\n" if area.text else "") + text)
        area.scroll_end(animate=False)

    def _publish_selected_ids(self) -> tuple[str, ...]:
        widget = self.query_one("#sample-publish-list", SelectionList)
        return tuple(str(item) for item in widget.selected)

    def _publish_selected_samples(self) -> list[dict[str, object]]:
        selected = set(self._publish_selected_ids())
        return [
            item for item in self._produced_samples if str(item.get("sample_id")) in selected
        ]

    def _publish_scope(self) -> str:
        value = self.query_one("#sample-publish-scope", Select).value
        if value in {"unpublished", "published", "all"}:
            return str(value)
        return "unpublished"

    def _visible_publish_samples(self) -> list[dict[str, object]]:
        query = self.query_one("#sample-publish-filter", Input).value
        scope = self._publish_scope()
        selected = set(self._publish_selected_ids())
        visible: list[dict[str, object]] = []
        for item in sorted(
            self._produced_samples,
            key=lambda row: (
                produced_sample_is_published(row),
                str(row.get("sample_id") or ""),
            ),
        ):
            sample_id = str(item.get("sample_id") or "")
            if not sample_id:
                continue
            if sample_id not in selected and (
                not produced_sample_matches_scope(item, scope)
                or not produced_sample_matches_filter(item, query)
            ):
                continue
            visible.append(item)
        return visible

    def _refresh_publish_list(self) -> None:
        try:
            inventory = list_produced_samples(self._config_path)
        except Exception as exc:
            self._append_publish_line(f"[刷新失败] {type(exc).__name__}: {exc}")
            return
        samples = list(inventory.get("samples") or [])
        self._produced_samples = [item for item in samples if isinstance(item, dict)]
        self._render_publish_options()
        self._update_publish_counts()
        self._render_publish_detail()
        self._update_publish_buttons()
        self._render_technique_board()

    def _coverage_registry(self) -> CoverageRegistry | None:
        if self._inputs is None:
            return None
        try:
            return CoverageRegistry.from_markdown(self._inputs.config.coverage_matrix)
        except Exception:
            return None

    def _render_technique_board(self) -> None:
        coverage = self._coverage_registry()
        published_count, attck_count, ph_count = published_coverage_summary(
            self._produced_samples
        )
        scope = len(coverage.rows) if coverage is not None else PH_MATRIX_ROW_COUNT
        summary = (
            f"已发布样本={published_count} · 覆盖 ATT&CK={attck_count} · "
            f"覆盖 PH={ph_count}/{scope}"
        )
        detail = render_covered_board_text(coverage, self._produced_samples)
        self.query_one("#technique-board-summary", Static).update(summary)
        self.query_one("#technique-board-detail", TextArea).load_text(detail)
        self._technique_board_copy_lines = [summary, "", detail]
        self._update_technique_board_buttons()

    def _technique_board_destination(self) -> Path:
        if self._inputs is None:
            inputs = load_inputs(self._config_path, self._run_path)
            return inputs.config.runtime_root / "exports" / "technique-board.html"
        return self._inputs.config.runtime_root / "exports" / "technique-board.html"

    def _export_technique_board(self, *, open_browser: bool) -> None:
        coverage = self._coverage_registry()
        if coverage is None:
            self.notify("预检未通过，无法读取 PH 覆盖矩阵", severity="error")
            return
        try:
            plugin_runs: list[dict[str, object]] = []
            try:
                inventory = list_plugin_inventory(self._config_path)
                plugin_runs = [
                    item
                    for item in list(inventory.get("runs") or [])
                    if isinstance(item, dict)
                ]
            except Exception:
                plugin_runs = []
            plugins = collect_factory_plugin_board_rows(coverage, plugin_runs)
            path = write_published_attck_board(
                self._technique_board_destination(),
                coverage,
                self._produced_samples,
                plugins,
            )
        except Exception as exc:
            self.notify(f"导出失败：{type(exc).__name__}: {exc}", severity="error", markup=False)
            return
        self._technique_board_html_path = path
        self._update_technique_board_buttons()
        self.notify(f"已导出 {path}")
        if not open_browser:
            return
        opened = webbrowser.open(path.as_uri())
        if not opened:
            self.notify("无法打开浏览器，请手动打开导出的 HTML", severity="warning")

    def _update_technique_board_buttons(self) -> None:
        busy = self._production_active or self._plugin_active or self._publish_active
        ready = self._inputs is not None
        self.query_one("#technique-board-refresh", Button).disabled = busy
        self.query_one("#technique-board-export", Button).disabled = busy or not ready
        self.query_one("#technique-board-open", Button).disabled = busy or not ready

    def _update_publish_counts(self) -> None:
        unpublished = sum(
            1 for item in self._produced_samples if not produced_sample_is_published(item)
        )
        published = sum(
            1 for item in self._produced_samples if produced_sample_is_published(item)
        )
        visible = len(self._visible_publish_samples())
        selected = len(self._publish_selected_ids())
        self.query_one("#sample-publish-catalog", Static).update(
            f"未发布={unpublished} 已发布={published} · 可见={visible} 已选={selected}"
        )

    def _render_publish_options(self) -> None:
        widget = self.query_one("#sample-publish-list", SelectionList)
        selected = set(self._publish_selected_ids())
        widget.clear_options()
        for item in self._visible_publish_samples():
            sample_id = str(item.get("sample_id") or "")
            widget.add_option(
                Selection(
                    _selection_list_prompt(produced_sample_option_prompt(item)),
                    sample_id,
                    sample_id in selected,
                )
            )

    def _render_publish_detail(self) -> None:
        selected = self._publish_selected_samples()
        if not selected:
            text = (
                "未勾选样本。默认只列出未发布；可切到「已发布」或「全部」。"
                "过滤后点「勾选可见」批量勾选当前列表中的未发布样本。"
                "转到目录：runtime/exports/published/export-<sample_id>/"
            )
        else:
            lines = ["已选："]
            for item in selected:
                lines.append(
                    "- "
                    + produced_sample_status_label(item)
                    + " "
                    + str(item.get("sample_id") or "-")
                    + f" · PH={item.get('ph_sequence') or '-'}"
                    + f" · atoms={item.get('atom_ids') or '-'}"
                )
            lines.append("")
            lines.append(json.dumps(selected, ensure_ascii=False, indent=2))
            text = "\n".join(lines)
        self.query_one("#sample-publish-detail", TextArea).load_text(text)

    def _update_publish_buttons(self) -> None:
        busy = self._production_active or self._plugin_active or self._publish_active
        unpublished_visible = [
            item
            for item in self._visible_publish_samples()
            if not produced_sample_is_published(item)
        ]
        selected = [
            item
            for item in self._publish_selected_samples()
            if not produced_sample_is_published(item)
        ]
        approved = self.query_one("#sample-publish-approve", Checkbox).value
        self.query_one("#sample-publish-refresh", Button).disabled = busy
        self.query_one("#sample-publish-filter", Input).disabled = busy
        self.query_one("#sample-publish-scope", Select).disabled = busy
        self.query_one("#sample-publish-select-visible", Button).disabled = (
            busy or not unpublished_visible
        )
        self.query_one("#sample-publish-approve", Checkbox).disabled = busy
        self.query_one("#sample-publish-transfer", Button).disabled = (
            busy or not selected or not approved
        )
        self._update_technique_board_buttons()

    def _select_visible_unpublished(self) -> None:
        if self._production_active or self._plugin_active or self._publish_active:
            self._append_publish_line("有任务运行中，不能批量勾选")
            return
        widget = self.query_one("#sample-publish-list", SelectionList)
        ids = [
            str(item.get("sample_id") or "")
            for item in self._visible_publish_samples()
            if not produced_sample_is_published(item)
        ]
        ids = [item for item in ids if item]
        if not ids:
            self.notify("当前可见列表没有未发布样本", severity="warning")
            return
        for sample_id in ids:
            widget.select(sample_id)
        self._render_publish_detail()
        self._update_publish_counts()
        self._update_publish_buttons()
        self._append_publish_line(f"[勾选可见] 未发布 {len(ids)} 个")

    def _try_start_sample_transfer(self) -> None:
        selected = [
            str(item.get("sample_id") or "")
            for item in self._publish_selected_samples()
            if item.get("export_status") != "published"
        ]
        selected = [item for item in selected if item]
        if self._production_active:
            self._append_publish_line("样本生产运行中，不能同时发布转到")
            return
        if self._plugin_active:
            self._append_publish_line("插件流程仍在运行，不能同时发布转到")
            return
        if self._publish_active:
            self._append_publish_line("发布转到仍在进行")
            return
        if not selected:
            self.notify("请先勾选尚未发布的 SUCCESS 样本", severity="warning")
            return
        if not self.query_one("#sample-publish-approve", Checkbox).value:
            self.notify("请先勾选「审批发布」", severity="warning")
            return
        self._publish_active = True
        self._update_publish_buttons()
        self._update_plugin_buttons()
        self._update_verify_buttons()
        self._update_start_button()
        self._append_publish_line("[审批发布转到] " + ", ".join(selected))
        self._run_sample_transfer(tuple(selected))

    @work(thread=True, exclusive=True, group="sample-publish", exit_on_error=False)
    def _run_sample_transfer(self, sample_ids: tuple[str, ...]) -> None:
        try:
            transferred = transfer_produced_samples(
                self._config_path,
                sample_ids,
                approved=True,
            )
        except Exception as exc:
            self.call_from_thread(self._sample_transfer_failed, exc)
            return
        self.call_from_thread(self._sample_transfer_finished, transferred)

    def _sample_transfer_finished(self, transferred: tuple[dict[str, object], ...]) -> None:
        self._publish_active = False
        for item in transferred:
            self._append_publish_line(
                f"[已发布转到] {item.get('sample_id')} → {item.get('export_ref')}"
            )
            self._append_publish_line(f"  - path: {item.get('artifact_path')}")
        self.query_one("#sample-publish-approve", Checkbox).value = False
        self._refresh_publish_list()
        self._update_plugin_buttons()
        self._update_verify_buttons()
        self._update_start_button()

    def _sample_transfer_failed(self, exc: Exception) -> None:
        self._publish_active = False
        self._exit_code = 1
        self._append_publish_line(f"[发布转到失败] {type(exc).__name__}: {exc}")
        self._update_publish_buttons()
        self._update_plugin_buttons()
        self._update_verify_buttons()
        self._update_start_button()

    def _append_publish_line(self, text: str) -> None:
        self._publish_event_lines.append(text)
        area = self.query_one("#sample-publish-events", TextArea)
        area.load_text((area.text + "\n" if area.text else "") + text)
        area.scroll_end(animate=False)

    def _set_plugin_intake_fields_disabled(self, disabled: bool) -> None:
        self.query_one("#plugin-description", TextArea).disabled = disabled
        self.query_one("#plugin-urls", TextArea).disabled = disabled
        self.query_one("#plugin-harness", Input).disabled = disabled

    def _update_plugin_buttons(self) -> None:
        ready = (
            self._plugin_intake is not None
            and self._plugin_intake.decision.status is PluginIntakeStatus.READY
            and (
                self._plugin_intake.decision.request is not None
                or self._plugin_intake.decision.decomposition is not None
            )
        )
        approved = self.query_one("#plugin-approve", Checkbox).value
        busy = self._production_active or self._plugin_active or self._publish_active
        self.query_one("#plugin-intake-start", Button).disabled = (
            busy or self._plugin_intake is not None
        )
        self.query_one("#plugin-intake-reset", Button).disabled = busy
        self.query_one("#plugin-message", Input).disabled = busy or self._plugin_intake is None
        self.query_one("#plugin-message-send", Button).disabled = (
            busy or self._plugin_intake is None
        )
        self.query_one("#plugin-approve", Checkbox).disabled = busy or not ready
        self.query_one("#plugin-author-start", Button).disabled = (
            self._production_active or self._plugin_active or self._publish_active or not ready or not approved
        )
        self._update_verify_buttons()
        self._update_publish_buttons()

    @work(thread=True, exclusive=True, group="preflight", exit_on_error=False)
    def _run_preflight(self) -> None:
        try:
            inputs = load_inputs(self._config_path, self._run_path)
            summary = preflight(inputs)
        except Exception as exc:
            self.call_from_thread(self._preflight_failed, exc)
            return
        self.call_from_thread(self._preflight_passed, inputs, summary)

    def _preflight_passed(self, inputs: FactoryInputs, summary: dict[str, object]) -> None:
        self._inputs = inputs
        self._preflight_ready = True
        self.query_one("#execution-logging", Checkbox).value = inputs.run.execution_logging
        self.query_one("#status", Static).update("等待人工审批")
        self.query_one("#phase", Static).update("预检通过")
        self._log_event("preflight_ready", summary)
        self._log_line("提示: 勾选「人工审批」后点「启动生产」或按 Ctrl+S")
        self._update_start_button()
        self._render_technique_board()

    def _preflight_failed(self, exc: Exception) -> None:
        self._exit_code = 3
        self.query_one("#status", Static).update("预检失败")
        self.query_one("#phase", Static).update(type(exc).__name__)
        self._log_line(str(exc))
        self._update_start_button()

    @on(Checkbox.Changed, "#approve")
    def _approval_changed(self) -> None:
        self._update_start_button()
        if self.query_one("#approve", Checkbox).value and self._preflight_ready:
            self._log_line("已勾选人工审批，「启动生产」可用")

    @on(Checkbox.Changed, "#execution-logging")
    def _execution_logging_changed(self, event: Checkbox.Changed) -> None:
        state = "开启" if event.value else "关闭"
        self._log_line(f"样本执行日志已{state}；该选择会改变编译输入和样本指纹")

    def _update_start_button(self) -> None:
        approved = self.query_one("#approve", Checkbox).value
        enabled = (
            self._preflight_ready
            and approved
            and not self._production_active
            and not self._plugin_active
            and not self._publish_active
        )
        self.query_one("#start", Button).disabled = not enabled
        stop_enabled = (
            self._production_active
            and self._stop_token is not None
            and not self._stop_token.is_stop_requested
        )
        self.query_one("#stop", Button).disabled = not stop_enabled

    @on(Button.Pressed, "#start")
    def _start_pressed(self) -> None:
        self._try_start_production()

    @on(Button.Pressed, "#stop")
    def _stop_pressed(self) -> None:
        self._try_stop_production()

    def _try_stop_production(self) -> None:
        if not self._production_active or self._stop_token is None:
            self._log_line("忽略停止：当前没有生产任务")
            return
        if self._stop_token.is_stop_requested:
            self._log_line("忽略停止：停止请求已发出")
            return
        self._stop_token.request_stop()
        self.query_one("#status", Static).update("正在停止生产")
        self.query_one("#phase", Static).update("等待当前安全阶段结束")
        self._log_event(
            "production_stop_requested",
            {"mode": "cooperative", "current_sample": "finish_safely"},
        )
        self._update_start_button()

    def _try_start_production(self) -> None:
        if self._production_active:
            self._log_line("忽略启动：本轮生产仍在进行")
            return
        if self._plugin_active:
            self._log_line("忽略启动：插件流程仍在进行")
            return
        if self._publish_active:
            self._log_line("忽略启动：样本发布仍在进行")
            return
        if not self._preflight_ready or self._inputs is None:
            self._log_line("忽略启动：预检未通过")
            self.query_one("#status", Static).update("预检未通过，无法启动")
            return
        if not self.query_one("#approve", Checkbox).value:
            self._log_line("忽略启动：尚未勾选「人工审批」")
            self.query_one("#status", Static).update("请先勾选人工审批")
            return

        high_risk = self.query_one("#high-risk", Checkbox).value
        execution_logging = self.query_one("#execution-logging", Checkbox).value
        self._stop_token = ProductionStopToken()
        self._production_active = True
        self._update_start_button()
        self._update_plugin_buttons()
        self.query_one("#approve", Checkbox).disabled = True
        self.query_one("#high-risk", Checkbox).disabled = True
        self.query_one("#execution-logging", Checkbox).disabled = True
        self.query_one("#status", Static).update("生产中")
        self.query_one("#phase", Static).update("启动流水线")
        self._log_event(
            "production_start_requested",
            {
                "high_risk_approved": high_risk,
                "execution_logging": execution_logging,
                "worker_id": self._inputs.run.worker_id,
            },
        )
        self._run_production(high_risk, execution_logging)

    @work(thread=True, exclusive=True, group="production", exit_on_error=False)
    def _run_production(self, high_risk_approved: bool, execution_logging: bool) -> None:
        assert self._inputs is not None

        def sink(event: tuple[str, dict[str, object]]) -> None:
            self.call_from_thread(self._render_event, event)

        try:
            result = execute_production(
                self._inputs,
                approved=True,
                high_risk_approved=high_risk_approved,
                execution_logging=execution_logging,
                sink=sink,
                stop_token=self._stop_token,
            )
        except ProductionStopped as exc:
            self.call_from_thread(
                self._production_stopped,
                {"batch": False, "produced": False, "phase": exc.phase},
            )
            return
        except Exception as exc:
            self.call_from_thread(self._production_failed, exc)
            return
        payload = result_payload(result)
        if bool(payload.get("stopped")) or (
            self._stop_token is not None
            and self._stop_token.is_stop_requested
            and not bool(payload.get("produced"))
        ):
            self.call_from_thread(self._production_stopped, payload)
            return
        self.call_from_thread(self._production_finished, payload)

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.group != "production":
            return
        if event.state is WorkerState.ERROR:
            error = event.worker.error
            self._production_failed(
                error if isinstance(error, Exception) else RuntimeError(str(error))
            )
        elif event.state is WorkerState.CANCELLED and self._production_active:
            self._production_active = False
            self.query_one("#status", Static).update("生产被取消")
            self._log_line("production worker cancelled")
            self._unlock_controls()

    def _render_event(self, event: tuple[str, dict[str, object]]) -> None:
        kind, data = event
        progress, phase = _PHASES.get(kind, (0, kind))
        if progress:
            self.query_one("#progress", ProgressBar).update(progress=progress)
            self.query_one("#phase", Static).update(phase)
        recipe_id = data.get("recipe_id")
        if recipe_id:
            self.query_one("#recipe", Static).update(str(recipe_id))
        ph_ids = data.get("ph_ids")
        if isinstance(ph_ids, list):
            self.query_one("#ph-ids", Static).update(" > ".join(str(item) for item in ph_ids))
        atom_ids = data.get("atom_ids")
        if isinstance(atom_ids, list):
            self.query_one("#atom-ids", Static).update("\n".join(str(item) for item in atom_ids))
        artifact = data.get("artifact_sha256")
        if artifact:
            self.query_one("#artifact", Static).update(str(artifact))
        if kind in _AGENT_ACTIVITY_EVENTS:
            self._log_agent_activity(kind, data)
        else:
            self._log_event(kind, data)
        if kind == "sample_factory_compile_failed":
            self._append_compile_diagnostics(data)

    def _append_compile_diagnostics(self, data: dict[str, object]) -> None:
        diagnostics_ref = data.get("diagnostics_ref")
        attempt = data.get("attempt")
        max_attempts = data.get("max_attempts")
        self._log_line(
            f"说明: 编译失败不是终态；流水线会自动让 AI 修复代码并重试 "
            f"({attempt}/{max_attempts})。只有耗尽重试才会记 COMPILE_FAIL。"
        )
        run_id = data.get("run_id")
        attempt_id = data.get("attempt_id")
        text = self._read_diagnostics(
            diagnostics_ref if isinstance(diagnostics_ref, str) else None,
            run_id=run_id if isinstance(run_id, str) else None,
            attempt_id=attempt_id if isinstance(attempt_id, str) else None,
        )
        if text:
            self._log_line("—— 编译诊断 ——")
            for line in text.strip().splitlines():
                self._log_line(line.rstrip())
            self._log_line("—— 诊断结束 ——")

    def _read_diagnostics(
        self,
        diagnostics_ref: str | None,
        *,
        run_id: str | None,
        attempt_id: str | None,
    ) -> str | None:
        if not diagnostics_ref or self._inputs is None or run_id is None or attempt_id is None:
            return None
        if not diagnostics_ref.startswith("build-diagnostics://"):
            return None
        build_id = diagnostics_ref.removeprefix("build-diagnostics://").strip("/")
        if (
            not build_id
            or "/" in build_id
            or "\\" in build_id
            or not re.fullmatch(r"run-[a-z0-9-]{8,79}", run_id)
            or not re.fullmatch(r"attempt-[a-z0-9-]{8,79}", attempt_id)
        ):
            return None
        matches = tuple(
            self._inputs.config.runtime_root.glob(
                f"runs/*/*/*/{run_id}/attempts/*-{attempt_id}/build/{build_id}/diagnostics.txt"
            )
        )
        if len(matches) != 1:
            return None
        raw = matches[0].read_bytes()
        for encoding in ("utf-8", "gb18030", "utf-16"):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="replace")

    def _production_stopped(self, payload: dict[str, object]) -> None:
        self._production_active = False
        self._exit_code = 130
        produced_value = payload.get("produced_count", 0)
        requested_value = payload.get("requested_count", 0)
        produced_count = produced_value if isinstance(produced_value, int) else 0
        requested_count = requested_value if isinstance(requested_value, int) else 0
        if payload.get("batch"):
            status = f"生产已停止 {produced_count}/{requested_count}"
        else:
            status = "生产已停止"
        self.query_one("#status", Static).update(status)
        self.query_one("#phase", Static).update("安全停止")
        self._log_event("production_stopped", payload)
        self._unlock_controls()

    def _production_finished(self, payload: dict[str, object]) -> None:
        self._production_active = False
        produced = bool(payload["produced"])
        self._exit_code = 0 if produced else 2
        if payload.get("batch"):
            produced_count = payload.get("produced_count", 0)
            requested_count = payload.get("requested_count", 0)
            status = (
                f"批量生产完成 {produced_count}/{requested_count}"
                if produced
                else f"批量生产未完成 {produced_count}/{requested_count}"
            )
        else:
            status = "生产成功" if produced else "生产未通过"
        self.query_one("#status", Static).update(status)
        if produced:
            self.query_one("#progress", ProgressBar).update(progress=8)
        artifact_ref = payload.get("artifact_ref")
        if artifact_ref:
            prefix = (
                f"{payload.get('produced_count', 0)} 个新样本\n" if payload.get("batch") else ""
            )
            self.query_one("#artifact", Static).update(prefix + str(artifact_ref))
        self._log_event("production_result", payload)
        taxonomy = payload.get("failure_taxonomy")
        if not produced and taxonomy == "RUNTIME_CRASH":
            self._log_line(
                "说明: RUNTIME_CRASH 来自本机构建宿主未做沙箱执行验证，不等于编译失败。"
                "若审计中已有 verification_started.artifact_sha256，对应构建产物通常已在 "
                "runtime/runs/<date>/<run_id>/attempts/<attempt_id>/build/<build_id>/ 下生成，"
                "只是未发布到 runtime/store、未记 SUCCESS。"
            )
        self._unlock_controls()

    def _production_failed(self, exc: Exception) -> None:
        self._production_active = False
        self._exit_code = 1
        self.query_one("#status", Static).update("生产异常")
        self.query_one("#phase", Static).update(type(exc).__name__)
        self._log_line(f"{type(exc).__name__}: {exc}")
        self._unlock_controls()

    def _unlock_controls(self) -> None:
        self.query_one("#approve", Checkbox).disabled = False
        self.query_one("#high-risk", Checkbox).disabled = False
        self.query_one("#execution-logging", Checkbox).disabled = False
        self._stop_token = None
        self._update_start_button()
        self._update_plugin_buttons()
        self._refresh_publish_list()

    def _log_event(self, kind: str, data: dict[str, object]) -> None:
        title = _EVENT_TITLES.get(kind, kind)
        self._log_line(f"[{title}] {kind}")
        for key in sorted(data):
            value = data[key]
            if isinstance(value, (dict, list)):
                rendered = json.dumps(value, ensure_ascii=False)
            else:
                rendered = str(value)
            self._log_line(f"  - {key}: {rendered}")

    def _log_agent_activity(self, kind: str, data: dict[str, object]) -> None:
        title = _EVENT_TITLES.get(kind, kind)
        turn = data.get("turn")
        session_ref = data.get("session_ref")
        suffix = f" · 回合 {turn}" if isinstance(turn, int) else ""
        self._log_line(f"[{title}{suffix}]")
        content = str(data.get("content", "")).strip()
        if content:
            self._log_line(f"  {content}")
        if session_ref and kind == "sample_factory_coding_session":
            state = "续接" if data.get("resumed") else "新会话"
            self._log_line(f"  {state}: {session_ref}")

    def _log_line(self, text: str) -> None:
        self._event_lines.append(text)
        area = self.query_one("#events", TextArea)
        existing = area.text
        area.load_text((existing + "\n" if existing else "") + text)
        area.scroll_end(animate=False)


def run_tui(config_path: str | Path, run_path: str | Path) -> int:
    result = SampleFactoryTui(config_path, run_path).run()
    return 0 if result is None else result


__all__ = ["SampleFactoryTui", "run_tui"]
