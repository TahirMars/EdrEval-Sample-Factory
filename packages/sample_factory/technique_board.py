"""Published-sample ATT&CK board: splice AEL planning views, PH table, plugin overlay."""

from __future__ import annotations

import html
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from packages.sample_factory.catalog import CoverageRegistry, CoverageRow, PH_MATRIX_ROW_COUNT
from packages.sample_factory.plugin_models import PluginRequest
from packages.sample_factory.plugin_run_select import (
    PLUGIN_LIFECYCLE_RANK as _PLUGIN_STATUS_RANK,
    plugin_run_sort_key,
)

_PH_FAMILY_RE = re.compile(r"^PH-([A-Z]{2})[0-9]{2}$")
_ATTACK_URL_RE = re.compile(
    r"https?://attack\.mitre\.org/techniques/T(\d+)(?:/(\d+))?/?",
    re.IGNORECASE,
)

# 14 战术列与 docs/superpowers/specs/attack-coverage-board.html 的 TACTICS 一致。
ATTACK_TACTICS: tuple[tuple[str, str], ...] = (
    ("RE", "Reconnaissance"),
    ("RD", "Resource Development"),
    ("IA", "Initial Access"),
    ("EX", "Execution"),
    ("PS", "Persistence"),
    ("PE", "Privilege Escalation"),
    ("DE", "Defense Evasion"),
    ("CA", "Credential Access"),
    ("DI", "Discovery"),
    ("LM", "Lateral Movement"),
    ("CO", "Collection"),
    ("C2", "Command and Control"),
    ("EF", "Exfiltration"),
    ("IM", "Impact"),
)

# PH 族前缀 → 战术列，与 attack-coverage-board.html 各 PH 行的 tac 字段一致。
# IN/HJ/BL/OB 在矩阵中按第一战术归入 Defense Evasion，不另开战术列。
_PH_FAMILY_TO_TACTIC = {
    "IA": "IA",
    "EX": "EX",
    "PS": "PS",
    "PE": "PE",
    "IN": "DE",
    "HJ": "DE",
    "BL": "DE",
    "OB": "DE",
    "DI": "DI",
    "IT": "C2",
}

# 明细表 / TUI 默认只预览前几个 sample_id；完整列表进 HTML 侧栏，避免 1000+ 撑爆单元格。
_SAMPLE_ID_INLINE_LIMIT = 3
_SAMPLE_ID_TEXT_PREVIEW = 8

# 种子里出现、矩阵尚未建行的 ATT&CK → 官方第一战术。不得据此发明 PH 号。
_NO_PH_ATTACK_TACTIC: dict[str, str] = {}

_IMPLEMENTED_PLUGIN_STATUSES = frozenset(
    {"behavior_valid", "reviewed", "dispatchable"}
)
_PLUGIN_STATUS_LABELS = {
    "seed_only": "仅种子",
    "requested": "已请求",
    "scaffolded": "已搭架",
    "compile_valid": "编译通过",
    "contract_valid": "合同有效",
    "atom_valid": "原子有效",
    "behavior_valid": "行为有效",
    "reviewed": "已评审",
    "dispatchable": "可调度",
    "failed": "失败",
    "deprecated": "已弃用",
    "revoked": "已撤销",
}

# 矩阵 §4：无 PH 行的官方战术不虚构卡片，只标一期范围处置。
_OUT_OF_SCOPE_TACTICS: dict[str, str] = {
    "RE": "超出主机执行链（PRE 阶段归 AD 矩阵 R 族与后续批次）",
    "RD": "超出主机执行链（基础设施侧，不入本矩阵）",
    "CA": "域侧行已在 AD 矩阵（HT-P01/P02 等），主机侧浏览器凭据（T1555.003）列 P3 候选",
    "LM": "域侧行已在 AD 矩阵（E 族/X 族），不重复建行",
    "CO": "超出本矩阵主机执行链范围",
    "EF": "超出范围",
    "IM": "超出本矩阵主机执行链范围",
}

# 与 attack-coverage-board.html 的 FAMS 一致。
_PH_FAMILY_NAMES = {
    "IA": "投递载体",
    "EX": "执行引擎",
    "PS": "主机持久化",
    "IN": "注入与内存执行",
    "PE": "提权",
    "HJ": "劫持与代理执行",
    "BL": "防御致盲",
    "OB": "混淆免杀",
    "DI": "主机立足点发现",
    "IT": "主机侧工具传入",
}

_AEL_BOARD_HTML = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "superpowers"
    / "specs"
    / "ael-eval-board-tech.html"
)
_AEL_TAB_HANDLER = (
    'document.querySelectorAll(".tabs .tab").forEach(t=>t.onclick=()=>{\n'
    '  document.querySelectorAll(".tabs .tab").forEach(x=>x.classList.remove("on"));'
    "t.classList.add(\"on\");\n"
    '  ["v-heat","v-gap","v-chain","v-lab","v-cover-hf","v-cover"]'
    ".forEach(v=>document.getElementById(v).hidden=(v!==t.dataset.v));\n"
    '  if(t.dataset.v==="v-cover-hf") renderCoverHf();\n'
    '  if(t.dataset.v==="v-cover") renderCover();\n'
    "});\n"
)

_BOARD_CSS = """
html,body{width:100%;max-width:100%}
#app{min-width:0;max-width:100%;overflow:hidden}
.tabs{flex-wrap:wrap;z-index:6;position:relative;flex:0 0 auto}
.tabs .tab{flex:0 0 auto;pointer-events:auto}
.view{min-width:0;position:relative;z-index:0}
.banner.factory{padding:6px 14px;background:rgba(63,185,80,.08);border-bottom:1px solid var(--border);
  color:var(--txt2);font-size:12px;flex:0 0 auto}
.banner.factory b{color:var(--green)}
.banner.factory code{font-family:var(--mono);color:var(--cyan)}
.plugin-summary{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}
tr.plugin-impl td{background:rgba(57,210,192,.08)}
tr.plugin-gap td{color:var(--txt2)}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}
.filters select,.filters input{background:var(--bg3);color:var(--txt);border:1px solid var(--border);
  border-radius:6px;padding:4px 8px;font-size:12px;font-family:inherit}
.cnt{font-family:var(--mono);font-size:11px;color:var(--txt3);align-self:center}
td.sid{white-space:normal;max-width:280px}
.sample-open{background:var(--bg3);color:var(--hi);border:1px solid var(--border);
  border-radius:4px;padding:2px 8px;cursor:pointer;font-family:var(--mono);font-size:11px}
.sample-open:hover{border-color:var(--hi)}
.sid-preview{color:var(--txt3);font-size:10px;font-family:var(--mono);margin-top:3px}
tr.covered-row td{background:var(--greenbg)}
tr.uncovered-row td{color:var(--txt2)}
tr.flash td{outline:1px solid var(--hi)}
#sample-drawer{position:fixed;inset:0;z-index:120}
#sample-drawer[hidden]{display:none}
.drawer-scrim{position:absolute;inset:0;background:rgba(1,4,9,.55)}
.drawer-panel{position:absolute;top:0;right:0;width:min(440px,100%);height:100%;
  background:var(--bg2);border-left:1px solid var(--border);display:flex;flex-direction:column;
  padding:12px 14px}
.drawer-panel header{display:flex;align-items:center;gap:8px;margin-bottom:8px}
#drawer-title{flex:1;font-weight:600;font-family:var(--mono);font-size:12px}
.drawer-tools{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.drawer-tools input{flex:1;min-width:140px;background:var(--bg3);color:var(--txt);
  border:1px solid var(--border);border-radius:6px;padding:4px 8px;font-size:12px}
.drawer-tools button,.drawer-panel header button{background:var(--bg3);color:var(--txt);
  border:1px solid var(--border);border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px}
#drawer-cnt{font-family:var(--mono);font-size:11px;color:var(--txt3)}
#drawer-list{flex:1;overflow:auto;margin:8px 0 0;padding:0;list-style:none;
  font-family:var(--mono);font-size:11px}
#drawer-list li{padding:3px 4px;border-bottom:1px solid var(--border2);word-break:break-all}
#drawer-copy-msg{font-size:11px;color:var(--green);min-height:16px}
"""


@dataclass(frozen=True)
class AelBoardParts:
    style: str
    banner: str
    views: str
    drawer: str
    script: str


def load_ael_board_parts(path: Path | None = None) -> AelBoardParts:
    """Split ael-eval-board-tech.html so factory export can splice views as-is."""
    source = path or _AEL_BOARD_HTML
    text = source.read_text(encoding="utf-8")
    style_match = re.search(r"<style>(.*?)</style>", text, re.S)
    banner_match = re.search(r'<div class="banner">.*?</div>', text, re.S)
    views_start = text.find('<div class="view" id="v-heat">')
    drawer_start = text.find('<div class="drawer" id="drawer">')
    script_start = text.find("<script>")
    script_end = text.find("</script>", script_start)
    if (
        style_match is None
        or banner_match is None
        or views_start < 0
        or drawer_start < 0
        or script_start < 0
        or script_end < 0
    ):
        raise ValueError(f"cannot split AEL board views from {source}")
    views = text[views_start:drawer_start].rstrip()
    if views.endswith("</div>"):
        views = views[: views.rfind("</div>")].rstrip()
    if 'id="v-cover"' not in views or 'id="v-chain"' not in views:
        raise ValueError(f"AEL board views incomplete in {source}")
    return AelBoardParts(
        style=style_match.group(1),
        banner=banner_match.group(0),
        views=views,
        drawer=text[drawer_start:script_start].strip(),
        script=text[script_start + len("<script>") : script_end],
    )


def patch_ael_tab_script(script: str) -> str:
    """Drop AEL's 6-view tab binder so factory showTab can include 明细表/插件."""
    if _AEL_TAB_HANDLER not in script:
        raise ValueError(
            "ael-eval-board-tech.html tab handler changed; cannot splice factory tabs"
        )
    return script.replace(
        _AEL_TAB_HANDLER,
        "/* factory showTab binds v-heat…v-cover plus v-tab/v-plug */\n",
        1,
    )


def ph_family(ph_id: str) -> str | None:
    match = _PH_FAMILY_RE.match(ph_id)
    if match is None:
        return None
    return match.group(1)


def ph_tactic(ph_id: str) -> str | None:
    family = ph_family(ph_id)
    if family is None:
        return None
    return _PH_FAMILY_TO_TACTIC.get(family)


def _published_samples(
    samples: Sequence[Mapping[str, object]],
) -> tuple[dict[str, object], ...]:
    published: list[dict[str, object]] = []
    for item in samples:
        if str(item.get("export_status") or "") != "published":
            continue
        sample_id = str(item.get("sample_id") or "").strip()
        if not sample_id:
            continue
        published.append(dict(item))
    return tuple(published)


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item).strip() for item in value if str(item).strip())


def _ph_ids_of(item: Mapping[str, object]) -> tuple[str, ...]:
    return _string_tuple(item.get("ph_sequence"))


@dataclass(frozen=True)
class PhCoverageHit:
    sample_ids: tuple[str, ...]
    atom_ids: tuple[str, ...]
    profiles: tuple[str, ...]


def published_ph_hits(
    samples: Sequence[Mapping[str, object]],
) -> dict[str, PhCoverageHit]:
    """Aggregate published samples onto PH ids (first-seen order)."""
    buckets: dict[str, dict[str, list[str]]] = {}
    for item in _published_samples(samples):
        sample_id = str(item.get("sample_id") or "").strip()
        atoms = _string_tuple(item.get("atom_ids"))
        profile = str(item.get("profile_id") or "").strip()
        for ph_id in _ph_ids_of(item):
            bucket = buckets.setdefault(
                ph_id, {"sample_ids": [], "atom_ids": [], "profiles": []}
            )
            if sample_id not in bucket["sample_ids"]:
                bucket["sample_ids"].append(sample_id)
            for atom_id in atoms:
                if atom_id not in bucket["atom_ids"]:
                    bucket["atom_ids"].append(atom_id)
            if profile and profile not in bucket["profiles"]:
                bucket["profiles"].append(profile)
    return {
        ph_id: PhCoverageHit(
            sample_ids=tuple(bucket["sample_ids"]),
            atom_ids=tuple(bucket["atom_ids"]),
            profiles=tuple(bucket["profiles"]),
        )
        for ph_id, bucket in buckets.items()
    }


CoverCat = str
_COVER_CAT_LABELS = {
    "now": "已覆盖（明确）",
    "inherit": "继承覆盖",
    "future": "可转换",
}


def _parent_attack_id(attack_id: str) -> str:
    return attack_id.split(".", 1)[0]


def _unique_strings(values: Sequence[str]) -> tuple[str, ...]:
    seen: list[str] = []
    for item in values:
        text = str(item).strip()
        if text and text not in seen:
            seen.append(text)
    return tuple(seen)


@dataclass(frozen=True)
class AttackCoverLeaf:
    """ATT&CK 细项：PH 分母去重后的 T 号，外加无 PH 的工厂插件 overlay。"""

    attack_id: str
    name: str
    tactic: str | None
    ph_ids: tuple[str, ...]
    sample_ids: tuple[str, ...]
    plugin_ids: tuple[str, ...]
    cat: CoverCat
    hint: str
    note: str
    in_ph51: bool

    @property
    def n(self) -> int:
        return len(self.sample_ids)

    def as_json(self) -> dict[str, object]:
        return {
            "id": self.attack_id,
            "name": self.name,
            "tacs": [] if self.tactic is None else [self.tactic],
            "n": self.n,
            "cat": self.cat,
            "hint": self.hint,
            "note": self.note,
            "ph_ids": list(self.ph_ids),
            "plugin_ids": list(self.plugin_ids),
            "in_ph51": self.in_ph51,
        }


def _cover_name(techniques: Sequence[str], ph_ids: Sequence[str]) -> str:
    names = _unique_strings(techniques)
    if not names:
        return next(iter(ph_ids), "—")
    if len(ph_ids) <= 1 or len(names) == 1:
        return names[0]
    return f"{names[0]} 等{len(ph_ids)}行"


def _cover_hint(
    *,
    cat: CoverCat,
    ph_ids: Sequence[str],
    sample_n: int,
    parent_id: str,
    plugins: Sequence[PluginBoardRow],
    in_ph51: bool,
) -> str:
    ph_label = ", ".join(ph_ids) if ph_ids else "无 PH"
    plugin_n = len(plugins)
    plugin_bit = ""
    if plugin_n:
        best = max(plugins, key=lambda item: _PLUGIN_STATUS_RANK.get(item.lifecycle_status, 0))
        plugin_bit = f" · 插件 {plugin_n} · {_status_label(best.lifecycle_status)}"
    if cat == "now":
        return f"{ph_label} · 样本 {sample_n}{plugin_bit}"
    if cat == "inherit":
        return f"继承 {parent_id} · {ph_label}{plugin_bit}"
    if not in_ph51:
        return f"{ph_label}{plugin_bit}"
    return f"{ph_label} · 未发布{plugin_bit}"


def build_attack_cover_leaves(
    coverage: CoverageRegistry,
    hits: Mapping[str, PhCoverageHit],
    plugins: Sequence[PluginBoardRow] = (),
) -> tuple[AttackCoverLeaf, ...]:
    """PH 分母的 ATT&CK 细项 + 无 PH 插件 overlay；now=已发布样本，不虚构 T 号。"""
    plugins_by_ph: dict[str, list[PluginBoardRow]] = {}
    plugins_by_attack: dict[str, list[PluginBoardRow]] = {}
    for item in plugins:
        for ph_id in item.ph_ids:
            plugins_by_ph.setdefault(ph_id, []).append(item)
        for attack_id in item.attck_ids:
            plugins_by_attack.setdefault(attack_id, []).append(item)

    grouped: dict[str, dict[str, object]] = {}
    for row in coverage.rows.values():
        tactic = ph_tactic(row.ph_id)
        for attack_id in row.attack_ids:
            bucket = grouped.setdefault(
                attack_id,
                {"ph_ids": [], "techniques": [], "tactic": tactic},
            )
            ph_ids = bucket["ph_ids"]
            techniques = bucket["techniques"]
            assert isinstance(ph_ids, list)
            assert isinstance(techniques, list)
            if row.ph_id not in ph_ids:
                ph_ids.append(row.ph_id)
                techniques.append(row.technique)

    published_attack = {
        attack_id
        for attack_id, bucket in grouped.items()
        if any(ph_id in hits for ph_id in bucket["ph_ids"])  # type: ignore[arg-type]
    }

    leaves: list[AttackCoverLeaf] = []
    for attack_id, bucket in grouped.items():
        ph_ids = tuple(bucket["ph_ids"])  # type: ignore[arg-type]
        techniques = tuple(bucket["techniques"])  # type: ignore[arg-type]
        tactic = bucket["tactic"]
        tactic_key = tactic if isinstance(tactic, str) else None
        sample_ids = _unique_strings(
            sample_id
            for ph_id in ph_ids
            if ph_id in hits
            for sample_id in hits[ph_id].sample_ids
        )
        related_plugins: list[PluginBoardRow] = []
        for ph_id in ph_ids:
            related_plugins.extend(plugins_by_ph.get(ph_id, ()))
        related_plugins.extend(plugins_by_attack.get(attack_id, ()))
        plugin_rows = tuple(dict.fromkeys(related_plugins))
        parent_id = _parent_attack_id(attack_id)
        if sample_ids:
            cat: CoverCat = "now"
        elif parent_id != attack_id and parent_id in published_attack:
            cat = "inherit"
        else:
            cat = "future"
        note = ""
        if cat == "inherit":
            note = f"父技术 {parent_id} 已有已发布样本，本子技术尚未单独出样"
        elif cat == "future":
            note = "PH 范围内可转换；尚未发布样本"
        leaves.append(
            AttackCoverLeaf(
                attack_id=attack_id,
                name=_cover_name(techniques, ph_ids),
                tactic=tactic_key,
                ph_ids=ph_ids,
                sample_ids=sample_ids,
                plugin_ids=tuple(item.plugin_id for item in plugin_rows),
                cat=cat,
                hint=_cover_hint(
                    cat=cat,
                    ph_ids=ph_ids,
                    sample_n=len(sample_ids),
                    parent_id=parent_id,
                    plugins=plugin_rows,
                    in_ph51=True,
                ),
                note=note,
                in_ph51=True,
            )
        )

    seen_attack = set(grouped)
    for item in plugins:
        if item.has_ph:
            continue
        for attack_id in item.attck_ids:
            if attack_id in seen_attack:
                continue
            seen_attack.add(attack_id)
            overlay = tuple(
                plugin
                for plugin in plugins
                if not plugin.has_ph and attack_id in plugin.attck_ids
            )
            leaves.append(
                AttackCoverLeaf(
                    attack_id=attack_id,
                    name=overlay[0].implementation_name if overlay else attack_id,
                    tactic=item.tactic,
                    ph_ids=(),
                    sample_ids=(),
                    plugin_ids=tuple(plugin.plugin_id for plugin in overlay),
                    cat="future",
                    hint=_cover_hint(
                        cat="future",
                        ph_ids=(),
                        sample_n=0,
                        parent_id=_parent_attack_id(attack_id),
                        plugins=overlay,
                        in_ph51=False,
                    ),
                    note="无 PH · 不计矩阵分母",
                    in_ph51=False,
                )
            )

    leaves.sort(key=lambda leaf: (leaf.tactic or "zzz", leaf.attack_id))
    return tuple(leaves)


def build_factory_cover_overlay(
    coverage: CoverageRegistry,
    samples: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """已发布样本落到的 T 号。插件未发布不算已覆盖，不把 COVER_PLAN 当生产状态。"""
    hits = published_ph_hits(samples)
    sample_ids_by_attack: dict[str, list[str]] = {}
    ph_ids_by_attack: dict[str, list[str]] = {}
    for row in coverage.rows.values():
        hit = hits.get(row.ph_id)
        if hit is None:
            continue
        for attack_id in row.attack_ids:
            ph_ids = ph_ids_by_attack.setdefault(attack_id, [])
            if row.ph_id not in ph_ids:
                ph_ids.append(row.ph_id)
            bucket = sample_ids_by_attack.setdefault(attack_id, [])
            for sample_id in hit.sample_ids:
                if sample_id not in bucket:
                    bucket.append(sample_id)
    for item in _published_samples(samples):
        sample_id = str(item.get("sample_id") or "").strip()
        if not sample_id:
            continue
        for attack_id in _string_tuple(item.get("attck_ids")):
            bucket = sample_ids_by_attack.setdefault(attack_id, [])
            if sample_id not in bucket:
                bucket.append(sample_id)
    now = list(sample_ids_by_attack)
    hint = {}
    for attack_id, sample_ids in sample_ids_by_attack.items():
        ph_ids = ph_ids_by_attack.get(attack_id) or []
        origin = ", ".join(ph_ids) if ph_ids else "样本自报 ATT&CK"
        hint[attack_id] = f"已发布 {len(sample_ids)} · {origin}"
    return {"now": now, "hint": hint}


def _relabel_ael_cover_views(views: str) -> str:
    """Export-only copy: keep AEL T 号范围，把已覆盖文案改成工厂已发布样本。"""
    return (
        views.replace("策略·已覆盖（明确）", "已覆盖（已发布样本）")
        .replace("策略·继承覆盖", "继承覆盖（父技术已发布）")
        .replace("策略·可转换", "可转换（尚未发布）")
        .replace(
            "按样本工厂 strategy 可覆盖性分类。",
            "按本仓库已发布样本真实覆盖分类（范围仍是 AEL T 号全集）。",
        )
        .replace(
            "显式覆盖表优先，其余按战术/样本工厂映射推断。",
            "绿格只认已发布样本；COVER_PLAN/SF_COVERED 不再当作已覆盖。",
        )
        .replace(
            "分类为规划视图，不承诺实现。",
            "绿=已发布样本覆盖该 T 号，不是规划映射，也不是检出率。",
        )
    )


@dataclass(frozen=True)
class PluginBoardRow:
    plugin_id: str
    implementation_name: str
    role: str
    ph_ids: tuple[str, ...]
    attck_ids: tuple[str, ...]
    tactic: str | None
    lifecycle_status: str
    catalog_status: str | None
    plugin_run_id: str | None
    provided_capabilities: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    origin: str

    @property
    def implemented(self) -> bool:
        return self.lifecycle_status in _IMPLEMENTED_PLUGIN_STATUSES

    @property
    def has_ph(self) -> bool:
        return bool(self.ph_ids)


def default_plugin_seed_requests_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "deployment" / "plugin-seeds" / "requests"


def attack_ids_from_source_refs(refs: Sequence[str]) -> tuple[str, ...]:
    found: list[str] = []
    for ref in refs:
        match = _ATTACK_URL_RE.search(str(ref))
        if match is None:
            continue
        attack_id = f"T{match.group(1)}"
        if match.group(2):
            attack_id = f"{attack_id}.{match.group(2)}"
        if attack_id not in found:
            found.append(attack_id)
    return tuple(found)


def _attack_tactic_index(coverage: CoverageRegistry) -> dict[str, str]:
    index: dict[str, str] = {}
    for row in coverage.rows.values():
        tactic = ph_tactic(row.ph_id)
        if tactic is None:
            continue
        for attack_id in row.attack_ids:
            index.setdefault(attack_id, tactic)
            parent = attack_id.split(".", 1)[0]
            index.setdefault(parent, tactic)
    return index


def tactic_for_plugin(
    ph_ids: Sequence[str],
    attck_ids: Sequence[str],
    coverage: CoverageRegistry,
) -> str | None:
    for ph_id in ph_ids:
        tactic = ph_tactic(ph_id)
        if tactic is not None:
            return tactic
    attack_tactics = _attack_tactic_index(coverage)
    for attack_id in attck_ids:
        parent = attack_id.split(".", 1)[0]
        tactic = (
            attack_tactics.get(attack_id)
            or attack_tactics.get(parent)
            or _NO_PH_ATTACK_TACTIC.get(attack_id)
            or _NO_PH_ATTACK_TACTIC.get(parent)
        )
        if tactic is not None:
            return tactic
    return None


def load_plugin_seed_requests(seeds_dir: str | Path | None = None) -> tuple[PluginRequest, ...]:
    directory = Path(seeds_dir) if seeds_dir is not None else default_plugin_seed_requests_dir()
    if not directory.is_dir():
        return ()
    return tuple(
        PluginRequest.model_validate_json(path.read_bytes())
        for path in sorted(directory.glob("*.json"))
    )


def _pick_plugin_run(
    runs: Sequence[Mapping[str, object]],
) -> Mapping[str, object] | None:
    if not runs:
        return None
    return max(runs, key=plugin_run_sort_key)


def _attck_ids_for_plugin(
    ph_ids: Sequence[str],
    source_refs: Sequence[str],
    coverage: CoverageRegistry,
) -> tuple[str, ...]:
    from_refs = attack_ids_from_source_refs(source_refs)
    if not ph_ids:
        return from_refs
    known = tuple(ph_id for ph_id in ph_ids if ph_id in coverage.rows)
    from_matrix = coverage.attack_ids_for(known) if known else ()
    merged: list[str] = list(from_matrix)
    for attack_id in from_refs:
        if attack_id not in merged:
            merged.append(attack_id)
    return tuple(merged)


def build_plugin_board_rows(
    coverage: CoverageRegistry,
    *,
    seed_requests: Sequence[PluginRequest] = (),
    plugin_runs: Sequence[Mapping[str, object]] = (),
) -> tuple[PluginBoardRow, ...]:
    """Merge seed requests with latest plugin-run status. Unmapped PH is not invented."""
    runs_by_plugin: dict[str, list[Mapping[str, object]]] = {}
    runs_by_name: dict[str, list[Mapping[str, object]]] = {}
    for item in plugin_runs:
        plugin_id = str(item.get("plugin_id") or "").strip()
        name = str(item.get("implementation_name") or "").strip()
        if plugin_id:
            runs_by_plugin.setdefault(plugin_id, []).append(item)
        if name:
            runs_by_name.setdefault(name, []).append(item)
    rows: list[PluginBoardRow] = []
    seen: set[str] = set()
    for request in seed_requests:
        plugin_id = request.seed_plugin_id or f"seed:{request.implementation_name}"
        matched = _pick_plugin_run(
            runs_by_plugin.get(plugin_id) or runs_by_name.get(request.implementation_name) or ()
        )
        ph_ids = request.intent.ph_ids
        attck_ids = _attck_ids_for_plugin(ph_ids, request.intent.source_refs, coverage)
        lifecycle = (
            str(matched.get("lifecycle_status") or "seed_only")
            if matched is not None
            else "seed_only"
        )
        catalog = None if matched is None else matched.get("catalog_status")
        rows.append(
            PluginBoardRow(
                plugin_id=plugin_id,
                implementation_name=request.implementation_name,
                role=request.intent.role.value,
                ph_ids=ph_ids,
                attck_ids=attck_ids,
                tactic=tactic_for_plugin(ph_ids, attck_ids, coverage),
                lifecycle_status=lifecycle,
                catalog_status=None if catalog in {None, ""} else str(catalog),
                plugin_run_id=(
                    None
                    if matched is None
                    else str(matched.get("plugin_run_id") or "") or None
                ),
                provided_capabilities=request.intent.provided_capabilities,
                required_capabilities=request.intent.required_capabilities,
                origin="seed+run" if matched is not None else "seed",
            )
        )
        seen.add(plugin_id)
        seen.add(request.implementation_name)
    for plugin_id, bucket in runs_by_plugin.items():
        if plugin_id in seen:
            continue
        matched = _pick_plugin_run(bucket)
        if matched is None:
            continue
        name = str(matched.get("implementation_name") or plugin_id)
        if name in seen:
            continue
        ph_ids = _string_tuple(matched.get("ph_ids"))
        known_ph = tuple(ph_id for ph_id in ph_ids if ph_id in coverage.rows)
        attck_ids = coverage.attack_ids_for(known_ph) if known_ph else ()
        catalog = matched.get("catalog_status")
        rows.append(
            PluginBoardRow(
                plugin_id=plugin_id,
                implementation_name=name,
                role=str(matched.get("role") or ""),
                ph_ids=ph_ids,
                attck_ids=attck_ids,
                tactic=tactic_for_plugin(ph_ids, attck_ids, coverage),
                lifecycle_status=str(matched.get("lifecycle_status") or "requested"),
                catalog_status=None if catalog in {None, ""} else str(catalog),
                plugin_run_id=str(matched.get("plugin_run_id") or "") or None,
                provided_capabilities=_string_tuple(matched.get("provided_capabilities")),
                required_capabilities=_string_tuple(matched.get("required_capabilities")),
                origin="run",
            )
        )
    rows.sort(key=lambda item: (item.plugin_id, item.implementation_name))
    return tuple(rows)


def collect_factory_plugin_board_rows(
    coverage: CoverageRegistry,
    plugin_runs: Sequence[Mapping[str, object]] = (),
    *,
    seeds_dir: str | Path | None = None,
) -> tuple[PluginBoardRow, ...]:
    return build_plugin_board_rows(
        coverage,
        seed_requests=load_plugin_seed_requests(seeds_dir),
        plugin_runs=plugin_runs,
    )


def published_ph_sample_index(
    samples: Sequence[Mapping[str, object]],
) -> dict[str, tuple[str, ...]]:
    """Map PH ids to unique published sample ids, first-seen order."""
    return {ph_id: hit.sample_ids for ph_id, hit in published_ph_hits(samples).items()}


def render_covered_board_text(
    coverage: CoverageRegistry | None,
    samples: Sequence[Mapping[str, object]],
) -> str:
    """Compact TUI listing of published PH coverage; HTML board is the ATT&CK figure."""
    published = _published_samples(samples)
    index = published_ph_sample_index(samples)
    if coverage is None:
        lines = [
            f"已发布样本={len(published)} · 覆盖矩阵未加载",
            f"范围：Procedure/Host PH {PH_MATRIX_ROW_COUNT}；导出 HTML 合入 ael-eval-board-tech.html 热力图/Gap/攻击链/靶场/适合覆盖。",
            "预检通过后可导出看板。当前仅列出已发布样本自报 PH。",
            "",
        ]
        if not index:
            lines.append("尚无已发布样本。请先在「样本发布」转到 exports/published。")
            return "\n".join(lines)
        lines.append("已发布样本自报 PH：")
        for ph_id, sample_ids in sorted(index.items()):
            lines.append(f"{ph_id}  · 样本 {len(sample_ids)}")
            lines.extend(_preview_sample_id_lines(sample_ids))
        return "\n".join(lines)
    scope_rows = tuple(coverage.rows.values())
    scope_count = len(scope_rows)
    covered_rows = [
        row for row in scope_rows if row.ph_id in index
    ]
    attck_ids = []
    for row in covered_rows:
        for attack_id in row.attack_ids:
            if attack_id not in attck_ids:
                attck_ids.append(attack_id)
    lines = [
        f"已发布样本={len(published)} · 覆盖 PH={len(covered_rows)}/{scope_count or '—'} · "
        f"覆盖 ATT&CK={len(attck_ids)}",
        f"范围：Procedure/Host PH {scope_count}（procedure-host-ttp-coverage-matrix.md）。导出 HTML 合入 ael-eval-board-tech.html 热力图/Gap/攻击链/靶场/适合覆盖。",
        f"明细表绿=已发布样本落入该 PH 行；插件 overlay 不计 {scope_count} 行分母。规划热力不是检测可见性。",
        "",
    ]
    if not covered_rows:
        lines.append(f"尚无已发布样本落入 PH {scope_count} 范围。请先在「样本发布」转到 exports/published。")
        unknown = sorted(ph_id for ph_id in index if ph_id not in coverage.rows)
        if unknown:
            lines.append("矩阵外 PH（不画卡片）：" + ", ".join(unknown))
        return "\n".join(lines)
    lines.append("已覆盖 PH：")
    for row in covered_rows:
        sample_ids = index[row.ph_id]
        attack = ", ".join(row.attack_ids) or "-"
        lines.append(
            f"{row.ph_id}  {attack}  {row.technique}  · 样本 {len(sample_ids)}"
        )
        lines.extend(_preview_sample_id_lines(sample_ids))
    unknown = sorted(ph_id for ph_id in index if ph_id not in coverage.rows)
    if unknown:
        lines.extend(["", "矩阵外 PH（不画卡片）：" + ", ".join(unknown)])
    return "\n".join(lines)


def _preview_sample_id_lines(sample_ids: Sequence[str]) -> list[str]:
    preview = tuple(sample_ids[:_SAMPLE_ID_TEXT_PREVIEW])
    lines = [f"  - {sample_id}" for sample_id in preview]
    extra = len(sample_ids) - len(preview)
    if extra:
        lines.append(f"  … 另 {extra} 个，完整列表见导出 HTML")
    return lines


def _status_label(status: str) -> str:
    return _PLUGIN_STATUS_LABELS.get(status, status)


def _oos_note_html(tactic_key: str) -> str:
    note = _OUT_OF_SCOPE_TACTICS.get(tactic_key)
    if not note:
        return ""
    return f'<div class="oos-note">{html.escape(note)}</div>'


def _cover_agg_cat(cats: Sequence[str]) -> str:
    values = set(cats)
    if "now" in values or "inherit" in values:
        return "now"
    return "future"


def _heat_cell_html(
    leaf: AttackCoverLeaf,
    *,
    tech_level: bool = False,
    sub_count: int = 1,
    agg_cat: str | None = None,
    agg_n: int | None = None,
    agg_name: str | None = None,
) -> str:
    cat = agg_cat or leaf.cat
    attack_id = _parent_attack_id(leaf.attack_id) if tech_level else leaf.attack_id
    name = agg_name if agg_name is not None else leaf.name
    count = leaf.n if agg_n is None else agg_n
    extra = " tech-level" if tech_level else ""
    if not leaf.in_ph51:
        extra += " plugin-only"
    why = ""
    if not tech_level:
        why = f'<span class="covwhy">{html.escape(leaf.hint)}</span>'
    subn = ""
    if tech_level and sub_count > 1:
        subn = f'<span class="subn">{sub_count}×</span>'
    ph_attr = ""
    if leaf.ph_ids:
        ph_attr = f' data-ph="{html.escape(leaf.ph_ids[0], quote=True)}"'
    plugin_attr = ""
    if leaf.plugin_ids and not leaf.in_ph51:
        plugin_attr = f' data-plugin="{html.escape(leaf.plugin_ids[0], quote=True)}"'
    return (
        f'<div class="heat cov-{html.escape(cat, quote=True)}{extra}" '
        f'data-id="{html.escape(attack_id, quote=True)}" '
        f'data-cat="{html.escape(cat, quote=True)}"{ph_attr}{plugin_attr}>'
        f'<span class="nn">{count}</span>{subn}'
        f'<span class="tid">{html.escape(attack_id)}</span>'
        f'<span class="tn">{html.escape(name)}</span>{why}</div>'
    )


def _cover_groups(
    leaves: Sequence[AttackCoverLeaf],
) -> list[tuple[str, str, str, int, tuple[AttackCoverLeaf, ...]]]:
    by_parent: dict[str, list[AttackCoverLeaf]] = {}
    for leaf in leaves:
        by_parent.setdefault(_parent_attack_id(leaf.attack_id), []).append(leaf)
    groups: list[tuple[str, str, str, int, tuple[AttackCoverLeaf, ...]]] = []
    for parent_id, bucket in by_parent.items():
        ordered = tuple(sorted(bucket, key=lambda item: item.attack_id))
        parent_leaf = next((item for item in ordered if item.attack_id == parent_id), ordered[0])
        cat = _cover_agg_cat(item.cat for item in ordered)
        n = max(item.n for item in ordered)
        groups.append((parent_id, cat, parent_leaf.name, n, ordered))
    groups.sort(key=lambda item: (-item[3], item[0]))
    return groups


def _cover_grid_html(leaves: Sequence[AttackCoverLeaf]) -> str:
    groups = _cover_groups(leaves)
    columns: list[str] = []
    for idx, (key, name) in enumerate(ATTACK_TACTICS, start=1):
        tactic_groups = [item for item in groups if any(leaf.tactic == key for leaf in item[4])]
        chips = []
        counts = {"now": 0, "inherit": 0, "future": 0}
        for _pid, cat, _nm, _n, _leaves in tactic_groups:
            counts[cat] = counts.get(cat, 0) + 1
        if counts["now"]:
            chips.append(f'<span class="gapchip tag cov-now">{counts["now"]}</span>')
        if counts["future"]:
            chips.append(f'<span class="gapchip tag cov-future">{counts["future"]}</span>')
        empty_class = " empty" if not tactic_groups else ""
        if tactic_groups:
            body_parts = []
            for parent_id, cat, gname, gn, bucket in tactic_groups:
                head_src = next(
                    (item for item in bucket if item.attack_id == parent_id),
                    bucket[0],
                )
                head = _heat_cell_html(
                    head_src,
                    tech_level=True,
                    sub_count=len(bucket),
                    agg_cat=cat,
                    agg_n=gn,
                    agg_name=gname,
                )
                subs = "".join(_heat_cell_html(item) for item in bucket if item.attack_id != parent_id)
                if not subs and len(bucket) == 1 and bucket[0].attack_id != parent_id:
                    subs = _heat_cell_html(bucket[0])
                body_parts.append(
                    f'<div class="tech-block" data-tech="{html.escape(parent_id, quote=True)}" '
                    f'data-cat="{html.escape(cat, quote=True)}">{head}'
                    f'<div class="subs">{subs}</div></div>'
                )
            body = "".join(body_parts)
        else:
            body = _oos_note_html(key)
        columns.append(
            f'<section class="tac-col{empty_class}" data-tactic="{html.escape(key, quote=True)}">'
            f'<div class="th"><span class="idx">{idx:02d}</span>{html.escape(name)}'
            f'<span class="n">{len(tactic_groups)}</span>{"".join(chips)}</div>'
            f'<div class="bd">{body}</div></section>'
        )
    return f'<div class="grid" id="covergrid">{"".join(columns)}</div>'


def _cover_unmapped_html(leaves: Sequence[AttackCoverLeaf]) -> str:
    groups = [
        item
        for item in _cover_groups(leaves)
        if all(leaf.tactic is None for leaf in item[4])
    ]
    if not groups:
        return '<div class="unmapped" id="cover-unmapped" hidden></div>'
    cells = []
    for _pid, cat, gname, gn, bucket in groups:
        cells.append(
            _heat_cell_html(
                bucket[0],
                tech_level=True,
                sub_count=len(bucket),
                agg_cat=cat,
                agg_n=gn,
                agg_name=gname,
            )
        )
    return (
        f'<div class="unmapped" id="cover-unmapped">'
        f'<div style="font-weight:600;margin-bottom:6px">未映射到 Enterprise 14 战术'
        f'（{len(groups)} technique）</div>'
        f'<div style="display:flex;flex-wrap:wrap;gap:4px">{"".join(cells)}</div></div>'
    )


def _cell(text: str, *, mono: bool = False) -> str:
    klass = ' class="mono"' if mono else ""
    return f"<td{klass}>{html.escape(text) if text else '—'}</td>"


def _join(values: Sequence[str]) -> str:
    return ", ".join(values) if values else ""


def _sample_id_cell(ph_id: str, sample_ids: Sequence[str]) -> str:
    if not sample_ids:
        return '<td class="sid">—</td>'
    count = len(sample_ids)
    preview = html.escape(_join(sample_ids[:_SAMPLE_ID_INLINE_LIMIT]))
    if count <= _SAMPLE_ID_INLINE_LIMIT:
        return f'<td class="sid mono">{preview}</td>'
    ph = html.escape(ph_id, quote=True)
    return (
        f'<td class="sid">'
        f'<button type="button" class="sample-open" data-ph="{ph}">查看 {count} 个</button>'
        f'<div class="sid-preview">{preview} …</div>'
        "</td>"
    )


def _json_script_payload(value: object) -> str:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _tactic_name(tactic: str | None) -> str:
    if not tactic:
        return ""
    return dict(ATTACK_TACTICS).get(tactic, tactic)


def _table_row_html(row: CoverageRow, hit: PhCoverageHit | None) -> str:
    family = ph_family(row.ph_id) or ""
    tactic = ph_tactic(row.ph_id) or ""
    covered = hit is not None
    sample_ids = hit.sample_ids if hit else ()
    atom_ids = hit.atom_ids if hit else ()
    profiles = hit.profiles if hit else ()
    attack = _join(row.attack_ids)
    hay = " ".join(
        [
            row.ph_id,
            attack,
            row.technique,
            family,
            tactic,
            _join(atom_ids),
            _join(profiles),
        ]
    ).lower()
    row_class = "covered-row" if covered else "uncovered-row"
    return (
        f'<tr class="row {row_class}" data-row-ph="{html.escape(row.ph_id, quote=True)}" '
        f'data-covered="{"1" if covered else "0"}" '
        f'data-fam="{html.escape(family, quote=True)}" '
        f'data-tac="{html.escape(tactic, quote=True)}" '
        f'data-hay="{html.escape(hay, quote=True)}">'
        + _cell(row.ph_id, mono=True)
        + _cell(attack or "—", mono=True)
        + _cell(row.technique)
        + _cell(_tactic_name(tactic) or "—")
        + _cell(_PH_FAMILY_NAMES.get(family, family) or "—")
        + _cell("已覆盖" if covered else "未覆盖")
        + _cell(str(len(sample_ids)) if covered else "0", mono=True)
        + _sample_id_cell(row.ph_id, sample_ids)
        + _cell(_join(atom_ids) or "—", mono=True)
        + _cell(_join(profiles) or "—", mono=True)
        + _cell(row.detection_layers)
        + _cell(row.endpoint_visibility)
        + _cell(row.audit_prerequisites)
        + _cell(row.matrix_evasion_tier)
        + _cell(row.expected_signals)
        + "</tr>"
    )


def _plugin_table_row_html(row: PluginBoardRow) -> str:
    tactic = row.tactic or ""
    ph = _join(row.ph_ids)
    attack = _join(row.attck_ids)
    hay = " ".join(
        [
            row.plugin_id,
            row.implementation_name,
            row.role,
            ph,
            attack,
            tactic,
            row.lifecycle_status,
            row.catalog_status or "",
            row.origin,
            _join(row.provided_capabilities),
            _join(row.required_capabilities),
            row.plugin_run_id or "",
        ]
    ).lower()
    row_class = "plugin-impl" if row.implemented else "plugin-gap"
    if not row.has_ph:
        row_class += " plugin-only"
    return (
        f'<tr class="row {row_class}" data-plugin="{html.escape(row.plugin_id, quote=True)}" '
        f'data-status="{html.escape(row.lifecycle_status, quote=True)}" '
        f'data-catalog="{html.escape(row.catalog_status or "none", quote=True)}" '
        f'data-ph="{1 if row.has_ph else 0}" '
        f'data-role="{html.escape(row.role, quote=True)}" '
        f'data-tac="{html.escape(tactic, quote=True)}" '
        f'data-impl="{"1" if row.implemented else "0"}" '
        f'data-hay="{html.escape(hay, quote=True)}">'
        + _cell(row.plugin_id, mono=True)
        + _cell(row.implementation_name)
        + _cell(row.role or "—", mono=True)
        + _cell(ph or "无 PH", mono=True)
        + _cell(attack or "—", mono=True)
        + _cell(_tactic_name(tactic) or "无战术列")
        + _cell(_status_label(row.lifecycle_status))
        + _cell(row.catalog_status or "未入目录")
        + _cell("已实现" if row.implemented else "未实现")
        + _cell(row.origin)
        + _cell(row.plugin_run_id or "—", mono=True)
        + _cell(_join(row.provided_capabilities) or "—", mono=True)
        + _cell(_join(row.required_capabilities) or "—", mono=True)
        + "</tr>"
    )


def _plugin_status_options(plugins: Sequence[PluginBoardRow]) -> str:
    seen: list[str] = []
    for row in plugins:
        if row.lifecycle_status not in seen:
            seen.append(row.lifecycle_status)
    seen.sort(key=lambda item: -_PLUGIN_STATUS_RANK.get(item, 0))
    return "".join(
        f'<option value="{html.escape(status, quote=True)}">'
        f"{html.escape(_status_label(status))}</option>"
        for status in seen
    )


_BOARD_JS = """
function esc(s){
  return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function sampleIds(ph){ return SAMPLE_INDEX[ph] || []; }
function matchQuery(tr,q){
  if(!q) return true;
  if((tr.dataset.hay||"").includes(q)) return true;
  return sampleIds(tr.dataset.rowPh).some(id=>String(id).toLowerCase().includes(q));
}
function showTab(id){
  if(!id) return;
  document.querySelectorAll(".tabs .tab").forEach(x=>x.classList.toggle("on", x.dataset.v===id));
  document.querySelectorAll("#app > .view").forEach(v=>v.hidden = v.id!==id);
  if(id==="v-cover-hf" && typeof renderCoverHf==="function") renderCoverHf();
  if(id==="v-cover" && typeof renderCover==="function") renderCover();
}
function applyFilters(){
  const cov=document.getElementById("f-cov").value;
  const fam=document.getElementById("f-fam").value;
  const tac=document.getElementById("f-tac").value;
  const q=document.getElementById("f-q").value.trim().toLowerCase();
  let shown=0, covered=0;
  document.querySelectorAll("#tabrows tr").forEach(tr=>{
    let ok=true;
    if(cov && tr.dataset.covered!==cov) ok=false;
    if(fam && tr.dataset.fam!==fam) ok=false;
    if(tac && tr.dataset.tac!==tac) ok=false;
    if(!matchQuery(tr,q)) ok=false;
    tr.hidden=!ok;
    if(ok){ shown+=1; if(tr.dataset.covered==="1") covered+=1; }
  });
  document.getElementById("tab-cnt").textContent="显示 "+shown+"/"+PH_ROW_COUNT+" · 已覆盖 "+covered;
}
function applyPluginFilters(){
  const status=document.getElementById("p-status");
  const catalog=document.getElementById("p-catalog");
  const ph=document.getElementById("p-ph");
  const role=document.getElementById("p-role");
  const tac=document.getElementById("p-tac");
  const impl=document.getElementById("p-impl");
  const qel=document.getElementById("p-q");
  if(!status) return;
  const q=(qel.value||"").trim().toLowerCase();
  let shown=0, implemented=0;
  const rows=document.querySelectorAll("#plugrows tr");
  rows.forEach(tr=>{
    let ok=true;
    if(status.value && tr.dataset.status!==status.value) ok=false;
    if(catalog.value && tr.dataset.catalog!==catalog.value) ok=false;
    if(ph.value && tr.dataset.ph!==ph.value) ok=false;
    if(role.value && tr.dataset.role!==role.value) ok=false;
    if(tac.value==="none" && tr.dataset.tac) ok=false;
    if(tac.value && tac.value!=="none" && tr.dataset.tac!==tac.value) ok=false;
    if(impl.value && tr.dataset.impl!==impl.value) ok=false;
    if(q && !(tr.dataset.hay||"").includes(q)) ok=false;
    tr.hidden=!ok;
    if(ok){ shown+=1; if(tr.dataset.impl==="1") implemented+=1; }
  });
  document.getElementById("plug-cnt").textContent="显示 "+shown+"/"+rows.length+" · 已实现 "+implemented;
}
function filteredDrawerIds(){
  const ph=document.getElementById("sample-drawer").dataset.ph||"";
  const q=document.getElementById("drawer-q").value.trim().toLowerCase();
  const ids=sampleIds(ph);
  return q ? ids.filter(id=>String(id).toLowerCase().includes(q)) : ids;
}
function renderDrawerList(){
  const all=sampleIds(document.getElementById("sample-drawer").dataset.ph||"");
  const ids=filteredDrawerIds();
  document.getElementById("drawer-list").innerHTML=ids.map(id=>"<li>"+esc(id)+"</li>").join("");
  document.getElementById("drawer-cnt").textContent="显示 "+ids.length+"/"+all.length;
}
function openSampleDrawer(ph){
  const drawer=document.getElementById("sample-drawer");
  drawer.hidden=false;
  drawer.dataset.ph=ph||"";
  document.getElementById("drawer-title").textContent=(ph||"-")+" · "+sampleIds(ph).length+" 个已发布样本";
  document.getElementById("drawer-q").value="";
  document.getElementById("drawer-copy-msg").textContent="";
  renderDrawerList();
  document.getElementById("drawer-q").focus();
}
function closeSampleDrawer(){ document.getElementById("sample-drawer").hidden=true; }
function copyDrawerIds(){
  const ids=filteredDrawerIds();
  const text=ids.join("\\n");
  const done=()=>{ document.getElementById("drawer-copy-msg").textContent="已复制 "+ids.length+" 个 ID"; };
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(done).catch(()=>{ window.prompt("复制 sample_id", text); done(); });
  } else { window.prompt("复制 sample_id", text); done(); }
}
document.querySelector(".tabs").addEventListener("click", ev=>{
  const t=ev.target.closest(".tab");
  if(!t || !t.dataset.v) return;
  showTab(t.dataset.v);
});
["f-cov","f-fam","f-tac","f-q"].forEach(id=>document.getElementById(id).addEventListener("input", applyFilters));
["p-status","p-catalog","p-ph","p-role","p-tac","p-impl","p-q"].forEach(id=>{
  const el=document.getElementById(id);
  if(el) el.addEventListener("input", applyPluginFilters);
});
document.getElementById("tabrows").addEventListener("click", ev=>{
  const btn=ev.target.closest(".sample-open");
  if(!btn) return;
  ev.preventDefault();
  ev.stopPropagation();
  openSampleDrawer(btn.dataset.ph);
});
document.getElementById("drawer-close").onclick=closeSampleDrawer;
document.getElementById("drawer-scrim").onclick=closeSampleDrawer;
document.getElementById("drawer-q").addEventListener("input", renderDrawerList);
document.getElementById("drawer-copy").onclick=copyDrawerIds;
document.addEventListener("keydown", ev=>{
  if(ev.key!=="Escape") return;
  closeSampleDrawer();
  const ael=document.getElementById("drawer");
  if(ael) ael.classList.remove("open");
});
applyFilters();
applyPluginFilters();
(function applyFactoryCover(){
  if(typeof classifyCover!=="function") return;
  const _aelClassify=classifyCover;
  const _aelStrategy=typeof coverStrategyLabel==="function"?coverStrategyLabel:null;
  const nowIds=(FACTORY_COVER&&FACTORY_COVER.now)||[];
  const hints=(FACTORY_COVER&&FACTORY_COVER.hint)||{};
  const nowSet=new Set(nowIds);
  function parentOf(id){ return String(id).split(".")[0]; }
  function factoryCat(tid){
    if(nowSet.has(tid)) return "now";
    const parent=parentOf(tid);
    const familyPublished=nowSet.has(parent)||nowIds.some(id=>parentOf(id)===parent);
    if(!familyPublished) return "";
    if(tid===parent) return "now";
    return "inherit";
  }
  classifyCover=function(t){
    const base=_aelClassify(t);
    const fact=factoryCat(t.id);
    if(fact==="now"){
      return Object.assign({}, base, {
        cat:"now",
        hint:hints[t.id]||hints[parentOf(t.id)]||("已发布样本 · "+t.id),
        note:"工厂已发布样本覆盖该 T 号",
        src:"factory-now"
      });
    }
    if(fact==="inherit" && base.cat!=="unsuitable" && base.cat!=="postex"){
      return Object.assign({}, base, {
        cat:"inherit",
        hint:"继承 "+parentOf(t.id)+" · 尚无本子技术已发布样本",
        note:"父技术已有已发布样本，本子技术尚未单独出样",
        src:"factory-inherit"
      });
    }
    if(base.cat==="now"||base.cat==="inherit"){
      return Object.assign({}, base, {
        cat:"future",
        note:"规划可转换；工厂尚无已发布样本",
        src:"factory-gap"
      });
    }
    return base;
  };
  if(_aelStrategy){
    coverStrategyLabel=function(row){
      if(row && (row.src==="factory-now"||row.src==="factory-inherit")) return row.hint||"";
      if(row && (row.cat==="now"||row.cat==="inherit") && hints[row.id]) return hints[row.id];
      return _aelStrategy(row);
    };
  }
  if(typeof COVER_CAT!=="undefined"){
    COVER_CAT.now.label="已覆盖（已发布样本）";
    COVER_CAT.now.short="已覆盖";
    COVER_CAT.inherit.label="继承覆盖（父技术已发布）";
    COVER_CAT.inherit.short="继承";
    COVER_CAT.future.label="可转换（尚未发布）";
    COVER_CAT.future.short="可转换";
  }
  if(typeof renderCoverHf==="function") renderCoverHf();
  if(typeof renderCover==="function") renderCover();
})();
"""


def render_published_attck_board_html(
    coverage: CoverageRegistry,
    samples: Sequence[Mapping[str, object]],
    plugins: Sequence[PluginBoardRow] = (),
) -> str:
    """AEL 规划视图原样合入 + PH 明细表 + 工厂插件状态。"""
    ael = load_ael_board_parts()
    published = _published_samples(samples)
    hits = published_ph_hits(samples)
    plugin_rows = tuple(plugins)
    covered_rows = [row for row in coverage.rows.values() if row.ph_id in hits]
    unknown_ph = sorted(ph_id for ph_id in hits if ph_id not in coverage.rows)
    leaves = build_attack_cover_leaves(coverage, hits, plugin_rows)
    attck_ids = [leaf.attack_id for leaf in leaves if leaf.cat == "now"]
    generated = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    source = html.escape(coverage.source_ref)
    unknown_note = ""
    if unknown_ph:
        unknown_note = (
            " 矩阵外 PH 已忽略、不虚构技术："
            + html.escape(", ".join(unknown_ph))
            + "。"
        )
    table_rows = [
        _table_row_html(row, hits.get(row.ph_id)) for row in coverage.rows.values()
    ]
    family_options = []
    seen_families: list[str] = []
    for row in coverage.rows.values():
        family = ph_family(row.ph_id)
        if not family or family in seen_families:
            continue
        seen_families.append(family)
        label = _PH_FAMILY_NAMES.get(family, family)
        family_options.append(
            f'<option value="{html.escape(family, quote=True)}">'
            f"{html.escape(label)}</option>"
        )
    tactic_options = "".join(
        f'<option value="{html.escape(key, quote=True)}">{html.escape(name)}</option>'
        for key, name in ATTACK_TACTICS
    )
    sample_index = {
        row.ph_id: list(hits[row.ph_id].sample_ids)
        for row in coverage.rows.values()
        if row.ph_id in hits
    }
    sample_index_js = _json_script_payload(sample_index)
    overlay_js = _json_script_payload(build_factory_cover_overlay(coverage, samples))
    implemented_n = sum(1 for item in plugin_rows if item.implemented)
    no_ph_n = sum(1 for item in plugin_rows if not item.has_ph)
    no_tac_n = sum(1 for item in plugin_rows if item.tactic is None)
    seed_only_n = sum(1 for item in plugin_rows if item.lifecycle_status == "seed_only")
    plugin_table = "".join(_plugin_table_row_html(item) for item in plugin_rows)
    role_options = []
    seen_roles: list[str] = []
    for item in plugin_rows:
        if not item.role or item.role in seen_roles:
            continue
        seen_roles.append(item.role)
        role_options.append(
            f'<option value="{html.escape(item.role, quote=True)}">'
            f"{html.escape(item.role)}</option>"
        )
    ph_n = len(coverage.rows)
    factory_banner = (
        '<div class="banner factory">工厂增量：明细表分母仍是 '
        f"<code>procedure-host-ttp-coverage-matrix.md</code> PH {ph_n}，插件 overlay 不计 {ph_n}。"
        "热力图 / 战术 Gap / 攻击链 / 靶场需求范围原样合入 "
        "<code>docs/superpowers/specs/ael-eval-board-tech.html</code>。"
        "<b>适合覆盖/转换的绿格=本仓库已发布样本</b>，不是 COVER_PLAN/SF_COVERED 规划映射。"
        "后渗透/不适合仍用 AEL 范围。不计入 PBS 33。本页不是 detected / not_detected。"
        f" 已发布样本权威来源：<code>{source}</code>。{unknown_note}</div>"
    )
    tabs = (
        '<div class="tabs">'
        '<div class="tab on" data-v="v-heat">热力图（AEL T 号）</div>'
        '<div class="tab" data-v="v-gap">战术 Gap（14 列 × AEL 卡）</div>'
        '<div class="tab" data-v="v-chain">攻击链（16 案例）</div>'
        '<div class="tab" data-v="v-lab">靶场需求</div>'
        '<div class="tab" data-v="v-cover-hf">适合覆盖/转换（高频）</div>'
        '<div class="tab" data-v="v-cover">适合覆盖/转换</div>'
        f'<div class="tab" data-v="v-tab">明细表（{ph_n} 行）</div>'
        f'<div class="tab" data-v="v-plug">插件状态（{len(plugin_rows)}）</div>'
        "</div>\n"
    )
    factory_views = (
        '<div class="view" id="v-tab" hidden>\n'
        '<div class="filters">'
        '<select id="f-cov"><option value="">覆盖：全部</option>'
        '<option value="1">已覆盖</option><option value="0">未覆盖</option></select>'
        f'<select id="f-fam"><option value="">技术族：全部</option>{"".join(family_options)}</select>'
        f'<select id="f-tac"><option value="">战术：全部</option>{tactic_options}</select>'
        '<input id="f-q" placeholder="搜索 PH- / T编号 / 名称 / sample_id / atom…">'
        '<span class="cnt" id="tab-cnt"></span></div>\n'
        "<table><thead><tr>"
        "<th>ph_id</th><th>ATT&amp;CK</th><th>技术名/变体</th><th>战术</th><th>族</th>"
        "<th>覆盖</th><th>样本数</th><th>sample_id</th><th>atom_ids</th><th>profile</th>"
        "<th>检测层</th><th>矩阵可见性</th><th>审计前置</th><th>tier</th><th>期望信号</th>"
        "</tr></thead>"
        f'<tbody id="tabrows">{"".join(table_rows)}</tbody></table>\n'
        "</div>\n"
        '<div class="view" id="v-plug" hidden>\n'
        '<div class="plugin-summary">'
        f'<span class="pill">插件 {len(plugin_rows)}</span>'
        f'<span class="pill">行为有效 {implemented_n}</span>'
        f'<span class="pill">仅种子 {seed_only_n}</span>'
        f'<span class="pill">无 PH {no_ph_n}</span>'
        f'<span class="pill">无战术列 {no_tac_n}</span>'
        "</div>\n"
        '<div class="filters">'
        f'<select id="p-status"><option value="">生命周期：全部</option>{_plugin_status_options(plugin_rows)}</select>'
        '<select id="p-catalog"><option value="">目录：全部</option>'
        '<option value="candidate">candidate</option>'
        '<option value="reviewed">reviewed</option>'
        '<option value="dispatchable">dispatchable</option>'
        '<option value="none">未入目录</option></select>'
        '<select id="p-ph"><option value="">PH：全部</option>'
        '<option value="1">有 PH</option><option value="0">无 PH</option></select>'
        f'<select id="p-role"><option value="">角色：全部</option>{"".join(role_options)}</select>'
        f'<select id="p-tac"><option value="">战术：全部</option>{tactic_options}'
        '<option value="none">无战术列</option></select>'
        '<select id="p-impl"><option value="">实现：全部</option>'
        '<option value="1">已实现</option><option value="0">未实现</option></select>'
        '<input id="p-q" placeholder="搜索 plugin_id / 实现名 / PH / T编号 / capability…">'
        '<span class="cnt" id="plug-cnt"></span></div>\n'
        "<table><thead><tr>"
        "<th>plugin_id</th><th>实现名</th><th>角色</th><th>PH</th><th>ATT&amp;CK</th><th>战术</th>"
        "<th>生命周期</th><th>目录</th><th>实现</th><th>来源</th><th>plugin_run_id</th>"
        "<th>provides</th><th>requires</th>"
        "</tr></thead>"
        f'<tbody id="plugrows">{plugin_table}</tbody></table>\n'
        "</div>\n"
    )
    sample_drawer = (
        '<div id="sample-drawer" hidden>'
        '<div class="drawer-scrim" id="drawer-scrim"></div>'
        '<aside class="drawer-panel" role="dialog" aria-labelledby="drawer-title">'
        '<header><div id="drawer-title"></div>'
        '<button type="button" id="drawer-close">关闭</button></header>'
        '<div class="drawer-tools">'
        '<input id="drawer-q" placeholder="过滤 sample_id">'
        '<button type="button" id="drawer-copy">复制当前列表</button>'
        '<span id="drawer-cnt"></span></div>'
        '<div id="drawer-copy-msg"></div>'
        '<ul id="drawer-list"></ul>'
        "</aside></div>\n"
    )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="zh-CN">\n<head>\n'
        '<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        "<title>已发布样本 ATT&amp;CK 覆盖看板</title>\n"
        "<style>"
        + ael.style
        + _BOARD_CSS
        + "</style>\n"
        "</head>\n<body>\n"
        '<div id="app">\n'
        '<div class="hdr"><div class="ttl">AEL 覆盖看板（Technique 层）'
        "<small>热力图 / Gap / 攻击链 / 靶场 / 适合覆盖原样合入 · 明细表 PH "
        f"{ph_n} · 插件 overlay</small></div>"
        '<div class="sp"></div>'
        f'<div class="meta">生成 {html.escape(generated)} · 已发布 {len(published)} · '
        f"覆盖 PH {len(covered_rows)}/{len(coverage.rows)} · "
        f"覆盖 ATT&amp;CK {len(attck_ids)} · "
        f"插件 {len(plugin_rows)} · 行为有效 {implemented_n}</div></div>\n"
        + ael.banner
        + "\n"
        + factory_banner
        + "\n"
        + tabs
        + _relabel_ael_cover_views(ael.views)
        + "\n"
        + factory_views
        + "</div>\n"
        + ael.drawer
        + "\n"
        + sample_drawer
        + "<script>"
        + patch_ael_tab_script(ael.script)
        + "</script>\n"
        + f"<script>const PH_ROW_COUNT={ph_n};\n"
        f"const SAMPLE_INDEX={sample_index_js};\n"
        f"const FACTORY_COVER={overlay_js};\n{_BOARD_JS}</script>\n"
        "</body>\n</html>\n"
    )


def write_published_attck_board(
    destination: str | Path,
    coverage: CoverageRegistry,
    samples: Sequence[Mapping[str, object]],
    plugins: Sequence[PluginBoardRow] = (),
) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        render_published_attck_board_html(coverage, samples, plugins),
        encoding="utf-8",
    )
    return path
