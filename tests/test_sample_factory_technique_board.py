from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.catalog import CoverageRegistry, PH_MATRIX_ROW_COUNT
from packages.sample_factory.technique_board import (
    ATTACK_TACTICS,
    PluginBoardRow,
    attack_ids_from_source_refs,
    build_attack_cover_leaves,
    build_factory_cover_overlay,
    build_plugin_board_rows,
    collect_factory_plugin_board_rows,
    ph_tactic,
    published_ph_hits,
    render_covered_board_text,
    render_published_attck_board_html,
    write_published_attck_board,
)
from packages.sample_factory.plugin_models import PluginRequest

_MATRIX = Path("docs/coverage/procedure-host-ttp-coverage-matrix.md")


class PublishedAttckBoardHtmlTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.coverage = CoverageRegistry.from_markdown(_MATRIX)

    def test_ph51_rows_map_to_docs_board_tactics(self) -> None:
        tactic_keys = {key for key, _name in ATTACK_TACTICS}
        self.assertEqual(14, len(ATTACK_TACTICS))
        self.assertEqual(PH_MATRIX_ROW_COUNT, len(self.coverage.rows))
        for ph_id in self.coverage.rows:
            tactic = ph_tactic(ph_id)
            self.assertIsNotNone(tactic, ph_id)
            self.assertIn(tactic, tactic_keys)

    def test_html_shows_full_ph51_scope_and_greens_published(self) -> None:
        samples = [
            {
                "sample_id": "pub-1",
                "ph_sequence": ["PH-IN04", "PH-IN08"],
                "attck_ids": ["T1055.004", "T1055"],
                "export_status": "published",
            },
            {
                "sample_id": "draft-1",
                "ph_sequence": ["PH-EX01"],
                "attck_ids": ["T1059.001"],
                "export_status": None,
            },
        ]
        html = render_published_attck_board_html(self.coverage, samples)
        self.assertIn('data-row-ph="PH-IN04"', html)
        self.assertIn('data-row-ph="PH-IN08"', html)
        self.assertIn("cov-now", html)
        self.assertIn("cov-inherit", html)
        self.assertIn("T1055.004", html)
        self.assertIn("Defense Evasion", html)
        self.assertIn("Initial Access", html)
        self.assertIn("ael-eval-board-tech.html", html)
        self.assertIn("detected / not_detected", html)
        self.assertIn('"T1055.004"', html)
        self.assertNotIn("未覆盖不画卡片", html)
        self.assertIn('data-row-ph="PH-EX01"', html)
        self.assertIn('data-row-ph="PH-PS03"', html)
        self.assertIn('data-row-ph="PH-DI01"', html)
        self.assertIn('data-row-ph="PH-IT01"', html)
        self.assertIn("Discovery", html)
        self.assertIn("Command and Control", html)
        self.assertIn(f"明细表（{PH_MATRIX_ROW_COUNT} 行）", html)
        self.assertIn("适合覆盖/转换", html)
        self.assertIn("热力图（AEL T 号）", html)
        self.assertIn("战术 Gap（14 列 × AEL 卡）", html)
        self.assertIn("攻击链（16 案例）", html)
        self.assertIn("靶场需求", html)
        self.assertIn('id="v-heat"', html)
        self.assertIn('id="v-gap"', html)
        self.assertIn('id="v-chain"', html)
        self.assertIn('id="v-lab"', html)
        self.assertIn('id="v-cover-hf"', html)
        self.assertIn('id="v-cover"', html)
        self.assertIn('id="v-tab"', html)
        self.assertIn("const COVER_PLAN", html)
        self.assertIn("function classifyCover", html)
        self.assertIn("const FACTORY_COVER", html)
        self.assertIn("factory-now", html)
        self.assertIn("已覆盖（已发布样本）", html)
        self.assertIn("规划可转换；工厂尚无已发布样本", html)
        overlay = build_factory_cover_overlay(self.coverage, samples)
        self.assertIn("T1055.004", overlay["now"])
        self.assertIn("T1055", overlay["now"])
        self.assertNotIn("T1059.001", overlay["now"])
        self.assertIn("function showTab", html)
        self.assertIn("#app > .view", html)
        self.assertNotIn(
            '["v-heat","v-gap","v-chain","v-lab","v-cover-hf","v-cover"]'
            ".forEach(v=>document.getElementById(v).hidden",
            html,
        )
        self.assertIn("sample_id", html)
        self.assertIn("矩阵可见性", html)
        self.assertEqual(PH_MATRIX_ROW_COUNT, html.count('data-row-ph="PH-'))
        for key, _name in ATTACK_TACTICS:
            self.assertIn(f'k:"{key}"', html)
        self.assertIn(f"覆盖 PH 2/{PH_MATRIX_ROW_COUNT}", html)
        self.assertIn("插件状态", html)
        self.assertIn('"cat":"now"', html)

    def test_many_sample_ids_are_summarized_not_inlined(self) -> None:
        samples = [
            {
                "sample_id": f"sample-{index:04d}",
                "ph_sequence": ["PH-IN04"],
                "export_status": "published",
            }
            for index in range(1200)
        ]
        html = render_published_attck_board_html(self.coverage, samples)
        self.assertIn("查看 1200 个", html)
        self.assertIn(">1200<", html)
        self.assertIn("SAMPLE_INDEX", html)
        self.assertIn("sample-drawer", html)
        self.assertIn('"sample-1199"', html)
        self.assertEqual(1, html.count("sample-0500"))
        self.assertNotIn(">sample-0500<", html)
        self.assertIn("sample-0000, sample-0001, sample-0002 …", html)
        self.assertNotIn("<ul class=\"samples\">", html)

    def test_few_sample_ids_stay_inline(self) -> None:
        samples = [
            {
                "sample_id": f"pub-{index}",
                "ph_sequence": ["PH-IN04"],
                "export_status": "published",
            }
            for index in range(3)
        ]
        html = render_published_attck_board_html(self.coverage, samples)
        self.assertIn("pub-0, pub-1, pub-2", html)
        self.assertNotIn("查看 3 个", html)

    def test_tui_text_truncates_long_sample_id_lists(self) -> None:
        samples = [
            {
                "sample_id": f"sample-{index:04d}",
                "ph_sequence": ["PH-IN04"],
                "export_status": "published",
            }
            for index in range(20)
        ]
        text = render_covered_board_text(self.coverage, samples)
        self.assertIn("样本 20", text)
        self.assertIn("sample-0000", text)
        self.assertIn("sample-0007", text)
        self.assertNotIn("sample-0008", text)
        self.assertIn("另 12 个", text)
        self.assertIn("完整列表见导出 HTML", text)

    def test_detail_table_includes_published_sample_fields(self) -> None:
        samples = [
            {
                "sample_id": "pub-1",
                "ph_sequence": ["PH-IN04"],
                "atom_ids": ["atom.in.apc"],
                "profile_id": "profile.sysmon",
                "export_status": "published",
            }
        ]
        html = render_published_attck_board_html(self.coverage, samples)
        self.assertIn("atom.in.apc", html)
        self.assertIn("profile.sysmon", html)
        self.assertIn(">已覆盖<", html)
        self.assertIn(">未覆盖<", html)

    def test_write_board_and_tui_text(self) -> None:
        samples = [
            {
                "sample_id": "pub-1",
                "ph_sequence": ["PH-IN04"],
                "export_status": "published",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = write_published_attck_board(
                Path(tmp) / "exports" / "technique-board.html",
                self.coverage,
                samples,
            )
            self.assertTrue(path.is_file())
            body = path.read_text(encoding="utf-8")
            self.assertTrue(body.startswith("<!DOCTYPE html>"))
        text = render_covered_board_text(self.coverage, samples)
        self.assertIn("PH-IN04", text)
        self.assertIn("pub-1", text)
        self.assertNotIn("PH-EX01", text)

    def test_source_refs_parse_attack_technique_urls(self) -> None:
        self.assertEqual(
            ("T1053.005",),
            attack_ids_from_source_refs(
                ["plugin-seed://atom.ps.create_scheduled_task_com",
                 "https://attack.mitre.org/techniques/T1053/005"]
            ),
        )

    def test_no_ph_plugin_cards_stay_out_of_ph_denominator(self) -> None:
        samples = [
            {
                "sample_id": "pub-1",
                "ph_sequence": ["PH-IN04"],
                "export_status": "published",
            }
        ]
        plugins = (
            PluginBoardRow(
                plugin_id="atom.ps.wmi_event_subscription",
                implementation_name="WmiEventSubscription",
                role="execution_atom",
                ph_ids=(),
                attck_ids=("T1546.003",),
                tactic="PS",
                lifecycle_status="seed_only",
                catalog_status=None,
                plugin_run_id=None,
                provided_capabilities=(),
                required_capabilities=(),
                origin="seed",
            ),
            PluginBoardRow(
                plugin_id="atom.ld.rc4_systemfunction033",
                implementation_name="Rc4SystemFunction033",
                role="loader_atom",
                ph_ids=(),
                attck_ids=(),
                tactic=None,
                lifecycle_status="behavior_valid",
                catalog_status="candidate",
                plugin_run_id="plugin-run-rc4",
                provided_capabilities=("cap.payload.shellcode",),
                required_capabilities=(),
                origin="seed+run",
            ),
        )
        html = render_published_attck_board_html(self.coverage, samples, plugins)
        self.assertIn(f"覆盖 PH 1/{PH_MATRIX_ROW_COUNT}", html)
        self.assertIn("plugin-only", html)
        self.assertIn("WmiEventSubscription", html)
        self.assertIn("T1546.003", html)
        self.assertIn("无 PH", html)
        self.assertIn("id=\"v-plug\"", html)
        self.assertIn("插件状态", html)
        self.assertIn("p-status", html)
        self.assertIn("p-impl", html)
        self.assertIn("atom.ld.rc4_systemfunction033", html)
        self.assertIn("行为有效", html)
        self.assertIn("无战术列", html)
        self.assertEqual(PH_MATRIX_ROW_COUNT, html.count('data-row-ph="PH-'))
        self.assertIn('data-plugin="atom.ps.wmi_event_subscription"', html)
        self.assertIn('data-ph="0"', html)
        self.assertNotIn('data-row-ph="PH-T1546"', html)

    def test_seed_inventory_overlays_run_status_without_inventing_ph(self) -> None:
        path = Path("deployment/plugin-seeds/requests/atom.ps.create_scheduled_task_com.json")
        request = PluginRequest.model_validate_json(path.read_bytes())
        rows = build_plugin_board_rows(
            self.coverage,
            seed_requests=(request,),
            plugin_runs=(
                {
                    "plugin_id": "atom.ps.create_scheduled_task_com",
                    "implementation_name": "CreateScheduledTaskCom",
                    "lifecycle_status": "compile_valid",
                    "catalog_status": None,
                    "plugin_run_id": "plugin-run-task-0001",
                    "ph_ids": ["PH-PS03"],
                },
            ),
        )
        self.assertEqual(1, len(rows))
        row = rows[0]
        self.assertEqual(("PH-PS03",), row.ph_ids)
        self.assertEqual(("T1053.005",), row.attck_ids)
        self.assertEqual("PS", row.tactic)
        self.assertEqual("compile_valid", row.lifecycle_status)
        self.assertFalse(row.implemented)

    def test_collect_factory_plugin_board_includes_repo_seeds(self) -> None:
        rows = collect_factory_plugin_board_rows(self.coverage)
        plugin_ids = {item.plugin_id for item in rows}
        self.assertIn("atom.ps.create_scheduled_task_com", plugin_ids)
        self.assertIn("atom.payload.msf_calc_x64", plugin_ids)
        scheduled = next(
            item for item in rows if item.plugin_id == "atom.ps.create_scheduled_task_com"
        )
        self.assertEqual(("PH-PS03",), scheduled.ph_ids)
        self.assertEqual("PS", scheduled.tactic)
        payload = next(
            item for item in rows if item.plugin_id == "atom.payload.msf_calc_x64"
        )
        self.assertIsNone(payload.tactic)

    def test_cover_leaves_mark_published_now_and_parent_inherit(self) -> None:
        samples = [
            {
                "sample_id": "pub-1",
                "ph_sequence": ["PH-IN04", "PH-IN08"],
                "export_status": "published",
            }
        ]
        plugins = (
            PluginBoardRow(
                plugin_id="atom.ps.create_scheduled_task_com",
                implementation_name="CreateScheduledTaskCom",
                role="execution_atom",
                ph_ids=("PH-PS03",),
                attck_ids=("T1053.005",),
                tactic="PS",
                lifecycle_status="seed_only",
                catalog_status=None,
                plugin_run_id=None,
                provided_capabilities=("cap.scheduled_task.created",),
                required_capabilities=(),
                origin="seed",
            ),
            PluginBoardRow(
                plugin_id="atom.ps.wmi_event_subscription",
                implementation_name="WmiEventSubscription",
                role="execution_atom",
                ph_ids=(),
                attck_ids=("T1546.003",),
                tactic="PS",
                lifecycle_status="seed_only",
                catalog_status=None,
                plugin_run_id=None,
                provided_capabilities=(),
                required_capabilities=(),
                origin="seed",
            ),
        )
        leaves = build_attack_cover_leaves(
            self.coverage, published_ph_hits(samples), plugins
        )
        by_id = {item.attack_id: item for item in leaves}
        self.assertEqual("now", by_id["T1055.004"].cat)
        self.assertEqual("now", by_id["T1055"].cat)
        self.assertEqual("inherit", by_id["T1055.001"].cat)
        self.assertEqual("future", by_id["T1059.001"].cat)
        self.assertTrue(by_id["T1055.004"].in_ph51)
        scheduled = by_id["T1053.005"]
        self.assertEqual("future", scheduled.cat)
        self.assertTrue(scheduled.in_ph51)
        self.assertEqual(("atom.ps.create_scheduled_task_com",), scheduled.plugin_ids)
        overlay = by_id["T1546.003"]
        self.assertFalse(overlay.in_ph51)
        self.assertEqual(("atom.ps.wmi_event_subscription",), overlay.plugin_ids)
        self.assertEqual(
            len({attack_id for row in self.coverage.rows.values() for attack_id in row.attack_ids}),
            sum(1 for item in leaves if item.in_ph51),
        )

    def test_factory_cover_overlay_ignores_drafts_and_unpublished_plugins(self) -> None:
        samples = [
            {
                "sample_id": "pub-1",
                "ph_sequence": ["PH-IN04"],
                "attck_ids": ["T1055.004"],
                "export_status": "published",
            },
            {
                "sample_id": "draft-1",
                "ph_sequence": ["PH-EX01"],
                "attck_ids": ["T1059.001"],
                "export_status": None,
            },
        ]
        overlay = build_factory_cover_overlay(self.coverage, samples)
        self.assertEqual(["T1055.004"], overlay["now"])
        self.assertIn("PH-IN04", overlay["hint"]["T1055.004"])
        html = render_published_attck_board_html(
            self.coverage,
            samples,
            (
                PluginBoardRow(
                    plugin_id="atom.ps.create_scheduled_task_com",
                    implementation_name="CreateScheduledTaskCom",
                    role="execution_atom",
                    ph_ids=(),
                    attck_ids=("T1053.005",),
                    tactic="PS",
                    lifecycle_status="behavior_valid",
                    catalog_status=None,
                    plugin_run_id=None,
                    provided_capabilities=(),
                    required_capabilities=(),
                    origin="seed",
                ),
            ),
        )
        self.assertIn('"T1055.004"', html[html.find("const FACTORY_COVER") :])
        self.assertNotIn('"T1059.001"', html[html.find("const FACTORY_COVER"):html.find("function esc")])
        self.assertNotIn('"T1053.005"', html[html.find("const FACTORY_COVER"):html.find("function esc")])
        self.assertIn("绿格=本仓库已发布样本", html)

