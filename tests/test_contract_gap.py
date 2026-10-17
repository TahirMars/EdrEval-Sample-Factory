"""Contract Gap 报告/异常助手（packages.contract_gap）。"""

from __future__ import annotations

import unittest

from packages.contract_gap import ContractGap, ContractGapError


class ContractGapHelper(unittest.TestCase):
    def test_render_matches_agreements_format(self) -> None:
        gap = ContractGap(
            capability="cap",
            missing="field",
            checked=("a", "b"),
            risk="why",
        )
        text = gap.render()
        self.assertIn("### Contract Gap Found", text)
        self.assertIn("- 需要的能力：cap", text)
        self.assertIn("- 缺失的数据/字段/映射：field", text)
        self.assertIn("  - a", text)
        self.assertIn("- 为什么伪造不安全：why", text)
        self.assertIn("- 建议下一步：", text)

    def test_error_carries_gap_and_renders(self) -> None:
        gap = ContractGap(capability="cap", missing="m", checked=("c",), risk="r")
        err = ContractGapError(gap)
        self.assertIs(err.gap, gap)
        self.assertIn("### Contract Gap Found", str(err))


if __name__ == "__main__":
    unittest.main()
