"""Contract-gap reporting helpers.

External gates such as Sliver, GOAD sensors, Sigma rules, or an LLM provider must
fail explicitly when a required authority or runtime resource is absent. This
module keeps that failure shape machine-readable while rendering the project
standard report format from AGENTS.md.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ContractGap:
    """A missing authority/resource that must not be papered over with fixtures."""

    capability: str
    missing: str
    checked: tuple[str, ...]
    risk: str
    options: tuple[str, ...] = (
        "补权威来源",
        "调整需求",
        "显式标注 TODO",
    )
    next_step: str = "补齐前置后重跑验收。"

    def render(self) -> str:
        """Render the project-mandated Contract Gap report."""
        checked = "\n".join(f"  - {item}" for item in self.checked)
        options = " ".join(f"{idx}) {item}" for idx, item in enumerate(self.options, start=1))
        return "\n".join(
            [
                "### Contract Gap Found",
                f"- 需要的能力：{self.capability}",
                f"- 缺失的数据/字段/映射：{self.missing}",
                "- 已检查的权威来源与证据：",
                checked,
                f"- 为什么伪造不安全：{self.risk}",
                f"- 安全的实现选项：{options}",
                f"- 建议下一步：{self.next_step}",
            ]
        )


class ContractGapError(RuntimeError):
    """Raised when a task requires a missing authority/resource."""

    def __init__(self, gap: ContractGap) -> None:
        super().__init__(gap.render())
        self.gap = gap
