"""Run / Step 状态机（主设计 §2.2）。

以合法迁移邻接表编码；`assert_transition` 供 Orchestrator 在推进状态前校验。
非法迁移抛 IllegalTransition —— 防止状态机被绕过（M0 DoD：全迁移路径单测覆盖）。
"""

from __future__ import annotations

from .enums import RunState, StepState


class IllegalTransition(ValueError):
    """尝试进行未登记的状态迁移。"""


# Run: created → planning → executing → correlating → (planning|completed|aborted|failed)
RUN_TRANSITIONS: dict[RunState, set[RunState]] = {
    RunState.CREATED: {RunState.PLANNING, RunState.ABORTED},
    RunState.PLANNING: {RunState.EXECUTING, RunState.COMPLETED, RunState.ABORTED, RunState.FAILED},
    RunState.EXECUTING: {RunState.CORRELATING, RunState.ABORTED, RunState.FAILED},
    RunState.CORRELATING: {RunState.PLANNING, RunState.COMPLETED, RunState.ABORTED, RunState.FAILED},
    RunState.COMPLETED: set(),
    RunState.ABORTED: set(),
    RunState.FAILED: set(),
}

# Step: proposed → gated → (awaiting_approval|approved|rejected) → dispatched → finished → correlated
STEP_TRANSITIONS: dict[StepState, set[StepState]] = {
    StepState.PROPOSED: {StepState.GATED},
    StepState.GATED: {StepState.AWAITING_APPROVAL, StepState.APPROVED, StepState.REJECTED},
    StepState.AWAITING_APPROVAL: {StepState.APPROVED, StepState.REJECTED},
    StepState.APPROVED: {StepState.DISPATCHED},
    StepState.REJECTED: set(),
    StepState.DISPATCHED: {StepState.FINISHED},
    StepState.FINISHED: {StepState.CORRELATED},
    StepState.CORRELATED: set(),
}

RUN_TERMINAL: frozenset[RunState] = frozenset(
    {RunState.COMPLETED, RunState.ABORTED, RunState.FAILED}
)
STEP_TERMINAL: frozenset[StepState] = frozenset({StepState.REJECTED, StepState.CORRELATED})


def can_transition_run(src: RunState, dst: RunState) -> bool:
    return dst in RUN_TRANSITIONS[src]


def can_transition_step(src: StepState, dst: StepState) -> bool:
    return dst in STEP_TRANSITIONS[src]


def assert_transition_run(src: RunState, dst: RunState) -> None:
    if not can_transition_run(src, dst):
        raise IllegalTransition(f"Run: {src.value} -> {dst.value} 非法")


def assert_transition_step(src: StepState, dst: StepState) -> None:
    if not can_transition_step(src, dst):
        raise IllegalTransition(f"Step: {src.value} -> {dst.value} 非法")
