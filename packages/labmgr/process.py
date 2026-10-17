"""进程执行接缝（ProcessRunner 协议 + subprocess 真实实现）。

独立于具体使用者（sliver_server / resource），避免相互引用成环。
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Protocol


class ProcessRunner(Protocol):
    """进程操作接缝（测试注入 fake；真实实现为 subprocess）。"""

    def run(self, argv: list[str], *, timeout: float | None = None) -> tuple[int, str]:
        """同步执行，返回 (returncode, stdout+stderr)。"""
        ...

    def spawn(self, argv: list[str], *, log_path: Path) -> int:
        """后台启动守护进程，返回 pid。"""
        ...

    def alive(self, pid: int) -> bool:
        """进程是否存活。"""
        ...

    def terminate(self, pid: int) -> None:
        """终止进程。"""
        ...


class SubprocessRunner:
    """真实进程执行器（subprocess；显式 UTF-8 解码）。"""

    def run(self, argv: list[str], *, timeout: float | None = None) -> tuple[int, str]:
        proc = subprocess.run(
            argv, capture_output=True, timeout=timeout, check=False,
        )
        out = (proc.stdout + b"\n" + proc.stderr).decode("utf-8", errors="replace")
        return proc.returncode, out

    def spawn(self, argv: list[str], *, log_path: Path) -> int:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("ab") as log:
            proc = subprocess.Popen(  # noqa: S603 - argv 由调用方受控构造
                argv, stdout=log, stderr=log, start_new_session=True,
            )
        return proc.pid

    def alive(self, pid: int) -> bool:
        try:
            Path(f"/proc/{pid}").stat()
        except FileNotFoundError:
            return False
        return True

    def terminate(self, pid: int) -> None:
        subprocess.run(["kill", str(pid)], check=False, capture_output=True)


__all__ = ["ProcessRunner", "SubprocessRunner"]
