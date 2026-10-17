"""重操作资源护栏（memory guard）。

背景（2026-08-24 实测事故）：sliver CLI 客户端在 --rc 模式执行 generate 时内存
膨胀至 ~28GB，31GB RAM + 5GB swap 耗尽触发 OOM killer；generate 作为工具调用
子进程运行在宿主 GUI 会话的 cgroup 内，OOM 事件连带杀死会话（内核日志两例：
anon-rss 28.3GB / 28.6GB，sliver-client）。

机制（双层）：
- 首选 systemd-run --user --scope -p MemoryMax=<cap>：把子进程放进瞬态 cgroup，
  内存超限只死该 cgroup，宿主会话免疫（内核级硬限额）；
- 回退软看门狗：无 systemd 用户会话时，轮询 /proc/<pid>/status VmRSS，超限
  SIGKILL（尽力而为：避免触发全局 OOM）。

监控：MemoryMonitor 采样 RSS 峰值供台账/报告（peak_rss_kb）。
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from packages.labmgr.process import SubprocessRunner


def systemd_scope_available() -> bool:
    """systemd-run --user --scope 是否可用（缓存一次探测结果）。"""
    global _SYSTEMD_SCOPE_CACHE
    if _SYSTEMD_SCOPE_CACHE is None:
        try:
            probe = subprocess.run(
                ["systemd-run", "--user", "--scope", "--quiet", "-p",
                 "MemoryMax=512M", "true"],
                capture_output=True, timeout=15, check=False,
            )
            _SYSTEMD_SCOPE_CACHE = probe.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            _SYSTEMD_SCOPE_CACHE = False
    return _SYSTEMD_SCOPE_CACHE


_SYSTEMD_SCOPE_CACHE: bool | None = None


class MemoryWatchdog:
    """软限额看门狗：轮询 /proc/<pid>/status VmRSS，超限 SIGKILL。"""

    def __init__(self, pid: int, *, limit_mb: int, interval_s: float = 0.5) -> None:
        self._pid = pid
        self._limit_kb = limit_mb * 1024
        self._interval = interval_s
        self._stop = threading.Event()
        self._peak_kb = 0
        self.killed = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> int:
        """停止采样；返回观测到的 RSS 峰值（KB）。"""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2 * self._interval + 1)
        return self._peak_kb

    def _rss_kb(self) -> int:
        try:
            with Path(f"/proc/{self._pid}/status").open(encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1])
        except (OSError, ValueError, IndexError):
            return 0
        return 0

    def _run(self) -> None:
        while not self._stop.is_set():
            rss = self._rss_kb()
            if rss > self._peak_kb:
                self._peak_kb = rss
            if rss > self._limit_kb > 0:
                self.killed = True
                with contextlib.suppress(OSError):
                    os.kill(self._pid, 9)
                return
            time.sleep(self._interval)


@dataclass
class _SpawnHandle:
    proc: subprocess.Popen[bytes]
    watchdog: MemoryWatchdog | None
    unit: str | None


class MemoryCappedRunner(SubprocessRunner):
    """内存限额执行器：systemd cgroup 硬限额优先，软看门狗回退。

    run() 覆盖 generate 等同步重操作路径；spawn() 覆盖 listener client 等
    后台常驻路径。后台路径保留 stdin 管道，避免 rc 执行后落入交互控制台时
    立即读到 EOF 触发 readline 膨胀；同时用 cgroup/看门狗限制 RSS。
    """

    def __init__(self, *, limit_mb: int = 8192, force_watchdog: bool = False) -> None:
        super().__init__()
        self._limit_mb = limit_mb
        self._force_watchdog = force_watchdog
        self.last_peak_rss_kb = 0
        self.last_killed_by_limit = False
        self._spawned: dict[int, _SpawnHandle] = {}
        self._spawn_lock = threading.Lock()

    def run(self, argv: list[str], *, timeout: float | None = None) -> tuple[int, str]:
        self.last_killed_by_limit = False
        if not self._force_watchdog and systemd_scope_available():
            capped = [
                "systemd-run", "--user", "--scope", "--quiet",
                "-p", f"MemoryMax={self._limit_mb}M",
                # cgroup v2：MemoryMax 只限 RAM，须同时关掉 swap 溢出（否则
                # 超限页换出到 swap 而非处决，护栏失效）
                "-p", "MemorySwapMax=0",
                *argv,
            ]
            proc = subprocess.run(capped, capture_output=True, timeout=timeout, check=False)
            out = (proc.stdout + b"\n" + proc.stderr).decode("utf-8", errors="replace")
            if proc.returncode != 0 and "memory" in out.lower():
                self.last_killed_by_limit = True
            self.last_peak_rss_kb = 0  # cgroup 硬限额；峰值由系统 cgroup 统计
            return proc.returncode, out
        # 回退：裸跑 + 软看门狗
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        watchdog = MemoryWatchdog(child.pid, limit_mb=self._limit_mb)
        watchdog.start()
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            child.kill()
            stdout, stderr = child.communicate()
            self.last_peak_rss_kb = watchdog.stop()
            return 124, (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
        self.last_peak_rss_kb = watchdog.stop()
        self.last_killed_by_limit = watchdog.killed
        out = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
        return child.returncode, out

    def spawn(self, argv: list[str], *, log_path: Path) -> int:
        """后台启动并继承同一内存护栏；返回可 terminate 的 wrapper pid。"""
        self.last_killed_by_limit = False
        log_path.parent.mkdir(parents=True, exist_ok=True)

        launch = list(argv)
        unit: str | None = None
        watchdog: MemoryWatchdog | None = None
        if not self._force_watchdog and systemd_scope_available():
            unit = f"edreval-sliver-client-{uuid.uuid4().hex[:12]}.scope"
            launch = [
                "systemd-run", "--user", "--scope", "--quiet",
                "--unit", unit,
                "-p", f"MemoryMax={self._limit_mb}M",
                "-p", "MemorySwapMax=0",
                *argv,
            ]

        with log_path.open("ab") as log:
            proc = subprocess.Popen(  # noqa: S603 - argv 由调用方受控构造
                launch,
                stdin=subprocess.PIPE,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )

        if unit is None:
            watchdog = MemoryWatchdog(proc.pid, limit_mb=self._limit_mb)
            watchdog.start()
        with self._spawn_lock:
            self._spawned[proc.pid] = _SpawnHandle(proc=proc, watchdog=watchdog, unit=unit)
        return proc.pid

    def alive(self, pid: int) -> bool:
        with self._spawn_lock:
            handle = self._spawned.get(pid)
        if handle is None:
            return super().alive(pid)
        if handle.proc.poll() is None:
            return True
        self._finish_spawn(pid, handle)
        return False

    def terminate(self, pid: int) -> None:
        with self._spawn_lock:
            handle = self._spawned.pop(pid, None)
        if handle is None:
            super().terminate(pid)
            return

        self._close_stdin(handle.proc)
        if handle.proc.poll() is None:
            self._terminate_handle(handle, signal.SIGTERM)
            try:
                handle.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._terminate_handle(handle, signal.SIGKILL)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    handle.proc.wait(timeout=5)
        self._finish_handle(handle)

    def _finish_spawn(self, pid: int, handle: _SpawnHandle) -> None:
        with self._spawn_lock:
            self._spawned.pop(pid, None)
        self._finish_handle(handle)

    def _finish_handle(self, handle: _SpawnHandle) -> None:
        self._close_stdin(handle.proc)
        if handle.watchdog is not None:
            self.last_peak_rss_kb = handle.watchdog.stop()
            self.last_killed_by_limit = handle.watchdog.killed

    @staticmethod
    def _close_stdin(proc: subprocess.Popen[bytes]) -> None:
        if proc.stdin is not None:
            with contextlib.suppress(OSError):
                proc.stdin.close()

    def _terminate_handle(self, handle: _SpawnHandle, sig: signal.Signals) -> None:
        if handle.unit is not None:
            signal_name = f"SIG{sig.name}" if not sig.name.startswith("SIG") else sig.name
            subprocess.run(
                ["systemctl", "--user", "kill", "--kill-who=all",
                 "--signal", signal_name, handle.unit],
                check=False, capture_output=True, timeout=10,
            )
            subprocess.run(
                ["systemctl", "--user", "stop", handle.unit],
                check=False, capture_output=True, timeout=10,
            )
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(handle.proc.pid, sig)


def monitor_rss(pid: int, *, duration_s: float, interval_s: float = 1.0) -> int:
    """采样进程 RSS 峰值（KB）；用于长驻进程（daemon/隧道）的资源观测。"""
    peak = 0
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        try:
            with Path(f"/proc/{pid}/status").open(encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        peak = max(peak, int(line.split()[1]))
                        break
        except (OSError, ValueError, IndexError):
            break
        time.sleep(interval_s)
    return peak


__all__ = [
    "MemoryCappedRunner",
    "MemoryWatchdog",
    "monitor_rss",
    "systemd_scope_available",
]
