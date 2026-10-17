"""主机资源守卫（HostResourceGuard）——防 32GB 主机卡死。

根因（2026-08-25 用户报告主机卡死数秒）：
  sliver generate 命令触发 Go+garble 编译，默认 GOMAXPROCS=全部 CPU 核数，
  每个 worker 占 1-4GB 内存 → 8核×4GB=32GB 瞬间耗尽 → 主机冻结。

三层防护：
  1. 预检：启动重操作前检查可用内存≥阈值（默认 4GB）+ 并发互斥
  2. CPU 限制：子进程环境注入 GOMAXPROCS（默认 max_cpu=4，限制并行编译）
  3. 内存看门狗：系统级 /proc/meminfo 监控，低于阈值时终止重操作
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ResourceLimits:
    """资源限制配置。"""

    # 启动重操作前，系统至少需要这么多可用内存（GB）
    min_available_mem_gb: float = 8.0
    # Go 编译并行度上限（GOMAXPROCS）
    max_cpu: int = 4
    # 重操作自身的内存上限（GB）——交给 MemoryCappedRunner
    max_mem_gb: int = 8
    # 同时允许的重操作数（互斥锁）
    max_concurrent_heavy: int = 1


class ResourceGuardError(RuntimeError):
    """资源不足，拒绝启动重操作。"""


class HostResourceGuard:
    """系统级资源守卫：预检+CPU限制+互斥。"""

    def __init__(self, *, limits: ResourceLimits | None = None) -> None:
        self._limits = limits or ResourceLimits()
        self._heavy_lock = threading.Semaphore(self._limits.max_concurrent_heavy)
        self._active_heavy: list[str] = []
        self._lock = threading.Lock()

    # ── 系统资源查询 ─────────────────────────────────────────────────────
    @staticmethod
    def available_mem_gb() -> float:
        """当前可用内存（GB），从 /proc/meminfo 读取（含 buff/cache 可回收部分）。"""
        try:
            info: dict[str, int] = {}
            with Path("/proc/meminfo").open(encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        info[parts[0].rstrip(":")] = int(parts[1])  # kB
            mem_available = info.get("MemAvailable", 0)
            return mem_available / (1024 * 1024)  # kB → GB
        except (OSError, ValueError):
            return 999.0  # 读不到就假设充足（不阻塞）

    @staticmethod
    def total_mem_gb() -> float:
        try:
            with Path("/proc/meminfo").open(encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        return int(line.split()[1]) / (1024 * 1024)
        except OSError:
            pass
        return 0.0

    @staticmethod
    def cpu_count() -> int:
        return os.cpu_count() or 1

    # ── 预检 ─────────────────────────────────────────────────────────────
    def check_can_start_heavy(self, *, operation: str = "unknown") -> None:
        """启动重操作前预检：可用内存+并发数。不足抛 ResourceGuardError。"""
        avail = self.available_mem_gb()
        if avail < self._limits.min_available_mem_gb:
            raise ResourceGuardError(
                f"可用内存 {avail:.1f}GB < 最低要求 "
                f"{self._limits.min_available_mem_gb}GB（{operation}）——"
                f"拒绝启动以保护主机不冻结"
            )
        with self._lock:
            if len(self._active_heavy) >= self._limits.max_concurrent_heavy:
                names = ", ".join(self._active_heavy)
                raise ResourceGuardError(
                    f"已有 {len(self._active_heavy)} 个重操作在运行（{names}），"
                    f"最多允许 {self._limits.max_concurrent_heavy} 个——拒绝 {operation}"
                )

    # ── 重操作执行（互斥+CPU限制+内存预检）───────────────────────────────
    def heavy_env(self) -> dict[str, str]:
        """返回重操作的环境变量（限制 CPU 并行度）。"""
        return {"GOMAXPROCS": str(self._limits.max_cpu)}

    def acquire_heavy(self, operation: str) -> None:
        """获取重操作权限（预检+登记）。"""
        self.check_can_start_heavy(operation=operation)
        self._heavy_lock.acquire()
        with self._lock:
            self._active_heavy.append(operation)

    def release_heavy(self, operation: str) -> None:
        """释放重操作权限。"""
        with self._lock:
            if operation in self._active_heavy:
                self._active_heavy.remove(operation)
        self._heavy_lock.release()

    # ── 状态报告 ─────────────────────────────────────────────────────────
    def status(self) -> dict[str, object]:
        return {
            "available_mem_gb": round(self.available_mem_gb(), 2),
            "total_mem_gb": round(self.total_mem_gb(), 2),
            "cpu_count": self.cpu_count(),
            "max_cpu_for_heavy": self._limits.max_cpu,
            "min_mem_gb": self._limits.min_available_mem_gb,
            "active_heavy": list(self._active_heavy),
            "can_start_heavy": (
                self.available_mem_gb() >= self._limits.min_available_mem_gb
                and len(self._active_heavy) < self._limits.max_concurrent_heavy
            ),
        }

    def __enter__(self) -> HostResourceGuard:
        self.acquire_heavy("context_manager")
        return self

    def __exit__(self, *args: object) -> None:
        self.release_heavy("context_manager")


__all__ = ["HostResourceGuard", "ResourceGuardError", "ResourceLimits"]
