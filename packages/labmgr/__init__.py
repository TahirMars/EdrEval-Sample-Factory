"""样本工厂裁剪的 labmgr 子集：进程执行与主机资源护栏。

完整靶场生命周期 / Sliver 管理仍归属 EdrEvalAgent；本仓只保留工厂编译与
验证所需的 ``HostResourceGuard`` / ``SubprocessRunner`` / ``MemoryCappedRunner``。
"""

from packages.labmgr.host_guard import HostResourceGuard, ResourceGuardError, ResourceLimits
from packages.labmgr.process import ProcessRunner, SubprocessRunner
from packages.labmgr.resource import (
    MemoryCappedRunner,
    MemoryWatchdog,
    monitor_rss,
    systemd_scope_available,
)

__all__ = [
    "HostResourceGuard",
    "MemoryCappedRunner",
    "MemoryWatchdog",
    "ProcessRunner",
    "ResourceGuardError",
    "ResourceLimits",
    "SubprocessRunner",
    "monitor_rss",
    "systemd_scope_available",
]
