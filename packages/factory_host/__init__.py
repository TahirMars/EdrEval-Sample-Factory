"""Windows 构建宿主部署接线（operator-owned backends）。"""

from packages.factory_host.plugin_harness_vmware import (
    PluginDependencyLinkResult,
    VmwarePluginHarnessBackend,
    VmwarePluginHarnessConfig,
    create_vmware_plugin_harness_backend,
)
from packages.factory_host.vmware_verification import (
    VmwareVerificationBackend,
    VmwareVerificationSettings,
)

__all__ = [
    "PluginDependencyLinkResult",
    "VmwarePluginHarnessBackend",
    "VmwarePluginHarnessConfig",
    "VmwareVerificationBackend",
    "VmwareVerificationSettings",
    "create_vmware_plugin_harness_backend",
]
