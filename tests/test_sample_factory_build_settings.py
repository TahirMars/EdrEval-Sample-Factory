from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from packages.sample_factory.build_settings import (
    effective_toolchain_fp,
    enforce_msvc_static_runtime,
    normalize_msvc_project_layout,
    validate_msvc_static_runtime,
)
from packages.sample_factory.errors import BuildError

_PROJECT = '''<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <ClCompile><WarningLevel>Level3</WarningLevel></ClCompile>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile><WarningLevel>Level3</WarningLevel><RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary></ClCompile>
  </ItemDefinitionGroup>
</Project>
'''


class MsvcStaticRuntimeTest(unittest.TestCase):
    def _workspace(self, content: str = _PROJECT) -> Path:
        root = Path(tempfile.mkdtemp())
        generated = root / "generated"
        generated.mkdir()
        (generated / "sample.vcxproj").write_text(content, encoding="utf-8")
        return root

    def test_enforce_normalizes_debug_and_release_to_static_runtime(self) -> None:
        root = self._workspace()

        enforce_msvc_static_runtime(root, "build-target://initial/windows-msvc-v143-x64")
        validate_msvc_static_runtime(root, "build-target://initial/windows-msvc-v143-x64")

        text = (root / "generated" / "sample.vcxproj").read_text(encoding="utf-8")
        self.assertEqual(1, text.count("<RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>"))
        self.assertEqual(1, text.count("<RuntimeLibrary>MultiThreaded</RuntimeLibrary>"))

    def test_non_msvc_target_is_untouched(self) -> None:
        root = self._workspace()
        before = (root / "generated" / "sample.vcxproj").read_text(encoding="utf-8")

        enforce_msvc_static_runtime(root, "build-target://initial/linux-clang-mingw-x64")

        self.assertEqual(before, (root / "generated" / "sample.vcxproj").read_text(encoding="utf-8"))

    def test_missing_project_is_fail_closed(self) -> None:
        root = Path(tempfile.mkdtemp())
        with self.assertRaises(BuildError):
            enforce_msvc_static_runtime(root, "build-target://initial/windows-msvc-v143-x64")

    def test_invalid_namespace_is_fail_closed(self) -> None:
        root = self._workspace(_PROJECT.replace("schemas.microsoft.com/developer/msbuild/2003", "example.invalid"))
        with self.assertRaises(BuildError):
            validate_msvc_static_runtime(root, "build-target://initial/windows-msvc-v143-x64")

    def test_toolchain_fingerprint_records_static_runtime_policy(self) -> None:
        self.assertEqual(
            "msvc-v143-x64@operator-pinned+crt-static",
            effective_toolchain_fp(
                "msvc-v143-x64@operator-pinned",
                "build-target://initial/windows-msvc-v143-x64",
            ),
        )
        self.assertEqual(
            "clang-21-mingw-x64@operator-pinned",
            effective_toolchain_fp(
                "clang-21-mingw-x64@operator-pinned",
                "build-target://initial/linux-clang-mingw-x64",
            ),
        )

    def test_normalize_msvc_project_layout_rewrites_glue_paths(self) -> None:
        project = _PROJECT.replace(
            "</Project>",
            """
  <ItemGroup>
    <ClCompile Include="generated\\main.cpp" />
    <ClCompile Include="src\\atom.cpp" />
    <ClInclude Include="generated\\handoff_shellcode_v1.h" />
  </ItemGroup>
</Project>
""",
        )
        root = self._workspace(project)
        normalize_msvc_project_layout(root, "build-target://initial/windows-msvc-v143-x64")
        text = (root / "generated" / "sample.vcxproj").read_text(encoding="utf-8")
        self.assertIn('Include="main.cpp"', text)
        self.assertIn('Include="..\\src\\atom.cpp"', text)
        self.assertIn('Include="handoff_shellcode_v1.h"', text)
        self.assertNotIn('Include="generated\\main.cpp"', text)


if __name__ == "__main__":
    unittest.main()
