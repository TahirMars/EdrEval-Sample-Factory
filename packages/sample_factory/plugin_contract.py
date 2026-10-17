"""C++ TTP plugin source, ABI, and validation-harness contract."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from xml.sax.saxutils import escape

from packages.sample_factory.errors import PlanningError

PLUGIN_ABI_VERSION = "edreval-ttp-c-v1"
PLUGIN_RESULT_SCHEMA_VERSION = "edreval-ttp-result-v1"
_IMPLEMENTATION_NAME_RE = re.compile(r"[A-Z][A-Za-z0-9]{2,79}")
_FORBIDDEN_ENTRY_RE = re.compile(
    r"(?m)^\s*(?:(?:extern\s+\"C\"\s+)?(?:[A-Za-z_][\w:<>,*&]*\s+)+)"
    r"(?:main|wmain|WinMain|wWinMain|DllMain)\s*\("
)
_SOURCE_SUFFIXES = frozenset({".h", ".cpp"})


def validate_implementation_name(value: str) -> str:
    """Require a readable, stable UpperCamelCase technique/variant name."""
    if not _IMPLEMENTATION_NAME_RE.fullmatch(value):
        raise ValueError(
            "implementation_name 必须是 3..80 字符的 UpperCamelCase 技术/变体名称"
        )
    return value


def plugin_entry_symbol(implementation_name: str) -> str:
    validate_implementation_name(implementation_name)
    return f"EdrEvalTtp_{implementation_name}_Execute"


def canonical_source_paths(implementation_name: str) -> tuple[str, str]:
    validate_implementation_name(implementation_name)
    return (
        f"src/{implementation_name}.h",
        f"src/{implementation_name}.cpp",
    )


def validate_candidate_source_snapshot(
    snapshot: Mapping[str, str], implementation_name: str
) -> tuple[str, ...]:
    """Validate authored source while allowing generated build metadata outside ``src``."""
    expected = set(canonical_source_paths(implementation_name))
    source_paths = tuple(
        sorted(path for path in snapshot if PurePosixPath(path).parts[:1] == ("src",))
    )
    missing = sorted(expected - set(source_paths))
    if missing:
        raise PlanningError(f"插件缺少规范实现文件：{missing}")
    validate_catalog_source_files(
        tuple(PurePosixPath(path).relative_to("src").as_posix() for path in source_paths),
        implementation_name,
    )
    for path, content in snapshot.items():
        if PurePosixPath(path).suffix.lower() == ".lib":
            raise PlanningError(f"插件源码候选不得包含验证制品：{path}")
        if PurePosixPath(path).suffix.lower() in {".c", ".cc", ".cpp"} and _FORBIDDEN_ENTRY_RE.search(
            content
        ):
            raise PlanningError(f"TTP 插件不得定义进程入口：{path}")
    header = snapshot[f"src/{implementation_name}.h"]
    entry_symbol = plugin_entry_symbol(implementation_name)
    if 'extern "C"' not in header or entry_symbol not in header:
        raise PlanningError(
            f"公共头文件必须声明 C ABI 入口 {entry_symbol}"
        )
    return source_paths


def validate_catalog_source_files(
    files: Sequence[str], implementation_name: str
) -> tuple[str, ...]:
    """Validate source paths relative to a published plugin ``src`` directory."""
    validate_implementation_name(implementation_name)
    normalized: list[str] = []
    for value in files:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or ".." in path.parts
            or not path.parts
            or path.suffix.lower() not in _SOURCE_SUFFIXES
        ):
            raise ValueError(f"插件发布源码只允许相对路径 .h/.cpp：{value}")
        stem = path.stem
        if not _IMPLEMENTATION_NAME_RE.fullmatch(stem) or not stem.startswith(
            implementation_name
        ):
            raise ValueError(
                f"插件源码文件必须以 implementation_name 开头并使用 UpperCamelCase：{value}"
            )
        normalized.append(path.as_posix())
    if len(normalized) != len(set(normalized)):
        raise ValueError("插件发布源码清单不得重复")
    required = {f"{implementation_name}.h", f"{implementation_name}.cpp"}
    missing = sorted(required - set(normalized))
    if missing:
        raise ValueError(f"插件发布源码缺少规范文件：{missing}")
    return tuple(sorted(normalized))


def render_validation_harness_main(implementation_name: str) -> str:
    """Render the compile-time stub main; callers keep it outside plugin source/catalog."""
    entry_symbol = plugin_entry_symbol(implementation_name)
    return f'''#include <array>
#include <cstddef>
#include <iostream>

#include "{implementation_name}.h"

int main(int argc, char** argv) {{
    const char* request_json = argc > 1 ? argv[1] : "{{}}";
    std::array<char, 65536> result_json{{}};
    const int rc = {entry_symbol}(
        request_json, result_json.data(), result_json.size());
    if (result_json[0] != '\\0') {{
        std::cout << result_json.data() << '\\n';
    }}
    return rc;
}}
'''


def _cpp_cstring(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _harness_runtime_helpers() -> str:
    return r'''
struct TtpAbiResult {
    bool success = false;
    long result_code = 0;
    unsigned long win32_error = 0;
    std::string reason;
    std::string detail;
};

static const char* SkipWs(const char* cursor) {
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        ++cursor;
    }
    return cursor;
}

static const char* FindJsonKey(const char* json, const char* key) {
    if (json == nullptr || key == nullptr) {
        return nullptr;
    }
    const std::string needle = std::string("\"") + key + "\"";
    const char* found = std::strstr(json, needle.c_str());
    if (found == nullptr) {
        return nullptr;
    }
    const char* cursor = std::strchr(found + needle.size(), ':');
    return cursor == nullptr ? nullptr : SkipWs(cursor + 1);
}

static bool CopyJsonStringValue(const char* json, const char* key, std::string& out) {
    const char* cursor = FindJsonKey(json, key);
    if (cursor == nullptr || *cursor != '"') {
        return false;
    }
    ++cursor;
    out.clear();
    while (*cursor != '\0' && *cursor != '"') {
        if (*cursor == '\\') {
            ++cursor;
            if (*cursor == '\0') {
                return false;
            }
        }
        out.push_back(*cursor);
        ++cursor;
    }
    return *cursor == '"';
}

static bool ReadJsonBool(const char* json, const char* key, bool* out) {
    const char* cursor = FindJsonKey(json, key);
    if (cursor == nullptr || out == nullptr) {
        return false;
    }
    if (std::strncmp(cursor, "true", 4) == 0) {
        *out = true;
        return true;
    }
    if (std::strncmp(cursor, "false", 5) == 0) {
        *out = false;
        return true;
    }
    return false;
}

static bool ReadJsonLong(const char* json, const char* key, long* out) {
    const char* cursor = FindJsonKey(json, key);
    if (cursor == nullptr || out == nullptr) {
        return false;
    }
    char* end = nullptr;
    const long value = std::strtol(cursor, &end, 10);
    if (end == cursor) {
        return false;
    }
    *out = value;
    return true;
}

static bool ReadJsonULong(const char* json, const char* key, unsigned long* out) {
    const char* cursor = FindJsonKey(json, key);
    if (cursor == nullptr || out == nullptr) {
        return false;
    }
    char* end = nullptr;
    const unsigned long value = std::strtoul(cursor, &end, 10);
    if (end == cursor) {
        return false;
    }
    *out = value;
    return true;
}

static bool CopyPayloadArray(const char* json, std::string& out) {
    const char* cursor = FindJsonKey(json, "payload");
    if (cursor == nullptr || *cursor != '[') {
        return false;
    }
    int depth = 0;
    const char* start = cursor;
    while (*cursor != '\0') {
        if (*cursor == '[') {
            ++depth;
        } else if (*cursor == ']') {
            --depth;
            if (depth == 0) {
                out.assign(start, static_cast<std::size_t>(cursor - start + 1));
                return true;
            }
        }
        ++cursor;
    }
    return false;
}

static TtpAbiResult ParseTtpResult(const char* json, int fallback_rc) {
    TtpAbiResult out;
    out.result_code = fallback_rc;
    out.success = fallback_rc == 0;
    const char* schema = json == nullptr
        ? nullptr
        : std::strstr(json, "\"schema_version\":\"__PLUGIN_RESULT_SCHEMA__\"");
    if (schema == nullptr) {
        out.success = false;
        out.reason = "invalid ttp result schema";
        if (fallback_rc == 0) {
            out.result_code = 2;
        }
        return out;
    }
    bool success = out.success;
    if (ReadJsonBool(json, "success", &success)) {
        out.success = success;
    }
    long code = out.result_code;
    if (ReadJsonLong(json, "result_code", &code)) {
        out.result_code = code;
    }
    unsigned long win32 = 0;
    if (ReadJsonULong(json, "win32_error", &win32)) {
        out.win32_error = win32;
    }
    CopyJsonStringValue(json, "reason", out.reason);
    CopyJsonStringValue(json, "detail", out.detail);
    return out;
}

static void SignalElevatedDone(int argc, char** argv, int rc) {
    const char* prefix = "--edreval-elevated-done=";
    const std::size_t prefix_len = std::strlen(prefix);
    for (int i = 1; i < argc; ++i) {
        if (std::strncmp(argv[i], prefix, prefix_len) != 0) {
            continue;
        }
        const char* name = argv[i] + prefix_len;
        char temp[MAX_PATH];
        if (::GetTempPathA(MAX_PATH, temp) != 0) {
            std::string file = std::string(temp) + "edreval-elev-rc-";
            for (const char* cursor = name; *cursor != '\0'; ++cursor) {
                const char ch = *cursor;
                if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                    (ch >= '0' && ch <= '9')) {
                    file.push_back(ch);
                } else {
                    file.push_back('_');
                }
            }
            file += ".txt";
            HANDLE handle = ::CreateFileA(
                file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (handle != INVALID_HANDLE_VALUE) {
                const std::string body = std::to_string(rc);
                DWORD written = 0;
                ::WriteFile(
                    handle, body.c_str(), static_cast<DWORD>(body.size()), &written, nullptr);
                ::CloseHandle(handle);
            }
        }
        HANDLE event = ::OpenEventA(EVENT_MODIFY_STATE, FALSE, name);
        if (event != nullptr) {
            ::SetEvent(event);
            ::CloseHandle(event);
        }
        break;
    }
}
'''.replace("__PLUGIN_RESULT_SCHEMA__", PLUGIN_RESULT_SCHEMA_VERSION)


def _record_ttp_start(atom_id: str, ph_ids: Sequence[str]) -> str:
    if not ph_ids:
        return ""
    items = ", ".join(_cpp_cstring(item) for item in ph_ids)
    return f'''    static const char kAtomId[] = {_cpp_cstring(atom_id)};
    static const char* kPhIds[] = {{{items}}};
    for (std::size_t i = 0; i < sizeof(kPhIds) / sizeof(kPhIds[0]); ++i) {{
        edreval::sample_log::RecordTtpStart(kPhIds[i], kAtomId, "execute");
    }}
'''


def _record_ttp_result(ph_ids: Sequence[str]) -> str:
    if not ph_ids:
        return ""
    return '''    for (std::size_t i = 0; i < sizeof(kPhIds) / sizeof(kPhIds[0]); ++i) {
        edreval::sample_log::RecordTtpResult(
            kPhIds[i],
            kAtomId,
            "execute",
            parsed.success,
            parsed.result_code,
            parsed.win32_error,
            parsed.reason.c_str(),
            parsed.detail.c_str());
    }
'''


def render_logged_validation_harness_main(
    implementation_name: str,
    *,
    atom_id: str,
    ph_ids: Sequence[str],
) -> str:
    """Render the VM-bound Harness main that writes edreval-sample-log-v1."""
    entry_symbol = plugin_entry_symbol(implementation_name)
    return f'''#include <array>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>

#include "edreval_execution_log.h"
#include "{implementation_name}.h"
#include <windows.h>
{_harness_runtime_helpers()}
int main(int argc, char** argv) {{
    std::string log_error;
    (void)edreval::sample_log::Initialize(&log_error);
    const char* request_json = argc > 1 ? argv[1] : "{{}}";
    std::array<char, 65536> result_json{{}};
{_record_ttp_start(atom_id, ph_ids)}    const int rc = {entry_symbol}(
        request_json, result_json.data(), result_json.size());
    const TtpAbiResult parsed = ParseTtpResult(result_json.data(), rc);
{_record_ttp_result(ph_ids)}    edreval::sample_log::RecordSampleResult(
        parsed.success && rc == 0,
        rc == 0 ? parsed.result_code : rc,
        parsed.reason.c_str(),
        parsed.detail.c_str());
    SignalElevatedDone(argc, argv, rc);
    return rc;
}}
'''


def render_joint_validation_harness_main(
    consumer_implementation_name: str,
    producer_implementation_names: Sequence[str],
    *,
    consumer_atom_id: str,
    consumer_ph_ids: Sequence[str],
    payload_handoff: bool = True,
) -> str:
    """Render the operator-owned EXE that calls producers then the consumer.

    Payload consumers cannot use empty-json smoke for ``port.payload``. Producers
    run in dependency order; the first still sees the original request JSON, and
    each later producer receives the previous ``payload`` array in-process.
    Service-style joints only need producer side effects and reuse the original
    request JSON.
    """
    consumer = plugin_entry_symbol(consumer_implementation_name)
    producers = tuple(
        plugin_entry_symbol(name) for name in producer_implementation_names
    )
    if not producers:
        raise ValueError("联合 Harness 至少需要一个 producer implementation_name")
    includes = "\n".join(
        f'#include "{name}.h"'
        for name in (*producer_implementation_names, consumer_implementation_name)
    )
    if payload_handoff:
        producer_blocks: list[str] = []
        for index, symbol in enumerate(producers):
            if index == 0:
                request_setup = "        const char* producer_input = request_json;\n"
            else:
                request_setup = """        if (last_payload.empty()) {
            edreval::sample_log::RecordSampleResult(
                false, 2, "producer missing payload", "");
            return 2;
        }
        std::string producer_request = "{\\"payload\\":";
        producer_request.append(last_payload);
        producer_request.append("}");
        const char* producer_input = producer_request.c_str();
"""
            producer_blocks.append(
                f'''    {{
{request_setup}        std::array<char, 65536> producer_json{{}};
        const int producer_rc = {symbol}(
            producer_input, producer_json.data(), producer_json.size());
        const TtpAbiResult producer_parsed = ParseTtpResult(
            producer_json.data(), producer_rc);
        if (producer_rc != 0) {{
            edreval::sample_log::RecordSampleResult(
                false,
                producer_rc,
                producer_parsed.reason.c_str(),
                producer_parsed.detail.c_str());
            SignalElevatedDone(argc, argv, producer_rc);
            return producer_rc;
        }}
        bool delegated = false;
        if (ReadJsonBool(producer_json.data(), "delegated_to_elevated_process", &delegated) &&
            delegated) {{
            edreval::sample_log::RecordSampleResult(
                producer_parsed.success,
                producer_rc,
                producer_parsed.reason.c_str(),
                producer_parsed.detail.c_str());
            SignalElevatedDone(argc, argv, producer_rc);
            return producer_rc;
        }}
        if (!CopyPayloadArray(producer_json.data(), last_payload)) {{
            edreval::sample_log::RecordSampleResult(
                false, 2, "producer missing payload", "");
            return 2;
        }}
    }}'''
            )
        producer_body = "\n".join(producer_blocks)
        request_setup = (
            "    std::string last_payload;\n"
            f"{producer_body}\n"
            """    if (last_payload.empty()) {
        edreval::sample_log::RecordSampleResult(
            false, 2, "producer missing payload", "");
        return 2;
    }
    std::string consumer_request = "{\\"payload\\":";
    consumer_request.append(last_payload);
    consumer_request.append(",\\"target_image\\":\\"notepad.exe\\"}");
    const char* consumer_json = consumer_request.c_str();
"""
        )
    else:
        producer_body = "\n".join(
            f'''    {{
        std::array<char, 65536> producer_json{{}};
        const int producer_rc = {symbol}(
            request_json, producer_json.data(), producer_json.size());
        const TtpAbiResult producer_parsed = ParseTtpResult(
            producer_json.data(), producer_rc);
        if (producer_rc != 0 || !producer_parsed.success) {{
            edreval::sample_log::RecordSampleResult(
                false,
                producer_rc == 0 ? 2 : producer_rc,
                producer_parsed.reason.c_str(),
                producer_parsed.detail.c_str());
            SignalElevatedDone(argc, argv, producer_rc == 0 ? 2 : producer_rc);
            return producer_rc == 0 ? 2 : producer_rc;
        }}
        bool delegated = false;
        if (ReadJsonBool(producer_json.data(), "delegated_to_elevated_process", &delegated) &&
            delegated) {{
            edreval::sample_log::RecordSampleResult(
                producer_parsed.success,
                producer_rc,
                producer_parsed.reason.c_str(),
                producer_parsed.detail.c_str());
            SignalElevatedDone(argc, argv, producer_rc);
            return producer_rc;
        }}
    }}'''
            for symbol in producers
        )
        request_setup = f"{producer_body}\n    const char* consumer_json = request_json;\n"
    return f'''#include <array>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>

#include "edreval_execution_log.h"
{includes}
#include <windows.h>
{_harness_runtime_helpers()}
int main(int argc, char** argv) {{
    std::string log_error;
    (void)edreval::sample_log::Initialize(&log_error);
    const char* request_json = argc > 1 ? argv[1] : "{{}}";
{request_setup}    std::array<char, 65536> result_json{{}};
{_record_ttp_start(consumer_atom_id, consumer_ph_ids)}    const int rc = {consumer}(
        consumer_json, result_json.data(), result_json.size());
    const TtpAbiResult parsed = ParseTtpResult(result_json.data(), rc);
{_record_ttp_result(consumer_ph_ids)}    edreval::sample_log::RecordSampleResult(
        parsed.success && rc == 0,
        rc == 0 ? parsed.result_code : rc,
        parsed.reason.c_str(),
        parsed.detail.c_str());
    SignalElevatedDone(argc, argv, rc);
    return rc;
}}
'''


def render_public_header(implementation_name: str) -> str:
    """Render the control-plane-owned ABI declaration for one plugin implementation."""
    entry_symbol = plugin_entry_symbol(implementation_name)
    return f'''#pragma once

#include <cstddef>

extern "C" int {entry_symbol}(
    const char* request_json,
    char* result_json,
    std::size_t result_json_capacity);
'''


def render_validation_harness_project(
    implementation_name: str,
    artifact_path: str | Path,
    include_path: str | Path,
    *,
    dependency_artifact_paths: Sequence[str | Path] = (),
    dependency_include_paths: Sequence[str | Path] = (),
    project_name: str = "PluginValidationHarness",
    runtime_logging: bool = False,
) -> str:
    """Render the fixed MSBuild EXE that links one validation ``.lib``.

    The source agent never writes this project.  The control plane creates it
    after the static library has been hashed, so an EXE link failure cannot be
    hidden by a compile-only result.
    """
    validate_implementation_name(implementation_name)
    if not project_name or any(char in project_name for char in '<>"&'):
        raise ValueError("Harness project_name contains invalid XML characters")
    artifacts = (Path(artifact_path).resolve(),) + tuple(
        Path(item).resolve() for item in dependency_artifact_paths
    )
    if any(any(char in str(path) for char in (";", "$", "%", "\r", "\n")) for path in artifacts):
        raise ValueError("Harness artifact path contains an MSBuild list/property metacharacter")
    include = Path(include_path).resolve()
    includes = (include,) + tuple(Path(item).resolve() for item in dependency_include_paths)
    escaped_artifacts = ";".join(escape(str(path), {'"': "&quot;"}) for path in artifacts)
    escaped_include = ";".join(
        escape(str(path), {'"': "&quot;"}) for path in includes
    )
    if runtime_logging:
        escaped_include = escaped_include + ";$(ProjectDir)generated"
    escaped_name = escape(f"{implementation_name}Harness")
    escaped_project = escape(project_name)
    cl_compile_items = '    <ClCompile Include="main.cpp" />'
    if runtime_logging:
        cl_compile_items += (
            '\n    <ClCompile Include="generated\\edreval_execution_log.cpp" />'
        )
    return f'''<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <ProjectGuid>{{00000000-0000-0000-0000-000000000001}}</ProjectGuid>
    <Keyword>Win32Proj</Keyword>
    <RootNamespace>{escaped_project}</RootNamespace>
    <ProjectName>{escaped_project}</ProjectName>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.props" />
  <PropertyGroup>
    <IntDir>$(OutDir)obj\\</IntDir>
    <TargetName>{escaped_name}</TargetName>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile>
      <WarningLevel>Level4</WarningLevel>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <SDLCheck>true</SDLCheck>
      <AdditionalIncludeDirectories>{escaped_include};%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <LanguageStandard>stdcpp17</LanguageStandard>
      <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
    </ClCompile>
    <Link>
      <SubSystem>Console</SubSystem>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <AdditionalDependencies>{escaped_artifacts};%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
{cl_compile_items}
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />
</Project>
'''


def materialize_validation_harness(
    plugin_root: str | Path, implementation_name: str
) -> Path:
    """Write the fixed validation entry outside the plugin source tree."""
    root = Path(plugin_root).resolve()
    harness_root = (root / "harness").resolve()
    if not harness_root.is_relative_to(root):  # pragma: no cover - constant child path
        raise ValueError("plugin harness 路径越界")
    harness_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    target = harness_root / "main.cpp"
    expected = render_validation_harness_main(implementation_name)
    if target.exists() and target.read_text(encoding="utf-8") != expected:
        raise ValueError("Canonical Harness main.cpp 已存在但内容不一致")
    if not target.exists():
        target.write_text(expected, encoding="utf-8", newline="\n")
    return target


__all__ = [
    "PLUGIN_ABI_VERSION",
    "PLUGIN_RESULT_SCHEMA_VERSION",
    "canonical_source_paths",
    "materialize_validation_harness",
    "plugin_entry_symbol",
    "render_public_header",
    "render_joint_validation_harness_main",
    "render_logged_validation_harness_main",
    "render_validation_harness_project",
    "render_validation_harness_main",
    "validate_candidate_source_snapshot",
    "validate_catalog_source_files",
    "validate_implementation_name",
]
