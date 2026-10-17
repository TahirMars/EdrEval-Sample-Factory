"""Deterministic optional runtime logger sources for Windows samples."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Protocol

from packages.sample_factory.errors import BuildError

LOGGER_HEADER = "generated/edreval_execution_log.h"
LOGGER_SOURCE = "generated/edreval_execution_log.cpp"
LOGGER_CONFIG = "generated/edreval_execution_log_config.h"
LOGGER_FILES = frozenset({LOGGER_HEADER, LOGGER_SOURCE, LOGGER_CONFIG})


class RuntimeLoggingMetadata(Protocol):
    @property
    def recipe_id(self) -> str: ...

    @property
    def ph_ids(self) -> tuple[str, ...]: ...

    @property
    def atom_ids(self) -> tuple[str, ...]: ...

    @property
    def execution_logging(self) -> bool: ...

    @property
    def trigger_mode(self) -> object: ...


_HEADER = r'''#pragma once

#include <string>

namespace edreval::sample_log {

bool Initialize(std::string* error = nullptr) noexcept;

void RecordTtpStart(
    const char* ph_id,
    const char* atom_id,
    const char* stage) noexcept;

void RecordTtpResult(
    const char* ph_id,
    const char* atom_id,
    const char* stage,
    bool success,
    long result_code,
    unsigned long win32_error,
    const char* reason,
    const char* detail) noexcept;

void RecordSampleResult(
    bool success,
    long result_code,
    const char* reason,
    const char* detail) noexcept;

const wchar_t* LogPath() noexcept;

}  // namespace edreval::sample_log
'''


_SOURCE = r'''#include "edreval_execution_log.h"
#include "edreval_execution_log_config.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace edreval::sample_log {
namespace {

using Clock = std::chrono::steady_clock;

std::mutex g_mutex;
HANDLE g_file = INVALID_HANDLE_VALUE;
bool g_initialized = false;
bool g_init_attempted = false;
std::string g_init_error;
std::string g_run_id;
std::wstring g_log_path;
Clock::time_point g_sample_started;
std::map<std::string, Clock::time_point> g_ttp_started;

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::string Win32Message(DWORD code) {
    if (code == ERROR_SUCCESS) {
        return {};
    }
    char* raw = nullptr;
    const DWORD length = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<char*>(&raw),
        0,
        nullptr);
    std::string result = length && raw ? std::string(raw, length) : "Win32 error";
    if (raw) {
        LocalFree(raw);
    }
    while (!result.empty() && (result.back() == '\r' || result.back() == '\n' || result.back() == ' ')) {
        result.pop_back();
    }
    return result;
}

std::string UtcNow() {
    SYSTEMTIME now{};
    GetSystemTime(&now);
    std::ostringstream out;
    out << std::setfill('0') << std::setw(4) << now.wYear << '-' << std::setw(2)
        << now.wMonth << '-' << std::setw(2) << now.wDay << 'T' << std::setw(2)
        << now.wHour << ':' << std::setw(2) << now.wMinute << ':' << std::setw(2)
        << now.wSecond << '.' << std::setw(3) << now.wMilliseconds << 'Z';
    return out.str();
}

std::string JsonString(const std::string& value) {
    std::ostringstream out;
    out << '"';
    static constexpr char hex[] = "0123456789abcdef";
    for (unsigned char ch : value) {
        switch (ch) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (ch < 0x20) {
                    out << "\\u00" << hex[(ch >> 4) & 0x0f] << hex[ch & 0x0f];
                } else {
                    out << static_cast<char>(ch);
                }
        }
    }
    out << '"';
    return out.str();
}

bool ContainsLongHex(const std::string& value) {
    std::size_t run = 0;
    for (unsigned char ch : value) {
        run = std::isxdigit(ch) ? run + 1 : 0;
        if (run >= 32) {
            return true;
        }
    }
    return false;
}

std::string Sanitize(const char* raw) {
    std::string value = raw ? raw : "";
    if (value.size() > 4096) {
        value.resize(4096);
    }
    std::string lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    static constexpr const char* sensitive[] = {
        "secret://", "lab-secret://", "password", "passwd", "authorization",
        "cookie", "token", "ghp_", "github_pat_", "akia", "begin private key"};
    for (const char* marker : sensitive) {
        if (lowered.find(marker) != std::string::npos) {
            return "[REDACTED]";
        }
    }
    return ContainsLongHex(value) ? "[REDACTED]" : value;
}

std::string JsonArray(const char* const* values, std::size_t count) {
    std::ostringstream out;
    out << '[';
    for (std::size_t index = 0; index < count; ++index) {
        if (index) {
            out << ',';
        }
        out << JsonString(values[index]);
    }
    out << ']';
    return out.str();
}

long long ElapsedMs(Clock::time_point start) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
}

std::string TtpKey(const char* ph_id, const char* atom_id, const char* stage) {
    return std::string(ph_id ? ph_id : "") + '\x1f' + (atom_id ? atom_id : "") +
        '\x1f' + (stage ? stage : "");
}

void WriteLineUnlocked(const std::string& line) {
    if (g_file == INVALID_HANDLE_VALUE) {
        return;
    }
    const std::string framed = line + "\r\n";
    DWORD written = 0;
    if (!WriteFile(
            g_file,
            framed.data(),
            static_cast<DWORD>(framed.size()),
            &written,
            nullptr) || written != framed.size()) {
        CloseHandle(g_file);
        g_file = INVALID_HANDLE_VALUE;
    }
}

std::wstring ProgramDataRoot() {
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetEnvironmentVariableW(
        L"ProgramData", buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length > 0 && length < buffer.size()) {
        return std::wstring(buffer.data(), length);
    }
    return L"C:\\ProgramData";
}

bool EnsureDirectory(const std::wstring& path, std::string* error) {
    if (CreateDirectoryW(path.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS) {
        return true;
    }
    const DWORD code = GetLastError();
    if (error) {
        *error = "CreateDirectoryW(" + WideToUtf8(path) + ") failed: " +
            std::to_string(code) + " " + Win32Message(code);
    }
    return false;
}

std::wstring SafeFileComponent(const char* raw) {
    std::wstring result;
    for (unsigned char ch : std::string(raw ? raw : "sample")) {
        result.push_back(std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.'
            ? static_cast<wchar_t>(ch)
            : L'_');
    }
    return result.empty() ? L"sample" : result;
}

std::string NewRunId(unsigned int attempt) {
    FILETIME time{};
    GetSystemTimeAsFileTime(&time);
    ULARGE_INTEGER ticks{};
    ticks.LowPart = time.dwLowDateTime;
    ticks.HighPart = time.dwHighDateTime;
    std::ostringstream out;
    out << std::hex << ticks.QuadPart << '-' << GetCurrentProcessId() << '-' << attempt;
    return out.str();
}

std::string HostName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD length = MAX_COMPUTERNAME_LENGTH + 1;
    return GetComputerNameW(buffer, &length) ? WideToUtf8(std::wstring(buffer, length)) : "";
}

std::string ImagePath() {
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    return length > 0 && length < buffer.size() ? WideToUtf8(std::wstring(buffer.data(), length)) : "";
}

void SignalElevatedDoneFromCommandLine() noexcept {
    // UACME relaunches the sample with --edreval-elevated-done=<event>. Signal the
    // medium-IL parent as soon as the elevated child starts logging, so the parent
    // does not time out waiting while the child continues the chain.
    const wchar_t* cmd = ::GetCommandLineW();
    if (cmd == nullptr) {
        return;
    }
    const wchar_t* marker = L"--edreval-elevated-done=";
    const wchar_t* found = ::wcsstr(cmd, marker);
    if (found == nullptr) {
        return;
    }
    found += 24;  // strlen("--edreval-elevated-done=")
    std::string name;
    while (*found != L'\0' && *found != L' ' && *found != L'"') {
        if (*found < 128) {
            name.push_back(static_cast<char>(*found));
        }
        ++found;
    }
    if (name.empty()) {
        return;
    }
    HANDLE event = ::OpenEventA(EVENT_MODIFY_STATE, FALSE, name.c_str());
    if (event != nullptr) {
        ::SetEvent(event);
        ::CloseHandle(event);
    }
}

}  // namespace

bool Initialize(std::string* error) noexcept {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_initialized) {
            return true;
        }
        if (g_init_attempted) {
            if (error) {
                *error = g_init_error;
            }
            return false;
        }
        g_init_attempted = true;
        const std::wstring product_dir = ProgramDataRoot() + L"\\EdrEvalAgent";
        const std::wstring log_dir = product_dir + L"\\SampleLogs";
        if (!EnsureDirectory(product_dir, &g_init_error) ||
            !EnsureDirectory(log_dir, &g_init_error)) {
            if (error) {
                *error = g_init_error;
            }
            return false;
        }
        for (unsigned int attempt = 0; attempt < 8; ++attempt) {
            g_run_id = NewRunId(attempt);
            g_log_path = log_dir + L"\\" + SafeFileComponent(config::kRecipeId) + L"-" +
                SafeFileComponent(g_run_id.c_str()) + L".jsonl";
            g_file = CreateFileW(
                g_log_path.c_str(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (g_file != INVALID_HANDLE_VALUE) {
                break;
            }
            if (GetLastError() != ERROR_FILE_EXISTS) {
                break;
            }
        }
        if (g_file == INVALID_HANDLE_VALUE) {
            const DWORD code = GetLastError();
            g_init_error = "CreateFileW failed: " + std::to_string(code) + " " + Win32Message(code);
            if (error) {
                *error = g_init_error;
            }
            return false;
        }
        g_sample_started = Clock::now();
        g_initialized = true;
        std::ostringstream line;
        line << "{\"schema_version\":\"edreval-sample-log-v1\",\"event\":\"sample_start\""
             << ",\"timestamp_utc\":" << JsonString(UtcNow())
             << ",\"sample_id\":" << JsonString(config::kSampleId)
             << ",\"recipe_id\":" << JsonString(config::kRecipeId)
             << ",\"run_id\":" << JsonString(g_run_id)
             << ",\"trigger_mode\":" << JsonString(config::kTriggerMode)
             << ",\"process_id\":" << GetCurrentProcessId()
             << ",\"host_name\":" << JsonString(HostName())
             << ",\"image_path\":" << JsonString(ImagePath())
             << ",\"execution_logging\":true"
             << ",\"ph_ids\":" << JsonArray(config::kPhIds, config::kPhIdCount)
             << ",\"atom_ids\":" << JsonArray(config::kAtomIds, config::kAtomIdCount)
             << '}';
        WriteLineUnlocked(line.str());
        SignalElevatedDoneFromCommandLine();
        return true;
    } catch (const std::exception& exc) {
        if (error) {
            *error = exc.what();
        }
        return false;
    } catch (...) {
        if (error) {
            *error = "unknown logger initialization failure";
        }
        return false;
    }
}

void RecordTtpStart(const char* ph_id, const char* atom_id, const char* stage) noexcept {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_initialized) {
            return;
        }
        g_ttp_started[TtpKey(ph_id, atom_id, stage)] = Clock::now();
        std::ostringstream line;
        line << "{\"schema_version\":\"edreval-sample-log-v1\",\"event\":\"ttp_start\""
             << ",\"timestamp_utc\":" << JsonString(UtcNow())
             << ",\"sample_id\":" << JsonString(config::kSampleId)
             << ",\"run_id\":" << JsonString(g_run_id)
             << ",\"elapsed_ms\":" << ElapsedMs(g_sample_started)
             << ",\"ph_id\":" << JsonString(ph_id ? ph_id : "")
             << ",\"atom_id\":" << JsonString(atom_id ? atom_id : "")
             << ",\"stage\":" << JsonString(stage ? stage : "") << '}';
        WriteLineUnlocked(line.str());
    } catch (...) {
    }
}

void RecordTtpResult(
    const char* ph_id,
    const char* atom_id,
    const char* stage,
    bool success,
    long result_code,
    unsigned long win32_error,
    const char* reason,
    const char* detail) noexcept {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_initialized) {
            return;
        }
        const auto found = g_ttp_started.find(TtpKey(ph_id, atom_id, stage));
        std::ostringstream line;
        line << "{\"schema_version\":\"edreval-sample-log-v1\",\"event\":\"ttp_result\""
             << ",\"timestamp_utc\":" << JsonString(UtcNow())
             << ",\"sample_id\":" << JsonString(config::kSampleId)
             << ",\"run_id\":" << JsonString(g_run_id)
             << ",\"elapsed_ms\":" << ElapsedMs(g_sample_started)
             << ",\"duration_ms\":";
        if (found == g_ttp_started.end()) {
            line << "null";
        } else {
            line << ElapsedMs(found->second);
            g_ttp_started.erase(found);
        }
        line << ",\"ph_id\":" << JsonString(ph_id ? ph_id : "")
             << ",\"atom_id\":" << JsonString(atom_id ? atom_id : "")
             << ",\"stage\":" << JsonString(stage ? stage : "")
             << ",\"success\":" << (success ? "true" : "false")
             << ",\"result_code\":" << result_code
             << ",\"win32_error\":" << win32_error
             << ",\"win32_error_message\":" << JsonString(Sanitize(Win32Message(win32_error).c_str()))
             << ",\"reason\":" << JsonString(Sanitize(reason))
             << ",\"detail\":" << JsonString(Sanitize(detail)) << '}';
        WriteLineUnlocked(line.str());
    } catch (...) {
    }
}

void RecordSampleResult(
    bool success,
    long result_code,
    const char* reason,
    const char* detail) noexcept {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_initialized) {
            return;
        }
        std::ostringstream line;
        line << "{\"schema_version\":\"edreval-sample-log-v1\",\"event\":\"sample_result\""
             << ",\"timestamp_utc\":" << JsonString(UtcNow())
             << ",\"sample_id\":" << JsonString(config::kSampleId)
             << ",\"run_id\":" << JsonString(g_run_id)
             << ",\"success\":" << (success ? "true" : "false")
             << ",\"result_code\":" << result_code
             << ",\"duration_ms\":" << ElapsedMs(g_sample_started)
             << ",\"reason\":" << JsonString(Sanitize(reason))
             << ",\"detail\":" << JsonString(Sanitize(detail)) << '}';
        WriteLineUnlocked(line.str());
        FlushFileBuffers(g_file);
    } catch (...) {
    }
}

const wchar_t* LogPath() noexcept {
    return g_log_path.c_str();
}

}  // namespace edreval::sample_log
'''


def runtime_logging_sources(metadata: RuntimeLoggingMetadata) -> dict[str, str]:
    trigger = getattr(metadata.trigger_mode, "value", str(metadata.trigger_mode))
    config = f'''#pragma once

#include <cstddef>

namespace edreval::sample_log::config {{

inline constexpr const char kSampleId[] = {_cpp_string(metadata.recipe_id)};
inline constexpr const char kRecipeId[] = {_cpp_string(metadata.recipe_id)};
inline constexpr const char kTriggerMode[] = {_cpp_string(str(trigger))};
inline constexpr const char* kPhIds[] = {{{_cpp_items(metadata.ph_ids)}}};
inline constexpr std::size_t kPhIdCount = {len(metadata.ph_ids)};
inline constexpr const char* kAtomIds[] = {{{_cpp_items(metadata.atom_ids)}}};
inline constexpr std::size_t kAtomIdCount = {len(metadata.atom_ids)};

}}  // namespace edreval::sample_log::config
'''
    return {
        LOGGER_HEADER: _HEADER,
        LOGGER_SOURCE: _SOURCE,
        LOGGER_CONFIG: config,
    }


def configure_runtime_logging(root: str | Path, metadata: RuntimeLoggingMetadata) -> None:
    base = Path(root).resolve()
    if not metadata.execution_logging:
        remove_runtime_logging(base)
        return
    for relative, content in runtime_logging_sources(metadata).items():
        target = (base / relative).resolve()
        if not target.is_relative_to(base):  # pragma: no cover - constant paths
            raise BuildError(f"runtime logger path escaped workspace: {relative}")
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        staging = target.with_name(target.name + ".part")
        staging.write_text(content, encoding="utf-8", newline="\n")
        os.chmod(staging, 0o600)
        staging.replace(target)


def remove_runtime_logging(root: str | Path) -> None:
    base = Path(root).resolve()
    for relative in LOGGER_FILES:
        target = (base / relative).resolve()
        if target.is_relative_to(base):
            target.unlink(missing_ok=True)
            target.with_name(target.name + ".part").unlink(missing_ok=True)


def validate_runtime_logging(root: str | Path, metadata: RuntimeLoggingMetadata) -> None:
    base = Path(root).resolve()
    expected = runtime_logging_sources(metadata)
    present = {relative for relative in LOGGER_FILES if (base / relative).is_file()}
    if not metadata.execution_logging:
        if present:
            raise BuildError(
                "execution_logging=False but runtime logger sources remain: "
                + ", ".join(sorted(present))
            )
        return
    missing = LOGGER_FILES - present
    if missing:
        raise BuildError("execution_logging=True but runtime logger sources are missing: " + ", ".join(sorted(missing)))
    for relative, content in expected.items():
        if (base / relative).read_text(encoding="utf-8") != content:
            raise BuildError(f"deterministic runtime logger source was modified: {relative}")


def validate_runtime_logging_build_inputs(
    root: str | Path,
    metadata: RuntimeLoggingMetadata,
    argv: tuple[str, ...] | list[str],
) -> None:
    """Prove that an enabled logger source is part of the registered build input."""
    validate_runtime_logging(root, metadata)
    if not metadata.execution_logging:
        return
    base = Path(root).resolve()
    source_name = Path(LOGGER_SOURCE).name.lower()
    direct_sources = {
        token.strip('"').replace("\\", "/").rsplit("/", 1)[-1].lower()
        for token in argv
    }
    if source_name in direct_sources:
        return

    referenced_projects: list[Path] = []
    for token in argv:
        candidate = Path(token.strip('"'))
        if candidate.suffix.lower() in {".vcxproj", ".csproj"} and candidate.is_file():
            referenced_projects.append(candidate)
        if candidate.suffix.lower() in {".c", ".cc", ".cpp"} and candidate.is_file():
            try:
                compiled_source = candidate.read_text(encoding="utf-8")
            except UnicodeDecodeError as exc:
                raise BuildError(f"build input is not UTF-8: {candidate}") from exc
            if '#include "edreval_execution_log.cpp"' in compiled_source:
                return
    executable = Path(argv[0]).name.lower() if argv else ""
    if "cmake" in executable:
        cmake = base / "CMakeLists.txt"
        if cmake.is_file():
            referenced_projects.append(cmake)
    if executable in {"make", "gmake", "mingw32-make", "nmake"}:
        makefile = base / "Makefile"
        if makefile.is_file():
            referenced_projects.append(makefile)

    for project in referenced_projects:
        try:
            text = project.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise BuildError(f"build input is not UTF-8: {project}") from exc
        if source_name in text.lower():
            return
    raise BuildError(
        "execution_logging=True but the registered build input does not include "
        + LOGGER_SOURCE
    )


def _cpp_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _cpp_items(values: tuple[str, ...]) -> str:
    return ", ".join(_cpp_string(value) for value in values)


__all__ = [
    "LOGGER_CONFIG",
    "LOGGER_FILES",
    "LOGGER_HEADER",
    "LOGGER_SOURCE",
    "configure_runtime_logging",
    "remove_runtime_logging",
    "runtime_logging_sources",
    "validate_runtime_logging",
    "validate_runtime_logging_build_inputs",
]
