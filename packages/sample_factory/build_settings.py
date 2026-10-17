"""Deterministic build settings applied to generated sample projects."""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from pathlib import Path

from packages.sample_factory.errors import BuildError

MSVC_PROJECT = "generated/sample.vcxproj"
_MSBUILD_NS = "http://schemas.microsoft.com/developer/msbuild/2003"


def enforce_msvc_static_runtime(root: str | Path, build_target_ref: str) -> None:
    """Normalize generated MSVC projects to static CRT/STL linkage."""
    if not _is_msvc_target(build_target_ref):
        return
    normalize_msvc_project_layout(root, build_target_ref)
    project = _project_path(root)
    tree, namespace = _load_project(project)
    compile_items = _compile_definitions(tree, namespace)
    if not compile_items:
        raise BuildError(f"MSVC project has no ClCompile item definitions: {MSVC_PROJECT}")

    changed = False
    for condition, item in compile_items:
        expected = "MultiThreadedDebug" if "Debug|" in condition else "MultiThreaded"
        runtime = item.find(_tag(namespace, "RuntimeLibrary"))
        if runtime is None:
            runtime = ET.SubElement(item, _tag(namespace, "RuntimeLibrary"))
            changed = True
        if runtime.text != expected:
            runtime.text = expected
            changed = True
    if changed:
        _write_project(project, tree)


def validate_msvc_static_runtime(root: str | Path, build_target_ref: str) -> None:
    """Reject MSVC projects that are not explicitly configured for /MT."""
    if not _is_msvc_target(build_target_ref):
        return
    validate_msvc_project_layout(root, build_target_ref)
    project = _project_path(root)
    tree, namespace = _load_project(project)
    compile_items = _compile_definitions(tree, namespace)
    if not compile_items:
        raise BuildError(f"MSVC project has no ClCompile item definitions: {MSVC_PROJECT}")
    for condition, item in compile_items:
        expected = "MultiThreadedDebug" if "Debug|" in condition else "MultiThreaded"
        runtime = item.find(_tag(namespace, "RuntimeLibrary"))
        if runtime is None or runtime.text != expected:
            raise BuildError(
                f"MSVC project must explicitly use {expected} in ClCompile: {MSVC_PROJECT}"
            )


def validate_msvc_static_library(root: str | Path, build_target_ref: str) -> None:
    """Reject plugin projects that build an executable or DLL instead of a static library."""
    if not _is_msvc_target(build_target_ref):
        return
    project = _project_path(root)
    tree, namespace = _load_project(project)
    configuration_types = {
        (item.text or "").strip()
        for item in tree.getroot().iter(_tag(namespace, "ConfigurationType"))
        if (item.text or "").strip()
    }
    if configuration_types != {"StaticLibrary"}:
        raise BuildError(
            f"MSVC plugin project must use ConfigurationType=StaticLibrary: {MSVC_PROJECT}"
        )


def normalize_msvc_project_layout(root: str | Path, build_target_ref: str) -> None:
    """Rewrite glue-generated vcxproj paths to be relative to generated/ (ProjectDir)."""
    if not _is_msvc_target(build_target_ref):
        return
    project = _project_path(root)
    tree, namespace = _load_project(project)
    changed = False
    for tag in ("ClCompile", "ClInclude"):
        for group in tree.getroot().findall(_tag(namespace, "ItemGroup")):
            for item in group.findall(_tag(namespace, tag)):
                include = item.get("Include")
                if include is None:
                    continue
                normalized = _normalize_msvc_item_path(include)
                if normalized != include:
                    item.set("Include", normalized)
                    changed = True
    expected_dirs = "$(ProjectDir);$(ProjectDir)..\\src"
    for _condition, compile_item in _compile_definitions(tree, namespace):
        dirs = compile_item.find(_tag(namespace, "AdditionalIncludeDirectories"))
        if dirs is None:
            dirs = ET.SubElement(compile_item, _tag(namespace, "AdditionalIncludeDirectories"))
            changed = True
        current = (dirs.text or "").strip()
        if "$(ProjectDir)" not in current:
            dirs.text = expected_dirs + ";%(AdditionalIncludeDirectories)"
            changed = True
        lang = compile_item.find(_tag(namespace, "LanguageStandard"))
        if lang is None:
            lang = ET.SubElement(compile_item, _tag(namespace, "LanguageStandard"))
            changed = True
        if lang.text != "stdcpp17":
            lang.text = "stdcpp17"
            changed = True
    if changed:
        _write_project(project, tree)


def validate_msvc_project_layout(root: str | Path, build_target_ref: str) -> None:
    if not _is_msvc_target(build_target_ref):
        return
    project = _project_path(root)
    tree, namespace = _load_project(project)
    for tag in ("ClCompile", "ClInclude"):
        for group in tree.getroot().findall(_tag(namespace, "ItemGroup")):
            for item in group.findall(_tag(namespace, tag)):
                include = item.get("Include")
                if include is None:
                    continue
                lowered = include.replace("/", "\\").lower()
                if lowered.startswith("generated\\"):
                    raise BuildError(
                        f"MSVC project item paths must be relative to generated/: {include}"
                    )
                if lowered.startswith("src\\"):
                    raise BuildError(
                        f"MSVC project must reference src via ..\\src: {include}"
                    )
    for _condition, compile_item in _compile_definitions(tree, namespace):
        dirs = compile_item.find(_tag(namespace, "AdditionalIncludeDirectories"))
        if dirs is None or "$(ProjectDir)" not in (dirs.text or ""):
            raise BuildError(
                f"MSVC project must use $(ProjectDir) include roots: {MSVC_PROJECT}"
            )
        lang = compile_item.find(_tag(namespace, "LanguageStandard"))
        if lang is None or lang.text != "stdcpp17":
            raise BuildError(
                f"MSVC project must set LanguageStandard=stdcpp17: {MSVC_PROJECT}"
            )


def _normalize_msvc_item_path(include: str) -> str:
    normalized = include.replace("/", "\\")
    lowered = normalized.lower()
    if lowered.startswith("generated\\"):
        return normalized[len("generated\\") :]
    if lowered.startswith("src\\"):
        return "..\\" + normalized
    return normalized


def effective_toolchain_fp(toolchain_fp: str, build_target_ref: str) -> str:
    """Include the control-plane CRT policy in the reproducibility fingerprint."""
    if not _is_msvc_target(build_target_ref):
        return toolchain_fp
    suffix = "+crt-static"
    return toolchain_fp if toolchain_fp.endswith(suffix) else toolchain_fp + suffix


def _is_msvc_target(build_target_ref: str) -> bool:
    return "msvc" in build_target_ref.lower()


def _project_path(root: str | Path) -> Path:
    base = Path(root).resolve()
    project = (base / MSVC_PROJECT).resolve()
    if not project.is_relative_to(base) or not project.is_file():
        raise BuildError(f"MSVC project does not exist: {MSVC_PROJECT}")
    return project


def _load_project(project: Path) -> tuple[ET.ElementTree[ET.Element[str]], str]:
    try:
        tree = ET.parse(project)
    except (ET.ParseError, OSError) as exc:
        raise BuildError(f"MSVC project is not valid XML: {project}") from exc
    root_namespace = ""
    if (root_tag := tree.getroot().tag) and root_tag.startswith("{"):
        root_namespace = root_tag[1:].split("}", 1)[0]
    if root_namespace != _MSBUILD_NS:
        raise BuildError(f"MSVC project has unexpected XML namespace: {project}")
    return tree, root_namespace


def _write_project(project: Path, tree: ET.ElementTree[ET.Element[str]]) -> None:
    ET.register_namespace("", _MSBUILD_NS)
    ET.indent(tree, space="  ")
    staging = project.with_name(project.name + ".part")
    tree.write(staging, encoding="utf-8", xml_declaration=True, short_empty_elements=True)
    os.chmod(staging, 0o600)
    staging.replace(project)


def _compile_definitions(
    tree: ET.ElementTree[ET.Element[str]], namespace: str
) -> list[tuple[str, ET.Element]]:
    result: list[tuple[str, ET.Element]] = []
    for group in tree.getroot().findall(_tag(namespace, "ItemDefinitionGroup")):
        compile_item = group.find(_tag(namespace, "ClCompile"))
        if compile_item is not None:
            result.append((group.get("Condition", ""), compile_item))
    return result


def _tag(namespace: str, name: str) -> str:
    return f"{{{namespace}}}{name}"


__all__ = [
    "MSVC_PROJECT",
    "effective_toolchain_fp",
    "enforce_msvc_static_runtime",
    "normalize_msvc_project_layout",
    "validate_msvc_project_layout",
    "validate_msvc_static_library",
    "validate_msvc_static_runtime",
]
