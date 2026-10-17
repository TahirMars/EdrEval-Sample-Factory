"""类型化 handoff 图：闭合校验与编译期确定性物化。

控制面只解析 ``payload://`` / ``lab-secret://`` 引用并写入 generated 头文件；
LLM 不得接触载荷字节。策略与具体 TTP 解耦，供 APC/注入/映像篡改等复用。
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath

from packages.sample_factory.errors import CatalogError, SampleFactoryError
from packages.sample_factory.models import (
    AtomSpec,
    GlueMaterializeItem,
    HandoffMaterialize,
)

_HANDOFF_TOKEN_RE = re.compile(r"[^a-zA-Z0-9]+")
_HANDOFF_ARRAY_ELEMENT_CPP_TYPE = "const unsigned char"
HANDOFF_ARRAY_CPP_TYPE = f"{_HANDOFF_ARRAY_ELEMENT_CPP_TYPE}[]"
HANDOFF_SIZE_CPP_TYPE = "const size_t"
_CPP_IDENTIFIER_CHARS = r"A-Za-z0-9_"
_CPP_REFERENCE_SUFFIXES = frozenset(
    {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
)
_CPP_NON_CODE_RE = re.compile(
    r'''R"(?P<raw_delimiter>[^\s()\\]{0,16})\(.*?\)(?P=raw_delimiter)"'''
    r'''|//[^\r\n]*|/\*.*?\*/'''
    r'''|"(?:\\.|[^"\\])*"'''
    r"|'(?:\\.|[^'\\])*'",
    re.DOTALL,
)


class HandoffError(SampleFactoryError, ValueError):
    """handoff 图或物化失败。"""


def validate_handoff_closure(specs: Sequence[AtomSpec]) -> None:
    """按 Recipe 原子顺序校验 consumes ⊆ 前方 produces。"""
    available: set[str] = set()
    for spec in specs:
        missing = [item for item in spec.consumes_handoffs if item not in available]
        if missing:
            raise CatalogError(
                f"{spec.atom_id} 缺少上游 handoff 生产者：{missing}；"
                "请在同一次组合中选择 produces 这些边的 loader/支撑原子"
            )
        available.update(spec.produces_handoffs)


def materialize_items_for(specs: Sequence[AtomSpec]) -> tuple[GlueMaterializeItem, ...]:
    items: list[GlueMaterializeItem] = []
    for spec in specs:
        if spec.materialize is not HandoffMaterialize.EMBED_AT_BUILD:
            continue
        if not spec.artifact_ref:
            raise HandoffError(f"{spec.atom_id} embed_at_build 缺 artifact_ref")
        if not spec.produces_handoffs:
            raise HandoffError(f"{spec.atom_id} embed_at_build 必须 produces 至少一个 handoff")
        for handoff_id in spec.produces_handoffs:
            items.append(
                GlueMaterializeItem(
                    atom_id=spec.atom_id,
                    handoff_id=handoff_id,
                    artifact_ref=spec.artifact_ref,
                    strategy=spec.materialize,
                )
            )
    return tuple(items)


def handoff_header_path(handoff_id: str) -> str:
    return f"generated/{handoff_symbol_prefix(handoff_id)}.h"


def handoff_symbol_prefix(handoff_id: str) -> str:
    token = handoff_id.removeprefix("handoff://")
    cleaned = _HANDOFF_TOKEN_RE.sub("_", token).strip("_")
    if not cleaned:
        raise HandoffError(f"无法从 handoff id 派生符号：{handoff_id}")
    return f"handoff_{cleaned}"


def handoff_array_symbol(handoff_id: str) -> str:
    """Return the deterministic C symbol for an embedded handoff payload."""
    return f"k{_camel(handoff_symbol_prefix(handoff_id))}"


def handoff_size_symbol(handoff_id: str) -> str:
    """Return the deterministic C symbol for an embedded handoff payload size."""
    return f"{handoff_array_symbol(handoff_id)}Size"


def validate_embedded_handoff_references(
    sources: Mapping[str, str],
    items: Sequence[GlueMaterializeItem],
) -> None:
    """Require glue to use each materialized handoff's final C++ identifiers verbatim."""
    handoff_ids = tuple(
        dict.fromkeys(
            item.handoff_id
            for item in items
            if item.strategy is HandoffMaterialize.EMBED_AT_BUILD
        )
    )
    if not handoff_ids:
        return

    protected_headers = {handoff_header_path(handoff_id) for handoff_id in handoff_ids}
    consumers = {
        path.replace("\\", "/"): content
        for path, content in sources.items()
        if path.replace("\\", "/").startswith("generated/")
        and PurePosixPath(path.replace("\\", "/")).suffix.lower()
        in _CPP_REFERENCE_SUFFIXES
        and path.replace("\\", "/") not in protected_headers
    }
    source_text = "\n".join(consumers.values())
    code_text = _CPP_NON_CODE_RE.sub(" ", source_text)
    errors: list[str] = []

    for handoff_id in handoff_ids:
        header_name = PurePosixPath(handoff_header_path(handoff_id)).name
        include_pattern = re.compile(
            rf'^\s*#\s*include\s*["<](?:[^">\r\n]*[\\/])?{re.escape(header_name)}[">]',
            re.MULTILINE,
        )
        if not include_pattern.search(source_text):
            errors.append(f'缺少 #include "{header_name}"')

        for symbol in (handoff_array_symbol(handoff_id), handoff_size_symbol(handoff_id)):
            exact_pattern = re.compile(
                rf"(?<![{_CPP_IDENTIFIER_CHARS}]){re.escape(symbol)}"
                rf"(?![{_CPP_IDENTIFIER_CHARS}])"
            )
            qualified_pattern = re.compile(
                rf"(?<![{_CPP_IDENTIFIER_CHARS}])"
                rf"(?:(?:[A-Za-z_][A-Za-z0-9_]*)?\s*::\s*)+"
                rf"{re.escape(symbol)}(?![{_CPP_IDENTIFIER_CHARS}])"
            )
            if qualified_pattern.search(code_text):
                errors.append(f"{symbol} 不得用 symbol_prefix 或命名空间限定")
            elif not exact_pattern.search(code_text):
                errors.append(f"缺少完整 C++ 标识符 {symbol}")

    if errors:
        raise HandoffError("embedded handoff 编译前静态门禁失败：" + "；".join(errors))


def validate_embedded_handoff_workspace(
    source_root: Path,
    items: Sequence[GlueMaterializeItem],
) -> None:
    """Load generated text sources and apply the embedded-handoff reference gate."""
    if not items:
        return
    generated = source_root / "generated"
    sources: dict[str, str] = {}
    if generated.is_dir():
        for path in sorted(generated.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in _CPP_REFERENCE_SUFFIXES:
                continue
            relative = path.relative_to(source_root).as_posix()
            try:
                sources[relative] = path.read_text(encoding="utf-8")
            except UnicodeDecodeError as exc:
                raise HandoffError(f"handoff 静态门禁无法读取 UTF-8 源码：{relative}") from exc
    validate_embedded_handoff_references(sources, items)


def resolve_payload_bytes(
    artifact_ref: str, *, payload_root: Path | Sequence[Path]
) -> bytes:
    if artifact_ref.startswith("payload://"):
        relative = artifact_ref.removeprefix("payload://").strip("/")
        if not relative or ".." in PurePosixPath(relative).parts:
            raise HandoffError(f"非法 payload:// 引用：{artifact_ref}")
        roots = _payload_roots(payload_root)
        searched: list[str] = []
        for root in roots:
            candidates = [(root / relative).resolve()]
            if not relative.endswith(".bin"):
                candidates.append((root / f"{relative}.bin").resolve())
            for candidate in candidates:
                searched.append(candidate.as_posix())
                if candidate.is_relative_to(root) and candidate.is_file():
                    data = candidate.read_bytes()
                    if not data:
                        raise HandoffError(f"payload 为空：{artifact_ref}")
                    if len(data) > 4 * 1024 * 1024:
                        raise HandoffError(f"payload 超过 4MiB 嵌入上限：{artifact_ref}")
                    return data
        raise HandoffError(
            f"payload 文件不存在：{artifact_ref}（已查：{', '.join(searched)}）"
        )
    if artifact_ref.startswith(("lab-secret://", "secret://")):
        raise HandoffError(
            f"artifact_ref {artifact_ref} 需密钥库解析；本机构建宿主尚未接线 secret 物化"
        )
    raise HandoffError(f"不支持的 artifact_ref：{artifact_ref}")


def render_embed_header(handoff_id: str, payload: bytes) -> str:
    array_name = handoff_array_symbol(handoff_id)
    size_name = handoff_size_symbol(handoff_id)
    body = ", ".join(f"0x{byte:02x}" for byte in payload)
    return (
        "#pragma once\n"
        "#include <stddef.h>\n"
        f"/* auto-generated from {handoff_id}; do not edit */\n"
        f"static {_HANDOFF_ARRAY_ELEMENT_CPP_TYPE} {array_name}[] = {{ {body} }};\n"
        f"static {HANDOFF_SIZE_CPP_TYPE} {size_name} = sizeof({array_name});\n"
    )


def apply_embed_materialize(
    workspace_root: Path,
    items: Sequence[GlueMaterializeItem],
    *,
    payload_root: Path | Sequence[Path],
) -> tuple[str, ...]:
    """写入 generated/handoff_*.h，返回相对路径列表。"""
    written: list[str] = []
    generated = workspace_root / "generated"
    generated.mkdir(parents=True, mode=0o700, exist_ok=True)
    for item in items:
        if item.strategy is not HandoffMaterialize.EMBED_AT_BUILD:
            raise HandoffError(f"暂不支持的物化策略：{item.strategy.value}")
        relative = handoff_header_path(item.handoff_id)
        target = (workspace_root / relative).resolve()
        if not target.is_relative_to(workspace_root.resolve()):
            raise HandoffError(f"物化路径越界：{relative}")
        payload = resolve_payload_bytes(item.artifact_ref, payload_root=payload_root)
        target.write_text(render_embed_header(item.handoff_id, payload), encoding="utf-8")
        written.append(relative)
    return tuple(written)


def _payload_roots(payload_root: Path | Sequence[Path]) -> tuple[Path, ...]:
    if isinstance(payload_root, (str, Path)):
        roots = (Path(payload_root).resolve(),)
    else:
        roots = tuple(Path(item).resolve() for item in payload_root)
    if not roots:
        raise HandoffError("payload 根目录为空")
    return roots


def _camel(token: str) -> str:
    parts = [part for part in token.split("_") if part]
    return "".join(part[:1].upper() + part[1:] for part in parts)


__all__ = [
    "HANDOFF_ARRAY_CPP_TYPE",
    "HANDOFF_SIZE_CPP_TYPE",
    "HandoffError",
    "apply_embed_materialize",
    "handoff_array_symbol",
    "handoff_header_path",
    "handoff_size_symbol",
    "handoff_symbol_prefix",
    "materialize_items_for",
    "render_embed_header",
    "resolve_payload_bytes",
    "validate_embedded_handoff_references",
    "validate_embedded_handoff_workspace",
    "validate_handoff_closure",
]
