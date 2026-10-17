"""Safe, structured activity events emitted by sample-factory LLM roles."""

from __future__ import annotations

import re
from collections.abc import Callable

AgentActivitySink = Callable[[tuple[str, dict[str, object]]], None]

_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|token|authorization|cookie|api[_-]?key)\b"
    r"\s*[:=]\s*[^\s,;]+"
)
_TOKEN_PATTERNS = (
    re.compile(r"\bghp_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


def safe_activity_text(value: object, *, max_chars: int = 600) -> str:
    """Render one bounded audit line without credential-shaped values."""
    text = " ".join(str(value).replace("\x00", "").split())
    text = _CREDENTIAL_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    lowered = text.lower()
    if "begin private key" in lowered or "begin openssh private key" in lowered:
        return "[REDACTED PRIVATE KEY MATERIAL]"
    if len(text) > max_chars:
        return text[: max_chars - 3] + "..."
    return text


def emit_activity(
    sink: AgentActivitySink | None,
    kind: str,
    data: dict[str, object],
) -> None:
    if sink is not None:
        sink((kind, data))


__all__ = ["AgentActivitySink", "emit_activity", "safe_activity_text"]
