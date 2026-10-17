"""组合身份的确定性 canonicalization。

JSON 序列化空白被消除、映射键排序；字符串值保持原样，避免把语义不同的参数
（例如带空格的文件名）错误折叠为同一组合。ph_sequence 保序，ATT&CK ID、
profile_id、delivery、trigger_mode 与 production_policy 均不进入 combo_digest。
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from typing import Any


class CanonicalizationError(ValueError):
    """参数不是确定性 JSON 值。"""


def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("NaN/Infinity 不能进入组合主键")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise CanonicalizationError("canonical 参数映射只允许非空字符串键")
            normalized[key] = _normalize(item)
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize(item) for item in value]
    raise CanonicalizationError(f"不支持的 canonical 参数类型：{type(value).__name__}")


def canonical_json(value: Any) -> str:
    """返回稳定 UTF-8 JSON 文本；不改变数组顺序或字符串内容。"""
    normalized = _normalize(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def combo_digest(ph_sequence: Sequence[str], parameters: Mapping[str, Any]) -> str:
    """按 D1a 计算 sha256(canonical(ph_sequence + parameters))。"""
    if not ph_sequence:
        raise CanonicalizationError("ph_sequence 不得为空")
    payload = {"parameters": dict(parameters), "ph_sequence": list(ph_sequence)}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def canonical_parameters(
    atom_parameters: Mapping[str, Mapping[str, Any]],
    *,
    evasion_tier: str,
    pointer_mode: str | None,
    execution_logging: bool = False,
) -> dict[str, Any]:
    """把 Atom 参数与构建变体身份字段投影为 parameters_canonical。"""
    normalized = _normalize(
        {
            "atoms": {atom_id: dict(values) for atom_id, values in atom_parameters.items()},
            "evasion_tier": evasion_tier,
            "pointer_mode": pointer_mode,
            "execution_logging": execution_logging,
        }
    )
    if not isinstance(normalized, dict):  # pragma: no cover - 固定输入形状
        raise AssertionError("canonical parameters must be a mapping")
    return normalized


__all__ = [
    "CanonicalizationError",
    "canonical_json",
    "canonical_parameters",
    "combo_digest",
]
