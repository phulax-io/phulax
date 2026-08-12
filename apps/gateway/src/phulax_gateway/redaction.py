"""Redaction before transmission (plan §7 Day 20, R3).

You cannot leak what you never wrote down: sensitive fields are removed
from the approval preview *inside the gateway process*, before anything is
persisted or transmitted. And the removal is marked — the preview travels
with the list of field paths that were taken out, so a reviewer is
informed, never deceived.

Paths are dotted (``customer.ssn``); a JSONPath-style ``$.`` prefix is
accepted and stripped. A path that doesn't exist in the arguments is
simply not listed — nothing was there to redact.
"""

from typing import Any


def redact(arguments: dict[str, Any], sensitive_paths: list[str]) -> tuple[dict, list[str]]:
    """A deep-copied preview with sensitive paths removed, plus the
    normalized paths that were actually redacted."""
    preview = _copy(arguments)
    redacted: list[str] = []
    for raw_path in sensitive_paths:
        path = raw_path.removeprefix("$.")
        if _remove(preview, path.split(".")):
            redacted.append(path)
    return preview, redacted


def _remove(node: Any, parts: list[str]) -> bool:
    if not isinstance(node, dict) or not parts:
        return False
    head, rest = parts[0], parts[1:]
    if head not in node:
        return False
    if not rest:
        del node[head]
        return True
    return _remove(node[head], rest)


def _copy(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _copy(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_copy(item) for item in value]
    return value
