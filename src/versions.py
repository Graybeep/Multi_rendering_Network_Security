"""OS version ranges. Compares the leading numeric release only: `15.2(4)M3` → (15, 2); `18.4R2` → (18, 4)."""

from __future__ import annotations

import operator
import re
from collections.abc import Callable

_LEADING = re.compile(r"^\d+(?:\.\d+)*")
_CLAUSE = re.compile(r"^(>=|<=|>|<|==)(\d+(?:\.\d+)*)$")
_OPS: dict[str, Callable[[tuple[int, ...], tuple[int, ...]], bool]] = {
    ">=": operator.ge, "<=": operator.le, ">": operator.gt, "<": operator.lt, "==": operator.eq,
}


def release(version: str) -> tuple[int, ...] | None:
    m = _LEADING.match(version.strip())
    return tuple(int(p) for p in m.group(0).split(".")) if m else None


def _pad(a: tuple[int, ...], n: int) -> tuple[int, ...]:
    return a + (0,) * (n - len(a))


def in_range(version: str | None, spec: str) -> bool | None:
    """True/False, or None when the version is unknown and the spec is not `*`."""
    if spec == "*":
        return True
    rel = release(version) if version else None
    if rel is None:
        return None
    for clause in spec.split(","):
        m = _CLAUSE.match(clause)
        if not m:
            raise ValueError(f"bad version spec {spec!r}")
        bound = tuple(int(p) for p in m.group(2).split("."))
        n = max(len(rel), len(bound))
        if not _OPS[m.group(1)](_pad(rel, n), _pad(bound, n)):
            return False
    return True
