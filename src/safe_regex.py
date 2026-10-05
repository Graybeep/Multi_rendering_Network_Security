"""Pack regexes are user-authored. Every match runs with a time cap so a pathological pattern cannot hang a worker."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import regex

MATCH_TIMEOUT_S = 0.05


class PatternError(ValueError):
    pass


@dataclass(frozen=True)
class SafePattern:
    source: str
    _compiled: Any = field(repr=False, compare=False)

    def match(self, text: str) -> regex.Match[str] | None:
        """Anchored-at-start match. Raises TimeoutError when the cap is exceeded."""
        result: regex.Match[str] | None = self._compiled.match(text, timeout=MATCH_TIMEOUT_S)
        return result

    def search(self, text: str) -> regex.Match[str] | None:
        result: regex.Match[str] | None = self._compiled.search(text, timeout=MATCH_TIMEOUT_S)
        return result


def compile_pattern(source: str) -> SafePattern:
    try:
        return SafePattern(source, regex.compile(source, flags=regex.V0))
    except regex.error as exc:
        raise PatternError(f"invalid regex {source!r}: {exc}") from exc
