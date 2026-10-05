"""Redaction at ingest. Secrets become `****`; the algorithm token survives so hash-strength rules still evaluate.

Runs line by line before anything else touches the text, so line numbers are preserved exactly.
Patterns are deliberately vendor-generic: redaction must not depend on detection succeeding.
"""

from __future__ import annotations

import re

MASK = "****"

# Well-known default community strings are not secrets; keeping them lets a rule flag `public`.
_DEFAULT_COMMUNITIES = frozenset({"public", "private"})

# `$6$salt$hash` keeps `$6$`; Junos `$9$...` keeps `$9$`.
_CRYPT_PREFIX = re.compile(r'^"?(\$\d[a-z]?\$)')

_RULES: tuple[re.Pattern[str], ...] = (
    # enable secret 9 X · username u secret 5 X · password 7 X · key-string 7 X · encrypted-password "X"
    re.compile(
        r"(?P<head>(?<!\S)(?:secret|password|key-string|pre-shared-key|encrypted-password|"
        r"authentication-key\s+\d+\s+md5)(?:\s+[0-9])?\s+)(?P<val>\S+)"
    ),
    # tacacs-server key 7 X · radius-server key X · `key X` as the final token pair
    re.compile(r"(?P<head>(?<!\S)key(?:\s+[0-9])?\s+)(?P<val>\S+)\s*$"),
)

_COMMUNITY = re.compile(r"(?P<head>\bcommunity\s+)(?P<val>\S+)")


def _mask(value: str) -> str:
    prefix = _CRYPT_PREFIX.match(value)
    return f"{prefix.group(1)}{MASK}" if prefix else MASK


def redact_line(line: str) -> str:
    out = line
    for rule in _RULES:
        out = rule.sub(lambda m: m.group("head") + _mask(m.group("val")), out)
    if out.lstrip().startswith(("snmp-server community", "snmp community")):
        out = _COMMUNITY.sub(
            lambda m: m.group(0)
            if m.group("val").lower() in _DEFAULT_COMMUNITIES
            else m.group("head") + MASK,
            out,
        )
    return out


def redact(text: str) -> list[str]:
    """Split into lines (CR stripped) and redact each. Index i holds source line i + 1."""
    return [redact_line(line.rstrip("\r")) for line in text.split("\n")]
