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

# A quoted value is one secret even with spaces in it; otherwise the next whitespace-free token.
_VALUE = r'(?P<val>"(?:[^"\\]|\\.)*"?|\S+)'
# Encoding words sit between keyword and secret. Like the algorithm digit, they are kept.
_FORM = r"(?:(?:ascii-text|hexadecimal|ENC)\s+)?"

_RULES: tuple[re.Pattern[str], ...] = (
    # enable secret 9 X · username u secret 5 X · password 7 X · key-string 7 X · encrypted-password "X"
    # Junos pre-shared-key ascii-text "X" · authentication-key "X" · FortiOS set passwd ENC X
    re.compile(
        r"(?P<head>(?<!\S)(?:secret|password|passwd|psksecret|api-key|key-string|pre-shared-key|"
        r"encrypted-password|authentication-key\s+\d+\s+md5|authentication-key\s+\d+\s+type\s+\S+\s+value|"
        r"authentication-key)(?:\s+[0-9])?\s+" + _FORM + ")" + _VALUE
    ),
    # tacacs-server key 7 X · radius-server key X · `key X` as the final token pair
    re.compile(r"(?P<head>(?<!\S)key(?:\s+[0-9])?\s+)(?P<val>\S+)\s*$"),
)

_COMMUNITY = re.compile(r"(?P<head>\bcommunity\s+)(?P<val>\S+)")
# `set` / `deactivate` forms carry the same community string as the IOS form.
_SNMP_COMMUNITY_LINE = re.compile(r"^(?:(?:set|delete|deactivate|activate)\s+)?snmp(?:-server)?\s+community\s")


def _mask(value: str) -> str:
    # A brace-form statement ends in `;`; keep it so the tree still parses after masking.
    end = ";" if value.endswith(";") and not value.startswith('"') else ""
    prefix = _CRYPT_PREFIX.match(value)
    return (f"{prefix.group(1)}{MASK}" if prefix else MASK) + end


def redact_line(line: str) -> str:
    out = line
    for rule in _RULES:
        out = rule.sub(lambda m: m.group("head") + _mask(m.group("val")), out)
    if _SNMP_COMMUNITY_LINE.match(out.lstrip()):
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
