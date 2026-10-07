"""Redaction at ingest. Secrets become `****`; the algorithm token survives so hash-strength rules still evaluate.

Runs line by line before anything else touches the text, so line numbers are preserved exactly.
Patterns are deliberately vendor-generic: redaction must not depend on detection succeeding.

Redaction keys on secret-bearing *constructs* (a keyword, then optional level / type digit / encoding
word, then the value), not on bare words: `password minimum-length 12` is policy, `key 1` in a key
chain is an id. tests/test_redaction_cases.py holds one regression row per construct.
"""

from __future__ import annotations

import re

MASK = "****"

# Well-known default community strings are not secrets; keeping them lets a rule flag `public`.
_DEFAULT_COMMUNITIES = frozenset({"public", "private"})

# `$6$salt$hash` keeps `$6$`; Junos `$9$...` keeps `$9$`.
_CRYPT_PREFIX = re.compile(r'^"?(\$\d[a-z]?\$)')

_B = r"(?<!\S)"  # keyword is a whole token: `password`, not `plain-text-password` or `Xy9!secret`
_TYPE = r"(?:\s+[0-9])?"  # Cisco type digit: password 7 X
_FORM = r"(?:\s+(?:ascii-text|hexadecimal|ENC))?"  # encoding word, kept like the type digit
# Words that follow `password` in policy statements; they are settings, not secrets.
_POLICY = r"(?!(?:minimum-|maximum-)|(?:change-type|format|encryption|strength-check)(?:\s|$))"
# A quoted value is one secret even with spaces in it; otherwise the next whitespace-free token.
# A `{` or `[` is never a value: brace-form Junos opens a block or a list there (`key 0 {`), and masking it
# breaks the tree. tests/test_redaction_structure.py holds the invariant.
_NOT_DELIM = r"(?![{\[])"
_QUOTED = r'"(?:[^"\\]|\\.)*"?'
_VALUE = rf"(?P<val>{_QUOTED}|{_NOT_DELIM}\S+)"

_CONSTRUCTS: tuple[re.Pattern[str], ...] = (
    # enable secret level 15 5 X · username u secret 8 X · password 7 X · neighbor n password 7 X
    # Junos encrypted-password "X" · pre-shared-key ascii-text "X" · SNMPv3 authentication-password "X"
    # FortiOS set passwd ENC X · set psksecret ENC X · set api-key ENC X
    re.compile(
        rf"(?P<head>{_B}(?:secret|password|passwd|psksecret|api-key|key-string|encrypted-password|"
        rf"pre-shared-key|authentication-password|privacy-password)(?:\s+level\s+\d+)?{_TYPE}{_FORM}\s+)"
        rf"{_POLICY}{_VALUE}"
    ),
    # Longest form first, in one alternation, so a shorter form never re-reads a masked line:
    # IOS ntp authentication-key 1 md5 X 7 · Junos authentication-key 1 type md5 value "X"
    # IOS ip ospf authentication-key 7 X · Junos bgp authentication-key "X"
    re.compile(
        rf"(?P<head>{_B}authentication-key(?:\s+\d+\s+(?:md5|type\s+\S+\s+value){_TYPE}|{_TYPE}){_FORM}\s+)"
        rf"{_VALUE}"
    ),
    # IOS ip ospf message-digest-key 1 md5 [7] X
    re.compile(rf"(?P<head>{_B}message-digest-key\s+\d+\s+md5{_TYPE}\s+){_VALUE}"),
    # IOS crypto isakmp key [6] X address A
    re.compile(rf"(?P<head>{_B}crypto\s+isakmp\s+key{_TYPE}\s+)(?P<val>\S+)"),
    # Junos encoding word on its own line, its keyword on the block header above: `pre-shared-key {` then
    # `ascii-text "X";`. These words only ever precede a secret. Quoted values only, as Junos prints them.
    re.compile(rf"(?P<head>{_B}(?:ascii-text|hexadecimal)\s+)(?P<val>{_QUOTED};?)"),
    # tacacs-server key 7 X · radius-server key X · Junos `key "X"` — `key X` as the final token pair.
    # Must stay last: redact_line skips it on a key-chain id line.
    re.compile(rf"(?P<head>{_B}key{_TYPE}\s+)(?P<val>{_NOT_DELIM}\S+)\s*$"),
)

# A key chain's `key 1` names a key; the secret is on its key-string line.
_KEY_ID_LINE = re.compile(r"^\s*key\s+\d+\s*$")

# SNMP community strings, in each place they appear. The verb prefix covers flat `set` syntax. A quoted community
# is one value; a bare one stops before a delimiter, so `snmp community X;` keeps its `;` and `{` is never masked.
_SNMP_COMMUNITY = re.compile(
    rf"^(?P<head>\s*(?:(?:set|delete|deactivate|activate)\s+)?snmp(?:-server)?\s+community\s+)"
    rf"(?P<val>{_QUOTED}|[^\s;{{}}\[\]]+)")
# Brace-form Junos states the community alone on its line, inside `snmp { ... }`: `community X {` or
# `community X;`. Policy communities (`community NAME members ...`) carry more words and are not matched.
_BRACE_COMMUNITY = re.compile(r'^(?P<head>\s*community\s+)(?P<val>"(?:[^"\\]|\\.)*"|[^\s;{]+)(?=\s*[{;]\s*$)')
_SNMP_HOST = re.compile(  # snmp-server host H [vrf V] [informs|traps] [version 1|2c|3 auth|noauth|priv] C
    r"^(?P<head>\s*snmp-server\s+host\s+\S+(?:\s+vrf\s+\S+)?(?:\s+(?:informs|traps))?"
    r"(?:\s+version\s+(?:1|2c|3\s+(?:auth|noauth|priv)))?\s+)(?P<val>\S+)")
_SNMP_USER = re.compile(r"^\s*snmp-server\s+user\s")
_SNMP_USER_SECRETS = (  # auth <algorithm> X · priv [des|3des|aes N|aes-128] X
    re.compile(r"(?P<head>\bauth\s+\S+\s+)(?P<val>\S+)"),
    re.compile(r"(?P<head>\bpriv\s+(?:(?:des|3des|aes)(?:\s+\d+)?\s+|aes-128\s+)?)(?P<val>\S+)"),
)


def _mask(value: str) -> str:
    if value == MASK or value.endswith(f"${MASK}"):
        return value  # already masked by an earlier construct
    # A brace-form statement ends in `;`; keep it so the tree still parses after masking. Inside an
    # unterminated quote the `;` belongs to the string; after a closed one (`"X";`) it ends the statement.
    end = ";" if value.endswith(";") and (not value.startswith('"') or value.endswith('";')) else ""
    prefix = _CRYPT_PREFIX.match(value)
    return (f"{prefix.group(1)}{MASK}" if prefix else MASK) + end


def _sub(pattern: re.Pattern[str], text: str) -> str:
    return pattern.sub(lambda m: m.group("head") + _mask(m.group("val")), text)


def _community(m: re.Match[str]) -> str:
    val = m.group("val")
    return m.group(0) if val.lower() in _DEFAULT_COMMUNITIES else m.group("head") + MASK


def redact_line(line: str) -> str:
    out = line
    for i, pattern in enumerate(_CONSTRUCTS):
        if i == len(_CONSTRUCTS) - 1 and _KEY_ID_LINE.match(out):
            continue
        out = _sub(pattern, out)
    out = _SNMP_COMMUNITY.sub(_community, out)
    out = _BRACE_COMMUNITY.sub(_community, out)
    out = _SNMP_HOST.sub(_community, out)
    if _SNMP_USER.match(out):
        for pattern in _SNMP_USER_SECRETS:
            out = _sub(pattern, out)
    return out


def redact(text: str) -> list[str]:
    """Split into lines (CR stripped) and redact each. Index i holds source line i + 1."""
    return [redact_line(line.rstrip("\r")) for line in text.split("\n")]
