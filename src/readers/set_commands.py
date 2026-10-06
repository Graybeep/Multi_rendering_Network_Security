"""Reader for configurations written as one full path per line (Junos `display set`, PAN-OS CLI).

Each effective statement becomes one root node whose text is the path after the verb, with
whitespace outside quotes collapsed: `set interfaces fe-0/0/0 unit 0  family inet` reads as
`interfaces fe-0/0/0 unit 0 family inet`. Scope lives inside the text itself, so mappings bind
collection keys with named groups in `match` rather than with `scope`.

The flat path is the normal form for this family. A brace-nested file flattens to it
deterministically; the reverse needs schema knowledge (`unit 0 {` is one block header of two
tokens). So `brace_tree` must emit exactly these nodes for the same configuration.

Verbs are applied in order, as the device would load them:
  set P         add statement P
  delete P      remove P and everything under it
  deactivate P  P and everything under it stays in the file but is not in effect
  activate P    undo a deactivate of exactly P
Statements left inactive are dropped: auditing them would judge configuration the device ignores.
A verb that rewrites or reorders configuration (`rename`, `insert`, `copy`) cannot be applied
without knowing the schema, so it fails the device instead of silently producing a wrong tree.
"""

from __future__ import annotations

from src.readers.node import Node

_NO_EFFECT = frozenset({"protect", "unprotect", "annotate"})


class UnsupportedStatement(ValueError):
    """A line whose effect on the configuration this reader cannot reproduce."""


def tokens(statement: str) -> list[str]:
    """Split on whitespace outside double quotes. A quoted string, quotes included, is one token."""
    out: list[str] = []
    cur: list[str] = []
    quoted = escaped = False
    for ch in statement:
        if quoted:
            cur.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
            cur.append(ch)
        elif ch.isspace():
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:  # an unterminated quote runs to end of line, as the device would read it
        out.append("".join(cur))
    return out


def _under(path: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    return path[: len(prefix)] == prefix


def read_set_commands(lines: list[str]) -> list[Node]:
    """Build the effective statement list. `lines[i]` is source line i + 1."""
    live: dict[tuple[str, ...], int] = {}  # statement path → line it was set on; insertion-ordered
    inactive: set[tuple[str, ...]] = set()

    for idx, raw in enumerate(lines):
        line_no = idx + 1
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        verb, *rest = tokens(stripped)
        path = tuple(rest)
        if verb in _NO_EFFECT:
            continue
        if not path:
            raise UnsupportedStatement(f"line {line_no}: {verb!r} with no statement path")
        if verb == "set":
            live.setdefault(path, line_no)
        elif verb == "delete":
            live = {p: n for p, n in live.items() if not _under(p, path)}
            inactive = {p for p in inactive if not _under(p, path)}
        elif verb == "deactivate":
            inactive.add(path)
        elif verb == "activate":
            inactive.discard(path)
        else:
            raise UnsupportedStatement(f"line {line_no}: verb {verb!r} cannot be applied without a schema")

    return [
        Node(path=(), line_no=line_no, text=" ".join(path))
        for path, line_no in live.items()
        if not any(_under(path, off) for off in inactive)
    ]
