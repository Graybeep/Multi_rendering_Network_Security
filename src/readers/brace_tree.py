"""Reader for brace-nested configurations (Junos `show configuration`, the default display form).

A brace file and a `display set` file are two encodings of one configuration. This reader flattens
the braces into the same statements `set_commands` reads and applies them with the same function,
so both forms yield identical nodes. Flattening needs no schema: each leaf's path is its enclosing
block headers followed by its own tokens.

    interfaces {                         set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
        ge-0/0/0 {                       set interfaces ge-0/0/0 disable
            unit 0 {
                family inet {        →
                    address 192.0.2.1/24;
        ...     disable;

Structure handled here, with no vendor knowledge:
  `{` `}` `;`              block open, block close, leaf end
  `x [ a b ];`             one statement per element: `x a`, `x b`
  `foo { }`                an empty block is a statement in its own right: `foo`
  `inactive: S`            S is deactivated, as `deactivate S` would be
  `protect: S`             no effect on what is configured
  `/* ... */`, `# ...`     comments, dropped (a `#` only when it starts a token)
  `! ...`                  a RANCID header line, dropped when it starts a statement
  `set P`, `delete P`, ... a flat statement mixed into the file at top level, read as `set_commands` reads it

A double quote opens a string only at the start of a token and closes at the next unescaped quote
or at end of line, as in `set_commands`. A quote inside a word is a literal character.

Anything unbalanced (a stray `}`, a block left open at end of file, a statement with no `;` before
`}`) fails the device. Guessing where a block ends would attribute settings to the wrong scope.
Load-time tags (`replace:`, `delete:`, `update:`) merge into a configuration this file does not
contain, so they fail the device too.

KNOWN DIVERGENCE from `set_commands`, undecided (docs/review-queue.md, "Reader divergence"):
a flat file holding both `set a b` and `set a b c` yields two statements, `a b` and `a b c`. A brace
file can only say `a { b { c; } }`, which yields one, `a b c`; the block `b` is a statement only when
empty. The two encodings of that configuration therefore give different canonical models whenever a
mapping matches the prefix statement alone. We carry this on one assumption: Junos `display set`
prints only leaves, so device output never holds both lines and only a hand-edited flat file can.
That assumption is about vendor output and has not been verified against a captured pair (PLAN 3.1c).
tests/test_brace_tree.py pins the current behaviour so a change to either side is deliberate.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

from src.readers.node import Node
from src.readers.set_commands import (
    VERBS,
    Statement,
    UnsupportedStatement,
    apply_statements,
    flat_statement,
)

_TAGS_NO_EFFECT = frozenset({"protect:"})
_TAGS_LOAD_TIME = frozenset({"replace:", "delete:", "update:"})
_TAGS = _TAGS_NO_EFFECT | _TAGS_LOAD_TIME | {"inactive:"}
_PUNCT = frozenset("{};[]")


class MalformedConfig(ValueError):
    """Braces, brackets or statement terminators that do not balance."""


@dataclass
class _Block:
    path: tuple[str, ...]
    line_no: int
    has_children: bool = False


@dataclass
class _Pending:
    words: list[tuple[str, int]] = field(default_factory=list)  # token, line
    items: list[str] | None = None  # elements of an open or closed `[ ]` list
    list_closed: bool = False

    def empty(self) -> bool:
        return not self.words and self.items is None


def _lex_line(line: str, in_comment: bool, at_statement_start: bool) -> tuple[list[str], bool]:
    """Tokens of one line, and whether a `/* */` comment is still open at its end."""
    out: list[str] = []
    cur: list[str] = []
    i, n = 0, len(line)

    def flush() -> None:
        if cur:
            out.append("".join(cur))
            cur.clear()

    while i < n:
        ch = line[i]
        if in_comment:
            end = line.find("*/", i)
            if end < 0:
                return out, True
            in_comment, i = False, end + 2
            continue
        if line.startswith("/*", i):
            flush()
            in_comment, i = True, i + 2
            continue
        if ch.isspace():
            flush()
        elif ch in _PUNCT:
            flush()
            out.append(ch)
        elif not cur and ch == "#" or not cur and ch == "!" and at_statement_start and not out:
            break
        elif not cur and ch == '"':
            j, escaped = i + 1, False
            while j < n:
                if escaped:
                    escaped = False
                elif line[j] == "\\":
                    escaped = True
                elif line[j] == '"':
                    break
                j += 1
            out.append(line[i : j + 1])  # an unterminated quote runs to end of line
            i = j + 1
            continue
        else:
            cur.append(ch)
        i += 1
    flush()
    return out, in_comment


def _statements(lines: list[str]) -> Iterator[Statement]:
    stack: list[_Block] = []
    pending = _Pending()
    in_comment = False

    def prefix() -> tuple[str, ...]:
        return stack[-1].path if stack else ()

    def head(line_no: int) -> tuple[tuple[str, ...], bool]:
        """The pending words as a path under the current block, and whether an `inactive:` tag led them."""
        words = [w for w, _ in pending.words]
        inactive = False
        while words and words[0] in _TAGS:
            tag = words.pop(0)
            if tag in _TAGS_LOAD_TIME:
                raise UnsupportedStatement(f"line {line_no}: load-time tag {tag!r} merges into a configuration "
                                           "this file does not contain")
            inactive = inactive or tag == "inactive:"
        if not words:
            raise MalformedConfig(f"line {line_no}: statement with no words")
        return prefix() + tuple(words), inactive

    def mark_child() -> None:
        if stack:
            stack[-1].has_children = True

    for idx, raw in enumerate(lines):
        line_no = idx + 1
        if not in_comment and not stack and pending.empty():
            first = raw.split(None, 1)
            if first and first[0] in VERBS:
                stmt = flat_statement(raw, line_no)
                if stmt is not None:
                    yield stmt
                continue
        toks, in_comment = _lex_line(raw, in_comment, pending.empty())
        for tok in toks:
            if pending.items is not None and not pending.list_closed:
                if tok == "]":
                    pending.list_closed = True
                elif tok in _PUNCT:
                    raise MalformedConfig(f"line {line_no}: {tok!r} inside a [ ] list")
                else:
                    pending.items.append(tok)
                continue
            if tok == "[":
                if pending.items is not None or not pending.words:
                    raise MalformedConfig(f"line {line_no}: '[' without a statement before it")
                pending.items = []
            elif tok == "]":
                raise MalformedConfig(f"line {line_no}: ']' without '['")
            elif tok == ";":
                if pending.empty():
                    continue  # `;` after a comment, or a doubled `;`
                start = pending.words[0][1] if pending.words else line_no
                path, inactive = head(start)
                mark_child()
                if pending.items is not None:
                    if not pending.items:
                        raise MalformedConfig(f"line {start}: empty [ ] list")
                    for item in pending.items:
                        yield "set", path + (item,), start
                else:
                    yield "set", path, start
                if inactive:
                    yield "deactivate", path, start
                pending = _Pending()
            elif tok == "{":
                if pending.items is not None:
                    raise MalformedConfig(f"line {line_no}: block opened after a [ ] list")
                if not pending.words:
                    raise MalformedConfig(f"line {line_no}: '{{' without a block header")
                start = pending.words[0][1]
                path, inactive = head(start)
                mark_child()
                if inactive:
                    yield "deactivate", path, start
                stack.append(_Block(path, start))
                pending = _Pending()
            elif tok == "}":
                if not pending.empty():
                    raise MalformedConfig(f"line {line_no}: statement not ended with ';' before '}}'")
                if not stack:
                    raise MalformedConfig(f"line {line_no}: '}}' closes no block")
                block = stack.pop()
                if not block.has_children:
                    yield "set", block.path, block.line_no  # `foo { }` configures `foo`
            elif pending.list_closed:
                raise MalformedConfig(f"line {line_no}: {tok!r} after a [ ] list")
            else:
                pending.words.append((tok, line_no))

    if not pending.empty():
        raise MalformedConfig(f"line {pending.words[0][1] if pending.words else len(lines)}: "
                              "statement not ended with ';' at end of file")
    if stack:
        raise MalformedConfig(f"line {stack[-1].line_no}: block opened here is never closed")


def read_brace_tree(lines: list[str]) -> list[Node]:
    """Build the effective statement list. `lines[i]` is source line i + 1."""
    return apply_statements(_statements(lines))
