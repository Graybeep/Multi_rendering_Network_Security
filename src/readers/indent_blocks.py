"""Reader for configurations where indentation defines nesting (IOS, NX-OS, EOS, Huawei)."""

from __future__ import annotations

import re

from src.readers.node import Node

# `banner motd ^C` … `^C`: the body is free text and must not be parsed as statements.
_BANNER = re.compile(r"^banner\s+\S+\s+(?P<delim>\^C|\S)")


def _is_comment(stripped: str) -> bool:
    return stripped == "" or stripped.startswith(("!", "#"))


def read_indent_blocks(lines: list[str]) -> list[Node]:
    """Build a line-numbered tree. `lines[i]` is source line i + 1."""
    roots: list[Node] = []
    stack: list[tuple[int, Node]] = []  # (indent, node)
    banner_delim: str | None = None

    for idx, raw in enumerate(lines):
        line_no = idx + 1
        if banner_delim is not None:
            if banner_delim in raw:
                banner_delim = None
            continue

        stripped = raw.strip()
        if _is_comment(stripped):
            continue

        indent = len(raw) - len(raw.lstrip(" \t"))
        while stack and stack[-1][0] >= indent:
            stack.pop()

        parent = stack[-1][1] if stack else None
        path = (*parent.path, parent.text) if parent else ()
        node = Node(path=path, line_no=line_no, text=stripped)
        (parent.children if parent else roots).append(node)
        stack.append((indent, node))

        banner = _BANNER.match(stripped) if indent == 0 else None
        if banner:
            delim = banner.group("delim")
            rest = stripped[banner.end():]
            if delim not in rest:  # body continues on following lines
                banner_delim = delim

    return roots
