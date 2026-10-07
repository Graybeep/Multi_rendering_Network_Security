"""Format readers: structure only, no vendor knowledge."""

from collections.abc import Callable

from src.readers.brace_tree import read_brace_tree
from src.readers.indent_blocks import read_indent_blocks
from src.readers.node import Node
from src.readers.set_commands import read_set_commands

Reader = Callable[[list[str]], list[Node]]

READERS: dict[str, Reader] = {
    "brace_tree": read_brace_tree,
    "indent_blocks": read_indent_blocks,
    "set_commands": read_set_commands,
}



def _display_set(nodes: list[Node], n_lines: int) -> list[str]:
    """Each source line as the flat statement it holds (`set ` + path), or "" if it holds none in effect.

    A brace file states `host-name r1;` three blocks deep; its display form is `set system host-name r1`.
    Pack `detect` and `facts` patterns are written once, against the display form, and keep the source line.
    Where one line holds several statements (a `[ ]` list), the first is shown.
    """
    view = [""] * n_lines
    for node in nodes:
        if not view[node.line_no - 1]:
            view[node.line_no - 1] = f"set {node.text}"
    return view


def pattern_lines(reader: str, lines: list[str], nodes: list[Node] | None = None) -> list[str]:
    """The lines a pack's `detect` and `facts` patterns run against, index i for source line i + 1.

    Raw lines for every reader except `brace_tree`, whose packs write patterns against the flat display
    form. A file `brace_tree` cannot read is shown raw: it is not in that format, and reading it fails later.
    """
    if reader != "brace_tree":
        return lines
    if nodes is None:
        try:
            nodes = read_brace_tree(lines)
        except ValueError:
            return lines
    return _display_set(nodes, len(lines))


__all__ = ["READERS", "Node", "Reader", "pattern_lines"]
