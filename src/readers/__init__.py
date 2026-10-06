"""Format readers: structure only, no vendor knowledge."""

from collections.abc import Callable

from src.readers.indent_blocks import read_indent_blocks
from src.readers.node import Node
from src.readers.set_commands import read_set_commands

Reader = Callable[[list[str]], list[Node]]

READERS: dict[str, Reader] = {
    "indent_blocks": read_indent_blocks,
    "set_commands": read_set_commands,
}

__all__ = ["READERS", "Node", "Reader"]
