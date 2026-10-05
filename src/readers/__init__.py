"""Format readers: structure only, no vendor knowledge."""

from collections.abc import Callable

from src.readers.indent_blocks import read_indent_blocks
from src.readers.node import Node

Reader = Callable[[list[str]], list[Node]]

READERS: dict[str, Reader] = {
    "indent_blocks": read_indent_blocks,
}

__all__ = ["READERS", "Node", "Reader"]
