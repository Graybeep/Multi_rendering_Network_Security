from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field


@dataclass
class Node:
    """One configuration statement. `path` is the texts of the enclosing blocks, outermost first."""

    path: tuple[str, ...]
    line_no: int
    text: str
    children: list[Node] = field(default_factory=list)

    def walk(self) -> Iterator[Node]:
        yield self
        for child in self.children:
            yield from child.walk()

    def to_dict(self) -> dict[str, object]:
        return {
            "path": list(self.path),
            "line_no": self.line_no,
            "text": self.text,
            "children": [c.to_dict() for c in self.children],
        }
