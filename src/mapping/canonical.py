"""Canonical model: path grammar, field catalogue read from schemas/canonical.schema.json, model helpers.

Every leaf is a {value, state, evidence} triple; every collection is {state, evidence, items}.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "canonical.schema.json"

_SEGMENT = re.compile(r"^(?P<name>[a-z_]+)(?P<coll>\[(?:\{(?P<var>[a-z_]+)\})?\])?$")
_BOUND = re.compile(r"\[\{[a-z_]+\}\]")

Triple = dict[str, Any]
Model = dict[str, Any]


@dataclass(frozen=True)
class Segment:
    name: str
    collection: bool
    var: str | None  # `name` in `interfaces[{name}]`


def parse_path(path: str) -> tuple[Segment, ...]:
    segments = []
    for part in path.split("."):
        m = _SEGMENT.match(part)
        if not m:
            raise ValueError(f"bad canonical path {path!r} at {part!r}")
        segments.append(Segment(m["name"], m["coll"] is not None, m["var"]))
    return tuple(segments)


def normalise(path: str) -> str:
    """`interfaces[{name}].proxy_arp` → `interfaces[].proxy_arp`."""
    return _BOUND.sub("[]", path)


@dataclass(frozen=True)
class FieldSpec:
    path: str  # normalised, e.g. interfaces[].proxy_arp or interfaces[]
    description: str
    absent: str
    collection: bool
    key: str | None  # collection join attribute
    value_schema: dict[str, Any] | None  # leaf value schema; scalar-list items for collections
    object_items: bool  # collection whose items are objects (vs. a list of triples)


def unknown() -> Triple:
    return {"value": None, "state": "unknown", "evidence": None}


class Catalogue:
    """The field list, the empty-model skeleton and schema validation."""

    def __init__(self, schema: dict[str, Any]) -> None:
        self.schema = schema
        self.validator = jsonschema.Draft202012Validator(schema)
        self.fields: dict[str, FieldSpec] = {}
        self._item_templates: dict[str, dict[str, Any]] = {}
        self._skeleton = self._build(schema)
        self.version: str = schema["properties"]["canonical_schema_version"]["const"]

    @classmethod
    def load(cls, path: Path = SCHEMA_PATH) -> Catalogue:
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def _build(self, node: dict[str, Any]) -> Any:
        if "const" in node:
            return node["const"]
        if "x-path" in node:
            path = node["x-path"]
            if path.endswith("[]"):
                items = node["allOf"][1]["properties"]["items"]["items"]
                object_items = items.get("type") == "object"
                if object_items:
                    self._item_templates[path] = {k: self._build(v) for k, v in items["properties"].items()}
                    value_schema = None
                else:
                    value_schema = items["allOf"][1]["properties"]["value"]
                self.fields[path] = FieldSpec(path, node["description"], node["x-absent"], True,
                                              node.get("x-key"), value_schema, object_items)
                return {"state": "unknown", "evidence": None, "items": []}
            value_schema = node["allOf"][1]["properties"]["value"]
            self.fields[path] = FieldSpec(path, node["description"], node["x-absent"], False,
                                          None, value_schema, False)
            return unknown()
        if node.get("type") == "object":
            return {k: self._build(v) for k, v in node["properties"].items()}
        raise ValueError(f"unexpected schema node: {node}")

    def empty_model(self) -> Model:
        """Every field unknown — what a device we could not read at all looks like."""
        model: Model = copy.deepcopy(self._skeleton)
        return model

    def new_item(self, collection_path: str) -> dict[str, Any]:
        return copy.deepcopy(self._item_templates[collection_path])

    def validate(self, model: Model) -> None:
        self.validator.validate(model)


def collection_of(path: str) -> str:
    """`interfaces[].proxy_arp` → `interfaces[]`; `acl.lists[].entries[]` → `acl.lists[]`."""
    head, _, _ = normalise(path).rpartition("[]")
    return head + "[]"


def get_node(model: Model, path: str) -> Any:
    """Follow a path made of plain segments only (no collections)."""
    node: Any = model
    for seg in parse_path(path):
        node = node[seg.name]
    return node


def project(node: Any) -> Any:
    """Strip triples to bare values for assertion evaluation."""
    if isinstance(node, dict):
        if "state" in node and "items" in node:
            return [project(item) for item in node["items"]]
        if "state" in node and "value" in node:
            return node["value"]
        return {k: project(v) for k, v in node.items() if k != "canonical_schema_version"}
    return node


def iter_states(model: Model, path: str) -> list[tuple[str, Triple | None]]:
    """States reached by a normalised path. A collection with unknown state yields one `unknown`.

    `services.ssh.version` → one state. `interfaces[]` → the collection's state.
    `interfaces[].proxy_arp` → the collection's state if unknown, else every item's attribute state
    (an attribute missing from an item is unknown).
    """
    segments = parse_path(normalise(path))
    frontier: list[Any] = [model]
    for i, seg in enumerate(segments):
        last = i == len(segments) - 1
        nxt: list[Any] = []
        for node in frontier:
            child = node.get(seg.name) if isinstance(node, dict) else None
            if child is None:
                return [("unknown", None)]
            if seg.collection:
                if child["state"] == "unknown":
                    return [("unknown", None)]
                if last:
                    nxt.append(child)
                else:
                    nxt.extend(child["items"])
            else:
                nxt.append(child)
        frontier = nxt
    out: list[tuple[str, Triple | None]] = []
    for node in frontier:
        if isinstance(node, dict) and "state" in node:
            out.append((node["state"], node if "value" in node else None))
    return out
