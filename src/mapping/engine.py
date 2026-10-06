"""Mapping engine: reader tree + vendor pack → canonical model. Pure: no I/O, no globals.

Matching is binary. A line either matches a mapping's anchored regex in the right scope or it does not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.mapping.canonical import Catalogue, Model, Triple, parse_path
from src.mapping.pack import Mapping, VendorPack
from src.readers.node import Node
from src.versions import in_range

_NOT_UNDERSTOOD = object()
_TRUE_WORDS = frozenset({"true", "yes", "enable", "enabled", "on"})
_FALSE_WORDS = frozenset({"false", "no", "disable", "disabled", "off"})


class AmbiguousMapping(ValueError):
    """Two mappings at equal priority claim the same line for the same canonical field."""


@dataclass
class Detection:
    pack: VendorPack | None
    ambiguous: bool
    candidates: list[str]
    line: int | None  # strongest signature line for the chosen pack


@dataclass
class Unmatched:
    line_no: int
    text: str
    path: tuple[str, ...]


@dataclass
class MapResult:
    model: Model
    unmatched: list[Unmatched]
    warnings: list[str] = field(default_factory=list)


def detect(lines: list[str], packs: list[VendorPack]) -> Detection:
    """Weighted anchored signatures. A tie for the top score is ambiguous, never first-match-wins."""
    scored: list[tuple[int, VendorPack, int | None]] = []
    for pack in packs:
        score, first_line = 0, None
        for pattern, weight in pack.detect:
            for i, line in enumerate(lines):
                try:
                    hit = pattern.match(line)
                except TimeoutError:
                    hit = None
                if hit:
                    score += weight
                    first_line = first_line or i + 1
                    break
        if score >= pack.min_score:
            scored.append((score, pack, first_line))
    if not scored:
        return Detection(None, False, [], None)
    scored.sort(key=lambda s: -s[0])
    top = [s for s in scored if s[0] == scored[0][0]]
    if len(top) > 1:
        return Detection(None, True, sorted(s[1].id for s in top), None)
    return Detection(top[0][1], False, [top[0][1].id], top[0][2])


def _evidence(line: int | None, mapping_id: str, pack_version: str) -> dict[str, Any]:
    return {"line": line, "mapping_id": mapping_id, "pack_version": pack_version}


def _mapped(value: Any, line: int, mapping_id: str, pack_version: str) -> Triple:
    return {"value": value, "state": "mapped", "evidence": _evidence(line, mapping_id, pack_version)}


def _defaulted(value: Any, mapping_id: str, pack_version: str) -> Triple:
    return {"value": value, "state": "defaulted", "evidence": _evidence(None, mapping_id, pack_version)}


def _value_type(schema: dict[str, Any] | None) -> str:
    if not schema:
        return "string"
    t = schema.get("type")
    types = [t] if isinstance(t, str) else list(t or [])
    return next((x for x in types if x != "null"), "string")


def _convert(captured: str | None, schema: dict[str, Any] | None, cast: str | None,
             table: dict[str, Any] | None) -> Any:
    if captured is None:
        return _NOT_UNDERSTOOD
    if table is not None:
        return table.get(captured, _NOT_UNDERSTOOD)
    kind = cast or {"integer": "int", "boolean": "bool", "array": "list"}.get(_value_type(schema), "str")
    try:
        if kind == "int":
            return int(captured)
        if kind == "bool":
            low = captured.lower()
            return True if low in _TRUE_WORDS else False if low in _FALSE_WORDS else _NOT_UNDERSTOOD
        if kind == "list":
            return captured.split()
    except ValueError:
        return _NOT_UNDERSTOOD
    return captured


class _Writer:
    def __init__(self, model: Model, catalogue: Catalogue) -> None:
        self.model = model
        self.catalogue = catalogue

    def container(self, canonical: str, binds: dict[str, str | None], line: int,
                  mapping: Mapping) -> dict[str, Any] | None:
        """Walk to the dict holding the last segment, selecting (or creating) collection items by key."""
        node: Any = self.model
        prefix = ""
        segments = parse_path(canonical)
        for seg in segments[:-1]:
            prefix = f"{prefix}.{seg.name}" if prefix else seg.name
            child = node[seg.name]
            if not seg.collection:
                node = child
                continue
            prefix += "[]"
            spec = self.catalogue.fields[prefix]
            key_value = binds.get(seg.var or "")
            if key_value is None or spec.key is None:
                return None
            key_value = _convert(key_value, self.catalogue.fields[f"{prefix}.{spec.key}"].value_schema,
                                 None, None)
            item = next((it for it in child["items"] if it[spec.key]["value"] == key_value), None)
            if item is None:
                item = self.catalogue.new_item(prefix)
                item[spec.key] = _mapped(key_value, line, mapping.id, mapping.pack_version)
                child["items"].append(item)
            child["state"] = "mapped"
            node = item
        return node  # type: ignore[no-any-return]

    def apply(self, m: Mapping, mm: Any, scope_binds: dict[str, str | None], line: int) -> bool:
        groups: dict[str, str | None] = {**scope_binds, **mm.groupdict()}
        parent = self.container(m.canonical, groups, line, m)
        if parent is None:
            return False
        last = parse_path(m.canonical)[-1]
        if m.collection:
            return self._apply_collection(m, mm, groups, parent[last.name], line)

        if m.has_value:
            value = m.raw["value"]
        else:
            if "value" in mm.re.groupindex:
                captured = mm.group("value")
            else:
                captured = mm.group(1)
            if m.raw.get("cast") == "min_sec":
                try:
                    value = int(mm.group(1)) * 60 + int(mm.group(2) or 0)
                except (TypeError, ValueError, IndexError):
                    value = _NOT_UNDERSTOOD
            else:
                value = _convert(captured, m.spec.value_schema, m.raw.get("cast"), m.raw.get("map"))
        if value is _NOT_UNDERSTOOD:
            return False
        # A list-valued setting spread over several lines: the weakest (or strongest) value is the truth,
        # not whichever line happened to come last.
        held = parent[last.name]
        keep = m.raw.get("keep")
        if keep and held["state"] == "mapped" and held["value"] is not None and (
                value >= held["value"] if keep == "min" else value <= held["value"]):
            return True
        parent[last.name] = _mapped(value, line, m.id, m.pack_version)
        return True

    def _apply_collection(self, m: Mapping, mm: Any, groups: dict[str, str | None],
                          coll: dict[str, Any], line: int) -> bool:
        tables: dict[str, Any] = m.raw.get("map") or {}
        if not m.spec.object_items:
            captured = mm.group("value") if "value" in mm.re.groupindex else (mm.group(1) if mm.re.groups else None)
            value = m.raw["value"] if m.has_value else _convert(captured, m.spec.value_schema, None, None)
            if value is _NOT_UNDERSTOOD:
                return False
            if any(it["value"] == value for it in coll["items"]):  # one server named on several lines
                return True
            coll["items"].append(_mapped(value, line, m.id, m.pack_version))
            coll["state"] = "mapped"
            return True

        key = m.spec.key
        attrs: dict[str, Triple] = {}
        for attr, spec in m.item_specs.items():
            captured = mm.groupdict().get(attr)
            if captured is not None:
                value = _convert(captured, spec.value_schema, None, tables.get(attr))
                if value is _NOT_UNDERSTOOD:
                    return False
                attrs[attr] = _mapped(value, line, m.id, m.pack_version)
            elif attr in (m.raw.get("defaults") or {}):
                attrs[attr] = _defaulted(m.raw["defaults"][attr], m.id, m.pack_version)
        if key and key not in attrs:
            if not m.raw.get("auto_key"):
                return False
            attrs[key] = _defaulted(10 * (len(coll["items"]) + 1), m.id, m.pack_version)

        item = None
        if key:
            item = next((it for it in coll["items"] if it[key]["value"] == attrs[key]["value"]), None)
        if item is None:
            item = self.catalogue.new_item(m.target)
            coll["items"].append(item)
        item.update(attrs)
        coll["state"] = "mapped"
        return True


def _containers(model: Model, path: str) -> list[dict[str, Any]]:
    """All dicts that hold the last segment of a normalised path (one per collection item)."""
    frontier: list[Any] = [model]
    for seg in parse_path(path)[:-1]:
        nxt: list[Any] = []
        for node in frontier:
            child = node[seg.name]
            nxt.extend(child["items"] if seg.collection else [child])
        frontier = nxt
    return frontier


def _apply_absent(model: Model, pack: VendorPack, os_version: str | None) -> None:
    by_target: dict[str, Mapping] = {}
    for m in pack.mappings:
        by_target.setdefault(m.target, m)
    # Outer collections before inner ones, so nested `empty` sees its parents.
    for target, m in sorted(by_target.items(), key=lambda kv: kv[0].count("[]")):
        name = parse_path(target)[-1].name
        for holder in _containers(model, target):
            node = holder[name]
            if m.collection:
                if node["state"] == "unknown" and not node["items"] and m.raw["empty"] == "mapped":
                    node["state"] = "mapped"
                continue
            if node["state"] != "unknown" or m.raw["absent"] != "default":
                continue
            if in_range(os_version, m.raw["default_os_version"]):
                holder[name] = _defaulted(m.raw["default"], m.id, m.pack_version)


def _inheritance_line(pack: VendorPack, nodes: list[Node], warnings: list[str]) -> int | None:
    """First effective statement that pulls in configuration the pack does not resolve (e.g. Junos apply-groups)."""
    if not pack.inheritance:
        return None
    for root in nodes:
        for node in root.walk():
            for pattern in pack.inheritance:
                try:
                    if pattern.search(node.text):
                        return node.line_no
                except TimeoutError:
                    warnings.append(f"inheritance check timed out on line {node.line_no}")
                    return node.line_no  # cannot rule it out, so treat it as inherited
    return None


def _all_collections(node: Any) -> list[dict[str, Any]]:
    """Every collection holder in the model, nested ones included."""
    found: list[dict[str, Any]] = []
    if isinstance(node, dict):
        if "items" in node and "state" in node:
            found.append(node)
            for item in node["items"]:
                found.extend(_all_collections(item))
        else:
            for v in node.values():
                found.extend(_all_collections(v))
    return found


def _sourced(value: Any, mapping_id: str, pack_version: str, source: str) -> Triple:
    """A value no config line backs, labelled with where it did come from."""
    return {"value": value, "state": "defaulted",
            "evidence": {**_evidence(None, mapping_id, pack_version), "source": source}}


def map_device(pack: VendorPack, nodes: list[Node], lines: list[str], catalogue: Catalogue,
               detect_line: int | None, operator_os_version: str | None = None) -> MapResult:
    """`operator_os_version` is used only when the config states none. The engine never infers a version."""
    model = catalogue.empty_model()
    result = MapResult(model, [])
    writer = _Writer(model, catalogue)

    device = model["device"]
    consumed: set[int] = set()  # fact and detection lines are understood, not questions for a human
    if detect_line is not None:
        consumed.add(detect_line)
    for name, value in (("vendor", pack.vendor), ("os_family", pack.os_family)):
        if detect_line is not None:
            device[name] = _mapped(value, detect_line, f"{pack.id}.detect", pack.tag)
    for name, (pattern, group) in pack.facts.items():
        for i, line in enumerate(lines):
            try:
                hit = pattern.match(line.strip())
            except TimeoutError:
                result.warnings.append(f"fact {name} timed out on line {i + 1}")
                continue
            if hit:
                device[name] = _mapped(hit.group(group), i + 1, f"{pack.id}.fact.{name}", pack.tag)
                consumed.add(i + 1)
                break
    if operator_os_version is not None:
        stated = device["os_version"]
        if stated["state"] == "unknown":
            device["os_version"] = _sourced(operator_os_version, "operator.os_version", pack.tag, "operator")
        elif stated["value"] != operator_os_version:
            result.warnings.append(
                f"line {stated['evidence']['line']}: config states OS version {stated['value']}; "
                f"operator-supplied {operator_os_version} was not used")

    def visit(node: Node, parent: Node | None) -> None:
        candidates = pack.dispatch.get(node.text.split(maxsplit=1)[0], []) + pack.wildcard
        hits: list[tuple[Mapping, Any, dict[str, str | None]]] = []
        for m in candidates:
            binds: dict[str, str | None] = {}
            try:
                if m.scope is None:
                    if parent is not None:
                        continue
                else:
                    if parent is None:
                        continue
                    sm = m.scope.match(parent.text)
                    if not sm:
                        continue
                    binds = sm.groupdict()
                mm = m.pattern.match(node.text)
            except TimeoutError:
                result.warnings.append(f"mapping {m.id} timed out on line {node.line_no}")
                continue
            if mm:
                hits.append((m, mm, binds))

        best: dict[str, list[tuple[Mapping, Any, dict[str, str | None]]]] = {}
        for hit in hits:
            group = best.setdefault(hit[0].target, [])
            if not group or hit[0].priority > group[0][0].priority:
                best[hit[0].target] = [hit]
            elif hit[0].priority == group[0][0].priority:
                group.append(hit)
        applied = False
        for target, group in best.items():
            if len(group) > 1:
                ids = ", ".join(sorted(h[0].id for h in group))
                raise AmbiguousMapping(f"line {node.line_no}: mappings {ids} all claim {target} at equal priority")
            m, mm, binds = group[0]
            applied = writer.apply(m, mm, binds, node.line_no) or applied
        if not applied and node.line_no not in consumed:
            result.unmatched.append(Unmatched(node.line_no, node.text, node.path))
        for child in node.children:
            visit(child, node)

    for root in nodes:
        visit(root, None)

    inherited = _inheritance_line(pack, nodes, result.warnings)
    if inherited is None:
        _apply_absent(model, pack, device["os_version"]["value"])
    else:
        result.warnings.append(
            f"line {inherited}: configuration is inherited from elsewhere in the file and not resolved; "
            "settings not stated directly are NOT_DETERMINED")
        # A group can add items (users, interfaces) the local lines do not show. Visible items are real,
        # so they stay; the list is marked incomplete and only rules that opt in may judge it. A list
        # with nothing visible stays unread, never "read and empty".
        for holder in _all_collections(model):
            if holder["items"]:
                holder["complete"] = False
    # Platform facts hold whatever the config says or inherits; the loader guarantees no mapping targets them.
    for path, value in pack.constants.items():
        name = parse_path(path)[-1].name
        for holder in _containers(model, path):
            holder[name] = _sourced(value, f"{pack.id}.constant.{path}", pack.tag, "platform_constant")
    catalogue.validate(model)
    return result
