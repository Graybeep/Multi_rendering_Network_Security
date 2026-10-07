"""Turn a confirmed cluster into a learned mapping (PLAN 2.6). Pure: no file I/O.

The mapping uses the vendor-pack mapping schema unchanged, plus provenance, so a labelling session
is a pack fragment that can ship as a vendor pack. The administrator chooses the field and states
what an absent line means; nothing here guesses either.

The regex is built from the cluster's signature, literal words kept and each slot matched by its
type, and it must match every recorded occurrence of the cluster before it is offered. The fixture is
synthetic: documentation addresses and names, never this site's.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import jsonschema
import regex
import yaml

from src.learning.cluster import Cluster, Member
from src.learning.normalise import EXAMPLE, SLOT_REGEX, Slot, Template, example_line
from src.mapping.canonical import Catalogue, FieldSpec, collection_of
from src.safe_regex import compile_pattern

FIRST_VERSION = "0.1.0"


class AuthorError(ValueError):
    """The confirmation cannot become a mapping. `status` is the HTTP status the API should use."""

    def __init__(self, message: str, field: str | None = None, status: int = 422) -> None:
        super().__init__(message)
        self.field, self.status = field, status


def learnable(path: str, catalogue: Catalogue) -> str | None:
    """None if a learned mapping can target `path`, else the reason it cannot."""
    spec = catalogue.fields.get(path)
    if spec is None:
        return f"{path!r} is not a canonical field"
    depth = path.count("[]")
    if depth == 0:
        return None
    if spec.collection and depth == 1:
        if spec.object_items:
            return (f"{path} holds objects; a line that creates one needs a hand-written mapping. "
                    "Choose one of its attributes instead")
        return None
    if depth == 1 and not spec.collection:
        coll = catalogue.fields[collection_of(path)]
        if coll.key is None:
            return f"{coll.path} has no key, so a line cannot say which item it belongs to"
        if path == f"{coll.path}.{coll.key}":
            return f"{path} is the key of {coll.path}; it is set by the line that creates the item"
        return None
    return f"{path} is nested in more than one list; learned mappings do not reach it yet"


def _value_kind(spec: FieldSpec) -> str:
    t = (spec.value_schema or {}).get("type", "string")
    types = [t] if isinstance(t, str) else list(t)
    return next((x for x in types if x != "null"), "string")


def _check_value(value: Any, spec: FieldSpec, what: str) -> None:
    if spec.value_schema is None:
        return
    try:
        jsonschema.validate(value, spec.value_schema)
    except jsonschema.ValidationError as exc:
        raise AuthorError(f"{what} {value!r} does not fit {spec.path}: {exc.message}", what) from exc


@dataclass(frozen=True)
class _Where:
    part: str  # "scope" or "line"
    index: int  # position in the template's parts


def _key_slot(sample: Member, coll: FieldSpec) -> _Where:
    """The slot holding the item's key, recognised from the device's own list of items."""
    for part, template in (("scope", sample.scope), ("line", sample.line)):
        if template is None:
            continue
        for i, p in enumerate(template.parts):
            if isinstance(p, Slot) and p.origin == coll.path:
                return _Where(part, i)
    raise AuthorError(f"cannot tell which item of {coll.path} this line belongs to: no part of it names an "
                      f"item the device already lists", "canonical_field")


def _value_slot(sample: Member, spec: FieldSpec, key: _Where | None) -> int:
    kind = _value_kind(spec)
    candidates = [i for i, p in enumerate(sample.line.parts) if isinstance(p, Slot)
                  and (key is None or key != _Where("line", i))
                  and (kind != "integer" or p.kind == "INT")]
    if kind == "boolean" or not candidates:
        raise AuthorError(f"the line carries no {kind} to read into {spec.path}; state the value it means",
                          "value")
    if len(candidates) > 1:
        shown = ", ".join(f"<{sample.line.parts[i].kind}>" for i in candidates)  # type: ignore[union-attr]
        raise AuthorError(f"the line carries several values ({shown}) that could fill {spec.path}; "
                          "state a fixed value or choose a field that names which", "value")
    return candidates[0]


def _pattern(template: Template, groups: dict[int, str]) -> str:
    out = []
    for i, p in enumerate(template.parts):
        if isinstance(p, str):
            out.append(regex.escape(p))
            continue
        body = SLOT_REGEX[p.kind]
        name = groups.get(i)
        if name is None:
            out.append(body)
        elif p.kind == "STR":
            out.append(f'"(?P<{name}>[^"]*)"')
        else:
            out.append(f"(?P<{name}>{body})")
    return "^" + r"\s+".join(out) + "$"


def _example_value(slot: Slot, spec: FieldSpec) -> Any:
    text = EXAMPLE.get(slot.kind, slot.text)
    if slot.kind == "STR":
        text = text[1:-1]
    return int(text) if _value_kind(spec) == "integer" else text


def author_mapping(cluster: Cluster, request: dict[str, Any], catalogue: Catalogue,
                   created: str) -> dict[str, Any]:
    """`request` is a `ConfirmRequest` from docs/openapi.yaml, plus `default_os_version`."""
    path = request["canonical_field"]
    reason = learnable(path, catalogue)
    if reason:
        raise AuthorError(reason, "canonical_field")
    spec = catalogue.fields[path]
    sample = cluster.sample
    is_list = spec.collection
    item_of = None if is_list or "[]" not in path else catalogue.fields[collection_of(path)]

    groups: dict[str, dict[int, str]] = {"scope": {}, "line": {}}
    key: _Where | None = None
    canonical = path
    if item_of is not None and item_of.key:
        key = _key_slot(sample, item_of)
        groups[key.part][key.index] = item_of.key
        canonical = f"{item_of.path[:-2]}[{{{item_of.key}}}].{path.rsplit('.', 1)[1]}"

    mapping: dict[str, Any] = {"id": f"{cluster.vendor}.learned.{cluster.cluster_id[1:]}",
                               "canonical": canonical}
    value_spec = spec
    expect: Any = None
    if "value" in request and request["value"] is not None:
        _check_value(request["value"], value_spec, "value")
        expect = request["value"]
    else:
        vi = _value_slot(sample, value_spec, key)
        groups["line"][vi] = "value"
        slot = sample.line.parts[vi]
        assert isinstance(slot, Slot)
        expect = _example_value(slot, value_spec)

    mapping["match"] = _pattern(sample.line, groups["line"])
    if sample.scope is not None:
        mapping["scope"] = _pattern(sample.scope, groups["scope"])
    if "value" in request and request["value"] is not None:
        mapping["value"] = request["value"]
    if _value_kind(value_spec) == "integer" and "value" not in mapping:
        mapping["cast"] = "int"

    absent = request["absent"]
    if is_list:
        if request.get("default") is not None:
            raise AuthorError("a list takes no default; absent=default means no line is an empty list", "default")
        mapping["empty"] = "mapped" if absent == "default" else "unknown"
    else:
        mapping["absent"] = absent
        if absent == "default":
            if "default" not in request:
                raise AuthorError("absent=default needs the value the device uses when the line is missing",
                                  "default")
            if not request.get("default_os_version"):
                raise AuthorError("absent=default needs default_os_version: defaults change between releases",
                                  "default_os_version")
            _check_value(request["default"], value_spec, "default")
            mapping["default"] = request["default"]
            mapping["default_os_version"] = request["default_os_version"]

    fixture = example_line(sample.raw, sample.known)
    if sample.parent_raw is not None:
        fixture = example_line(sample.parent_raw, sample.known) + "\n" + fixture
    mapping["fixture"] = fixture
    mapping["expect"] = expect
    mapping.update({"source": "learned", "author": request.get("author") or "unattributed",
                    "created": created,
                    "cluster_signature": f"{cluster.scope} :: {cluster.signature}" if cluster.scope
                    else cluster.signature})
    _check_covers(mapping, cluster)
    return mapping


def _check_covers(mapping: dict[str, Any], cluster: Cluster) -> None:
    """The mapping must match every recorded occurrence, or the question was not answered for all of them."""
    line = compile_pattern(mapping["match"])
    scope = compile_pattern(mapping["scope"]) if "scope" in mapping else None
    for m in cluster.members:
        try:
            ok = bool(line.match(m.text)) and (
                scope is None or (m.parent_text is not None and bool(scope.match(m.parent_text))))
        except TimeoutError:
            ok = False
        if not ok:
            raise AuthorError(f"the generated pattern does not match the occurrence on device {m.device_id}",
                              status=409)


def bump(version: str) -> str:
    major, minor, patch = (int(x) for x in re.findall(r"\d+", version)[:3])
    return f"{major}.{minor}.{patch + 1}"


def dump(data: Any) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=1_000_000)


def append(doc: dict[str, Any] | None, vendor: str, mapping: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """The learned pack after appending `mapping`, and the exact YAML of the appended entry."""
    if doc is None:
        new = {"vendor_pack": vendor, "version": FIRST_VERSION, "mappings": [mapping]}
    else:
        new = {**doc, "version": bump(str(doc["version"])), "mappings": [*doc["mappings"], mapping]}
    return new, dump([mapping])
