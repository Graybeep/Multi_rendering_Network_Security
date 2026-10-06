"""Vendor pack model and loader. Vendor knowledge arrives here as data; nothing in this module knows a vendor."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import regex

from src.mapping.canonical import Catalogue, FieldSpec, normalise, parse_path
from src.packs import PackError, read_yaml, validate_pack
from src.safe_regex import PatternError, SafePattern, compile_pattern

LEARNED_PRIORITY = 100
_SCOPE_VAR = re.compile(r"\{([a-z_]+)\}")
_LITERAL_TOKEN = re.compile(r"^\^([A-Za-z0-9_-]+)(?:\s|\\s|\\ |\$|$)")


def scope_pattern(template: str) -> SafePattern:
    """`interface {name}` → `^interface (?P<name>.+?)$`. A scope starting with `^` is already a regex."""
    if template.startswith("^"):
        return compile_pattern(template)
    parts = _SCOPE_VAR.split(template)
    out = []
    for i, part in enumerate(parts):
        out.append(f"(?P<{part}>.+?)" if i % 2 else regex.escape(part, literal_spaces=True))
    return compile_pattern("^" + "".join(out) + "$")


def first_token(pattern: str) -> str | None:
    """Literal first word a regex requires, for dispatch. None means try it on every line."""
    m = _LITERAL_TOKEN.match(pattern)
    return m.group(1) if m else None


@dataclass
class Mapping:
    id: str
    canonical: str
    target: str  # normalised path
    collection: bool
    pattern: SafePattern
    scope: SafePattern | None
    raw: dict[str, Any]
    pack_version: str
    priority: int
    spec: FieldSpec
    item_specs: dict[str, FieldSpec] = field(default_factory=dict)

    @property
    def has_value(self) -> bool:
        return "value" in self.raw

    @property
    def fixture(self) -> str:
        return str(self.raw["fixture"])


@dataclass
class VendorPack:
    id: str
    version: str
    vendor: str
    os_family: str
    reader: str
    detect: list[tuple[SafePattern, int]]
    min_score: int
    facts: dict[str, tuple[SafePattern, int]]
    mappings: list[Mapping]
    learned_version: str | None = None
    inheritance: list[SafePattern] = field(default_factory=list)
    dispatch: dict[str, list[Mapping]] = field(default_factory=dict)
    wildcard: list[Mapping] = field(default_factory=list)

    @property
    def tag(self) -> str:
        return f"{self.id}@{self.version}"

    def index(self) -> None:
        self.dispatch, self.wildcard = {}, []
        for m in self.mappings:
            token = first_token(m.pattern.source)
            if token is None:
                self.wildcard.append(m)
            else:
                self.dispatch.setdefault(token, []).append(m)


def _compile(source: str, where: str, what: str) -> SafePattern:
    try:
        return compile_pattern(source)
    except PatternError as exc:
        raise PackError(f"{where}: field {what}: {exc}") from exc


def build_mapping(raw: dict[str, Any], catalogue: Catalogue, pack_version: str,
                  where: str, default_priority: int) -> Mapping:
    mid = raw["id"]
    loc = f"{where}: mapping {mid}"
    canonical = raw["canonical"]
    target = normalise(canonical)
    spec = catalogue.fields.get(target)
    if spec is None:
        raise PackError(f"{loc}: field canonical: {canonical!r} is not a canonical field")
    collection = target.endswith("[]")
    if collection != spec.collection:
        raise PackError(f"{loc}: field canonical: {canonical!r} collection/scalar mismatch")

    pattern = _compile(raw["match"], loc, "match")
    scope = scope_pattern(raw["scope"]) if "scope" in raw else None
    groups = set(pattern._compiled.groupindex)
    scope_vars = set(scope._compiled.groupindex) if scope else set()

    bound = {seg.var for seg in parse_path(canonical) if seg.var}
    missing = bound - groups - scope_vars
    if missing:
        raise PackError(f"{loc}: field canonical: variable(s) {sorted(missing)} not bound by scope or match")

    item_specs: dict[str, FieldSpec] = {}
    if collection and spec.object_items:
        attrs = {k[len(target) + 1:]: v for k, v in catalogue.fields.items()
                 if k.startswith(target + ".") and "[]" not in k[len(target) + 1:]}
        item_specs = attrs
        unknown_groups = groups - set(attrs) - bound
        if unknown_groups:
            raise PackError(f"{loc}: field match: named group(s) {sorted(unknown_groups)} are not item attributes")
        if spec.key and spec.key not in groups and not raw.get("auto_key"):
            raise PackError(f"{loc}: field match: must capture the key attribute {spec.key!r} or set auto_key")
    if "keep" in raw and collection:
        raise PackError(f"{loc}: field keep: only scalar fields can keep a min or max")
    if not (collection and spec.object_items) and "value" not in raw:
        if pattern._compiled.groups == 0:
            raise PackError(f"{loc}: field value: no fixed value and no capture group")
        if raw.get("cast") == "min_sec" and pattern._compiled.groups < 1:
            raise PackError(f"{loc}: field cast: min_sec needs capture groups")

    priority = int(raw.get("priority", default_priority))
    return Mapping(mid, canonical, target, collection, pattern, scope, raw, pack_version,
                   priority, spec, item_specs)


def _check_absent_consistency(mappings: list[Mapping], where: str) -> None:
    decl: dict[str, tuple[Any, ...]] = {}
    for m in mappings:
        if m.collection:
            key: tuple[Any, ...] = ("empty", m.raw["empty"])
        else:
            key = (m.raw["absent"], repr(m.raw.get("default")), m.raw.get("default_os_version"))
        prev = decl.setdefault(m.target, key)
        if prev != key:
            raise PackError(f"{where}: mapping {m.id}: field absent: conflicts with another mapping "
                            f"for {m.target} ({prev} vs {key})")


def load_vendor_pack(path: Path, catalogue: Catalogue) -> VendorPack:
    doc = read_yaml(path)
    validate_pack(doc, "vendor_pack", path.name)
    tag = f"{doc['id']}@{doc['version']}"
    if path.stem != doc["id"]:
        raise PackError(f"{path.name}: field id: {doc['id']!r} must match the file name")

    detect = []
    for i, sig in enumerate(doc["detect"]):
        src, weight = (sig, 1) if isinstance(sig, str) else (sig["pattern"], sig.get("weight", 1))
        detect.append((_compile(src, path.name, f"detect/{i}"), int(weight)))
    facts = {name: (_compile(f["pattern"], path.name, f"facts/{name}"), int(f.get("group", 1)))
             for name, f in (doc.get("facts") or {}).items()}

    seen: set[str] = set()
    mappings = []
    for raw in doc["mappings"]:
        if raw["id"] in seen:
            raise PackError(f"{path.name}: mapping {raw['id']}: field id: duplicate")
        seen.add(raw["id"])
        mappings.append(build_mapping(raw, catalogue, tag, path.name, 0))
    _check_absent_consistency(mappings, path.name)

    inheritance = [_compile(src, path.name, f"unresolved_inheritance/{i}")
                   for i, src in enumerate(doc.get("unresolved_inheritance") or [])]
    pack = VendorPack(doc["id"], doc["version"], doc["vendor"], doc["os_family"], doc["reader"],
                      detect, int(doc.get("min_score", 1)), facts, mappings, inheritance=inheritance)
    pack.index()
    return pack


def merge_learned(pack: VendorPack, path: Path, catalogue: Catalogue) -> VendorPack:
    """Learned mappings use the vendor-pack mapping schema and outrank shipped ones by default."""
    doc = read_yaml(path)
    validate_pack(doc, "learned_pack", path.name)
    if doc["vendor_pack"] != pack.id:
        raise PackError(f"{path.name}: field vendor_pack: {doc['vendor_pack']!r} does not match {pack.id!r}")
    tag = f"{pack.id}_learned@{doc['version']}"
    seen = {m.id for m in pack.mappings}
    learned = []
    for raw in doc["mappings"]:
        if raw["id"] in seen:
            raise PackError(f"{path.name}: mapping {raw['id']}: field id: duplicate of an existing mapping")
        seen.add(raw["id"])
        learned.append(build_mapping(raw, catalogue, tag, path.name, LEARNED_PRIORITY))
    merged = VendorPack(pack.id, pack.version, pack.vendor, pack.os_family, pack.reader, pack.detect,
                        pack.min_score, pack.facts, pack.mappings + learned, doc["version"],
                        inheritance=pack.inheritance)
    _check_absent_consistency(merged.mappings, path.name)
    merged.index()
    return merged
