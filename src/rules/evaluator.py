"""Rule packs and the three-state verdict. Pure: no I/O, no globals.

Order of decision, per rule:
  1. any `requires` field unknown            → NOT_DETERMINED, assertion not evaluated
  2. `for_each` collection of unknown state  → NOT_DETERMINED (never a vacuous PASS)
  3. evaluate the JMESPath assertion         → PASS / FAIL
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jmespath
import jsonschema
from jmespath.exceptions import JMESPathError

from src.mapping.canonical import Catalogue, Model, iter_states, normalise, parse_path, project
from src.packs import PackError, read_yaml, validate_pack
from src.rules.fixtures import model_from_fragment
from src.versions import in_range

PASS, FAIL, NOT_DETERMINED = "PASS", "FAIL", "NOT_DETERMINED"


@dataclass
class Rule:
    raw: dict[str, Any]
    compiled: Any
    pack_tag: str
    framework: str

    @property
    def id(self) -> str:
        return str(self.raw["id"])

    @property
    def requires(self) -> list[str]:
        return [normalise(p) for p in self.raw["requires"]]

    @property
    def for_each(self) -> str | None:
        return self.raw.get("for_each")


@dataclass
class RulePack:
    id: str
    version: str
    framework: str
    rules: list[Rule]

    @property
    def tag(self) -> str:
        return f"{self.id}@{self.version}"


@dataclass
class Verdict:
    rule: Rule
    verdict: str
    missing_fields: list[str]
    failing_items: list[dict[str, Any]]  # raw model items, for per-item evidence and fixes
    error: str | None = None


def _field_names(ast: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(ast, dict):
        if ast.get("type") == "field":
            names.add(ast["value"])
        for child in ast.get("children", []):
            names |= _field_names(child)
    return names


def load_rule_pack(path: Path, catalogue: Catalogue) -> RulePack:
    doc = read_yaml(path)
    validate_pack(doc, "rule_pack", path.name)
    tag = f"{doc['id']}@{doc['version']}"
    rules, seen = [], set()
    for raw in doc["rules"]:
        loc = f"{path.name}: rule {raw['id']}"
        if raw["id"] in seen:
            raise PackError(f"{loc}: field id: duplicate")
        seen.add(raw["id"])
        for p in raw["requires"]:
            if normalise(p) not in catalogue.fields:
                raise PackError(f"{loc}: field requires: {p!r} is not a canonical field")
        each = raw.get("for_each")
        if each is not None:
            if each not in catalogue.fields:
                raise PackError(f"{loc}: field for_each: {each!r} is not a canonical collection")
            if not any(normalise(p).startswith(each) for p in raw["requires"]):
                raise PackError(f"{loc}: field requires: must include a path under {each!r}")
        try:
            compiled = jmespath.compile(raw["assert"])
        except JMESPathError as exc:
            raise PackError(f"{loc}: field assert: {exc}") from exc
        # Every name the assertion reads must be covered by `requires`, or an unread field could FAIL.
        allowed = {seg.name for p in raw["requires"] for seg in parse_path(normalise(p))}
        stray = _field_names(compiled.parsed) - allowed
        if stray:
            raise PackError(f"{loc}: field assert: reads {sorted(stray)} which are not in requires")
        rule = Rule(raw, compiled, tag, doc["framework"])
        _check_fixtures(rule, catalogue, loc)
        rules.append(rule)
    return RulePack(doc["id"], doc["version"], doc["framework"], rules)


def _check_fixtures(rule: Rule, catalogue: Catalogue, loc: str) -> None:
    """A rule whose own fixtures disagree with it is silently wrong on every device; reject it at load."""
    expected = (("pass", PASS), ("fail", FAIL))
    for name, want in expected:
        try:
            model = model_from_fragment(catalogue, rule.raw["fixtures"][name])
        except (ValueError, jsonschema.ValidationError) as exc:
            raise PackError(f"{loc}: field fixtures/{name}: {exc}") from exc
        got = evaluate(rule, model).verdict
        if got != want:
            raise PackError(f"{loc}: field fixtures/{name}: expected {want}, got {got}")
    got = evaluate(rule, catalogue.empty_model()).verdict
    if got != NOT_DETERMINED:
        raise PackError(f"{loc}: field requires: an unread device must be NOT_DETERMINED, got {got}")


def applies(rule: Rule, os_family: str | None, os_version: str | None) -> bool | None:
    """None when applicability cannot be decided (unknown OS) — reported as NOT_DETERMINED."""
    spec = rule.raw["applies_to"]
    family = spec.get("os_family", "*")
    if family != "*":
        if os_family is None:
            return None
        if family != os_family:
            return False
    return in_range(os_version, spec.get("os_version", "*"))


def _items(model: Model, collection: str) -> tuple[str, list[dict[str, Any]]]:
    node: Any = model
    for seg in parse_path(collection):
        node = node[seg.name]
    return node["state"], node["items"]


def _truth(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def evaluate(rule: Rule, model: Model) -> Verdict:
    missing = sorted({p for p in rule.requires if any(s == "unknown" for s, _ in iter_states(model, p))})
    if missing:
        return Verdict(rule, NOT_DETERMINED, missing, [])

    each = rule.for_each
    if each is None:
        result = _truth(rule.compiled.search(project(model)))
        if result is None:
            return Verdict(rule, NOT_DETERMINED, [], [], "assertion did not return a boolean")
        return Verdict(rule, PASS if result else FAIL, [], [])

    state, items = _items(model, each)
    if state == "unknown":  # belt and braces: requires should already have caught this
        return Verdict(rule, NOT_DETERMINED, [each], [])
    failing = []
    for item in items:
        result = _truth(rule.compiled.search(project(item)))
        if result is None:
            return Verdict(rule, NOT_DETERMINED, [], [], "assertion did not return a boolean")
        if not result:
            failing.append(item)
    return Verdict(rule, FAIL if failing else PASS, [], failing)


def evidence_for(verdict: Verdict, model: Model) -> list[tuple[str, dict[str, Any] | None]]:
    """(canonical path, triple) pairs a finding should cite."""
    out: list[tuple[str, dict[str, Any] | None]] = []
    each = verdict.rule.for_each
    per_item = [p for p in verdict.rule.requires if each and p.startswith(each + ".")]
    if each and per_item:
        state, items = _items(model, each)
        if state == "unknown":
            out.extend((path, None) for path in per_item)
        for item in verdict.failing_items if verdict.verdict == FAIL else items:
            key = next(iter(item))  # the schema lists the key attribute first
            out.append((f"{each}.{key}", item[key]))
            out.extend((path, item.get(path[len(each) + 1:])) for path in per_item)
    for path in verdict.rule.requires:
        if path in per_item:
            continue
        if path.endswith("[]") and "[]" not in path[:-2]:
            state, items = _items(model, path)
            if not items:
                out.append((path, {"value": [], "state": state, "evidence": None}))
            for item in items:
                out.append((path, item if "value" in item else next(iter(item.values()))))
        else:
            for _, triple in iter_states(model, path):
                out.append((path, triple))
    return out
