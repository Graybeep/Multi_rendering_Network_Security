"""Pack registry: loads every pack from a directory at runtime and hot-reloads when files change.

Packs live outside the Python package, so adding a vendor never needs a code change or a restart.
A rejected pack is reported by name and skipped; the rest keep working.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.ingest.redact import redact
from src.mapping.canonical import Catalogue
from src.mapping.engine import AmbiguousMapping, map_device
from src.mapping.pack import VendorPack, load_vendor_pack, merge_learned
from src.packs import PackError
from src.readers import READERS
from src.remediation.render import FixPack, load_fix_pack
from src.rules.evaluator import RulePack, load_rule_pack


def _find_mapped(node: Any, mapping_id: str) -> list[Any]:
    found: list[Any] = []
    if isinstance(node, dict):
        ev = node.get("evidence")
        if node.get("state") == "mapped" and isinstance(ev, dict) and ev.get("mapping_id") == mapping_id \
                and "value" in node:
            found.append(node["value"])
        for v in node.values():
            found.extend(_find_mapped(v, mapping_id))
    elif isinstance(node, list):
        for v in node:
            found.extend(_find_mapped(v, mapping_id))
    return found


def check_fixtures(pack: VendorPack, catalogue: Catalogue) -> None:
    """Every mapping's fixture must match it, produce `expect` if given, and never be ambiguous."""
    reader = READERS.get(pack.reader)
    if reader is None:
        raise PackError(f"{pack.id}: field reader: {pack.reader!r} is not implemented yet")
    for m in pack.mappings:
        lines = redact(m.fixture.rstrip("\n"))
        try:
            result = map_device(pack, reader(lines), lines, catalogue, None)
        except AmbiguousMapping as exc:
            raise PackError(f"{pack.id}: mapping {m.id}: field fixture: {exc}") from exc
        values = _find_mapped(result.model, m.id)
        if not values:
            raise PackError(f"{pack.id}: mapping {m.id}: field fixture: does not match its own mapping")
        if "expect" in m.raw and m.raw["expect"] not in values:
            raise PackError(f"{pack.id}: mapping {m.id}: field expect: fixture produced {values!r}, "
                            f"expected {m.raw['expect']!r}")


@dataclass
class Snapshot:
    """An immutable view of loaded packs; one scan uses one snapshot throughout."""

    vendors: dict[str, VendorPack] = field(default_factory=dict)
    rules: dict[str, RulePack] = field(default_factory=dict)  # by framework
    fixes: dict[str, FixPack] = field(default_factory=dict)  # by vendor pack id
    errors: list[str] = field(default_factory=list)

    def packs(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for v in self.vendors.values():
            out.append({"id": v.id, "kind": "vendor", "version": v.version, "source": "shipped",
                        "vendor": v.vendor, "mapping_count": sum(1 for m in v.mappings if m.priority < 100),
                        "rule_count": None})
            if v.learned_version:
                out.append({"id": f"{v.id}_learned", "kind": "learned", "version": v.learned_version,
                            "source": "learned", "vendor": v.vendor,
                            "mapping_count": sum(1 for m in v.mappings if m.raw.get("source") == "learned"),
                            "rule_count": None})
        for r in self.rules.values():
            out.append({"id": r.id, "kind": "rule", "version": r.version, "source": "shipped",
                        "framework": r.framework, "vendor": None, "mapping_count": None,
                        "rule_count": len(r.rules)})
        for f in self.fixes.values():
            out.append({"id": f.id, "kind": "fix", "version": f.version, "source": "shipped",
                        "vendor": f.vendor_pack, "mapping_count": None, "rule_count": None})
        return out


def load_snapshot(root: Path, catalogue: Catalogue) -> Snapshot:
    snap = Snapshot()
    for path in sorted((root / "vendors").glob("*.yaml")):
        try:
            pack = load_vendor_pack(path, catalogue)
            learned = root / "learned" / path.name
            if learned.exists():
                try:
                    merged = merge_learned(pack, learned, catalogue)
                    check_fixtures(merged, catalogue)
                    pack = merged
                except PackError as exc:
                    snap.errors.append(str(exc))
            check_fixtures(pack, catalogue)
            snap.vendors[pack.id] = pack
        except PackError as exc:
            snap.errors.append(str(exc))
    for path in sorted((root / "rules").glob("*.yaml")):
        try:
            rp = load_rule_pack(path, catalogue)
            if rp.framework in snap.rules:
                raise PackError(f"{path.name}: field framework: {rp.framework!r} already provided by "
                                f"{snap.rules[rp.framework].tag}")
            snap.rules[rp.framework] = rp
        except PackError as exc:
            snap.errors.append(str(exc))
    for path in sorted((root / "fixes").glob("*.yaml")):
        try:
            fp = load_fix_pack(path)
            snap.fixes[fp.vendor_pack] = fp
        except PackError as exc:
            snap.errors.append(str(exc))
    return snap


class Registry:
    """Reloads when any pack file is added, removed or modified."""

    def __init__(self, root: Path, catalogue: Catalogue | None = None) -> None:
        self.root = root
        self.catalogue = catalogue or Catalogue.load()
        self._signature: tuple[tuple[str, int, int], ...] | None = None
        self._snapshot = Snapshot()

    def _current_signature(self) -> tuple[tuple[str, int, int], ...]:
        sig = []
        for sub in ("vendors", "rules", "fixes", "learned"):
            for p in sorted((self.root / sub).glob("*.yaml")):
                st = p.stat()
                sig.append((str(p), st.st_mtime_ns, st.st_size))
        return tuple(sig)

    def snapshot(self) -> Snapshot:
        sig = self._current_signature()
        if sig != self._signature:
            self._snapshot = load_snapshot(self.root, self.catalogue)
            self._signature = sig
        return self._snapshot
