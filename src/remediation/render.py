"""Fix-template renderer. Pure: template + failing items → vendor CLI."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.mapping.canonical import project
from src.packs import PackError, read_yaml, validate_pack
from src.versions import in_range

_VAR = re.compile(r"\{([a-z_]+)\}")
ITEMS = "{items}"


@dataclass
class FixPack:
    id: str
    version: str
    vendor_pack: str
    fixes: dict[str, dict[str, Any]]

    @property
    def tag(self) -> str:
        return f"{self.id}@{self.version}"


def load_fix_pack(path: Path) -> FixPack:
    doc = read_yaml(path)
    validate_pack(doc, "fix_pack", path.name)
    fixes: dict[str, dict[str, Any]] = {}
    for fix in doc["fixes"]:
        if fix["id"] in fixes:
            raise PackError(f"{path.name}: fix {fix['id']}: field id: duplicate")
        for key, item_key in (("commands", "item_commands"), ("rollback", "item_rollback")):
            if ITEMS in fix[key] and item_key not in fix:
                raise PackError(f"{path.name}: fix {fix['id']}: field {item_key}: required when {key} uses {ITEMS}")
        fixes[fix["id"]] = fix
    return FixPack(doc["id"], doc["version"], doc["vendor_pack"], fixes)


def _fill(line: str, values: dict[str, Any]) -> str:
    def sub(m: re.Match[str]) -> str:
        value = values.get(m.group(1))
        if value is None:
            raise KeyError(m.group(1))
        return str(value)
    return _VAR.sub(sub, line)


def _expand(lines: list[str], item_lines: list[str], items: list[dict[str, Any]],
            overrides: dict[str, list[str]] | None = None) -> list[str]:
    out: list[str] = []
    for line in lines:
        if line == ITEMS:
            for item in items:
                own = (overrides or {}).get(str(item.get("name")), item_lines)
                out.extend(_fill(il, item) for il in own)
        else:
            out.append(line)
    return out


def render(fix: dict[str, Any], failing_items: list[dict[str, Any]], os_version: str | None) -> dict[str, Any] | None:
    """None when the fix does not apply to this OS version or an item lacks a value the template needs."""
    if in_range(os_version, fix["os_version"]) is not True:
        return None
    items = [project(item) for item in failing_items]
    try:
        commands = _expand(fix["commands"], fix.get("item_commands", []), items, fix.get("item_commands_for"))
        rollback = _expand(fix["rollback"], fix.get("item_rollback", []), items)
    except KeyError:
        return None
    return {
        "fix_id": fix["id"],
        "commands": commands,
        "rollback": rollback,
        "reload_required": bool(fix["reload_required"]),
        "operator_input": list(fix.get("operator_input", [])),
        "note": fix.get("note"),
    }
