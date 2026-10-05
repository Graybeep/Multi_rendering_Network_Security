"""Shared pack-file helpers: safe YAML loading and JSON Schema validation with field-naming errors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import yaml

PACK_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "packs.schema.json"


class PackError(ValueError):
    """A pack was rejected. The message names the file and the offending field."""


_PACK_SCHEMA: dict[str, Any] = json.loads(PACK_SCHEMA_PATH.read_text(encoding="utf-8"))


def read_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PackError(f"{path.name}: not valid YAML: {exc}") from exc


def validate_pack(doc: Any, kind: str, source: str) -> None:
    """`kind` is a $defs name in packs.schema.json, e.g. `vendor_pack`."""
    schema = {"$ref": f"#/$defs/{kind}", "$defs": _PACK_SCHEMA["$defs"]}
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    if errors:
        err = jsonschema.exceptions.best_match(errors)
        where = "/".join(str(p) for p in err.absolute_path) or "(root)"
        raise PackError(f"{source}: field {where}: {err.message}")
