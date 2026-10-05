"""Phase 0 contract checks: the canonical schema and the OpenAPI document are valid and say what we rely on."""

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from openapi_spec_validator import validate
from openapi_spec_validator.readers import read_from_filename

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas" / "canonical.schema.json").read_text(encoding="utf-8"))
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def _paths(node: Any) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        if "x-path" in node:
            found.append(node["x-path"])
        for key, value in node.items():
            if key != "$defs":
                found.extend(_paths(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_paths(value))
    return found


def _unknown() -> dict[str, Any]:
    return {"value": None, "state": "unknown", "evidence": None}


def _empty_model() -> dict[str, Any]:
    """Every field unknown: what the mapper emits for a file it could not read at all."""

    def fill(schema: Any) -> Any:
        if "x-path" in schema:
            if schema["x-path"].endswith("[]"):
                return {"state": "unknown", "evidence": None, "items": []}
            return _unknown()
        if "const" in schema:
            return schema["const"]
        if schema.get("type") == "object":
            return {k: fill(v) for k, v in schema["properties"].items() if k in schema["required"]}
        raise AssertionError(schema)

    model: dict[str, Any] = fill(SCHEMA)
    return model


def test_schema_is_valid_draft_2020_12() -> None:
    jsonschema.Draft202012Validator.check_schema(SCHEMA)


def test_schema_has_collections_and_unique_paths() -> None:
    paths = _paths(SCHEMA)
    assert len(paths) == len(set(paths))
    assert sum(p.endswith("[]") for p in paths) >= 2


def test_every_field_has_ranking_description() -> None:
    def leaves(node: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if isinstance(node, dict):
            if "x-path" in node:
                out.append(node)
            for k, v in node.items():
                if k != "$defs":
                    out.extend(leaves(v))
        return out

    for field in leaves(SCHEMA):
        assert len(field.get("description", "")) > 20, field["x-path"]
        assert field.get("x-absent"), field["x-path"]


def test_all_unknown_model_validates() -> None:
    VALIDATOR.validate(_empty_model())


def test_unknown_field_cannot_carry_a_value() -> None:
    model = _empty_model()
    model["services"]["ssh"]["version"] = {"value": 2, "state": "unknown", "evidence": None}
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(model)


def test_mapped_field_requires_a_line() -> None:
    model = _empty_model()
    evidence = {"line": None, "mapping_id": "ios.ssh.version", "pack_version": "cisco_ios@1.0.0"}
    model["services"]["ssh"]["version"] = {"value": 2, "state": "mapped", "evidence": evidence}
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(model)


def test_unknown_collection_cannot_have_items() -> None:
    model = _empty_model()
    model["interfaces"]["items"] = [{"name": _unknown()}]
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(model)


def test_openapi_is_valid() -> None:
    spec, _ = read_from_filename(str(ROOT / "docs" / "openapi.yaml"))
    validate(spec)


def test_engine_output_conforms_to_the_api_contract() -> None:
    """What the backend returns must validate against DeviceFindings, or Codex's mock-built UI breaks."""
    import yaml

    from src.audit import audit_device
    from src.registry import Registry

    spec = yaml.safe_load((ROOT / "docs" / "openapi.yaml").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(
        {"$ref": "#/components/schemas/DeviceFindings", "components": spec["components"]})
    registry = Registry(ROOT / "packs")
    cfg = ROOT / "fixtures" / "configs" / "batfish_example_live" / "as2dept1.cfg"
    for text in (cfg.read_text(), "not a config at all\n"):
        result = audit_device(text, cfg.name, "d1", registry.snapshot(), registry.catalogue, ["cis"])
        validator.validate(result)
