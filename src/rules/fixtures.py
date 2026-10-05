"""Rule fixtures are canonical-model fragments, so they stay vendor-neutral.

`{services.ssh.version: 2}` sets one field; `{interfaces[]: [{name: Gi0/1, proxy_arp: false}]}` sets a
collection. Everything not mentioned stays unknown.
"""

from __future__ import annotations

from typing import Any

from src.mapping.canonical import Catalogue, Model, Triple, get_node, parse_path

_EVIDENCE = {"line": 1, "mapping_id": "fixture", "pack_version": "fixture@0.0.0"}


def _triple(value: Any) -> Triple:
    return {"value": value, "state": "mapped", "evidence": dict(_EVIDENCE)}


def model_from_fragment(catalogue: Catalogue, fragment: dict[str, Any]) -> Model:
    model = catalogue.empty_model()
    for path, value in fragment.items():
        spec = catalogue.fields.get(path)
        if spec is None:
            raise ValueError(f"fixture path {path!r} is not a canonical field")
        segments = parse_path(path)
        parent = get_node(model, ".".join(s.name for s in segments[:-1])) if len(segments) > 1 else model
        name = segments[-1].name
        if not spec.collection:
            parent[name] = _triple(value)
            continue
        if "[]" in path[:-2]:
            raise ValueError(f"fixture path {path!r}: nested collections are not supported in fixtures")
        items: list[Any] = []
        coll: dict[str, Any] = {"state": "mapped", "evidence": None, "items": items}
        for element in value:
            if spec.object_items:
                item = catalogue.new_item(path)
                for attr, v in element.items():
                    if attr not in item:
                        raise ValueError(f"fixture path {path!r}: {attr!r} is not an item attribute")
                    item[attr] = _triple(v)
                items.append(item)
            else:
                items.append(_triple(element))
        parent[name] = coll
    catalogue.validate(model)
    return model
