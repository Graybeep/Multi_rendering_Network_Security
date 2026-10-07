"""One device, end to end: ingest → redact → detect → read → map → evaluate → remediate. Pure; no I/O.

The returned dict is shaped like `DeviceFindings` in docs/openapi.yaml, plus internal fields
(`canonical`, `unmatched`, `ignored`, `warnings`, `sha256`) the report, CLI and learning loop use.
"""

from __future__ import annotations

import hashlib
from typing import Any

from src.ingest.redact import redact
from src.mapping.canonical import Catalogue, Model, parse_path
from src.mapping.engine import AmbiguousMapping, detect, map_device
from src.readers import READERS
from src.registry import Snapshot
from src.remediation.render import render
from src.rules.evaluator import FAIL, NOT_DETERMINED, PASS, applies, evaluate, evidence_for

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
IDENTITY = ("hostname", "vendor", "os_family", "os_version", "model", "serial")


def coverage(model: Model, catalogue: Catalogue) -> dict[str, Any]:
    """Field coverage over top-level canonical fields: each scalar once, each collection once by its state."""
    counts = {"mapped": 0, "defaulted": 0, "unknown": 0}
    for path, spec in catalogue.fields.items():
        if "[]" in path[:-2] or (not spec.collection and "[]" in path):
            continue  # item attributes are counted through their collection
        node: Any = model
        for seg in parse_path(path):
            node = node[seg.name]
        counts[node["state"]] += 1
    total = sum(counts.values())
    known = counts["mapped"] + counts["defaulted"]
    return {**counts, "ratio": round(known / total, 4) if total else 0.0}


def _evidence_lines(pairs: list[tuple[str, dict[str, Any] | None]], lines: list[str]) -> list[dict[str, Any]]:
    out = []
    for path, triple in pairs:
        if triple is None:
            out.append({"canonical_field": path, "state": "unknown", "value": None, "line_no": None,
                        "text": None, "mapping_id": None, "pack_version": None, "source": None})
            continue
        ev = triple.get("evidence") or {}
        line_no = ev.get("line")
        out.append({
            "canonical_field": path,
            "state": triple["state"],
            "value": triple.get("value"),
            "line_no": line_no,
            "text": lines[line_no - 1].strip() if line_no else None,
            "mapping_id": ev.get("mapping_id"),
            "pack_version": ev.get("pack_version"),
            "source": ev.get("source"),
        })
    return out


def _error(device_id: str, filename: str, message: str, sha: str) -> dict[str, Any]:
    return {"device_id": device_id, "filename": filename, "status": "error", "error": message,
            "vendor_pack": None, "detection_ambiguous": False,
            "identity": dict.fromkeys(IDENTITY), "verdicts": {"pass": 0, "fail": 0, "not_determined": 0},
            "coverage": {"mapped": 0, "defaulted": 0, "unknown": 0, "ratio": 0.0},
            "findings": [], "sha256": sha, "canonical": None, "unmatched": [], "ignored": [], "warnings": []}


def audit_device(text: str, filename: str, device_id: str, snap: Snapshot, catalogue: Catalogue,
                 frameworks: list[str], os_version: str | None = None) -> dict[str, Any]:
    """`os_version` is operator-supplied, used only when the config does not state one."""
    sha = hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()
    lines = redact(text)

    detection = detect(lines, list(snap.vendors.values()))
    pack = detection.pack
    unmatched: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    warnings: list[str] = []
    if pack is None:
        # No pack (or a tie): every field stays unknown, so every rule is NOT_DETERMINED. No guessing.
        model = catalogue.empty_model()
        if detection.ambiguous:
            warnings.append(f"vendor detection tied between {', '.join(detection.candidates)}")
    else:
        reader = READERS.get(pack.reader)
        if reader is None:
            return _error(device_id, filename, f"reader {pack.reader!r} not implemented", sha)
        try:
            nodes = reader(lines)
            mapped = map_device(pack, nodes, lines, catalogue, detection.line, os_version)
        except AmbiguousMapping as exc:
            return _error(device_id, filename, f"ambiguous mapping: {exc}", sha)
        model, warnings = mapped.model, mapped.warnings
        # `raw` and `parent_raw` are the redacted source lines, indentation kept, for the learning loop.
        unmatched = [{"line_no": u.line_no, "text": u.text, "scope": list(u.path), "leaf": u.leaf,
                      "raw": lines[u.line_no - 1],
                      "parent_raw": lines[u.parent_line - 1] if u.parent_line else None}
                     for u in mapped.unmatched]
        # Lines an ignore entry answered as carrying no setting: kept so an audit can see what was set aside.
        ignored = [{"line_no": n, "ignore_id": i} for n, i in mapped.ignored]

    device = model["device"]
    os_family, os_version = device["os_family"]["value"], device["os_version"]["value"]
    fix_pack = snap.fixes.get(pack.id) if pack else None

    findings: list[dict[str, Any]] = []
    for framework in frameworks:
        rule_pack = snap.rules.get(framework)
        if rule_pack is None:
            warnings.append(f"no rule pack installed for framework {framework!r}")
            continue
        for rule in rule_pack.rules:
            applicable = applies(rule, os_family, os_version)
            if applicable is False:
                continue
            if applicable is None:
                verdict_name, missing, failing, err = NOT_DETERMINED, ["device.os_version"], [], None
                pairs: list[tuple[str, dict[str, Any] | None]] = [("device.os_version", device["os_version"])]
            else:
                v = evaluate(rule, model)
                verdict_name, missing, failing, err = v.verdict, v.missing_fields, v.failing_items, v.error
                pairs = evidence_for(v, model)
            remediation = None
            if verdict_name == FAIL and fix_pack and rule.raw.get("fix") in fix_pack.fixes:
                remediation = render(fix_pack.fixes[rule.raw["fix"]], failing, os_version)
            findings.append({
                "rule_id": rule.id,
                "title": rule.raw["title"],
                "control": rule.raw.get("control"),
                "framework": framework,
                "severity": rule.raw["severity"],
                "verdict": verdict_name,
                "rule_pack_version": rule.pack_tag,
                "evidence": _evidence_lines(pairs, lines),
                "missing_fields": missing,
                "remediation": remediation,
                "fix_pack_version": fix_pack.tag if remediation and fix_pack else None,
                "error": err,
            })

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["verdict"] != FAIL, f["rule_id"]))
    verdicts = {
        "pass": sum(f["verdict"] == PASS for f in findings),
        "fail": sum(f["verdict"] == FAIL for f in findings),
        "not_determined": sum(f["verdict"] == NOT_DETERMINED for f in findings),
    }
    return {
        "device_id": device_id,
        "filename": filename,
        "status": "done",
        "error": None,
        "vendor_pack": pack.tag if pack else None,
        "detection_ambiguous": detection.ambiguous,
        "identity": {k: device[k]["value"] for k in IDENTITY},
        "verdicts": verdicts,
        "coverage": coverage(model, catalogue),
        "findings": findings,
        "sha256": sha,
        "canonical": model,
        "unmatched": unmatched,
        "ignored": ignored,
        "warnings": warnings,
    }
