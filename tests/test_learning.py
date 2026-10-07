"""Learning loop (PLAN 2.3-2.6): normalise, cluster, rank, confirm, re-run.

The end-to-end tests take a shipped mapping out of a copy of the packs, answer the resulting question
through the API as an administrator would, and require the re-run to reproduce exactly what the
shipped mapping produced. The shipped pack is the ground truth; nothing is compared with a made-up value.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.audit import audit_device
from src.ingest.redact import redact
from src.learning.author import AuthorError, author_mapping, learnable
from src.learning.cluster import Cluster, Member, build_clusters
from src.learning.normalise import identifiers, normalise
from src.learning.rank import rank
from src.mapping.canonical import Catalogue
from src.readers import READERS
from src.registry import Snapshot, _find_mapped
from tests.conftest import CONFIGS, PACKS, ROOT

SPEC = yaml.safe_load((ROOT / "docs" / "openapi.yaml").read_text(encoding="utf-8"))
IOS_FILES = sorted(CONFIGS.glob("*.cfg"))


def _valid(body: Any, schema: str) -> None:
    jsonschema.Draft202012Validator({"$ref": f"#/components/schemas/{schema}",
                                     "components": SPEC["components"]}).validate(body)


def _audit_all(snapshot: Snapshot, catalogue: Catalogue) -> list[dict[str, Any]]:
    return [audit_device(p.read_text(encoding="utf-8"), p.name, p.stem, snapshot, catalogue, ["cis"])
            for p in IOS_FILES]


# ── 2.3 normaliser ───────────────────────────────────────────────────────


def test_values_that_vary_between_devices_collapse_to_one_signature() -> None:
    assert normalise("idle-timeout 600").signature == normalise("idle-timeout 900").signature \
        == "idle-timeout <INT>"
    assert normalise("ip address 10.1.1.1 255.255.255.0").signature == "ip address <IPV4> <IPV4>"
    assert normalise("set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24").signature \
        == "set interfaces <IFACE> unit <INT> family inet address <PREFIX>"
    assert normalise('description "to core"').signature == "description <STR>"
    assert normalise("ip domain name lab.local").signature == "ip domain name <DOMAIN>"


def test_words_that_carry_meaning_are_kept() -> None:
    """A guess that turned `sha256` or `v2` into a placeholder would merge settings that differ."""
    assert normalise("authentication-algorithm hmac-sha-256-128 v2 md5").signature \
        == "authentication-algorithm hmac-sha-256-128 v2 md5"


def test_names_come_from_the_device_own_model(snapshot: Snapshot, catalogue: Catalogue) -> None:
    result = audit_device((CONFIGS / "as2dept1.cfg").read_text(encoding="utf-8"), "as2dept1.cfg", "as2dept1",
                          snapshot, catalogue, ["cis"])
    known = identifiers(result["canonical"], catalogue)
    template = normalise("snmp-server contact as2dept1 Loopback0", known)
    assert template.signature == "snmp-server contact <NAME> <IFACE>"
    assert [s.origin for s in template.slots] == ["device.hostname", "interfaces[]"]


# ── 2.4 clustering ───────────────────────────────────────────────────────


def test_a_batch_becomes_a_short_question_list(snapshot: Snapshot, catalogue: Catalogue) -> None:
    results = _audit_all(snapshot, catalogue)
    lines = sum(1 for r in results for u in r["unmatched"] if u["leaf"])
    clusters = build_clusters(results, catalogue)
    assert len(clusters) * 5 < lines
    counts = [len(c.devices) for c in clusters]
    assert counts == sorted(counts, reverse=True)
    top = {(c.scope, c.signature): len(c.devices) for c in clusters}
    assert top[("line con <INT>", "exec-timeout <INT> <INT>")] == len(IOS_FILES)
    for c in clusters:
        _valid(c.view(), "Cluster")


def test_block_headers_are_not_questions(snapshot: Snapshot, catalogue: Catalogue) -> None:
    clusters = build_clusters(_audit_all(snapshot, catalogue), catalogue)
    assert not any(c.signature.startswith("router bgp") for c in clusters)
    assert any(c.scope == "router bgp <INT>" for c in clusters)


def test_devices_without_a_vendor_pack_raise_no_questions(catalogue: Catalogue) -> None:
    result = {"status": "done", "vendor_pack": None, "device_id": "x", "canonical": None,
              "unmatched": [{"text": "foo 1", "scope": [], "leaf": True, "raw": "foo 1"}]}
    assert build_clusters([result], catalogue) == []


# ── 2.5 ranking ──────────────────────────────────────────────────────────


def _shipped_cases(snapshot: Snapshot, catalogue: Catalogue) -> list[tuple[str, Cluster, str]]:
    """Every shipped mapping's own fixture line, posed as if no pack understood it."""
    cases = []
    for pack in snapshot.vendors.values():
        for m in pack.mappings:
            if learnable(m.target, catalogue) is not None:
                continue
            lines = redact(m.fixture.rstrip("\n"))
            leaf = list(READERS[pack.reader](lines)[-1].walk())[-1]
            parent = leaf.path[-1] if leaf.path else None
            member = Member("d", leaf.text, leaf.text, parent, parent, normalise(leaf.text),
                            normalise(parent) if parent else None, {})
            cases.append((m.id, Cluster("c0", pack.id, member.line.signature, None, [member]), m.target))
    return cases


def test_the_right_field_is_in_the_top_three(snapshot: Snapshot, catalogue: Catalogue) -> None:
    """Measured, not tuned: 54 of 57 shipped mappings. The misses are recorded so a regression shows."""
    cases = _shipped_cases(snapshot, catalogue)
    misses = sorted(mid for mid, cluster, target in cases
                    if target not in [c["canonical_field"] for c in rank(cluster, catalogue, 3)])
    assert misses == ["ios.logging.trap", "ios.ssh.auth_retries", "junos.ssh.version"]
    assert len(cases) == 57


def test_suggestions_match_the_contract_and_only_offer_learnable_fields(snapshot: Snapshot,
                                                                         catalogue: Catalogue) -> None:
    for _, cluster, _ in _shipped_cases(snapshot, catalogue):
        candidates = rank(cluster, catalogue)
        _valid({"cluster_id": "c0", "candidates": candidates}, "Suggestions")
        assert all(learnable(c["canonical_field"], catalogue) is None for c in candidates)


def test_learning_has_no_import_path_to_the_rules() -> None:
    code = ("import sys, src.learning.normalise, src.learning.cluster, src.learning.rank, src.learning.author;"
            "print(sorted(m for m in sys.modules if m.startswith('src.rules')))")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


# ── 2.6 authoring ────────────────────────────────────────────────────────


def _cluster_for(snapshot: Snapshot, catalogue: Catalogue, scope: str | None, signature: str) -> Cluster:
    clusters = build_clusters(_audit_all(snapshot, catalogue), catalogue)
    return next(c for c in clusters if c.scope == scope and c.signature == signature)


def test_a_line_with_two_numbers_is_refused_rather_than_guessed(snapshot: Snapshot, catalogue: Catalogue) -> None:
    """`exec-timeout 5 30` is minutes and seconds: reading either number alone would be wrong."""
    cluster = _cluster_for(snapshot, catalogue, "line con <INT>", "exec-timeout <INT> <INT>")
    with pytest.raises(AuthorError, match="several values"):
        author_mapping(cluster, {"canonical_field": "session.idle_timeout", "absent": "unknown"}, catalogue, "t")


def test_a_boolean_needs_a_stated_value(snapshot: Snapshot, catalogue: Catalogue) -> None:
    cluster = _cluster_for(snapshot, catalogue, None, "no ip domain lookup")
    with pytest.raises(AuthorError, match="state the value"):
        author_mapping(cluster, {"canonical_field": "services.http.enabled", "absent": "unknown"}, catalogue, "t")


@pytest.mark.parametrize("field", ["interfaces[]", "interfaces[].name", "acl.lists[].entries[].action", "nope"])
def test_fields_a_learned_line_cannot_fill_are_refused(catalogue: Catalogue, field: str) -> None:
    assert learnable(field, catalogue) is not None


# ── end to end through the API ───────────────────────────────────────────


@pytest.fixture()
def packs(tmp_path: Path) -> Path:
    import shutil
    dest = tmp_path / "packs"
    shutil.copytree(PACKS, dest)
    return dest


def _drop_mapping(packs: Path, vendor: str, mapping_id: str) -> None:
    path = packs / "vendors" / f"{vendor}.yaml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["mappings"] = [m for m in doc["mappings"] if m["id"] != mapping_id]
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _scan(client: TestClient) -> tuple[str, dict[str, Any]]:
    files = [("files", (p.name, p.read_bytes())) for p in IOS_FILES]
    scan_id = client.post("/api/scans", files=files, data={"frameworks": ["cis"]}).json()["scan_id"]
    return scan_id, _wait(client, scan_id)


def _wait(client: TestClient, scan_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        scan = client.get(f"/api/scans/{scan_id}").json()
        if scan["status"] in ("completed", "failed"):
            return scan
        time.sleep(0.2)
    raise AssertionError("scan did not finish")


def _devices(client: TestClient, scan_id: str) -> dict[str, dict[str, Any]]:
    return {p.stem: client.get(f"/api/scans/{scan_id}/devices/{p.stem}").json() for p in IOS_FILES}


def _values(model: dict[str, Any], path: str) -> Any:
    if path == "ntp.servers[]":
        return sorted(i["value"] for i in model["ntp"]["servers"]["items"])
    return sorted((i["name"]["value"], i["shutdown"]["value"], i["shutdown"]["state"])
                  for i in model["interfaces"]["items"])


@pytest.mark.parametrize("dropped, scope, signature, answer", [
    ("ios.ntp.server", None, "ntp server <IPV4>",
     {"canonical_field": "ntp.servers[]", "absent": "default"}),
    ("ios.intf.shutdown", "interface <IFACE>", "shutdown",
     {"canonical_field": "interfaces[].shutdown", "absent": "default", "value": True, "default": False,
      "default_os_version": ">=12.0"}),
])
def test_confirmed_answer_reproduces_the_shipped_mapping(packs: Path, snapshot: Snapshot, catalogue: Catalogue,
                                                         dropped: str, scope: str | None, signature: str,
                                                         answer: dict[str, Any]) -> None:
    """PLAN 2.6 and demo beat 4: question → confirm → re-run → resolved, with no restart."""
    _drop_mapping(packs, "cisco_ios", dropped)
    client = TestClient(create_app(packs=packs, workers=2, timeout=60))
    shipped = {r["device_id"]: r for r in _audit_all(snapshot, catalogue)}
    field = answer["canonical_field"]

    scan_id, _ = _scan(client)
    listing = client.get(f"/api/scans/{scan_id}/clusters").json()
    cluster = next(c for c in listing["clusters"] if c["scope"] == scope and c["signature"] == signature)
    holders = {d for d, r in shipped.items() if _find_mapped(r["canonical"], dropped)}
    assert cluster["device_count"] >= len(holders) > 0

    suggestions = client.get(f"/api/clusters/{cluster['cluster_id']}/suggestions").json()
    _valid(suggestions, "Suggestions")
    assert field in [c["canonical_field"] for c in suggestions["candidates"][:3]]

    learned = packs / "learned" / "cisco_ios.yaml"
    preview = client.post(f"/api/clusters/{cluster['cluster_id']}/confirm?dry_run=true", json=answer)
    assert preview.status_code == 200, preview.text
    _valid(preview.json(), "ConfirmResult")
    assert preview.json()["written"] is False and not learned.exists()

    done = client.post(f"/api/clusters/{cluster['cluster_id']}/confirm", json={**answer, "author": "test"})
    assert done.status_code == 200, done.text
    body = done.json()
    assert body["written"] is True and body["pack_version"] == "0.1.0"
    text = learned.read_text(encoding="utf-8")
    assert body["fragment_yaml"] in text
    assert "10." not in body["fragment_yaml"]  # the fixture carries documentation addresses, not this site's

    again = client.post(f"/api/clusters/{cluster['cluster_id']}/confirm", json=answer)
    assert again.status_code == 409  # the same question answered twice is refused, not appended twice

    assert client.post(f"/api/scans/{scan_id}/reevaluate").status_code == 202
    _wait(client, scan_id)
    after = _devices(client, scan_id)
    for device_id, result in after.items():
        assert _values(result["canonical"], field) == _values(shipped[device_id]["canonical"], field), device_id
        assert result["verdicts"] == shipped[device_id]["verdicts"], device_id
    remaining = client.get(f"/api/scans/{scan_id}/clusters").json()["clusters"]
    assert cluster["cluster_id"] not in {c["cluster_id"] for c in remaining}
    assert any(p["kind"] == "learned" for p in client.get("/api/packs").json()["packs"])


def test_a_bad_answer_names_the_field_and_writes_nothing(packs: Path) -> None:
    _drop_mapping(packs, "cisco_ios", "ios.ntp.server")
    client = TestClient(create_app(packs=packs, workers=2, timeout=60))
    scan_id, _ = _scan(client)
    cluster = next(c for c in client.get(f"/api/scans/{scan_id}/clusters").json()["clusters"]
                   if c["signature"] == "ntp server <IPV4>")
    url = f"/api/clusters/{cluster['cluster_id']}/confirm"
    for body, field in [({"canonical_field": "ntp.servers[]", "absent": "unknown", "extra": 1}, "extra"),
                        ({"canonical_field": "ntp.servers[]", "absent": "maybe"}, "absent"),
                        ({"canonical_field": "ntp.authenticate", "absent": "unknown"}, "value"),
                        ({"canonical_field": "logging.level", "absent": "default", "default": 6}, None)]:
        r = client.post(url, json=body)
        assert r.status_code == 422, (body, r.text)
        _valid(r.json(), "Error")
        if field:
            assert r.json()["field"] == field
    assert not (packs / "learned" / "cisco_ios.yaml").exists()
