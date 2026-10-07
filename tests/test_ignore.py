"""Ignore entries: "not a security setting" (packs/CLAUDE.md, Ignore entries).

The invariant under test: an ignore takes a line out of the question queue and changes nothing else.
It never writes a field, so it can never turn a NOT_DETERMINED into a PASS.
"""

from __future__ import annotations

import shutil
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
from src.learning.author import AuthorError, author_ignore
from src.learning.cluster import Cluster, build_clusters
from src.mapping.canonical import Catalogue
from src.mapping.engine import map_device, match_line
from src.mapping.pack import Ignore, build_ignore, load_vendor_pack, merge_learned
from src.packs import PackError
from src.readers import READERS
from src.registry import Snapshot, check_fixtures, load_snapshot
from tests.conftest import CONFIGS, PACKS, ROOT

SPEC = yaml.safe_load((ROOT / "docs" / "openapi.yaml").read_text(encoding="utf-8"))
IOS_FILES = sorted(CONFIGS.glob("*.cfg"))
IOS = PACKS / "vendors" / "cisco_ios.yaml"


def _valid(body: Any, schema: str) -> None:
    jsonschema.Draft202012Validator({"$ref": f"#/components/schemas/{schema}",
                                     "components": SPEC["components"]}).validate(body)


def _audit_all(snapshot: Snapshot, catalogue: Catalogue) -> dict[str, dict[str, Any]]:
    return {p.stem: audit_device(p.read_text(encoding="utf-8"), p.name, p.stem, snapshot, catalogue, ["cis"])
            for p in IOS_FILES}


def _verdicts(result: dict[str, Any]) -> list[tuple[str, str]]:
    return sorted((f["rule_id"], f["verdict"]) for f in result["findings"])


@pytest.fixture()
def packs(tmp_path: Path) -> Path:
    dest = tmp_path / "packs"
    shutil.copytree(PACKS, dest)
    return dest


def _learned(packs: Path, entries: list[dict[str, Any]]) -> Path:
    path = packs / "learned" / "cisco_ios.yaml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(yaml.safe_dump({"vendor_pack": "cisco_ios", "version": "0.1.0", "mappings": entries},
                                   sort_keys=False), encoding="utf-8")
    return path


def _entry(**over: Any) -> dict[str, Any]:
    base = {"id": "cisco_ios.ignore.test", "canonical": None, "ignore": True, "match": "^boot-start-marker$",
            "reason": "structural marker, carries no security setting", "fixture": "boot-start-marker",
            "source": "learned", "author": "test", "created": "2026-10-07T00:00:00Z",
            "cluster_signature": "boot-start-marker"}
    return {k: v for k, v in {**base, **over}.items() if v is not ...}


def _ignore(raw: dict[str, Any]) -> Ignore:
    return build_ignore(raw, "test", "test")


# ── the invariant ────────────────────────────────────────────────────────


def test_ignoring_every_question_changes_zero_verdicts(packs: Path, snapshot: Snapshot,
                                                       catalogue: Catalogue) -> None:
    """Answer every cluster from the 13 real IOS configs with "not a security setting". The questions
    go; every verdict and every canonical field stays exactly as it was."""
    before = _audit_all(snapshot, catalogue)
    pack = snapshot.vendors["cisco_ios"]
    entries, kept = [], []
    for cluster in build_clusters(before.values(), catalogue):
        if any(match_line(pack, m.text, m.parent_text, 0, []) for m in cluster.members):
            kept.append(cluster.cluster_id)  # a mapping reads part of it: the API refuses these
            continue
        try:
            entries.append(author_ignore(cluster, {"reason": "test: ignore everything"}, "t"))
        except AuthorError:
            kept.append(cluster.cluster_id)
    assert len(entries) > 100
    _learned(packs, entries)

    snap = load_snapshot(packs, catalogue)
    assert snap.errors == []
    after = _audit_all(snap, catalogue)
    for device_id, result in after.items():
        assert _verdicts(result) == _verdicts(before[device_id]), device_id
        assert result["coverage"] == before[device_id]["coverage"], device_id
        assert result["canonical"] == before[device_id]["canonical"], device_id
        assert result["ignored"], device_id
    remaining = {c.cluster_id for c in build_clusters(after.values(), catalogue)}
    assert remaining <= set(kept)


def test_an_ignore_never_hides_a_line_a_mapping_reads(catalogue: Catalogue) -> None:
    """`logging trap bogus` matches ios.logging.trap but is not in its map: the line stays a question."""
    pack = load_vendor_pack(IOS, catalogue)
    pack.ignores.append(_ignore(_entry(id="cisco_ios.ignore.trap", match=r"^logging trap \S+$",
                                                    fixture="logging trap bogus")))
    lines = redact("logging trap bogus\ninterface GigabitEthernet0/1\n ip proxy-arp")
    result = map_device(pack, READERS[pack.reader](lines), lines, catalogue, None)
    assert [u.text for u in result.unmatched if u.leaf] == ["logging trap bogus"]
    assert result.ignored == []


def test_a_block_header_is_never_ignored(catalogue: Catalogue) -> None:
    pack = load_vendor_pack(IOS, catalogue)
    pack.ignores.append(_ignore(_entry(match=r"^router bgp \d+$", fixture="router bgp 65000")))
    lines = redact("router bgp 65000\n neighbor 192.0.2.1 remote-as 65001")
    result = map_device(pack, READERS[pack.reader](lines), lines, catalogue, None)
    assert "router bgp 65000" in [u.text for u in result.unmatched if not u.leaf]
    assert result.ignored == []


# ── the loader ───────────────────────────────────────────────────────────


def test_a_learned_ignore_loads_and_answers_its_line(packs: Path, catalogue: Catalogue) -> None:
    merged = merge_learned(load_vendor_pack(IOS, catalogue), _learned(packs, [_entry()]), catalogue)
    check_fixtures(merged, catalogue)
    lines = redact("boot-start-marker\nhostname r1")
    result = map_device(merged, READERS[merged.reader](lines), lines, catalogue, None)
    assert result.ignored == [(1, "cisco_ios.ignore.test")]


def test_an_ignore_whose_fixture_a_mapping_reads_is_rejected(packs: Path, catalogue: Catalogue) -> None:
    learned = _learned(packs, [_entry(match=r"^ip ssh version \d+$", fixture="ip ssh version 2")])
    merged = merge_learned(load_vendor_pack(IOS, catalogue), learned, catalogue)
    with pytest.raises(PackError, match="a mapping reads that line"):
        check_fixtures(merged, catalogue)


@pytest.mark.parametrize("over, field", [
    ({"reason": ...}, "reason"),
    ({"reason": "  "}, "reason"),
    ({"absent": "unknown"}, "absent"),
    ({"expect": True}, "expect"),
    ({"canonical": "services.ssh.version"}, "canonical"),
])
def test_a_malformed_ignore_is_rejected_naming_the_field(packs: Path, catalogue: Catalogue,
                                                         over: dict[str, Any], field: str) -> None:
    learned = _learned(packs, [_entry(**over)])
    with pytest.raises(PackError, match=field):
        merge_learned(load_vendor_pack(IOS, catalogue), learned, catalogue)


def test_an_ignore_needs_a_reason(catalogue: Catalogue, snapshot: Snapshot) -> None:
    results = _audit_all(snapshot, catalogue).values()
    cluster: Cluster = next(c for c in build_clusters(results, catalogue) if c.signature == "boot-start-marker")
    for request in ({}, {"reason": ""}, {"reason": " x "}, {"reason": None}):
        with pytest.raises(AuthorError) as exc:
            author_ignore(cluster, request, "t")
        assert exc.value.field == "reason"


# ── through the API ──────────────────────────────────────────────────────


def _wait(client: TestClient, scan_id: str) -> None:
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if client.get(f"/api/scans/{scan_id}").json()["status"] in ("completed", "failed"):
            return
        time.sleep(0.2)
    raise AssertionError("scan did not finish")


def _scan(client: TestClient, extra: tuple[str, bytes] | None = None) -> str:
    files = [("files", (p.name, p.read_bytes())) for p in IOS_FILES] + ([("files", extra)] if extra else [])
    scan_id: str = client.post("/api/scans", files=files, data={"frameworks": ["cis"]}).json()["scan_id"]
    _wait(client, scan_id)
    return scan_id


def _findings(client: TestClient, scan_id: str) -> dict[str, list[tuple[str, str]]]:
    return {p.stem: _verdicts(client.get(f"/api/scans/{scan_id}/devices/{p.stem}").json()) for p in IOS_FILES}


def test_not_a_security_setting_through_the_api(packs: Path) -> None:
    client = TestClient(create_app(packs=packs, workers=2, timeout=60))
    scan_id = _scan(client)
    before = _findings(client, scan_id)
    cluster = next(c for c in client.get(f"/api/scans/{scan_id}/clusters").json()["clusters"]
                   if c["signature"] == "boot-start-marker" and c["scope"] is None)
    url = f"/api/clusters/{cluster['cluster_id']}/ignore"
    learned = packs / "learned" / "cisco_ios.yaml"

    for body, field in [({}, None), ({"reason": "  "}, "reason"), ({"reason": "x", "extra": 1}, "extra"),
                        ({"reason": 5}, "reason")]:
        r = client.post(url, json=body)
        assert r.status_code == 422, (body, r.text)
        _valid(r.json(), "Error")
        if field:
            assert r.json()["field"] == field
    assert not learned.exists()

    answer = {"reason": "structural marker, carries no security setting", "author": "test"}
    preview = client.post(f"{url}?dry_run=true", json=answer)
    assert preview.status_code == 200, preview.text
    _valid(preview.json(), "ConfirmResult")
    assert not learned.exists()

    done = client.post(url, json=answer)
    assert done.status_code == 200, done.text
    entry = yaml.safe_load(done.json()["fragment_yaml"])[0]
    assert entry["canonical"] is None and entry["ignore"] is True and entry["reason"] == answer["reason"]
    assert entry["author"] == "test" and entry["match"] == "^boot\\-start\\-marker$"
    assert client.post(url, json=answer).status_code == 409  # answered twice is refused

    assert client.post(f"/api/scans/{scan_id}/reevaluate").status_code == 202
    _wait(client, scan_id)
    remaining = {c["cluster_id"] for c in client.get(f"/api/scans/{scan_id}/clusters").json()["clusters"]}
    assert cluster["cluster_id"] not in remaining
    assert _findings(client, scan_id) == before


def test_a_line_a_mapping_cannot_read_is_not_ignorable(packs: Path) -> None:
    """The mapping needs extending; calling the line "not a setting" would drop a logging level."""
    client = TestClient(create_app(packs=packs, workers=2, timeout=60))
    text = (CONFIGS / "as2dept1.cfg").read_bytes() + b"\nlogging trap bogus\n"
    scan_id = _scan(client, ("extra.cfg", text))
    cluster = next(c for c in client.get(f"/api/scans/{scan_id}/clusters").json()["clusters"]
                   if c["signature"] == "logging trap bogus")
    r = client.post(f"/api/clusters/{cluster['cluster_id']}/ignore", json={"reason": "noise"})
    assert r.status_code == 409 and "ios.logging.trap" in r.json()["message"]
    assert not (packs / "learned" / "cisco_ios.yaml").exists()
