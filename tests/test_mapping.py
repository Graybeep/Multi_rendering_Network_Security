import json
import shutil
import time
from pathlib import Path

import pytest

from src.audit import audit_device
from src.ingest.redact import redact
from src.mapping.canonical import Catalogue
from src.mapping.engine import detect, map_device
from src.mapping.pack import load_vendor_pack
from src.packs import PackError
from src.readers import READERS
from src.registry import Registry, Snapshot
from tests.conftest import CONFIGS, GOLDEN, PACKS


def _map(snapshot: Snapshot, catalogue: Catalogue, text: str) -> dict:
    pack = snapshot.vendors["cisco_ios"]
    lines = redact(text)
    return map_device(pack, READERS[pack.reader](lines), lines, catalogue, None).model


def test_golden_fixture_round_trips(snapshot: Snapshot, catalogue: Catalogue) -> None:
    cfg = GOLDEN / "cisco_ios_as2dept1.cfg"
    expected = json.loads((GOLDEN / "cisco_ios_as2dept1.canonical.json").read_text(encoding="utf-8"))
    result = audit_device(cfg.read_text(), cfg.name, "g", snapshot, catalogue, ["cis"])
    assert result["canonical"] == expected


def test_every_fixture_config_is_detected_as_ios(snapshot: Snapshot) -> None:
    for cfg in CONFIGS.glob("*.cfg"):
        d = detect(redact(cfg.read_text()), list(snapshot.vendors.values()))
        assert d.pack is not None and d.pack.id == "cisco_ios", cfg.name


def test_scoped_mapping_lands_on_the_right_interface(snapshot: Snapshot, catalogue: Catalogue) -> None:
    model = _map(snapshot, catalogue, "version 15.2\ninterface Gi0/1\n no ip proxy-arp\ninterface Gi0/2\n shutdown\n")
    items = {i["name"]["value"]: i for i in model["interfaces"]["items"]}
    assert items["Gi0/1"]["proxy_arp"] == {"value": False, "state": "mapped", "evidence": {
        "line": 3, "mapping_id": "ios.intf.proxy_arp.off", "pack_version": "cisco_ios@1.1.0"}}
    assert items["Gi0/2"]["proxy_arp"]["state"] == "defaulted"
    assert items["Gi0/2"]["shutdown"]["value"] is True


def test_defaults_need_a_known_os_version(snapshot: Snapshot, catalogue: Catalogue) -> None:
    model = _map(snapshot, catalogue, "interface Gi0/1\n description x\n")
    assert model["interfaces"]["items"][0]["proxy_arp"]["state"] == "unknown"


def test_console_lines_are_not_vty_lines(snapshot: Snapshot, catalogue: Catalogue) -> None:
    model = _map(snapshot, catalogue, "line con 0\n exec-timeout 0 0\nline vty 0 4\n exec-timeout 5 30\n")
    vty = model["mgmt"]["vty_lines"]["items"]
    assert [(v["name"]["value"], v["exec_timeout"]["value"]) for v in vty] == [("vty 0 4", 330)]


def test_numbered_and_named_acls(snapshot: Snapshot, catalogue: Catalogue) -> None:
    model = _map(snapshot, catalogue, "access-list 10 permit 10.0.0.0\naccess-list 10 deny any\n"
                                      "ip access-list extended MGMT\n 20 permit ip any any\n")
    lists = {acl["name"]["value"]: [(e["seq"]["value"], e["action"]["value"]) for e in acl["entries"]["items"]]
             for acl in model["acl"]["lists"]["items"]}
    assert lists == {"10": [(10, "permit"), (20, "deny")], "MGMT": [(20, "permit")]}


def test_unrecognised_lines_are_recorded_for_learning(snapshot: Snapshot, catalogue: Catalogue) -> None:
    result = audit_device((CONFIGS / "as2dept1.cfg").read_text(), "x", "x", snapshot, catalogue, ["cis"])
    texts = {u["text"] for u in result["unmatched"]}
    assert "router bgp 65001" in texts
    assert "hostname as2dept1" not in texts and "version 15.2" not in texts  # facts are understood


def _write_pack(tmp: Path, body: str) -> Path:
    (tmp / "vendors").mkdir(parents=True, exist_ok=True)
    path = tmp / "vendors" / "toy.yaml"
    path.write_text(body, encoding="utf-8")
    return path


TOY_HEAD = "id: toy\nversion: 1.0.0\nvendor: toy\nos_family: toy\nreader: indent_blocks\ndetect: ['^toyos']\nmappings:\n"


def test_ambiguous_overlap_is_rejected(tmp_path: Path, catalogue: Catalogue) -> None:
    _write_pack(tmp_path, TOY_HEAD + """
  - {id: a, canonical: services.ssh.version, match: '^ssh v(\\d)$', absent: unknown, fixture: ssh v2}
  - {id: b, canonical: services.ssh.version, match: '^ssh v(\\d+)$', absent: unknown, fixture: ssh v2}
""")
    snap = Registry(tmp_path, catalogue).snapshot()
    assert "toy" not in snap.vendors
    assert any("equal priority" in e for e in snap.errors)


def test_invalid_pack_names_the_field(tmp_path: Path, catalogue: Catalogue) -> None:
    path = _write_pack(tmp_path, TOY_HEAD + """
  - {id: a, canonical: services.ssh.versoin, match: '^ssh v(\\d)$', absent: unknown, fixture: ssh v2}
""")
    with pytest.raises(PackError, match=r"field canonical: 'services.ssh.versoin' is not a canonical field"):
        load_vendor_pack(path, catalogue)


def test_default_without_version_range_is_rejected(tmp_path: Path, catalogue: Catalogue) -> None:
    path = _write_pack(tmp_path, TOY_HEAD + """
  - {id: a, canonical: ntp.authenticate, match: '^ntp auth$', value: true, absent: default, default: false, fixture: ntp auth}
""")
    with pytest.raises(PackError, match="default_os_version"):
        load_vendor_pack(path, catalogue)


def test_pathological_regex_times_out_instead_of_hanging(tmp_path: Path, catalogue: Catalogue) -> None:
    _write_pack(tmp_path, TOY_HEAD + """
  - {id: evil, canonical: device.model, match: '^(a+)+$', absent: unknown, fixture: aaa}
""")
    pack = Registry(tmp_path, catalogue).snapshot().vendors["toy"]
    lines = ["toyos", "a" * 5000 + "!"]
    start = time.monotonic()
    result = map_device(pack, READERS["indent_blocks"](lines), lines, catalogue, 1)
    assert time.monotonic() - start < 5
    assert any("timed out" in w for w in result.warnings)
    assert result.model["device"]["model"]["state"] == "unknown"


def test_hot_reload_picks_up_a_learned_mapping(tmp_path: Path, catalogue: Catalogue) -> None:
    shutil.copytree(PACKS, tmp_path / "packs")
    registry = Registry(tmp_path / "packs", catalogue)
    cfg = "version 15.2\nip ssh version 2\nip domain lookup source-interface Lo0\n"
    first = audit_device(cfg, "x", "x", registry.snapshot(), catalogue, ["cis"])
    assert any(u["text"].startswith("ip domain lookup") for u in first["unmatched"])

    (tmp_path / "packs" / "learned").mkdir(exist_ok=True)
    (tmp_path / "packs" / "learned" / "cisco_ios.yaml").write_text("""
vendor_pack: cisco_ios
version: 0.1.0
mappings:
  - id: learned.ssh.enabled_hint
    canonical: services.ssh.enabled
    match: '^ip ssh version \\d$'
    value: true
    absent: unknown
    fixture: ip ssh version 2
    source: learned
    author: test
    created: '2026-10-05'
    cluster_signature: ip ssh version <INT>
""", encoding="utf-8")
    snap = registry.snapshot()
    assert snap.errors == []
    second = audit_device(cfg, "x", "x", snap, catalogue, ["cis"])
    assert second["canonical"]["services"]["ssh"]["enabled"]["evidence"]["pack_version"] == "cisco_ios_learned@0.1.0"
