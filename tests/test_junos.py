"""Junos pack (PLAN 2.2): the same 15 CIS rules, unchanged, on a second vendor."""

from typing import Any

import pytest

from src.audit import audit_device
from src.ingest.redact import redact
from src.mapping.canonical import Catalogue
from src.mapping.engine import detect, map_device
from src.readers import READERS
from src.registry import Snapshot
from tests.conftest import CONFIGS, ROOT

JUNOS = ROOT / "fixtures" / "configs" / "batfish_example_juniper"
SRX = ROOT / "fixtures" / "configs" / "batfish_srx_testbed"


def _model(snapshot: Snapshot, catalogue: Catalogue, text: str) -> tuple[dict[str, Any], list[str]]:
    pack = snapshot.vendors["junos"]
    lines = redact(text)
    result = map_device(pack, READERS[pack.reader](lines), lines, catalogue, None)
    return result.model, result.warnings


def _verdicts(snapshot: Snapshot, catalogue: Catalogue, text: str) -> dict[str, str]:
    out = audit_device(text, "x.cfg", "x", snapshot, catalogue, ["cis"])
    return {f["rule_id"]: f["verdict"] for f in out["findings"]}


def _pack_defaults(node: Any) -> list[str]:
    """Mapping ids of values defaulted for an absent line (not platform constants or operator input)."""
    if isinstance(node, dict):
        ev = node.get("evidence")
        own = [ev["mapping_id"]] if node.get("state") == "defaulted" and ev and "source" not in ev else []
        return own + [m for k, v in node.items() if k != "evidence" for m in _pack_defaults(v)]
    if isinstance(node, list):
        return [m for v in node for m in _pack_defaults(v)]
    return []


def _states(node: Any) -> list[str]:
    if isinstance(node, dict):
        own = [node["state"]] if "state" in node else []
        return own + [s for k, v in node.items() if k != "evidence" for s in _states(v)]
    if isinstance(node, list):
        return [s for v in node for s in _states(v)]
    return []


@pytest.mark.parametrize("path", sorted(JUNOS.glob("*.cfg")) + sorted(SRX.glob("*.cfg")), ids=lambda p: p.name)
def test_junos_fixtures_detect_as_junos(snapshot: Snapshot, path: Any) -> None:
    d = detect(redact(path.read_text()), list(snapshot.vendors.values()))
    assert d.pack is not None and d.pack.id == "junos"


def test_ios_fixtures_still_detect_as_ios(snapshot: Snapshot) -> None:
    for cfg in CONFIGS.glob("*.cfg"):
        d = detect(redact(cfg.read_text()), list(snapshot.vendors.values()))
        assert d.pack is not None and d.pack.id == "cisco_ios", cfg.name


def test_same_rules_run_unchanged_on_junos(snapshot: Snapshot, catalogue: Catalogue) -> None:
    verdicts = _verdicts(snapshot, catalogue, (SRX / "junos-srx-1.cfg").read_text())
    assert sorted(verdicts) == sorted(r.id for r in snapshot.rules["cis"].rules)


def test_real_srx_verdicts(snapshot: Snapshot, catalogue: Catalogue) -> None:
    verdicts = _verdicts(snapshot, catalogue, (SRX / "junos-srx-1.cfg").read_text())
    assert verdicts == {
        "cis.http.disabled": "FAIL",                # web-management http on fxp0.0, line 17
        "cis.local_users.strong_hash": "FAIL",      # root and all three users are $1$ (md5-crypt)
        "cis.logging.remote_host": "FAIL",          # syslog writes local files only
        "cis.aaa.enabled": "FAIL",                  # no authentication-order: local passwords only
        "cis.ntp.authenticate": "FAIL",             # no NTP trusted key
        "cis.login_banner": "FAIL",                 # no system login message
        "cis.ssh.version_2": "PASS",                # ssh on, no protocol-version line: v2 only on 15.1
        "cis.interfaces.no_proxy_arp": "PASS",      # no unit enables proxy-arp
        "cis.cdp.disabled": "PASS",                 # platform constant: Junos has no CDP
        # Not expressible from this config, or not a Junos concept: never guessed.
        "cis.ssh.timeout": "NOT_DETERMINED",
        "cis.ssh.auth_retries": "NOT_DETERMINED",
        "cis.logging.trap_level": "NOT_DETERMINED",
        "cis.vty.ssh_only": "NOT_DETERMINED",
        "cis.vty.access_class": "NOT_DETERMINED",
        "cis.enable_secret.strong_hash": "NOT_DETERMINED",  # Junos has no enable mode
    }


def test_root_is_a_local_user_not_an_enable_secret(snapshot: Snapshot, catalogue: Catalogue) -> None:
    model, _ = _model(snapshot, catalogue, (SRX / "junos-srx-1.cfg").read_text())
    users = {u["name"]["value"]: u for u in model["auth"]["local_users"]["items"]}
    assert sorted(users) == ["admin", "padhye", "ratul", "root"]
    assert users["root"]["name"]["evidence"]["line"] == 3
    assert users["root"]["password_algorithm"]["value"] == "md5"
    assert model["auth"]["enable_secret"]["algorithm"]["state"] == "unknown"


def test_finding_cites_the_junos_line(snapshot: Snapshot, catalogue: Catalogue) -> None:
    out = audit_device((SRX / "junos-srx-1.cfg").read_text(), "srx", "srx", snapshot, catalogue, ["cis"])
    http = next(f for f in out["findings"] if f["rule_id"] == "cis.http.disabled")
    assert [(e["line_no"], e["text"]) for e in http["evidence"]] == [
        (17, "set system services web-management http interface fxp0.0")]


def test_no_os_version_means_no_defaults(snapshot: Snapshot, catalogue: Catalogue) -> None:
    # as1border1 carries no `set version` line, so no version-scoped default may be claimed.
    model, _ = _model(snapshot, catalogue, (JUNOS / "as1border1.cfg").read_text())
    assert _pack_defaults(model) == []
    assert model["device"]["hostname"]["value"] == "as1border1"


@pytest.mark.parametrize("order", [("v1", "v2"), ("v2", "v1")])
def test_ssh_version_is_the_weakest_accepted_whatever_the_line_order(
        snapshot: Snapshot, catalogue: Catalogue, order: tuple[str, str]) -> None:
    text = "".join(f"set system services ssh protocol-version {v}\n" for v in order)
    model, _ = _model(snapshot, catalogue, text)
    assert model["services"]["ssh"]["version"]["value"] == 1


@pytest.mark.parametrize("order", [("password", "radius"), ("radius", "password")])
def test_any_remote_authentication_method_means_aaa(
        snapshot: Snapshot, catalogue: Catalogue, order: tuple[str, str]) -> None:
    text = "".join(f"set system authentication-order {m}\n" for m in order)
    model, _ = _model(snapshot, catalogue, text)
    assert model["auth"]["aaa"]["enabled"]["value"] is True


def test_one_syslog_host_on_several_lines_is_one_server(snapshot: Snapshot, catalogue: Catalogue) -> None:
    model, _ = _model(snapshot, catalogue, "set system syslog host 10.0.0.5 any notice\n"
                                           "set system syslog host 10.0.0.5 authorization info\n")
    assert [s["value"] for s in model["logging"]["servers"]["items"]] == ["10.0.0.5"]


def test_applied_group_makes_unstated_settings_not_determined(snapshot: Snapshot, catalogue: Catalogue) -> None:
    text = (SRX / "junos-srx-1.cfg").read_text() + "set system apply-groups site-defaults\n"
    model, warnings = _model(snapshot, catalogue, text)
    assert _pack_defaults(model) == []
    assert model["services"]["http"]["enabled"]["state"] == "mapped"  # stated directly, so still known
    assert any("not resolved" in w for w in warnings)
    # Visible users are real; a group could add more, so the list is read but incomplete.
    users = model["auth"]["local_users"]
    assert (users["state"], users["complete"], len(users["items"])) == ("mapped", False, 4)
    assert model["logging"]["servers"]["state"] == "unknown"  # nothing visible: unread, not "read and empty"

    verdicts = _verdicts(snapshot, catalogue, text)
    assert verdicts["cis.local_users.strong_hash"] == "FAIL"  # a visible $1$ user is a sound counterexample
    assert verdicts["cis.interfaces.no_proxy_arp"] == "NOT_DETERMINED"  # nothing visible fails; unseen could
    assert verdicts["cis.logging.remote_host"] == "NOT_DETERMINED"
    assert verdicts["cis.login_banner"] == "NOT_DETERMINED"
    assert verdicts["cis.http.disabled"] == "FAIL"


@pytest.mark.parametrize("extra", ["set system apply-groups-except site-defaults\n",
                                   "set system apply-groups site-defaults\ndeactivate system apply-groups\n"])
def test_excluded_or_inactive_group_does_not_block_defaults(
        snapshot: Snapshot, catalogue: Catalogue, extra: str) -> None:
    model, _ = _model(snapshot, catalogue, (SRX / "junos-srx-1.cfg").read_text() + extra)
    assert model["auth"]["login_banner"]["present"]["state"] == "defaulted"


def test_cdp_is_a_platform_constant_with_its_source(snapshot: Snapshot, catalogue: Catalogue) -> None:
    out = audit_device((JUNOS / "as1border1.cfg").read_text(), "r", "r", snapshot, catalogue, ["cis"])
    cdp = next(f for f in out["findings"] if f["rule_id"] == "cis.cdp.disabled")
    assert cdp["verdict"] == "PASS"  # holds even with no OS version: it is not a version-scoped default
    assert [(e["state"], e["line_no"], e["source"]) for e in cdp["evidence"]] == [
        ("defaulted", None, "platform_constant")]


def _pack_with(tmp: Any, extra: str) -> Any:
    body = (ROOT / "packs" / "vendors" / "junos.yaml").read_text(encoding="utf-8")
    path = tmp / "junos.yaml"
    path.write_text(body + extra, encoding="utf-8")
    return path


_CDP_MAPPING = """  - id: junos.cdp
    canonical: discovery.cdp_enabled
    match: '^protocols cdp$'
    value: true
    absent: unknown
    fixture: set protocols cdp
"""


def test_constant_cannot_also_be_mapped(tmp_path: Any, catalogue: Catalogue) -> None:
    from src.mapping.pack import load_vendor_pack
    from src.packs import PackError
    with pytest.raises(PackError, match="platform constant"):
        load_vendor_pack(_pack_with(tmp_path, _CDP_MAPPING), catalogue)


@pytest.mark.parametrize("constants, message", [
    ("  interfaces.proxy_arp: false\n", "not a canonical scalar field"),
    ("  discovery.cdp_enabled: nope\n", "constants/discovery.cdp_enabled"),
])
def test_bad_constant_is_rejected(tmp_path: Any, catalogue: Catalogue, constants: str, message: str) -> None:
    from src.mapping.pack import load_vendor_pack
    from src.packs import PackError
    body = (ROOT / "packs" / "vendors" / "junos.yaml").read_text(encoding="utf-8")
    body = body.replace("constants:\n  discovery.cdp_enabled: false\n", "constants:\n" + constants)
    (tmp_path / "junos.yaml").write_text(body, encoding="utf-8")
    with pytest.raises(PackError, match=message):
        load_vendor_pack(tmp_path / "junos.yaml", catalogue)


def test_operator_version_unlocks_defaults_and_is_labelled(snapshot: Snapshot, catalogue: Catalogue) -> None:
    text = (JUNOS / "as1border1.cfg").read_text()
    without = _verdicts(snapshot, catalogue, text)
    out = audit_device(text, "r", "r", snapshot, catalogue, ["cis"], os_version="15.1R7")
    with_version = {f["rule_id"]: f["verdict"] for f in out["findings"]}
    assert out["canonical"]["device"]["os_version"] == {"value": "15.1R7", "state": "defaulted", "evidence": {
        "line": None, "mapping_id": "operator.os_version", "pack_version": "junos@1.3.0", "source": "operator"}}
    assert without["cis.login_banner"] == "NOT_DETERMINED"
    assert with_version["cis.login_banner"] == "FAIL"  # no `system login message`; default now applies


def test_config_stated_version_beats_operator_version(snapshot: Snapshot, catalogue: Catalogue) -> None:
    out = audit_device((SRX / "junos-srx-1.cfg").read_text(), "s", "s", snapshot, catalogue, ["cis"],
                       os_version="12.1")
    assert out["canonical"]["device"]["os_version"]["value"] == "15.1X49-D15.4"
    assert any("operator-supplied 12.1 was not used" in w for w in out["warnings"])


def test_cli_rejects_an_unparseable_operator_version(tmp_path: Any) -> None:
    from src.cli.main import main
    assert main([str(JUNOS / "as1border1.cfg"), "--out", str(tmp_path), "--os-version", "latest"]) == 2
