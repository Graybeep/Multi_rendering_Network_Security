"""Junos fix templates: apply the rendered fix to the real SRX config and re-audit; the rule must PASS."""

import re
from typing import Any

import pytest

from src.audit import audit_device
from src.mapping.canonical import Catalogue, project
from src.registry import Snapshot
from tests.conftest import ROOT

SRX = (ROOT / "fixtures" / "configs" / "batfish_srx_testbed" / "junos-srx-1.cfg").read_text()
MODE_LINES = {"configure", "commit confirmed 5", "commit"}
# Test values for operator placeholders. They exist only to prove the fix round-trips through the mapper.
OPERATOR = {"<TACACS_SERVER>": "10.0.0.9", "<SHARED_SECRET>": "s3cr3t", "<NEW_PASSWORD_HASH>": "$6$salt$hash",
            "<BANNER_TEXT>": "Authorised access only", "<SYSLOG_SERVER>": "10.0.0.5", "<KEY_ID>": "1",
            "<NTP_KEY>": "k3y", "<UNIT>": "0"}

# rule → statement that makes the SRX fail it, when the SRX does not already
CASES = {
    "cis.http.disabled": "",
    "cis.local_users.strong_hash": "",
    "cis.logging.remote_host": "",
    "cis.aaa.enabled": "",
    "cis.ntp.authenticate": "",
    "cis.login_banner": "",
    "cis.ssh.version_2": "set system services ssh protocol-version v1\n",
    "cis.ssh.auth_retries": "set system login retry-options tries-before-disconnect 5\n",
    "cis.interfaces.no_proxy_arp": "set interfaces ge-0/0/0 unit 0 proxy-arp\n",
}


def _audit(snapshot: Snapshot, catalogue: Catalogue, text: str) -> dict[str, Any]:
    return audit_device(text, "srx", "srx", snapshot, catalogue, ["cis"])


def _finding(result: dict[str, Any], rule_id: str) -> dict[str, Any]:
    return next(f for f in result["findings"] if f["rule_id"] == rule_id)


def _as_config(commands: list[str]) -> str:
    lines = []
    for c in commands:
        if c in MODE_LINES:
            continue
        for placeholder, value in OPERATOR.items():
            c = c.replace(placeholder, value)
        lines.append(c)
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_fix_makes_the_rule_pass_and_is_safe_to_apply_twice(
        snapshot: Snapshot, catalogue: Catalogue, rule_id: str) -> None:
    failing = SRX + CASES[rule_id]
    before = _finding(_audit(snapshot, catalogue, failing), rule_id)
    assert before["verdict"] == "FAIL"
    remediation = before["remediation"]
    assert remediation is not None and remediation["fix_id"]
    assert not any(re.search(r"\{[a-z_]+\}", c) for c in remediation["commands"])
    assert remediation["commands"][-1] == "commit confirmed 5"

    once = _audit(snapshot, catalogue, failing + _as_config(remediation["commands"]))
    assert _finding(once, rule_id)["verdict"] == "PASS", remediation["commands"]

    twice = _audit(snapshot, catalogue, failing + _as_config(remediation["commands"]) * 2)
    assert project(twice["canonical"]) == project(once["canonical"])
    assert [f["verdict"] for f in twice["findings"]] == [f["verdict"] for f in once["findings"]]


def test_root_password_fix_uses_the_root_path(snapshot: Snapshot, catalogue: Catalogue) -> None:
    commands = _finding(_audit(snapshot, catalogue, SRX), "cis.local_users.strong_hash")["remediation"]["commands"]
    assert 'set system root-authentication encrypted-password "<NEW_PASSWORD_HASH>"' in commands
    assert not any("login user root " in c for c in commands)
    assert sum("system login user" in c for c in commands) == 3  # admin, padhye, ratul


def test_every_fix_rolls_back_to_the_previous_commit(snapshot: Snapshot) -> None:
    for fix in snapshot.fixes["junos"].fixes.values():
        assert fix["rollback"] == ["configure", "rollback 1", "commit"], fix["id"]


def test_rules_without_a_junos_fix_cannot_fail_on_junos(snapshot: Snapshot, catalogue: Catalogue) -> None:
    fixes = snapshot.fixes["junos"].fixes
    for rule in snapshot.rules["cis"].rules:
        if rule.raw.get("fix") not in fixes:
            assert _finding(_audit(snapshot, catalogue, SRX), rule.id)["verdict"] != "FAIL", rule.id
