import re
from typing import Any

import pytest

from src.audit import audit_device
from src.ingest.redact import redact
from src.mapping.canonical import Catalogue
from src.mapping.engine import map_device
from src.readers import READERS
from src.registry import Snapshot
from src.remediation.render import render
from src.rules.evaluator import FAIL, NOT_DETERMINED, PASS, evaluate
from src.rules.fixtures import model_from_fragment
from tests.conftest import CONFIGS, PACKS

RULE_IDS = [r["id"] for r in __import__("yaml").safe_load((PACKS / "rules" / "cis.yaml").read_text())["rules"]]
# Every rule in every framework's pack, as (framework, rule id).
ALL_RULES = [(doc["framework"], r["id"]) for doc in (__import__("yaml").safe_load(f.read_text())
             for f in sorted((PACKS / "rules").glob("*.yaml"))) for r in doc["rules"]]
MODE_LINES = {"configure terminal", "end", "write memory", "exit"}


def _rule(snapshot: Snapshot, rule_id: str) -> Any:
    return next(r for r in snapshot.rules["cis"].rules if r.id == rule_id)


@pytest.mark.parametrize("framework, rule_id", ALL_RULES)
def test_rule_fixtures(snapshot: Snapshot, catalogue: Catalogue, framework: str, rule_id: str) -> None:
    rule = next(r for r in snapshot.rules[framework].rules if r.id == rule_id)
    assert evaluate(rule, model_from_fragment(catalogue, rule.raw["fixtures"]["pass"])).verdict == PASS
    assert evaluate(rule, model_from_fragment(catalogue, rule.raw["fixtures"]["fail"])).verdict == FAIL
    assert evaluate(rule, catalogue.empty_model()).verdict == NOT_DETERMINED


def test_unread_collection_is_not_determined_never_vacuous_pass(snapshot: Snapshot, catalogue: Catalogue) -> None:
    rule = _rule(snapshot, "cis.interfaces.no_proxy_arp")
    model = catalogue.empty_model()  # interfaces: state unknown, items []
    v = evaluate(rule, model)
    assert v.verdict == NOT_DETERMINED
    assert "interfaces[].proxy_arp" in v.missing_fields


def test_read_empty_collection_is_a_real_answer(snapshot: Snapshot, catalogue: Catalogue) -> None:
    rule = _rule(snapshot, "cis.local_users.strong_hash")
    model = catalogue.empty_model()
    model["auth"]["local_users"]["state"] = "mapped"
    assert evaluate(rule, model).verdict == PASS


def test_one_unknown_item_attribute_blocks_the_verdict(snapshot: Snapshot, catalogue: Catalogue) -> None:
    rule = _rule(snapshot, "cis.interfaces.no_proxy_arp")
    model = model_from_fragment(catalogue, {"interfaces[]": [
        {"name": "Gi0/1", "shutdown": False, "proxy_arp": True}, {"name": "Gi0/2", "shutdown": False}]})
    assert evaluate(rule, model).verdict == NOT_DETERMINED


def test_unrecognised_vendor_gets_no_false_failures(snapshot: Snapshot, catalogue: Catalogue) -> None:
    junos = "system {\n    host-name r1;\n    services {\n        ssh;\n        telnet;\n    }\n}\n"
    result = audit_device(junos, "r1.conf", "r1", snapshot, catalogue, ["cis"])
    assert result["vendor_pack"] is None
    assert result["verdicts"] == {"pass": 0, "fail": 0, "not_determined": 15}


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_fix_actually_fixes(snapshot: Snapshot, catalogue: Catalogue, rule_id: str) -> None:
    """Map the rendered fix as config: the rule must then PASS. Proves fix ↔ mapping ↔ rule agree."""
    rule = _rule(snapshot, rule_id)
    fix = snapshot.fixes["cisco_ios"].fixes.get(rule.raw.get("fix", ""))
    if fix is None or fix.get("operator_input"):
        pytest.skip("no fix, or the fix needs operator input")
    failing = model_from_fragment(catalogue, rule.raw["fixtures"]["fail"])
    each = rule.for_each
    items = failing
    for seg in (each or "").removesuffix("[]").split(".") if each else []:
        items = items[seg]
    rendered = render(fix, items["items"] if each else [], "15.2")
    assert rendered is not None
    assert not any(re.search(r"\{[a-z_]+\}", c) for c in rendered["commands"])
    config = ["version 15.2"] + [c for c in rendered["commands"] if c.strip() not in MODE_LINES]
    lines = redact("\n".join(config))
    pack = snapshot.vendors["cisco_ios"]
    model = map_device(pack, READERS["indent_blocks"](lines), lines, catalogue, None).model
    assert evaluate(rule, model).verdict == PASS, rendered["commands"]


def test_fix_is_idempotent_when_rendered_twice(snapshot: Snapshot, catalogue: Catalogue) -> None:
    result = audit_device((CONFIGS / "as2dept1.cfg").read_text(), "x", "x", snapshot, catalogue, ["cis"])
    again = audit_device((CONFIGS / "as2dept1.cfg").read_text(), "x", "x", snapshot, catalogue, ["cis"])
    assert result["findings"] == again["findings"]


def test_fix_withheld_when_os_too_old(snapshot: Snapshot, catalogue: Catalogue) -> None:
    result = audit_device((CONFIGS / "as2dept1.cfg").read_text(), "x", "x", snapshot, catalogue, ["cis"])
    f = next(f for f in result["findings"] if f["rule_id"] == "cis.enable_secret.strong_hash")
    assert f["verdict"] == FAIL and f["remediation"] is None  # algorithm-type scrypt needs 15.3+


def test_per_interface_fix_names_each_failing_interface(snapshot: Snapshot, catalogue: Catalogue) -> None:
    result = audit_device((CONFIGS / "as2dept1.cfg").read_text(), "x", "x", snapshot, catalogue, ["cis"])
    f = next(f for f in result["findings"] if f["rule_id"] == "cis.interfaces.no_proxy_arp")
    names = [c.split()[1] for c in f["remediation"]["commands"] if c.startswith("interface ")]
    assert "Ethernet0/0" not in names  # shut down in the config
    assert names == ["Loopback0", "GigabitEthernet0/0", "GigabitEthernet1/0", "GigabitEthernet2/0",
                     "GigabitEthernet3/0"]


def _incomplete(model: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    node = model
    for seg in path:
        node = node[seg]
    node["complete"] = False
    return model


def test_incomplete_list_with_visible_failure_is_fail(snapshot: Snapshot, catalogue: Catalogue) -> None:
    model = model_from_fragment(catalogue, {"auth.local_users[]": [
        {"name": "a", "password_algorithm": "md5"}, {"name": "b", "password_algorithm": "scrypt"}]})
    v = evaluate(_rule(snapshot, "cis.local_users.strong_hash"), _incomplete(model, ("auth", "local_users")))
    assert v.verdict == FAIL and [i["name"]["value"] for i in v.failing_items] == ["a"]


def test_incomplete_list_without_visible_failure_is_not_determined(snapshot: Snapshot, catalogue: Catalogue) -> None:
    model = model_from_fragment(catalogue, {"auth.local_users[]": [{"name": "b", "password_algorithm": "scrypt"}]})
    v = evaluate(_rule(snapshot, "cis.local_users.strong_hash"), _incomplete(model, ("auth", "local_users")))
    assert v.verdict == NOT_DETERMINED and v.missing_fields == ["auth.local_users[]"]


def test_incomplete_list_lower_bound_met_is_pass(snapshot: Snapshot, catalogue: Catalogue) -> None:
    model = model_from_fragment(catalogue, {"logging.servers[]": ["10.0.0.5"]})
    rule = _rule(snapshot, "cis.logging.remote_host")
    assert evaluate(rule, _incomplete(model, ("logging", "servers"))).verdict == PASS


def test_rule_without_partial_opt_in_stays_not_determined(snapshot: Snapshot, catalogue: Catalogue) -> None:
    rule = _rule(snapshot, "cis.local_users.strong_hash")
    raw = {k: v for k, v in rule.raw.items() if k != "partial"}
    plain = type(rule)(raw, rule.compiled, rule.pack_tag, rule.framework)
    model = model_from_fragment(catalogue, {"auth.local_users[]": [{"name": "a", "password_algorithm": "md5"}]})
    assert evaluate(plain, _incomplete(model, ("auth", "local_users"))).verdict == NOT_DETERMINED


_PARTIAL_RULE = """id: t
version: 1.0.0
framework: cis
rules:
  - id: t.r
    title: t
    applies_to: {os_family: '*'}
    requires: ['auth.local_users[].password_algorithm']
    assert: "password_algorithm == 'scrypt'"
EXTRA    severity: low
    fixtures:
      pass: {'auth.local_users[]': [{name: a, password_algorithm: scrypt}]}
      fail: {'auth.local_users[]': [{name: a, password_algorithm: md5}]}
"""


@pytest.mark.parametrize("extra", ["    for_each: 'auth.local_users[]'\n    partial: lower_bound\n",
                                   "    partial: counterexample_sufficient\n"])
def test_inconsistent_partial_is_rejected(tmp_path: Any, catalogue: Catalogue, extra: str) -> None:
    from src.packs import PackError
    from src.rules.evaluator import load_rule_pack
    (tmp_path / "t.yaml").write_text(_PARTIAL_RULE.replace("EXTRA", extra))
    with pytest.raises(PackError, match="field partial"):
        load_rule_pack(tmp_path / "t.yaml", catalogue)
