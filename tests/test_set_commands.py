import pytest

from src.ingest.redact import redact
from src.readers.set_commands import UnsupportedStatement, read_set_commands, tokens
from tests.conftest import ROOT

JUNOS = ROOT / "fixtures" / "configs" / "batfish_example_juniper"
SRX = ROOT / "fixtures" / "configs" / "batfish_srx_testbed"


def _texts(lines: list[str]) -> list[tuple[int, str]]:
    return [(n.line_no, n.text) for n in read_set_commands(lines)]


def test_statement_is_path_after_verb_with_whitespace_collapsed() -> None:
    assert _texts(["#", "set system host-name r1", "set interfaces fe-0/0/0 unit 0  family inet"]) == [
        (2, "system host-name r1"), (3, "interfaces fe-0/0/0 unit 0 family inet")]


def test_quoted_value_is_one_token_and_keeps_its_spaces() -> None:
    assert tokens('set system login message "Authorised  use only"') == [
        "set", "system", "login", "message", '"Authorised  use only"']
    assert tokens('set a "x \\" y" b') == ["set", "a", '"x \\" y"', "b"]


def test_deactivate_removes_the_subtree_from_effect() -> None:
    lines = ["set services telnet", "set services ssh", "set services ssh root-login deny", "deactivate services ssh"]
    assert _texts(lines) == [(1, "services telnet")]


def test_deactivate_matches_whole_tokens_not_text_prefixes() -> None:
    assert _texts(["set services sshd x", "deactivate services ssh"]) == [(1, "services sshd x")]


def test_activate_undoes_deactivate() -> None:
    assert _texts(["set services ssh", "deactivate services ssh", "activate services ssh"]) == [(1, "services ssh")]


def test_delete_removes_subtree_and_its_inactive_mark() -> None:
    lines = ["set services ssh", "deactivate services ssh", "delete services", "set services ssh"]
    assert _texts(lines) == [(4, "services ssh")]


def test_repeated_statement_keeps_first_line() -> None:
    assert _texts(["set services ssh", "set services ssh"]) == [(1, "services ssh")]


def test_effect_free_verbs_are_skipped() -> None:
    assert _texts(["set system host-name r1", "protect system", 'annotate system "core"']) == [
        (1, "system host-name r1")]


@pytest.mark.parametrize("line", ["rename interfaces ge-0/0/0 to ge-0/0/1", "insert policy p before policy q",
                                  "copy interfaces a to b", "set"])
def test_schema_dependent_or_empty_statement_fails_the_device(line: str) -> None:
    with pytest.raises(UnsupportedStatement, match="line 1"):
        read_set_commands([line])


@pytest.mark.parametrize("path", sorted(JUNOS.glob("*.cfg")) + sorted(SRX.glob("*.cfg")), ids=lambda p: p.name)
def test_real_config_every_set_line_is_a_node_unless_deactivated(path: object) -> None:
    lines = redact(path.read_text())  # type: ignore[attr-defined]
    nodes = read_set_commands(lines)
    inactive = [tokens(l)[1:] for l in lines if l.startswith("deactivate ")]
    expected = []
    for i, l in enumerate(lines, 1):
        if not l.startswith("set "):
            continue
        toks = tokens(l)[1:]
        if not any(toks[: len(off)] == off for off in inactive):
            expected.append(i)
    assert [n.line_no for n in nodes] == expected
    assert all(n.path == () and n.children == [] for n in nodes)


def test_real_srx_deactivated_security_policy_is_not_audited() -> None:
    # junos-srx-2.cfg:56 and :61 deactivate two zone pairs, including a `then deny` toward the host.
    # Reading that deny as active would credit the device with protection it is not enforcing.
    texts = [n.text for n in read_set_commands(redact((SRX / "junos-srx-2.cfg").read_text()))]
    assert not [t for t in texts if t.startswith("security policies from-zone untrust to-zone untrust ")]
    assert not [t for t in texts if t.startswith("security policies from-zone untrust to-zone junos-host ")]
    assert len([t for t in texts if t.startswith("security policies from-zone trust to-zone trust ")]) == 4
    assert "security policies default-policy permit-all" in texts


def test_same_router_reads_in_both_dialects() -> None:
    nodes = read_set_commands(redact((JUNOS / "as1border1.cfg").read_text()))
    assert nodes[0].line_no == 2 and nodes[0].text == "system host-name as1border1"
    assert "interfaces fe-0/0/0 unit 0 family inet address 1.0.1.1/24" in [n.text for n in nodes]
