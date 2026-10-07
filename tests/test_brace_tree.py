"""brace_tree reader (PLAN 3.1): hierarchical Junos reads to the same statements as its `display set` form."""

from pathlib import Path
from typing import Any

import pytest

from src.audit import audit_device
from src.ingest.redact import redact
from src.mapping.canonical import Catalogue
from src.mapping.engine import detect
from src.readers.brace_tree import MalformedConfig, read_brace_tree
from src.readers.set_commands import UnsupportedStatement, read_set_commands, tokens
from src.registry import Snapshot
from tests.conftest import ROOT

FLAT = sorted((ROOT / "fixtures" / "configs" / "batfish_example_juniper").glob("*.cfg")) + sorted(
    (ROOT / "fixtures" / "configs" / "batfish_srx_testbed").glob("*.cfg"))
SNIPPETS = ROOT / "fixtures" / "configs" / "batfish_juniper_testconfigs"


def _as_braces(flat: str) -> str:
    """The hierarchical encoding of a flat file, one token per block level, `deactivate` as `inactive:`.

    No real device config exists in both encodings, so the test derives one. Junos would print
    `unit 0 {` where this prints `unit { 0 {`; both flatten to the same path, which is the claim under test.
    A quoted value stays on its keyword's line (`encrypted-password "X";`): Junos never prints a value alone.
    """
    root: dict[str, Any] = {}
    inactive: set[tuple[str, ...]] = set()
    for line in flat.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        verb, *path = tokens(line)
        if len(path) > 1 and path[-1].startswith('"'):
            path[-2:] = [f"{path[-2]} {path[-1]}"]
        if verb == "set":
            node = root
            for tok in path:
                node = node.setdefault(tok, {})
        elif verb == "deactivate":
            inactive.add(tuple(path))
        else:
            raise AssertionError(f"fixture uses {verb!r}; extend the encoder")
    out: list[str] = []

    def emit(node: dict[str, Any], prefix: tuple[str, ...], depth: int) -> None:
        for tok, children in node.items():
            tag = "inactive: " if prefix + (tok,) in inactive else ""
            pad = "    " * depth
            if children:
                out.append(f"{pad}{tag}{tok} {{")
                emit(children, prefix + (tok,), depth + 1)
                out.append(f"{pad}}}")
            else:
                out.append(f"{pad}{tag}{tok};")

    emit(root, (), 0)
    return "\n".join(out) + "\n"


def _texts(lines: list[str]) -> list[tuple[int, str]]:
    return [(n.line_no, n.text) for n in read_brace_tree(lines)]


def _without_lines(node: Any) -> Any:
    """A canonical model or finding with source line numbers dropped; the two encodings number lines differently."""
    if isinstance(node, dict):
        return {k: _without_lines(v) for k, v in node.items() if k not in ("line", "line_no", "lines")}
    if isinstance(node, list):
        return [_without_lines(v) for v in node]
    return node


@pytest.mark.parametrize("path", FLAT, ids=lambda p: p.name)
def test_both_encodings_of_a_real_config_read_to_identical_statements(path: Path) -> None:
    flat = redact(path.read_text())
    braces = redact(_as_braces(path.read_text()))
    assert sorted(n.text for n in read_brace_tree(braces)) == sorted(n.text for n in read_set_commands(flat))


@pytest.mark.parametrize("path", FLAT, ids=lambda p: p.name)
def test_brace_tree_reads_the_flat_encoding_itself_unchanged(path: Path) -> None:
    lines = redact(path.read_text())
    assert _texts(lines) == [(n.line_no, n.text) for n in read_set_commands(lines)]


@pytest.mark.parametrize("path", FLAT, ids=lambda p: p.name)
def test_both_encodings_detect_as_junos_and_audit_identically(
        path: Path, snapshot: Snapshot, catalogue: Catalogue) -> None:
    flat, braces = path.read_text(), _as_braces(path.read_text())
    packs = list(snapshot.vendors.values())
    assert detect(redact(braces), packs).pack.id == "junos"  # type: ignore[union-attr]
    a = audit_device(flat, "x.cfg", "x", snapshot, catalogue, ["cis"])
    b = audit_device(braces, "x.cfg", "x", snapshot, catalogue, ["cis"])
    assert _without_lines(b["canonical"]) == _without_lines(a["canonical"])
    assert {f["rule_id"]: f["verdict"] for f in b["findings"]} == {f["rule_id"]: f["verdict"] for f in a["findings"]}


# Batfish parser snippets: each exists to exercise one edge of the hierarchical grammar.

def test_list_values_and_wildcards_flatten_one_statement_per_element() -> None:
    got = _texts(redact((SNIPPETS / "gh-6149-flatten").read_text()))
    assert (21, "groups FOO interfaces <*> unit <*> family inet filter input-list filterA") in got
    assert (21, "groups FOO interfaces <*> unit <*> family inet filter input-list filterB") in got
    assert (57, "firewall family inet filter filterB term xyz from source-address 0.0.0.0/8") in got
    assert (32, "interfaces ae1 apply-groups FOO") in got  # recorded, not resolved (PLAN 2.1 decision)


def test_block_comments_and_a_stray_semicolon_after_one_are_dropped() -> None:
    assert _texts(redact((SNIPPETS / "juniper_nested_multiline_comments").read_text())) == [
        (3, "system host-name juniper_nested_multiline_comments"),
        (12, "policy-options policy-statement p term t from protocol bgp"),
        (13, "policy-options policy-statement p term t from rib inet.0"),
        (18, "policy-options policy-statement p term t then reject")]


def test_comment_closing_mid_line_leaves_the_rest_of_the_line() -> None:
    assert _texts((SNIPPETS / "nested-config-with-multiline-comment").read_text().splitlines()) == [
        (4, "system host-name nested-config-with-multiline-comment")]


def test_rancid_bang_header_and_hash_comments_are_dropped() -> None:
    assert _texts((SNIPPETS / "nested-config-line-comments").read_text().splitlines()) == [
        (6, "system host-name nested-config-line-comments")]


def test_flat_statement_mixed_into_a_brace_file_is_read() -> None:
    assert _texts((SNIPPETS / "nested-config-with-flat-statements").read_text().splitlines()) == [
        (3, "system host-name nested-config-with-flat-statements"),
        (5, "security policies from-zone A to-zone B policy P match source-address any")]


def test_quote_inside_a_word_is_literal_and_does_not_swallow_the_file() -> None:
    assert _texts((SNIPPETS / "nested-config-with-quote-bug").read_text().splitlines()) == [
        (3, "system host-name nested-config-with-quote-bug"),
        (6, 'system license keys key foo bar"'),
        (13, "routing-instances VRF_NAME routing-options autonomous-system 1")]


def test_secret_is_masked_before_reading_and_the_statement_still_ends() -> None:
    got = _texts(redact((SNIPPETS / "nested-config-with-secret-data").read_text()))
    assert (14, "routing-instances VRF_NAME protocols bgp group VRF_GROUP authentication-key ****") in got
    assert not any("abacadd" in text for _, text in got)


def test_misbraced_file_fails_the_device() -> None:
    with pytest.raises(MalformedConfig, match="line 1"):
        read_brace_tree((SNIPPETS / "misbraced").read_text().splitlines())


def test_documented_divergence_flat_prefix_statement_has_no_brace_equivalent() -> None:
    """KNOWN DIVERGENCE, not parity: see brace_tree.py and docs/review-queue.md "Reader divergence".

    Flat keeps `services ssh` beside `services ssh root-login deny`; braces cannot state the prefix
    separately. If this test fails, one reader changed how it treats a prefix; decide it, then update both.
    """
    flat = read_set_commands(["set services ssh", "set services ssh root-login deny"])
    braces = read_brace_tree(["services {", "    ssh {", "        root-login deny;", "    }", "}"])
    assert [n.text for n in flat] == ["services ssh", "services ssh root-login deny"]
    assert [n.text for n in braces] == ["services ssh root-login deny"]


# Grammar edges with no Batfish snippet.

def test_inactive_tag_takes_the_subtree_out_of_effect() -> None:
    lines = ["system {", "    inactive: services {", "        telnet;", "    }", "    host-name r1;", "}"]
    assert _texts(lines) == [(5, "system host-name r1")]


def test_empty_block_is_a_statement() -> None:
    assert _texts(["system {", "    services {", "        ssh { }", "    }", "}"]) == [(3, "system services ssh")]


def test_protect_tag_has_no_effect() -> None:
    assert _texts(["protect: system {", "    host-name r1;", "}"]) == [(2, "system host-name r1")]


@pytest.mark.parametrize("lines, message", [
    (["system {", "    host-name r1;"], "line 1: block opened here is never closed"),
    (["system {", "    host-name r1", "}"], "statement not ended with ';' before '}'"),
    (["system host-name r1"], "statement not ended with ';' at end of file"),
    (["x [ a b ] c;"], "after a \\[ \\] list"),
    (["x [ ];"], "empty \\[ \\] list"),
])
def test_unbalanced_structure_fails_the_device(lines: list[str], message: str) -> None:
    with pytest.raises(MalformedConfig, match=message):
        read_brace_tree(lines)


def test_load_time_tag_fails_the_device() -> None:
    with pytest.raises(UnsupportedStatement, match="replace:"):
        read_brace_tree(["replace: system {", "    host-name r1;", "}"])
