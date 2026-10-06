import re

from src.ingest.redact import redact, redact_line
from src.readers.indent_blocks import read_indent_blocks
from tests.conftest import CONFIGS, ROOT


def test_redaction_keeps_algorithm_token() -> None:
    assert redact_line("enable secret 9 $9$abc$def") == "enable secret 9 $9$****"
    assert redact_line("enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0") == "enable secret 5 $1$****"
    assert redact_line("username admin privilege 15 secret 8 $8$xyz") == "username admin privilege 15 secret 8 $8$****"
    assert redact_line(" password 7 0822455D0A16") == " password 7 ****"
    assert redact_line("tacacs-server key 7 1234ABCD") == "tacacs-server key 7 ****"
    assert redact_line("ntp authentication-key 1 md5 s3cret 7") == "ntp authentication-key 1 md5 **** 7"


def test_junos_and_fortios_secrets_keep_their_encoding_token() -> None:
    # Real line from fixtures/configs/batfish_srx_testbed/junos-srx-1.cfg:24, which used to leak.
    assert (redact_line('set security ike policy test-ike-policy pre-shared-key ascii-text "$9$/E6g9tO1IcSrvfTCu1hKv-VwgJD"')
            == "set security ike policy test-ike-policy pre-shared-key ascii-text $9$****")
    assert redact_line('set system root-authentication encrypted-password "$1$CXKwIUfL$6vLSvatE2TCaM25U4u9Bh1"') == (
        "set system root-authentication encrypted-password $1$****")
    assert redact_line('set protocols bgp group g authentication-key "$9$abc"') == (
        "set protocols bgp group g authentication-key $9$****")
    assert redact_line('set system ntp authentication-key 1 type md5 value "$9$abc"') == (
        "set system ntp authentication-key 1 type md5 value $9$****")
    assert redact_line('set system radius-server 10.0.0.1 secret "two words"') == (
        "set system radius-server 10.0.0.1 secret ****")
    assert redact_line("    set password ENC SH2abc==") == "    set password ENC ****"
    assert redact_line("    set psksecret ENC xyz") == "    set psksecret ENC ****"


def test_brace_form_secret_keeps_statement_terminator() -> None:
    # Real line from fixtures/configs/batfish_juniper_testconfigs/nested-config-with-secret-data:14.
    assert redact_line('            authentication-key "abacadd"; ## SECRET-DATA') == (
        "            authentication-key ****; ## SECRET-DATA")
    assert redact_line("    authentication-key abacadd;") == "    authentication-key ****;"


def test_set_form_snmp_community_is_masked() -> None:
    assert redact_line("set snmp community s3cr3t authorization read-only") == (
        "set snmp community **** authorization read-only")
    assert redact_line("deactivate snmp community s3cr3t") == "deactivate snmp community ****"
    assert redact_line("set snmp community public authorization read-only") == (
        "set snmp community public authorization read-only")


def test_password_policy_options_are_not_secrets() -> None:
    for line in ("set system login password minimum-length 12", "set system login password change-type character-sets",
                 "set system login password format sha512", "set system login password maximum-length 64",
                 "set system authentication-order password"):
        assert redact_line(line) == line


def test_key_ids_are_not_secrets() -> None:
    # Real line from fixtures/configs/batfish_nxos_testconfigs/nxos_ntp:7 — `key 12345` names a key, it is not one.
    line = "ntp server 10.1.2.3 use-vrf management key 12345 minpoll 10 maxpoll 10"
    assert redact_line(line) == line


def test_no_secret_survives_in_any_fixture() -> None:
    leaks = re.compile(r'\$9\$[^*\s"]|\$1\$[^*\s"]|"abacadd"')
    for f in sorted((ROOT / "fixtures" / "configs").rglob("*")):
        if f.is_file() and f.name != "SOURCE.md":
            for i, line in enumerate(redact(f.read_text(errors="replace")), 1):
                assert not leaks.search(line), f"{f.name}:{i} leaks a secret after redaction"


def test_snmp_communities_masked_except_well_known_defaults() -> None:
    assert redact_line("snmp-server community Xy9!secret RO") == "snmp-server community **** RO"
    assert redact_line("snmp-server community public RO") == "snmp-server community public RO"


def test_redaction_leaves_ordinary_lines_alone() -> None:
    for line in ("crypto key generate rsa modulus 2048", "service password-encryption", "ip ssh version 2"):
        assert redact_line(line) == line


def test_redaction_preserves_line_numbers() -> None:
    text = (CONFIGS / "as2dept1.cfg").read_text()
    assert len(redact(text)) == len(text.split("\n"))


def test_indent_tree_scope_and_line_numbers() -> None:
    lines = ["!", "hostname r1", "interface Gi0/1", " ip proxy-arp", " shutdown", "!", "line vty 0 4", " login"]
    roots = read_indent_blocks(lines)
    assert [(n.line_no, n.text) for n in roots] == [(2, "hostname r1"), (3, "interface Gi0/1"), (7, "line vty 0 4")]
    intf = roots[1]
    assert [(c.line_no, c.text, c.path) for c in intf.children] == [
        (4, "ip proxy-arp", ("interface Gi0/1",)), (5, "shutdown", ("interface Gi0/1",))]


def test_banner_body_is_not_parsed() -> None:
    lines = ["banner motd ^C", "interface Gi0/9", "  shutdown", "^C", "hostname r1"]
    roots = read_indent_blocks(lines)
    assert [n.text for n in roots] == ["banner motd ^C", "hostname r1"]


def test_real_config_round_trips_every_statement() -> None:
    lines = redact((CONFIGS / "as2dept1.cfg").read_text())
    nodes = [n for r in read_indent_blocks(lines) for n in r.walk()]
    statements = [i + 1 for i, l in enumerate(lines) if l.strip() and not l.strip().startswith("!")]
    assert sorted(n.line_no for n in nodes) == statements
