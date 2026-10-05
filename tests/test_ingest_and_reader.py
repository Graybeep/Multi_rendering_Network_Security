from src.ingest.redact import redact, redact_line
from src.readers.indent_blocks import read_indent_blocks
from tests.conftest import CONFIGS


def test_redaction_keeps_algorithm_token() -> None:
    assert redact_line("enable secret 9 $9$abc$def") == "enable secret 9 $9$****"
    assert redact_line("enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0") == "enable secret 5 $1$****"
    assert redact_line("username admin privilege 15 secret 8 $8$xyz") == "username admin privilege 15 secret 8 $8$****"
    assert redact_line(" password 7 0822455D0A16") == " password 7 ****"
    assert redact_line("tacacs-server key 7 1234ABCD") == "tacacs-server key 7 ****"
    assert redact_line("ntp authentication-key 1 md5 s3cret 7") == "ntp authentication-key 1 md5 **** 7"


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
