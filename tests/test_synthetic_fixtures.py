"""Synthetic fixtures prove code paths no real fixture reaches. They never reach a demo (invariant 4)."""

import re

from src.audit import audit_device
from src.mapping.canonical import Catalogue
from src.registry import Snapshot
from tests.conftest import ROOT

SYNTHETIC = ROOT / "fixtures" / "synthetic"


def test_every_synthetic_fixture_says_so_in_its_header() -> None:
    for path in SYNTHETIC.glob("*.cfg"):
        assert path.read_text().startswith("! SYNTHETIC FIXTURE"), path.name


_SYNTHETIC_PATH = re.compile(r"""fixtures[/\\]synthetic|["']synthetic["']""")  # a path to the folder, not the word


def test_guard_matches_path_references_and_not_the_word() -> None:
    for ref in ['ROOT / "fixtures" / "synthetic"', "fixtures/synthetic/x.cfg", "fixtures\\synthetic\\x.cfg"]:
        assert _SYNTHETIC_PATH.search(ref), ref
    assert not _SYNTHETIC_PATH.search("nothing here is synthetic.")


def test_no_demo_script_reads_synthetic_fixtures() -> None:
    for script in (ROOT / "scripts").glob("*.py"):
        assert not _SYNTHETIC_PATH.search(script.read_text(encoding="utf-8")), script.name


def test_threshold_shape_one_syslog_server_passes_cis_and_fails_stig(
        snapshot: Snapshot, catalogue: Catalogue) -> None:
    """PLAN 3.2 demo acceptance, threshold shape: same device, same setting, frameworks disagree."""
    text = (SYNTHETIC / "ios_one_syslog_server.cfg").read_text()
    out = audit_device(text, "s.cfg", "s", snapshot, catalogue, ["cis", "stig"])
    verdicts = {f["rule_id"]: f["verdict"] for f in out["findings"]}
    assert [s["value"] for s in out["canonical"]["logging"]["servers"]["items"]] == ["192.0.2.10"]
    assert verdicts["cis.logging.remote_host"] == "PASS"
    assert verdicts["stig.logging.two_servers"] == "FAIL"
    assert verdicts["stig.ntp.two_servers"] == "PASS"  # two NTP servers: the STIG rule can pass too
