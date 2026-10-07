import json
import shutil
from pathlib import Path

from src.cli.main import main
from tests.conftest import CONFIGS


def test_cli_audits_a_batch_and_isolates_a_bad_file(tmp_path: Path) -> None:
    configs = tmp_path / "configs"
    configs.mkdir()
    for name in ("as2dept1.cfg", "as1core1.cfg", "as3border1.cfg"):
        shutil.copy(CONFIGS / name, configs / name)
    (configs / "garbage.cfg").write_bytes(b"\x00\xff\xfe" * 100)
    out = tmp_path / "reports"

    code = main([str(configs), "--framework", "cis", "--out", str(out), "--workers", "2"])

    summary = {s["device_id"]: s for s in json.loads((out / "summary.json").read_text())}
    assert {k for k, v in summary.items() if v["status"] == "done"} >= {"as2dept1", "as1core1", "as3border1"}
    for device in ("as2dept1", "as1core1", "as3border1"):
        assert (out / f"{device}.pdf").read_bytes().startswith(b"%PDF")
        assert summary[device]["vendor_pack"] == "cisco_ios@1.2.0"
    # An undetectable file is audited as all NOT_DETERMINED, not guessed and not a crash.
    assert summary["garbage"]["status"] == "done"
    assert summary["garbage"]["verdicts"]["fail"] == 0
    assert code == 0


def test_findings_cite_real_lines(tmp_path: Path) -> None:
    out = tmp_path / "r"
    main([str(CONFIGS / "as2dept1.cfg"), "--out", str(out), "--workers", "1"])
    result = json.loads((out / "as2dept1.json").read_text())
    source = (CONFIGS / "as2dept1.cfg").read_text().split("\n")
    cited = [e for f in result["findings"] for e in f["evidence"] if e["line_no"]]
    assert cited
    for e in cited:
        assert source[e["line_no"] - 1].strip() == e["text"]
