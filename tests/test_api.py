"""HTTP API against docs/openapi.yaml: every body is validated against the contract."""

import io
import re
import shutil
import time
import zipfile
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml
from fastapi.testclient import TestClient

from src.api.app import create_app
from tests.conftest import CONFIGS, PACKS, ROOT

SRX = ROOT / "fixtures" / "configs" / "batfish_srx_testbed" / "junos-srx-1.cfg"
JUNOS_ROUTER = ROOT / "fixtures" / "configs" / "batfish_example_juniper" / "as1border1.cfg"
IOS = CONFIGS / "as2dept1.cfg"
SPEC = yaml.safe_load((ROOT / "docs" / "openapi.yaml").read_text(encoding="utf-8"))


def _valid(body: Any, schema: str) -> None:
    jsonschema.Draft202012Validator({"$ref": f"#/components/schemas/{schema}",
                                     "components": SPEC["components"]}).validate(body)


@pytest.fixture()
def packs(tmp_path: Path) -> Path:
    dest = tmp_path / "packs"
    shutil.copytree(PACKS, dest)
    return dest


@pytest.fixture()
def client(packs: Path) -> TestClient:
    return TestClient(create_app(packs=packs, workers=2, timeout=60))


def _upload(client: TestClient, files: list[tuple[str, bytes]], **form: Any) -> Any:
    data = {"frameworks": ["cis"], **form}
    return client.post("/api/scans", files=[("files", (n, b)) for n, b in files], data=data)


def _wait(client: TestClient, scan_id: str, limit: float = 120) -> dict[str, Any]:
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        scan = client.get(f"/api/scans/{scan_id}").json()
        if scan["status"] in ("completed", "failed"):
            return scan
        time.sleep(0.2)
    raise AssertionError(f"scan {scan_id} did not finish")


def test_two_vendor_scan_end_to_end(client: TestClient) -> None:
    r = _upload(client, [(IOS.name, IOS.read_bytes()), (SRX.name, SRX.read_bytes())])
    assert r.status_code == 202
    _valid(r.json(), "ScanCreated")
    scan = _wait(client, r.json()["scan_id"])
    _valid(scan, "Scan")
    assert scan["status"] == "completed" and scan["progress"] == {"total": 2, "done": 2, "error": 0}
    packs_by_device = {d["device_id"]: d["vendor_pack"] for d in scan["devices"]}
    assert packs_by_device["as2dept1"].startswith("cisco_ios@")
    assert packs_by_device["junos-srx-1"].startswith("junos@")

    device = client.get(f"/api/scans/{scan['scan_id']}/devices/junos-srx-1")
    assert device.status_code == 200
    _valid(device.json(), "DeviceFindings")
    http = next(f for f in device.json()["findings"] if f["rule_id"] == "cis.http.disabled")
    assert http["verdict"] == "FAIL" and http["remediation"]["commands"][-1] == "commit confirmed 5"

    report = client.get(f"/api/scans/{scan['scan_id']}/devices/junos-srx-1/report")
    assert report.status_code == 200 and report.headers["content-type"] == "application/pdf"
    assert report.content.startswith(b"%PDF")


def test_pack_dropped_in_is_used_without_restart(client: TestClient, packs: Path, tmp_path: Path) -> None:
    """PLAN 2.2 gate: drop junos.yaml into the packs folder with the server running."""
    for pack in ("vendors/junos.yaml", "fixes/junos.yaml"):
        shutil.move(packs / pack, tmp_path / pack.replace("/", "_"))
    scan_id = _upload(client, [(SRX.name, SRX.read_bytes())]).json()["scan_id"]
    before = _wait(client, scan_id)["devices"][0]
    assert before["vendor_pack"] is None
    assert before["verdicts"]["fail"] == 0 and before["verdicts"]["pass"] == 0  # no false failures

    for pack in ("vendors/junos.yaml", "fixes/junos.yaml"):
        shutil.copy(tmp_path / pack.replace("/", "_"), packs / pack)
    assert client.post(f"/api/scans/{scan_id}/reevaluate").status_code == 202
    after = _wait(client, scan_id)["devices"][0]
    assert after["vendor_pack"].startswith("junos@")
    assert after["verdicts"]["fail"] > 0
    assert any(p["id"] == "junos" for p in client.get("/api/packs").json()["packs"])


def test_zip_members_become_devices_and_a_bad_archive_is_one_error_row(client: TestClient) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("site-a/" + IOS.name, IOS.read_bytes())
        z.writestr("site-a/" + SRX.name, SRX.read_bytes())
        z.writestr("__MACOSX/._junk", b"x")
        z.writestr("inner.zip", b"PK\x03\x04")
    r = _upload(client, [("batch.zip", buf.getvalue()), ("broken.zip", b"PK\x03\x04 not really")])
    scan = _wait(client, r.json()["scan_id"])
    rows = {d["filename"]: d["status"] for d in scan["devices"]}
    assert rows == {IOS.name: "done", SRX.name: "done", "inner.zip": "error", "broken.zip": "error"}
    assert scan["status"] == "completed"
    err = client.get(f"/api/scans/{scan['scan_id']}/devices/broken")
    assert err.status_code == 409
    _valid(err.json(), "Error")


def test_operator_os_version_reaches_the_engine(client: TestClient) -> None:
    r = _upload(client, [(JUNOS_ROUTER.name, JUNOS_ROUTER.read_bytes())], os_version="15.1R7")
    scan = _wait(client, r.json()["scan_id"])
    assert scan["devices"][0]["identity"]["os_version"] == "15.1R7"


@pytest.mark.parametrize("form, field", [({"frameworks": ["pci"]}, "frameworks"),
                                         ({"os_version": "latest"}, "os_version")])
def test_bad_request_names_the_field(client: TestClient, form: dict[str, Any], field: str) -> None:
    r = _upload(client, [(IOS.name, IOS.read_bytes())], **form)
    assert r.status_code == 400
    _valid(r.json(), "Error")
    assert r.json()["field"] == field


def test_missing_files_is_a_400_in_the_error_shape(client: TestClient) -> None:
    r = client.post("/api/scans", data={"frameworks": ["cis"]})
    assert r.status_code == 400
    _valid(r.json(), "Error")


def test_unknown_scan_is_404(client: TestClient) -> None:
    r = client.get("/api/scans/nope")
    assert r.status_code == 404
    _valid(r.json(), "Error")


@pytest.mark.parametrize("method, path", [("get", "/api/clusters/c1/suggestions"),
                                          ("post", "/api/clusters/c1/confirm")])
def test_learning_endpoints_say_not_implemented_never_fake_data(client: TestClient, method: str, path: str) -> None:
    r = getattr(client, method)(path)
    assert r.status_code == 501
    _valid(r.json(), "Error")


def test_schema_fields_carry_descriptions(client: TestClient) -> None:
    body = client.get("/api/schema/fields").json()
    for f in body["fields"]:
        _valid(f, "SchemaField")
    by_path = {f["path"]: f for f in body["fields"]}
    assert by_path["services.ssh.version"]["description"]
    assert by_path["interfaces[]"]["collection"] is True
    assert re.fullmatch(r"canonical@[0-9a-f]{12}", body["schema_version"])


def test_packs_listing_matches_the_contract(client: TestClient) -> None:
    for p in client.get("/api/packs").json()["packs"]:
        _valid(p, "Pack")


@pytest.mark.parametrize("origin, allowed", [("http://127.0.0.1:5173", True), ("http://localhost:5173", True),
                                             ("http://evil.example", False)])
def test_cors_allows_only_the_local_frontend(client: TestClient, origin: str, allowed: bool) -> None:
    r = client.options("/api/packs", headers={"Origin": origin, "Access-Control-Request-Method": "GET"})
    assert (r.headers.get("access-control-allow-origin") == origin) is allowed


def test_nothing_binds_beyond_loopback() -> None:
    offenders = [str(p) for p in (ROOT / "src").rglob("*.py") if "0.0.0.0" in p.read_text(encoding="utf-8")]
    assert offenders == []
    assert "HOST := 127.0.0.1" in (ROOT / "Makefile").read_text()
