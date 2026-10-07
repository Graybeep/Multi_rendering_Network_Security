"""Demonstrate the Phase 2 gates against a live server. Prints a Markdown transcript to stdout.

    PYTHONUTF8=1 python scripts/demo_phase2_gates.py \
        --confirm "syslog file messages any any=logging.enabled" --value true > docs/demos/phase2-gates.md

Gate 2.2: with the server running, drop `junos.yaml` into the packs folder; a Junos config goes from mostly
NOT_DETERMINED to audited, with no restart.
Gate 2.6: a confirmed answer writes `packs/learned/<vendor>.yaml`, the registry reloads, and the second run
maps the line, with no restart; a fresh scan of the same files then matches the re-evaluated one exactly.

The server is real (uvicorn on 127.0.0.1, an ephemeral port) and serves a temporary COPY of `packs/`, so the
repository's packs are never written. Configs are the committed Batfish fixtures; nothing here is synthetic.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

import httpx
import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.api.app import HOST, create_app

CONFIGS = sorted((ROOT / "fixtures" / "configs" / "batfish_example_juniper").glob("*.cfg")) + sorted(
    (ROOT / "fixtures" / "configs" / "batfish_srx_testbed").glob("*.cfg"))
JUNOS_FILES = [Path("vendors") / "junos.yaml", Path("fixes") / "junos.yaml"]


def _port() -> int:
    with socket.socket() as s:
        s.bind((HOST, 0))
        return int(s.getsockname()[1])


def _wait(client: httpx.Client, scan_id: str) -> dict[str, Any]:
    for _ in range(600):
        scan = client.get(f"/api/scans/{scan_id}").json()
        if scan["status"] in ("completed", "failed"):
            return scan
        time.sleep(0.2)
    raise TimeoutError(scan_id)


def _devices(client: httpx.Client, scan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {d["device_id"]: client.get(f"/api/scans/{scan['scan_id']}/devices/{d['device_id']}").json()
            for d in scan["devices"]}


def _table(devices: dict[str, dict[str, Any]]) -> list[str]:
    rows = ["| device | vendor pack | PASS | FAIL | NOT_DETERMINED |", "|---|---|---|---|---|"]
    for device_id, d in devices.items():
        c = Counter(f["verdict"] for f in d.get("findings", []))
        rows.append(f"| {device_id} | {d.get('vendor_pack') or '—'} | {c['PASS']} | {c['FAIL']} | {c['NOT_DETERMINED']} |")
    return rows


def _scan(client: httpx.Client) -> dict[str, Any]:
    files = [("files", (p.name, p.read_bytes(), "application/octet-stream")) for p in CONFIGS]
    created = client.post("/api/scans", files=files, data={"frameworks": ["cis"]})
    created.raise_for_status()
    return _wait(client, created.json()["scan_id"])


def _findings(devices: dict[str, dict[str, Any]]) -> dict[str, list[tuple[str, str]]]:
    return {k: sorted((f["rule_id"], f["verdict"]) for f in d["findings"]) for k, d in devices.items()}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--confirm", help='"<substring of the cluster sample>=<canonical field>" to confirm as a human')
    ap.add_argument("--value", help="fixed value for a true/false field")
    ap.add_argument("--list-all", action="store_true", help="list every cluster, to choose one to confirm")
    args = ap.parse_args()

    out: list[str] = []
    say = out.append
    tmp = Path(tempfile.mkdtemp(prefix="gates-"))
    packs = tmp / "packs"
    shutil.copytree(ROOT / "packs", packs, ignore=shutil.ignore_patterns("learned", "CLAUDE.md"))
    for rel in JUNOS_FILES:
        (packs / rel).unlink()

    port = _port()
    server = uvicorn.Server(uvicorn.Config(create_app(packs, workers=2), host=HOST, port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)

    try:
        with httpx.Client(base_url=f"http://{HOST}:{port}", timeout=60) as client:
            say(f"Server: uvicorn on {HOST}:{port}, process {os.getpid()}, started once for the whole transcript.")
            say("Configs: " + ", ".join(f"`{p.relative_to(ROOT).as_posix()}`" for p in CONFIGS)
                + " (committed fixtures). Framework: cis.\n")

            say("## Gate 2.2 — drop `junos.yaml` in with the server running\n")
            say("Installed packs before: " + ", ".join(
                f"{p['id']}@{p['version']}" for p in client.get("/api/packs").json()["packs"]))
            scan = _scan(client)
            before = _devices(client, scan)
            say(f"\nScan `{scan['scan_id']}`, no Junos pack installed:\n")
            out.extend(_table(before))

            for rel in JUNOS_FILES:
                shutil.copy2(ROOT / "packs" / rel, packs / rel)
            say("\nCopied `packs/vendors/junos.yaml` and `packs/fixes/junos.yaml` into the served packs folder. "
                "No restart.\n")
            say("Installed packs after: " + ", ".join(
                f"{p['id']}@{p['version']}" for p in client.get("/api/packs").json()["packs"]))
            client.post(f"/api/scans/{scan['scan_id']}/reevaluate").raise_for_status()
            scan = _wait(client, scan["scan_id"])
            after = _devices(client, scan)
            say(f"\nSame scan `{scan['scan_id']}`, re-evaluated:\n")
            out.extend(_table(after))

            say("\n## Gate 2.6 — confirm, reload, second run matches, no restart\n")
            clusters = client.get(f"/api/scans/{scan['scan_id']}/clusters").json()["clusters"]
            say(f"{len(clusters)} clusters of unrecognised lines. "
                f"{'All' if args.list_all else 'First ten'} by device count:\n")
            say("| devices | sample | top suggestion |")
            say("|---|---|---|")
            for c in clusters if args.list_all else clusters[:10]:
                sug = client.get(f"/api/clusters/{c['cluster_id']}/suggestions").json().get("candidates", [])
                top = f"{sug[0]['canonical_field']} ({sug[0]['score']:.2f})" if sug else "—"
                sample = c["sample_line"] if len(c["sample_line"]) <= 100 else c["sample_line"][:97] + "..."
                say(f"| {c['device_count']} | `{sample}` | {top} |")

            if args.confirm:
                needle, field = args.confirm.rsplit("=", 1)
                chosen = next(c for c in clusters if needle in c["sample_line"])
                body: dict[str, Any] = {"canonical_field": field, "absent": "unknown", "author": "demo (gate 2.6)"}
                if args.value is not None:
                    body["value"] = {"true": True, "false": False}.get(args.value, args.value)
                say(f"\nConfirming cluster `{chosen['sample_line']}` ({chosen['device_count']} devices) → `{field}`, "
                    f"as a human would. Body: `{body}`.\n")
                preview = client.post(f"/api/clusters/{chosen['cluster_id']}/confirm?dry_run=true", json=body)
                say(f"Dry run, HTTP {preview.status_code}. Fragment that would be written:\n")
                say("```yaml\n" + str(preview.json().get("fragment_yaml", preview.json())).rstrip() + "\n```")
                done = client.post(f"/api/clusters/{chosen['cluster_id']}/confirm", json=body)
                say(f"\nConfirm: HTTP {done.status_code}. `packs/learned/junos.yaml` exists in the served folder: "
                    f"{(packs / 'learned' / 'junos.yaml').exists()}.\n")
                done.raise_for_status()

                client.post(f"/api/scans/{scan['scan_id']}/reevaluate").raise_for_status()
                scan = _wait(client, scan["scan_id"])
                second = _devices(client, scan)
                remaining = client.get(f"/api/scans/{scan['scan_id']}/clusters").json()["clusters"]
                still = any(c["sample_line"] == chosen["sample_line"] for c in remaining)
                say(f"Re-evaluated `{scan['scan_id']}`: {len(remaining)} clusters; the confirmed one is "
                    f"{'STILL listed' if still else 'gone from the question list'}.\n")
                out.extend(_table(second))
                say("\nCoverage per device, before the confirm → after (`coverage` from the device endpoint):\n")
                for device_id in second:
                    say(f"- {device_id}: `{after[device_id].get('coverage')}` → `{second[device_id].get('coverage')}`")
                fresh_scan = _scan(client)
                fresh = _devices(client, fresh_scan)
                same = _findings(fresh) == _findings(second) and all(
                    fresh[k].get("coverage") == second[k].get("coverage") for k in second)
                say(f"\nFresh scan `{fresh_scan['scan_id']}` of the same files: findings and coverage "
                    f"{'IDENTICAL' if same else 'DIFFERENT'} to the re-evaluated scan.")
            say(f"\nProcess {os.getpid()} served every request above; the server was never restarted.")
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n".join(out))


if __name__ == "__main__":
    main()
