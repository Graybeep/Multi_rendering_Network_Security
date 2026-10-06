"""`scan ./configs --framework cis --out ./reports`

Reads files, runs them through `src.batch`, writes JSON and PDF per device.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.batch import MAX_BYTES, Job, device_ids, error_row, run_batch
from src.registry import Registry
from src.report.pdf import render_pdf
from src.versions import release

DEFAULT_PACKS = Path(__file__).resolve().parents[2] / "packs"


def _collect(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(p for p in target.rglob("*") if p.is_file() and not p.name.startswith(".")
                  and p.suffix.lower() not in {".md", ".txt", ".pdf", ".json"})


def run(paths: list[Path], frameworks: list[str], packs: Path, workers: int, timeout: float,
        os_version: str | None = None) -> list[dict[str, Any]]:
    ids = device_ids([p.name for p in paths])
    results: dict[int, dict[str, Any]] = {}
    jobs: list[Job] = []
    index: list[int] = []
    for i, p in enumerate(paths):
        if p.stat().st_size > MAX_BYTES:
            results[i] = error_row(ids[i], p.name, f"file larger than {MAX_BYTES // (1024 * 1024)} MB")
            continue
        jobs.append(Job(ids[i], p.name, p.read_bytes().decode("utf-8", errors="replace")))
        index.append(i)
    for i, r in zip(index, run_batch(jobs, frameworks, packs, workers, timeout, os_version), strict=True):
        results[i] = r
    return [results[i] for i in range(len(paths))]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scan", description="Audit network device configurations.")
    ap.add_argument("target", type=Path, help="config file or directory")
    ap.add_argument("--framework", action="append", dest="frameworks",
                    choices=["cis", "nist", "stig", "iso"], help="repeatable; default cis")
    ap.add_argument("--out", type=Path, required=True, help="output directory for JSON and PDF")
    ap.add_argument("--packs", type=Path, default=DEFAULT_PACKS, help="pack directory")
    ap.add_argument("--workers", type=int, default=max(1, (mp.cpu_count() or 2) - 1))
    ap.add_argument("--timeout", type=float, default=60.0, help="per-device seconds")
    ap.add_argument("--os-version", help="OS version to assume for devices whose config states none "
                                         "(recorded as operator-supplied; a version in the config wins)")
    args = ap.parse_args(argv)
    frameworks = args.frameworks or ["cis"]
    if args.os_version is not None and release(args.os_version) is None:
        print(f"scan: --os-version {args.os_version!r} does not start with a release number like 15.1",
              file=sys.stderr)
        return 2

    if not args.target.exists():
        print(f"scan: {args.target} does not exist", file=sys.stderr)
        return 2
    registry = Registry(args.packs)
    snap = registry.snapshot()
    for err in snap.errors:
        print(f"pack rejected: {err}", file=sys.stderr)
    if not snap.vendors:
        print("scan: no usable vendor pack; every rule would be NOT_DETERMINED", file=sys.stderr)

    paths = _collect(args.target)
    if not paths:
        print(f"scan: no configuration files under {args.target}", file=sys.stderr)
        return 2
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    results = run(paths, frameworks, args.packs, args.workers, args.timeout, args.os_version)

    args.out.mkdir(parents=True, exist_ok=True)
    print(f"{'device':<24} {'status':<6} {'FAIL':>4} {'PASS':>4} {'N/D':>4} {'coverage':>8}  pack")
    for r in results:
        stem = args.out / r["device_id"]
        stem.with_suffix(".json").write_text(json.dumps(r, indent=2), encoding="utf-8")
        if r["status"] == "done":
            stem.with_suffix(".pdf").write_bytes(render_pdf(r, generated))
            v = r["verdicts"]
            print(f"{r['device_id']:<24} {'done':<6} {v['fail']:>4} {v['pass']:>4} {v['not_determined']:>4} "
                  f"{100 * r['coverage']['ratio']:>7.0f}%  {r['vendor_pack'] or '-'}")
        else:
            print(f"{r['device_id']:<24} error  {r['error']}")
    summary = [{k: r.get(k) for k in ("device_id", "filename", "status", "error", "vendor_pack",
                                       "verdicts", "coverage")} for r in results]
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\n{len(results)} device(s) written to {args.out}")
    return 0 if all(r["status"] == "done" for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
