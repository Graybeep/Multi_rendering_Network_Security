"""`scan ./configs --framework cis --out ./reports`

Each device runs in a worker process with a hard timeout. A hung or crashing device becomes one
error row; the pool is torn down and rebuilt so the rest of the batch continues.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.audit import audit_device
from src.registry import Registry
from src.report.pdf import render_pdf

MAX_BYTES = 5 * 1024 * 1024
DEFAULT_PACKS = Path(__file__).resolve().parents[2] / "packs"

_registry: Registry | None = None  # per worker process


def _worker(path: str, device_id: str, packs: str, frameworks: list[str]) -> dict[str, Any]:
    global _registry
    if _registry is None or _registry.root != Path(packs):
        _registry = Registry(Path(packs))
    p = Path(path)
    try:
        text = p.read_bytes().decode("utf-8", errors="replace")
        return audit_device(text, p.name, device_id, _registry.snapshot(), _registry.catalogue, frameworks)
    except Exception as exc:  # noqa: BLE001 — per-device isolation: one bad file never kills the batch
        return {"device_id": device_id, "filename": p.name, "status": "error",
                "error": f"{type(exc).__name__}: {exc}"[:300]}


def _collect(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(p for p in target.rglob("*") if p.is_file() and not p.name.startswith(".")
                  and p.suffix.lower() not in {".md", ".txt", ".pdf", ".json"})


def _device_ids(paths: list[Path]) -> list[str]:
    seen: dict[str, int] = {}
    out = []
    for p in paths:
        base = re.sub(r"[^A-Za-z0-9_-]", "_", p.stem)[:56] or "device"
        n = seen.get(base, 0)
        seen[base] = n + 1
        out.append(base if n == 0 else f"{base}-{n + 1}")
    return out


def run(paths: list[Path], frameworks: list[str], packs: Path, workers: int, timeout: float) -> list[dict[str, Any]]:
    ids = _device_ids(paths)
    results: dict[int, dict[str, Any]] = {}
    pending = list(range(len(paths)))
    for i in list(pending):
        if paths[i].stat().st_size > MAX_BYTES:
            results[i] = {"device_id": ids[i], "filename": paths[i].name, "status": "error",
                          "error": f"file larger than {MAX_BYTES // (1024 * 1024)} MB"}
            pending.remove(i)

    ctx = mp.get_context("spawn")
    while pending:
        with ctx.Pool(processes=max(1, min(workers, len(pending)))) as pool:
            jobs = {i: pool.apply_async(_worker, (str(paths[i]), ids[i], str(packs), frameworks)) for i in pending}
            hung = None
            for i in pending:
                try:
                    results[i] = jobs[i].get(timeout=timeout)
                except mp.TimeoutError:
                    hung = i
                    break
            if hung is None:
                pending = []
            else:
                results[hung] = {"device_id": ids[hung], "filename": paths[hung].name, "status": "error",
                                 "error": f"timed out after {timeout:.0f}s; worker killed"}
                done = set(results)
                pending = [i for i in pending if i not in done]
                pool.terminate()
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
    args = ap.parse_args(argv)
    frameworks = args.frameworks or ["cis"]

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
    results = run(paths, frameworks, args.packs, args.workers, args.timeout)

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
