"""Run a batch of devices in worker processes. Shared by the CLI and the API; no file I/O here.

Each device runs in a worker process with a hard timeout. A hung or crashing device becomes one
error row; the pool is torn down and rebuilt so the rest of the batch continues. Config text is held
in memory only and never logged.
"""

from __future__ import annotations

import multiprocessing as mp
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.audit import audit_device
from src.registry import Registry

MAX_BYTES = 5 * 1024 * 1024

_registry: Registry | None = None  # per worker process


@dataclass(frozen=True)
class Job:
    device_id: str
    filename: str
    text: str


def error_row(device_id: str, filename: str, message: str) -> dict[str, Any]:
    return {"device_id": device_id, "filename": filename, "status": "error", "error": message}


def _worker(job: Job, packs: str, frameworks: list[str], os_version: str | None) -> dict[str, Any]:
    global _registry
    if _registry is None or _registry.root != Path(packs):
        _registry = Registry(Path(packs))
    try:
        return audit_device(job.text, job.filename, job.device_id, _registry.snapshot(), _registry.catalogue,
                            frameworks, os_version)
    except Exception as exc:  # noqa: BLE001 — per-device isolation: one bad file never kills the batch
        return error_row(job.device_id, job.filename, f"{type(exc).__name__}: {exc}"[:300])


def device_ids(filenames: list[str]) -> list[str]:
    """Stable, unique, URL-safe ids from file names."""
    seen: dict[str, int] = {}
    out = []
    for name in filenames:
        base = re.sub(r"[^A-Za-z0-9_-]", "_", Path(name).stem)[:56] or "device"
        n = seen.get(base, 0)
        seen[base] = n + 1
        out.append(base if n == 0 else f"{base}-{n + 1}")
    return out


def run_batch(jobs: list[Job], frameworks: list[str], packs: Path, workers: int, timeout: float,
              os_version: str | None = None,
              on_result: Callable[[int, dict[str, Any]], None] | None = None,
              on_start: Callable[[int], None] | None = None) -> list[dict[str, Any]]:
    """Results in job order. `on_start(i)` fires when job i is handed to a worker, `on_result(i, r)` as each lands."""
    results: dict[int, dict[str, Any]] = {}

    def land(i: int, result: dict[str, Any]) -> None:
        results[i] = result
        if on_result:
            on_result(i, result)

    pending = list(range(len(jobs)))
    ctx = mp.get_context("spawn")
    while pending:
        with ctx.Pool(processes=max(1, min(workers, len(pending)))) as pool:
            handles = {}
            for i in pending:
                handles[i] = pool.apply_async(_worker, (jobs[i], str(packs), frameworks, os_version))
                if on_start:
                    on_start(i)
            hung = None
            for i in pending:
                try:
                    land(i, handles[i].get(timeout=timeout))
                except mp.TimeoutError:
                    hung = i
                    break
            if hung is None:
                pending = []
            else:
                land(hung, error_row(jobs[hung].device_id, jobs[hung].filename,
                                     f"timed out after {timeout:.0f}s; worker killed"))
                pending = [i for i in pending if i not in results]
                pool.terminate()
    return [results[i] for i in range(len(jobs))]
