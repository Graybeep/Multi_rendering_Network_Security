"""Local HTTP API implementing docs/openapi.yaml. Bound to 127.0.0.1 only; nothing is exposed to the network.

Scans live in memory for the life of the process. Uploaded config text is held in memory so a scan
can be re-evaluated against newly installed packs; it is never written to disk and never logged.
Packs hot-reload: every scan takes a fresh registry snapshot, so a pack dropped into the packs
folder is used by the next scan or re-evaluation without a restart.
"""

from __future__ import annotations

import hashlib
import io
import multiprocessing as mp
import secrets
import threading
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from src.batch import MAX_BYTES, Job, device_ids, error_row, run_batch
from src.mapping.canonical import SCHEMA_PATH
from src.registry import Registry
from src.report.pdf import render_pdf
from src.versions import release

HOST = "127.0.0.1"
DEFAULT_PACKS = Path(__file__).resolve().parents[2] / "packs"
FRAMEWORKS = ("cis", "nist", "stig", "iso")
MAX_UPLOAD = 100 * 1024 * 1024  # whole request, archives expanded
MAX_DEVICES = 1000
MAX_SCANS = 50  # oldest finished scans are dropped beyond this
# The Vite dev and preview servers. Loopback origins only.
ALLOWED_ORIGINS = [f"http://{h}:{p}" for h in ("127.0.0.1", "localhost") for p in (5173, 4173)]
_SUMMARY_KEYS = ("device_id", "filename", "status", "error", "vendor_pack", "detection_ambiguous",
                 "identity", "verdicts", "coverage")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, field: str | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.field = status, code, message, field


@dataclass
class Device:
    device_id: str
    filename: str
    text: str | None  # None when the upload itself was rejected (too large, unreadable archive member)
    status: str = "queued"
    result: dict[str, Any] | None = None

    def summary(self) -> dict[str, Any]:
        if self.result is None:
            return {"device_id": self.device_id, "filename": self.filename, "status": self.status}
        return {k: self.result[k] for k in _SUMMARY_KEYS if k in self.result}


@dataclass
class Scan:
    scan_id: str
    frameworks: list[str]
    os_version: str | None
    created_at: datetime
    devices: list[Device]
    status: str = "queued"
    lock: threading.Lock = field(default_factory=threading.Lock)

    def view(self) -> dict[str, Any]:
        with self.lock:
            devices = [d.summary() for d in self.devices]
            status = self.status
        return {"scan_id": self.scan_id, "status": status, "frameworks": self.frameworks,
                "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
                "progress": {"total": len(devices), "done": sum(d["status"] == "done" for d in devices),
                             "error": sum(d["status"] == "error" for d in devices)},
                "devices": devices}


def _expand_upload(name: str, data: bytes) -> list[tuple[str, bytes | None, str | None]]:
    """(filename, bytes or None, error). Archives become one entry per member; a bad archive is one error entry."""
    if not (name.lower().endswith(".zip") or data[:4] == b"PK\x03\x04"):
        if len(data) > MAX_BYTES:
            return [(name, None, f"file larger than {MAX_BYTES // (1024 * 1024)} MB")]
        return [(name, data, None)]
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        members = [m for m in archive.infolist() if not m.is_dir()]
    except zipfile.BadZipFile:
        return [(name, None, "not a readable zip archive")]
    out: list[tuple[str, bytes | None, str | None]] = []
    for m in members:
        base = Path(m.filename).name
        if not base or base.startswith(".") or m.filename.startswith("__MACOSX/"):
            continue
        if m.flag_bits & 0x1:
            out.append((base, None, "encrypted archive member"))
        elif base.lower().endswith(".zip"):
            out.append((base, None, "nested archives are not expanded"))
        elif m.file_size > MAX_BYTES:
            out.append((base, None, f"file larger than {MAX_BYTES // (1024 * 1024)} MB"))
        else:
            with archive.open(m) as fh:
                body = fh.read(MAX_BYTES + 1)  # never trust the declared size
            if len(body) > MAX_BYTES:
                out.append((base, None, f"file larger than {MAX_BYTES // (1024 * 1024)} MB"))
            else:
                out.append((base, body, None))
    return out


def create_app(packs: Path = DEFAULT_PACKS, workers: int | None = None, timeout: float = 60.0) -> FastAPI:
    app = FastAPI(title="Wi-fight configuration compliance auditor", version="0.1.0",
                  docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=["GET", "POST"],
                       allow_headers=["Content-Type"])
    registry = Registry(packs)
    pool_size = workers or max(1, (mp.cpu_count() or 2) - 1)
    scans: dict[str, Scan] = {}
    scans_lock = threading.Lock()
    schema_version = "canonical@" + hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()[:12]

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse({"code": exc.code, "message": exc.message, "field": exc.field}, status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def _bad_request(_: Request, exc: RequestValidationError) -> JSONResponse:
        first = exc.errors()[0] if exc.errors() else {}
        loc = ".".join(str(p) for p in first.get("loc", [])[1:]) or None
        return JSONResponse({"code": "bad_request", "message": first.get("msg", "malformed request"),
                             "field": loc}, status_code=400)

    def _scan(scan_id: str) -> Scan:
        with scans_lock:
            scan = scans.get(scan_id)
        if scan is None:
            raise ApiError(404, "not_found", f"no scan {scan_id!r}")
        return scan

    def _device(scan: Scan, device_id: str) -> Device:
        device = next((d for d in scan.devices if d.device_id == device_id), None)
        if device is None:
            raise ApiError(404, "not_found", f"no device {device_id!r} in scan {scan.scan_id!r}")
        with scan.lock:
            if device.status == "error":
                raise ApiError(409, "device_error", (device.result or {}).get("error") or "device ended in error")
            if device.status != "done" or device.result is None:
                raise ApiError(409, "not_ready", f"device is {device.status}; poll the scan until it is done")
            return device

    def _run(scan: Scan) -> None:
        runnable = [i for i, d in enumerate(scan.devices) if d.text is not None]
        jobs = [Job(scan.devices[i].device_id, scan.devices[i].filename, scan.devices[i].text or "")
                for i in runnable]

        def started(j: int) -> None:
            with scan.lock:
                scan.devices[runnable[j]].status = "parsing"

        def landed(j: int, result: dict[str, Any]) -> None:
            with scan.lock:
                device = scan.devices[runnable[j]]
                device.result, device.status = result, result["status"]

        try:
            registry.snapshot()  # reload packs before the workers start, so errors surface once
            with scan.lock:
                scan.status = "running"
            run_batch(jobs, scan.frameworks, registry.root, pool_size, timeout, scan.os_version,
                      on_result=landed, on_start=started)
            with scan.lock:
                scan.status = "completed"
        except Exception:  # noqa: BLE001 — the scan is marked failed; per-device rows keep what landed
            with scan.lock:
                scan.status = "failed"

    def _start(scan: Scan) -> None:
        threading.Thread(target=_run, args=(scan,), name=f"scan-{scan.scan_id}", daemon=True).start()

    @app.post("/api/scans", status_code=202)
    async def create_scan(files: Annotated[list[UploadFile], File()],
                          frameworks: Annotated[list[str], Form()],
                          os_version: Annotated[str | None, Form()] = None) -> dict[str, str]:
        bad = [f for f in frameworks if f not in FRAMEWORKS]
        if bad:
            raise ApiError(400, "bad_framework", f"unknown framework(s) {bad}; expected {list(FRAMEWORKS)}",
                           "frameworks")
        if os_version is not None and release(os_version) is None:
            raise ApiError(400, "bad_os_version", "os_version must start with a release number like 15.1",
                           "os_version")
        entries: list[tuple[str, bytes | None, str | None]] = []
        total = 0
        for upload in files:
            data = await upload.read(MAX_UPLOAD + 1)
            total += len(data)
            if total > MAX_UPLOAD:
                raise ApiError(413, "too_large", f"upload exceeds {MAX_UPLOAD // (1024 * 1024)} MB", "files")
            entries.extend(_expand_upload(Path(upload.filename or "upload").name, data))
            if sum(len(b) for _, b, _ in entries if b) > MAX_UPLOAD:
                raise ApiError(413, "too_large", "archives expand beyond the upload limit", "files")
        if not entries:
            raise ApiError(400, "no_files", "no configuration files in the upload", "files")
        if len(entries) > MAX_DEVICES:
            raise ApiError(413, "too_many_devices", f"more than {MAX_DEVICES} devices in one scan", "files")

        ids = device_ids([name for name, _, _ in entries])
        devices = []
        for device_id, (name, body, err) in zip(ids, entries, strict=True):
            if body is None:
                devices.append(Device(device_id, name, None, "error", error_row(device_id, name, err or "")))
            else:
                devices.append(Device(device_id, name, body.decode("utf-8", errors="replace")))
        scan = Scan("s" + secrets.token_hex(8), list(dict.fromkeys(frameworks)), os_version, datetime.now(UTC),
                    devices)
        with scans_lock:
            finished = [s for s in scans.values() if s.status in ("completed", "failed")]
            for old in sorted(finished, key=lambda s: s.created_at)[: max(0, len(scans) + 1 - MAX_SCANS)]:
                del scans[old.scan_id]
            scans[scan.scan_id] = scan
        _start(scan)
        return {"scan_id": scan.scan_id}

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str) -> dict[str, Any]:
        return _scan(scan_id).view()

    @app.get("/api/scans/{scan_id}/devices/{device_id}")
    def get_device(scan_id: str, device_id: str) -> dict[str, Any]:
        result = _device(_scan(scan_id), device_id).result
        assert result is not None
        return result

    @app.get("/api/scans/{scan_id}/devices/{device_id}/report")
    def get_report(scan_id: str, device_id: str) -> Response:
        scan = _scan(scan_id)
        device = _device(scan, device_id)
        assert device.result is not None
        pdf = render_pdf(device.result, scan.created_at.strftime("%Y-%m-%d %H:%M UTC"))
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition": f'inline; filename="{device.device_id}.pdf"'})

    @app.post("/api/scans/{scan_id}/reevaluate", status_code=202)
    def reevaluate(scan_id: str) -> dict[str, str]:
        scan = _scan(scan_id)
        with scan.lock:
            if scan.status in ("queued", "running"):
                raise ApiError(409, "scan_running", "the scan is still running; re-evaluate when it completes")
            for d in scan.devices:
                if d.text is not None:
                    d.status, d.result = "queued", None
            scan.status = "queued"
        _start(scan)
        return {"scan_id": scan.scan_id}

    @app.get("/api/schema/fields")
    def schema_fields() -> dict[str, Any]:
        out = []
        for path, spec in registry.catalogue.fields.items():
            vs = spec.value_schema or {}
            kind = vs.get("type", "array" if spec.collection else "string")
            kind = next((t for t in kind if t != "null"), "string") if isinstance(kind, list) else kind
            out.append({"path": path, "type": "array" if spec.collection else kind,
                        "enum": vs.get("enum"), "description": spec.description,
                        "absent": spec.absent, "collection": spec.collection})
        return {"schema_version": schema_version, "fields": out}

    @app.get("/api/packs")
    def list_packs() -> dict[str, Any]:
        return {"packs": registry.snapshot().packs()}

    def _not_built(what: str) -> None:
        raise ApiError(501, "not_implemented", f"{what} arrives with the learning loop (PLAN 2.3-2.6)")

    @app.get("/api/scans/{scan_id}/clusters")
    def list_clusters(scan_id: str) -> None:
        _scan(scan_id)
        _not_built("clustering of unrecognised lines")

    @app.get("/api/clusters/{cluster_id}/suggestions")
    def cluster_suggestions(cluster_id: str) -> None:
        _not_built("ranked suggestions")

    @app.post("/api/clusters/{cluster_id}/confirm")
    def confirm_cluster(cluster_id: str) -> None:
        _not_built("confirming a mapping")

    return app


app = create_app()
