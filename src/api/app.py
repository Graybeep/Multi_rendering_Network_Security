"""Local HTTP API implementing docs/openapi.yaml. Bound to 127.0.0.1 only; nothing is exposed to the network.

Scans live in memory for the life of the process. Uploaded config text is held in memory so a scan
can be re-evaluated against newly installed packs; it is never written to disk and never logged.
Packs hot-reload: every scan takes a fresh registry snapshot, so a pack dropped into the packs
folder is used by the next scan or re-evaluation without a restart.

The learning loop writes only `packs/learned/<vendor>.yaml`, and only after a human confirms. A
confirmed mapping, or an ignore entry ("not a security setting"), is validated with the same loader and
fixture checks as a shipped pack before the file is replaced, so a bad answer is refused rather than
half-applied.
"""

from __future__ import annotations

import hashlib
import io
import multiprocessing as mp
import os
import secrets
import tempfile
import threading
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import yaml
from fastapi import Body, FastAPI, File, Form, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from src.batch import MAX_BYTES, Job, device_ids, error_row, run_batch
from src.learning.author import AuthorError, append, author_ignore, author_mapping
from src.learning.cluster import Cluster, build_clusters
from src.learning.rank import rank
from src.mapping.canonical import SCHEMA_PATH
from src.mapping.engine import match_line
from src.mapping.pack import load_vendor_pack, merge_learned
from src.packs import PackError, read_yaml, validate_pack
from src.registry import Registry, check_fixtures
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
_CONFIRM_KEYS = {"canonical_field", "absent", "default", "default_os_version", "value", "author"}
_IGNORE_KEYS = {"reason", "author"}
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

    clusters: dict[str, Cluster] = {}  # latest occurrence data per cluster id, across scans
    learn_lock = threading.Lock()  # one learned-pack write at a time

    @app.get("/api/scans/{scan_id}/clusters")
    def list_clusters(scan_id: str) -> dict[str, Any]:
        scan = _scan(scan_id)
        with scan.lock:
            results = [d.result for d in scan.devices if d.status == "done" and d.result is not None]
        found = build_clusters(results, registry.catalogue)
        with learn_lock:
            clusters.update((c.cluster_id, c) for c in found)
        return {"scan_id": scan.scan_id, "clusters": [c.view() for c in found]}

    def _cluster(cluster_id: str) -> Cluster:
        with learn_lock:
            cluster = clusters.get(cluster_id)
        if cluster is None:
            raise ApiError(404, "not_found", f"no cluster {cluster_id!r}; list a scan's clusters first")
        return cluster

    @app.get("/api/clusters/{cluster_id}/suggestions")
    def cluster_suggestions(cluster_id: str) -> dict[str, Any]:
        return {"cluster_id": cluster_id, "candidates": rank(_cluster(cluster_id), registry.catalogue)}

    @app.post("/api/clusters/{cluster_id}/confirm")
    def confirm_cluster(cluster_id: str, body: Annotated[Any, Body()], dry_run: bool = False) -> dict[str, Any]:
        cluster = _cluster(cluster_id)
        request = _confirm_request(body)
        return _learn(cluster, lambda created: author_mapping(cluster, request, registry.catalogue, created),
                      dry_run)

    @app.post("/api/clusters/{cluster_id}/ignore")
    def ignore_cluster(cluster_id: str, body: Annotated[Any, Body()], dry_run: bool = False) -> dict[str, Any]:
        cluster = _cluster(cluster_id)
        request = _ignore_request(body)
        _refuse_if_mapped(cluster)
        return _learn(cluster, lambda created: author_ignore(cluster, request, created), dry_run)

    def _refuse_if_mapped(cluster: Cluster) -> None:
        """A line a mapping matches but cannot read is a gap in that mapping, not a line without a setting."""
        pack = registry.snapshot().vendors.get(cluster.vendor)
        if pack is None:
            raise ApiError(409, "pack_missing", f"vendor pack {cluster.vendor!r} is no longer installed")
        for m in cluster.members:
            hits = match_line(pack, m.text, m.parent_text, 0, [])
            if hits:
                ids = ", ".join(sorted(h[0].id for h in hits))
                raise ApiError(409, "conflict", f"mapping {ids} matches this line but cannot read it, so it may "
                               "carry a setting; extend that mapping instead of ignoring the line")

    def _learn(cluster: Cluster, author: Callable[[str], dict[str, Any]], dry_run: bool) -> dict[str, Any]:
        vendor_path = registry.root / "vendors" / f"{cluster.vendor}.yaml"
        if not vendor_path.exists():
            raise ApiError(409, "pack_missing", f"vendor pack {cluster.vendor!r} is no longer installed")
        learned_path = registry.root / "learned" / f"{cluster.vendor}.yaml"
        created = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        with learn_lock:
            try:
                mapping = author(created)
            except AuthorError as exc:
                raise ApiError(exc.status, "not_learnable", str(exc), exc.field) from exc
            current = read_yaml(learned_path) if learned_path.exists() else None
            doc, fragment = append(current, cluster.vendor, mapping)
            text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=1_000_000)
            _validate_learned(vendor_path, learned_path.name, text)
            if not dry_run:
                learned_path.parent.mkdir(exist_ok=True)
                fd, tmp = tempfile.mkstemp(dir=learned_path.parent, prefix=".", suffix=".tmp")
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(text)
                os.replace(tmp, learned_path)  # atomic: the registry never sees half a file
                registry.snapshot()  # reload now, so the next scan or re-evaluation uses it
        return {"written": not dry_run, "pack_path": f"{registry.root.name}/learned/{learned_path.name}",
                "pack_version": doc["version"], "mapping_id": mapping["id"], "fragment_yaml": fragment}

    def _confirm_request(body: Any) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise ApiError(422, "unprocessable", "body must be a JSON object")
        extra = sorted(set(body) - _CONFIRM_KEYS)
        if extra:
            raise ApiError(422, "unprocessable", f"unknown field(s) {extra}", extra[0])
        if not isinstance(body.get("canonical_field"), str):
            raise ApiError(422, "unprocessable", "canonical_field is required", "canonical_field")
        if body.get("absent") not in ("unknown", "default"):
            raise ApiError(422, "unprocessable", "absent must be 'unknown' or 'default'", "absent")
        for name in ("author", "default_os_version"):
            if body.get(name) is not None and not isinstance(body[name], str):
                raise ApiError(422, "unprocessable", f"{name} must be a string", name)
        return body

    def _ignore_request(body: Any) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise ApiError(422, "unprocessable", "body must be a JSON object")
        extra = sorted(set(body) - _IGNORE_KEYS)
        if extra:
            raise ApiError(422, "unprocessable", f"unknown field(s) {extra}", extra[0])
        for name in ("reason", "author"):
            if body.get(name) is not None and not isinstance(body[name], str):
                raise ApiError(422, "unprocessable", f"{name} must be a string", name)
        return body

    def _validate_learned(vendor_path: Path, name: str, text: str) -> None:
        """The learned pack as it would be written must load beside its vendor pack, fixtures and all."""
        try:
            validate_pack(yaml.safe_load(text), "learned_pack", name)
        except PackError as exc:
            raise ApiError(422, "unprocessable", str(exc)) from exc
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / name
            candidate.write_text(text, encoding="utf-8")
            try:
                merged = merge_learned(load_vendor_pack(vendor_path, registry.catalogue), candidate,
                                       registry.catalogue)
                check_fixtures(merged, registry.catalogue)
            except PackError as exc:
                raise ApiError(409, "conflict", str(exc)) from exc

    return app


app = create_app()
