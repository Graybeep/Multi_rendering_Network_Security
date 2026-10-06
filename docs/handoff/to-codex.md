# Handoff log: Claude Code → Codex

Append-only. Newest entry at the bottom. Each entry: what landed, what did not, what is now unblocked for you.
Backend never edits `web/`; you never edit `src/`, `packs/`, `schemas/`. API changes go through `docs/openapi.yaml`.

---

## 2026-10-05 · Phase 0 contracts

**Landed:** `docs/openapi.yaml` (OpenAPI 3.1, validated, serves under Prism) and `schemas/canonical.schema.json` (54 canonical fields, 8 collections).
**Not landed:** golden fixture (0.5), any real endpoint.
**Unblocked for you — start PLAN 1.10 and 1.11 now:**
- Run the mock: `npx -y @stoplight/prism-cli@5 mock docs/openapi.yaml -h 127.0.0.1 -p 8001` (`make` is not installed on this machine).
- Generate the client from `docs/openapi.yaml`; do not hand-write types.
- Upload + scan progress: `POST /api/scans` (multipart `files[]`, `frameworks[]`) → poll `GET /api/scans/{id}`. A device with `status: error` is one row, not a failed batch.
- Findings: `GET /api/scans/{id}/devices/{device_id}`. `NOT_DETERMINED` carries `missing_fields`; render it distinct from FAIL. Show `coverage` beside any score.
- Training (Phase 2, preview only): `POST /api/clusters/{id}/confirm?dry_run=true` returns the YAML that would be written; use it for "show before writing".

---

## 2026-10-05 · Phase 1 backend (PLAN 1.1–1.9)

**Landed:** the CLI audits real Cisco IOS configs end to end and writes a PDF and a JSON file per device:
`python -m src.cli.main fixtures/configs/batfish_example_live --framework cis --out ./reports`.
That covers the reader, pack loader with hot reload, mapping engine, `cisco_ios.yaml` (47 mappings),
the three-state evaluator, `cis.yaml` (15 rules), fix templates and the PDF. 61 tests pass, ruff and
strict mypy are clean, and the engine's real output validates against `DeviceFindings` in `docs/openapi.yaml`.

**Not landed:** the FastAPI server (`make api`). Keep building against the mock; only the base URL will change.

**Contract changes (all additive, already in `docs/openapi.yaml`). Regenerate your client:**
- `Finding.control`: null means no human has cited the benchmark control yet. Render it as "uncited"; never show a guessed ID.
- `Finding.error`, `Finding.fix_pack_version`.
- `EvidenceLine.value`: for `state: defaulted` there is no config line (`line_no: null`, `text: null`). Show it as
  "not configured; pack default = <value>" so the user can see the verdict rests on a default.
- `Remediation.operator_input`: placeholders such as `<NEW_SECRET>` and `<MGMT_ACL>`. Highlight them, and do not let
  the copy button hide that they must be replaced. `Remediation.note` is a safety warning (lock-out risk). Show it with the commands.
- `remediation` can be null on a FAIL. This happens when no template fits that OS version (e.g. scrypt needs IOS 15.3+).
  Say "no remediation for this OS version" rather than leaving a blank.

**Real data you can look at (not invented):** `docs/examples/device_findings.as2dept1.json` is the engine's actual output
for a real Batfish config (as2dept1: 9 FAIL, 4 PASS, 2 NOT_DETERMINED, 76% coverage). Use it to check layout against
realistic shapes: a FAIL with 5 interfaces in evidence, NOT_DETERMINED with `missing_fields`, and a FAIL with null
remediation. Do not ship it as placeholder data in the UI.

**Unblocked for you:** PLAN 1.10 (upload and progress) and 1.11 (findings screen). For 1.11, note the evidence layout
for per-item rules: rows come in groups, the item's key row (e.g. `interfaces[].name`, "interface Loopback0", line 51)
followed by its attribute rows.

---

## 2026-10-06 · Phase 0 gaps closed, Phase 2.1 reader

**Landed:** CI (`.github/workflows/ci.yml`, backend only), README, Junos / FortiOS / NX-OS fixtures, a redaction fix for
Junos and FortiOS secrets, and the `set_commands` reader (PLAN 2.1). Reader order changed: `set_commands` now, `brace_tree`
in Phase 3. A Junos config with no Junos pack currently audits as 0 FAIL / 15 NOT_DETERMINED — that is demo beat 2.
**Not landed:** `junos.yaml` (2.2), the FastAPI server. **No change to `docs/openapi.yaml`.**
**Unblocked for you:** nothing new on the contract. If you want a real beat-2 screen, the fixture
`fixtures/configs/batfish_example_juniper/as1border1.cfg` produces an all-NOT_DETERMINED device via the CLI.

---

## 2026-10-06 · Junos pack (PLAN 2.2)

**Landed:** `packs/vendors/junos.yaml`. The 15 CIS rules run unchanged on Junos. The SRX fixtures audit to 7 FAIL / 2 PASS /
6 NOT_DETERMINED, each finding citing its `set` line. Junos output validates against `DeviceFindings`.
**Not landed:** Junos fix templates, so Junos FAILs have `remediation: null`. Render that as "no automated fix", not as an error.
New: a device can carry the warning "configuration is inherited from elsewhere in the file and not resolved…". Show device
warnings next to the verdict counts. **No change to `docs/openapi.yaml`.**
**Unblocked for you:** real two-vendor output for the results screen:
`python -m src.cli.main fixtures/configs/batfish_srx_testbed --framework cis --out ./reports`.
