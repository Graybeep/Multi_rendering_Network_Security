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

---

## 2026-10-06 · Real API server, Junos fixes, review corrections

**Landed:** `make api` / `python -m src.api` serves the contract on 127.0.0.1:8000. CORS allows the Vite dev and preview
origins (127.0.0.1 and localhost, ports 5173 and 4173). Set `VITE_API_BASE_URL=http://127.0.0.1:8000` to leave the mock.
Junos FAILs now carry remediation; every fix ends in `commit confirmed 5`.
**Contract changes in `docs/openapi.yaml` (additive):**
- `POST /api/scans` accepts an optional `os_version` form field.
- `EvidenceLine.source`: `platform_constant` | `operator` | null. Show it for defaulted evidence, e.g. "platform fact",
  "supplied by operator".
- `missing_fields` may contain a list path ending in `[]` that was read only in part.
- `501 NotImplemented` (Error body) on clusters, suggestions and confirm until the learning loop lands. Render it as
  "not available yet", never as an empty queue.
- `409` on `reevaluate` while the scan is still running.
**Not landed:** the learning loop (clusters, suggestions, confirm), so the training screen stays on the mock.
**Unblocked for you:** upload, progress, findings, PDF and packs screens against the real backend; the 2.2 gate
(drop `junos.yaml` in, re-evaluate, no restart) works through `POST /api/scans/{id}/reevaluate`.

---

## 2026-10-07 · Learning loop (PLAN 2.3–2.6)

**Landed:** the three training endpoints are real, and none of them returns 501 any more. `GET /api/scans/{id}/clusters` groups unrecognised
lines across the scan (13 real IOS configs: about 1,000 lines become about 160 questions, most-shared first). `GET /api/clusters/{id}/suggestions`
ranks canonical fields lexically (right field in the top 3 for 54 of the 57 shipped mappings; that is a regression check on fixture lines, not accuracy: see `docs/ranking-eval.md`). `POST /api/clusters/{id}/confirm` writes
`packs/learned/<vendor>.yaml`, and after `POST /api/scans/{id}/reevaluate` the cluster is gone and the field is mapped. No restart is needed.
**Not landed:** embedding and LLM tiers (`tier` is always `lexical`); an "ignore this line" answer (routing noise such as
`boot-start-marker` and `end` stays in the queue).
**Contract changes in `docs/openapi.yaml`. Regenerate your client:**
- `501` removed from the three training endpoints, and the `NotImplemented` response component removed.
- `ConfirmRequest.default_os_version` (new, additive). It is required whenever `absent: "default"` is sent for a single-value field.
- A refused answer is `422` with `field` naming what to fix (`value`, `default`, `default_os_version`, `canonical_field`), or `409` when
  it contradicts an existing mapping or the cluster was already confirmed. Either way nothing is written. Show `message` verbatim:
  it tells the administrator what to state (e.g. "the line carries several values … state a fixed value").
- A true/false field always needs `value` in the request. The form should ask for it rather than default it.
- Cluster ids are stable across scans. A suggestions or confirm call for an id not listed since the server started is `404`.
- `Cluster.signature` placeholders: `<INT> <IPV4> <PREFIX> <IPV6> <MAC> <STR> <IFACE> <DOMAIN> <NAME>`.
**Unblocked for you:** PLAN 2.7 against the real backend: queue → suggestions → `dry_run=true` preview of `fragment_yaml` → confirm →
reevaluate. Real data to try: scan `fixtures/configs/batfish_example_live`. Questions such as `line con <INT> :: exec-timeout <INT> <INT>`
are real. That one returns 422 for `session.idle_timeout` on purpose, because it holds minutes and seconds.

---

## 2026-10-07 · "Not a security setting" (ignore)

**Your uncommitted `web/` changes are blocking your own PLAN 2.7 start.** Nine modified files and four new test files
in `web/` have sat uncommitted since the learning-loop handoff. Commit or discard them before building on the API
below.

**Landed:** `POST /api/clusters/{id}/ignore` with body `IgnoreRequest {reason (required), author?}` and `?dry_run=true`.
The response is `ConfirmResult`, and `mapping_id` is the ignore entry's id. After `POST /api/scans/{id}/reevaluate`
the cluster is gone, and **no verdict changes**: an ignore writes no field.
**UI contract (please hold to it):**
- "Not a security setting" is a **third button** beside confirming a field, not a variant of confirm.
- It is never the default and never pre-selected, whatever the suggestion scores are, including when `candidates`
  is empty.
- `reason` is a required free-text box, **empty** when the form opens. Never pre-fill it. A 422 with
  `field: "reason"` means it was blank.
- A 409 means a pack mapping matches the line but cannot read it, so the line may hold a setting. Show `message`
  verbatim. It tells the administrator that mapping needs extending.
- Show the `dry_run` preview before writing, as for confirm.
**Also:** `/api/packs` `mapping_count` for a learned pack now counts ignore entries too. Regenerate your client from
`docs/openapi.yaml` (new path and new `IgnoreRequest` schema; nothing removed or renamed).
**Expect most questions to be ignores.** In a random 30 of the 160 real IOS questions, 29 have no v1 field
(`docs/ranking-eval.md`). Low suggestion scores are the normal case, not an error state.
