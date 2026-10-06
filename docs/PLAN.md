# Build Plan

21 working days. Compress by cutting Phase 3 scope, never by skipping Phase 0.

**CC** = Claude Code (backend, engine, packs) · **CX** = Codex (frontend) ·
**H** = humans, no agent

Definition of done for the whole build is the **four demo beats** in §6. If a
feature does not appear in those four beats, it is not in v1.

---

## Phase 0 — Contracts (Days 1–2) · SERIAL, DO NOT PARALLELISE

Two days of serial work here saves a week of integration debt. Nothing else starts
until these exist.

| # | Task | Owner | Done when |
|---|---|---|---|
| 0.1 | Pull 15–20 real configs from `github.com/batfish/batfish/tree/master/networks` into `fixtures/configs/`. Cisco IOS and NX-OS minimum, plus one Junos and one FortiOS | H | Files committed, licences noted |
| 0.2 | **Every team member reads three full configs end to end** | H | Done. This is not optional |
| 0.3 | Write `schemas/canonical.schema.json` — the ~45 fields in ARCHITECTURE §4, each with path, type, description, absent-semantics | H + CC | Validates, includes at least two collections |
| 0.4 | Write `docs/openapi.yaml` from ARCHITECTURE §7 | CC | `make mock` serves it |
| 0.5 | Commit one Cisco config + its expected canonical JSON as `fixtures/golden/` | H + CC | Both agents can assert against it |
| 0.6 | Repo skeleton, `Makefile`, CI running `make test lint` | CC | Green on an empty test suite |
| 0.7 | README skeleton with setup instructions | H | Exists. Grow it daily, not on the last night |

**Gate:** nobody proceeds until 0.3, 0.4 and 0.5 are committed.

---

## Phase 1 — Vertical slice (Days 3–7)

One vendor, end to end, ugly is fine. Build `indent_blocks` **only** — the other
four readers are Phase 2 or later.

| # | Task | Owner | Done when |
|---|---|---|---|
| 1.1 | `indent_blocks` reader producing a line-numbered tree | CC | Golden fixture round-trips |
| 1.2 | Pack loader + JSON Schema validation + registry with hot reload | CC | Invalid pack is rejected with a useful error |
| 1.3 | Mapping engine with first-token dispatch and the `{value,state,evidence}` triple | CC | Golden canonical JSON matches exactly |
| 1.4 | `cisco_ios.yaml` with ~25 mappings, each carrying a fixture | H + CC | All mapping fixtures pass |
| 1.5 | Rule evaluator with three-state verdicts and the `requires` gate | CC | Empty-collection case returns NOT_DETERMINED, with a test |
| 1.6 | `cis.yaml` with 15 rules, each with pass and fail fixtures | H + CC | 30 fixtures green |
| 1.7 | Fix templates for those 15 rules | H + CC | Rendered CLI is idempotent |
| 1.8 | PDF report: identification, findings by severity, cited lines, remediation | CC | A real PDF opens |
| 1.9 | CLI: `scan ./configs --framework cis --out ./reports` | CC | Works on the fixture set |
| 1.10 | Upload + scan-progress screens against the mock | CX | Four states each, mock only |
| 1.11 | Findings screen: verdict, evidence line, remediation block | CX | NOT_DETERMINED visually distinct from FAIL |

**Gate (end of Day 7):** the CLI audits a real Cisco config and produces a PDF you
would show a judge. If this slips, cut Phase 3, not Phase 1.

---

## Phase 2 — Second vendor and the learning loop (Days 8–12)

This is where the architecture stops being theoretical.

| # | Task | Owner | Done when |
|---|---|---|---|
| 2.1 | `set_commands` reader (Junos flat `set` syntax: each line is path + value) | CC | `as1border1/2` and the 3 SRX fixtures produce trees; `apply-groups` decision recorded (see hazards) |
| 2.2 | `junos.yaml` pack mapping to the **same** canonical fields as `cisco_ios.yaml` | H + CC | The 15 CIS rules run unchanged on Junos |
| 2.3 | Template signature normaliser (strip IPs, hostnames, interface names, integers) | CC | `idle-timeout 600` and `900` collapse to one signature |
| 2.4 | Clustering across a batch, sorted by device count | CC | 20 files → a short question list |
| 2.5 | Lexical ranking against canonical field descriptions (TF-IDF + token overlap) | CC | Correct field in top 3 on fixture cases |
| 2.6 | Confirm endpoint → write `packs/learned/<vendor>.yaml` → registry reload → cache invalidate | CC | Second run matches exactly, no restart |
| 2.7 | Training screen: cluster queue with device counts, ranked suggestions, confirm | CX | Human must click; no auto-apply |
| 2.8 | Fan-out job model, process pool, per-device isolation, parse cache | CC | One corrupt file does not kill the batch |

**Reader order (decided 2026-10-06):** `set_commands` first, `brace_tree` in Phase 3.
Every whole Junos device config we have is in `set` form; the only hierarchical Junos
available is Batfish parser snippets. `brace_tree` needs no new pack work (2.2 covers
both encodings), and building both now would take a day out of Phase 3, which holds the
non-negotiable 3.9. Hierarchical is what `show configuration` emits by default, so
RANCID and Oxidized archives are mostly hierarchical: `brace_tree` is required
long-term, just not first.

**Hazard — Junos configuration groups.** `set groups ...` plus `apply-groups` means a
value defined in one place is inherited elsewhere. Decide in 2.1 whether v1 resolves
`apply-groups`. If it does not, affected fields resolve `state=unknown`, never
`defaulted`. A silent wrong value here is a false PASS.

**Hazard — SRX is a different platform from the border routers.** Zones, security
policies and NAT exist on SRX only. The 15 system-level rules (ssh, telnet, ntp, syslog,
snmp) live under `system` and are unaffected. `junos.yaml` must not accumulate SRX-only
mappings without a platform scope; that rebuilds the per-vendor coupling the project
exists to avoid.

**Gate (end of Day 12):** drop `junos.yaml` into the packs folder with the server
running and a Junos config goes from mostly-NOT_DETERMINED to audited. That is the
demo.

---

## Phase 3 — Fill out and harden (Days 13–17)

Cut from here first if you are behind.

| # | Task | Owner | Priority |
|---|---|---|---|
| 3.1 | `brace_tree` reader (Junos hierarchical). Acceptance: produces an **identical** tree to `set_commands` for a config available in both forms. Flat and hierarchical are two encodings of one configuration; divergence is a bug in one reader | CC | High |
| 3.1b | FortiOS reader + `fortios.yaml` (third vendor). FortiOS is block-nested by `config`/`end` and `edit`/`next`, not path-per-line, so `set_commands` does not cover it | CC | High |
| 3.2 | NIST and STIG rule packs, 5 rules each, so the framework selector is real | H + CC | High |
| 3.3 | Fleet statistics: compliance rate by severity and control, Pareto ranking, coverage % | CC | High — this is the statistical-analysis slide |
| 3.4 | Results dashboard with fleet rollup | CX | High |
| 3.5 | Packs screen showing installed packs and versions | CX | Medium |
| 3.6 | Embedding tier (sentence-transformers + in-memory cosine) | CC | Medium |
| 3.7 | `structured` reader + SONiC `config_db.json` | CC | Low |
| 3.8 | LLM draft tier, shipped **off** by default | CC | Low |
| 3.9 | Security pass: `safe_load` audit, `defusedxml`, regex timeouts, redaction tests, loopback-only check | CC | **Non-negotiable, do not cut** |

---

## Phase 4 — Deliverables (Days 18–21)

| # | Task | Owner |
|---|---|---|
| 4.1 | Rehearse the four demo beats until they run without a stumble | H |
| 4.2 | **Record the demo as a fallback.** Venue wifi fails, ports get taken | H |
| 4.3 | Two-minute demo video | H |
| 4.4 | README: setup, usage, how to author a pack | CC + H |
| 4.5 | Architecture document (max 2 pages, from `ARCHITECTURE.md`) | H |
| 4.6 | Budget estimate — the round-2 judge asked for it | H |
| 4.7 | Answers rehearsed for the five standard questions (§7) | H |

---

## 5. Task-division rules

**Codex never blocks on Claude Code.** `make mock` serves `docs/openapi.yaml`.
Every frontend screen is built against the mock, including error and empty states.
When the real endpoint lands, only the base URL changes.

**Neither agent edits the other's tree.** CC owns `src/`, `packs/`, `schemas/`.
CX owns `web/`. An API change is a pull request against `docs/openapi.yaml`, not a
client-side workaround.

**Schema changes stop the line.** Renaming a canonical field breaks every pack and
rule already written. Adding one is free. Any rename is a team decision announced
before it happens.

**Every agent session ends with three sentences:** what landed, what did not, what
is now unblocked for the other agent. Paste that into the other agent's next
session.

**One reviewer per merge, human.** Agent-written code that nobody read is how an
invariant gets quietly deleted.

---

## 6. Definition of done — the four demo beats

1. Upload three Cisco configs → report in seconds, findings cite config lines.
2. Upload a Juniper config → mostly NOT_DETERMINED, **no false failures**.
3. Drop a Juniper YAML pack into the folder → re-run → it works. No restart.
4. Feed an unrecognised command → clustering shows one question covering all
   devices → confirm → re-run → resolved.

Beat 2 is the one that separates you from every team whose tool guesses. Do not
skip it in the demo because it "looks like a failure".

---

## 7. Questions to have answers for

- *"Where is the AI? This is regex and YAML."* — In the training loop, and
  deliberately not in the audit path. It turns a forty-minute manual mapping task
  into thirty seconds. A model in the verdict path would demo better and be
  unusable in an audit.
- *"How is this different from Ansible or a vendor's own tool?"* — Those check what
  they were coded to check. This is extended by the operator, at runtime, for
  hardware the vendor never supported.
- *"What is your accuracy?"* — Wrong metric. False-fail rate is zero by
  construction. The number that matters is coverage: what fraction of lines we map.
- *"Won't the admin get exhausted labelling?"* — Clustering. Twelve questions per
  two hundred devices, and the answer is permanent.
- *"What if the admin labels something wrong?"* — Packs are versioned with
  provenance and every report stamps the pack version, so a bad mapping is
  traceable and revertible across every past finding.
