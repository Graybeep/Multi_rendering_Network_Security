# web/AGENTS.md

Frontend rules. Applies to everything under `web/`.
API contract: `docs/openapi.yaml`. Build against `make mock`, never a live backend.

---

## Layout

```
web/src/pages/upload/      batch upload, scan progress
web/src/pages/results/     per-device findings, evidence, remediation
web/src/pages/training/    clustered labelling interface
web/src/pages/packs/       installed packs and versions
web/src/api/               generated client from docs/openapi.yaml
```

---

## UI invariants

These are product-safety claims, not style preferences. A change that violates one
is wrong even if it looks better.

1. **The human decides in the training screen.** Ranked suggestions are pre-filled
   form values. Never auto-apply a suggestion, never submit on a confidence
   threshold, never hide the "none of these" option, never add an "accept all"
   button. The entire project rests on AI being unable to issue a verdict; a
   convenience button would break that claim in one commit.

2. **`NOT_DETERMINED` is a first-class verdict, not a soft failure.** Render it
   visually distinct from `FAIL` — not warning-coloured, not grouped under
   "issues", not counted in a failure total. It means *we did not read this*. A
   user who reads it as a failure stops trusting the tool.

3. **Every finding shows its evidence.** Config line number, the line itself, the
   rule ID, and the pack version that produced the verdict. If the API returns it,
   display it. This is what makes a finding auditable rather than an assertion.

4. **Cluster size before question count.** The training queue sorts by how many
   devices a pattern affects, and that number is shown on every row. It is what
   makes twelve questions feel like progress across two hundred devices.

5. **Coverage travels with every score.** Wherever a compliance percentage is
   shown, show the mapped-field coverage beside it. A percentage without coverage
   is a number with no denominator.

---

## Screens

**Upload** — drag a folder or a zip. Show per-file status during fan-out; one
malformed file is a row with an error, not a failed batch. Stream results as
devices finish rather than blocking on the slowest.

**Results** — per-device findings grouped by severity. Each row: verdict, rule ID
and title, the cited config line, and the remediation block with a copy button.
Fleet rollup at the top: compliance rate by severity and by control, controls
ranked by frequency and severity, coverage percentage.

**Training** — the queue of unknown-line clusters, sorted by device count. For
each: the normalised template, a sample raw line, the affected device count, and
ranked candidate canonical fields with scores. The administrator picks a field,
sets the absent-semantics (`unknown` or `default`), and confirms. Show what will
be written before it is written.

**Packs** — installed vendor, rule and fix packs with versions and source
(shipped or learned). Read-only in v1.

---

## Conventions

- React + TypeScript + Vite. Tailwind. Functional components and hooks only.
- Plain, dense, information-first. This is an audit tool used by network engineers,
  not a consumer app — favour legible tables over decoration and animation.
- Accessible by default: real labels, keyboard navigation, visible focus. The
  training screen gets used with a keyboard for long stretches.
- Every screen handles four states: loading, empty, error, populated. A screen
  without all four is not finished.
- No external fonts, CDNs or analytics. Everything ships with the bundle.
