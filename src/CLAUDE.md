# src/CLAUDE.md

Engine rules. Applies to everything under `src/`.
Pack and rule file formats are in `packs/CLAUDE.md`.

---

## Layout

```
src/readers/       format readers — structure only, no vendor knowledge
src/mapping/       pack loader, dispatch table, canonical model writer
src/rules/         rule pack loader, evaluator, verdict logic
src/remediation/   fix template renderer
src/report/        PDF generation (ReportLab)
src/learning/      clustering, lexical ranking, suggestion service
src/api/           FastAPI app
src/cli/           CLI entry point
```

---

## The reader / mapper split

The **reader** establishes scope. It knows an indented `ip proxy-arp` belongs to
the enclosing `interface GigabitEthernet0/1` block. It knows nothing about what
proxy-arp means. Readers are vendor-agnostic: five of them cover thirty vendors.

The **mapping engine** establishes meaning. It knows `ip proxy-arp` maps to
`interfaces[].proxy_arp`, but without the tree it would not know which interface.

Never put vendor knowledge in a reader. Never put structural knowledge in a pack.
This split is what makes collection-scoped rules possible.

Readers produce nodes carrying their own source line number:

```python
Node(path=[...], line_no=412, text="ip proxy-arp", children=[...])
```

Five readers: `indent_blocks`, `brace_tree`, `set_commands`, `structured`,
`key_value`. Build `indent_blocks` first; the rest come in later phases.

---

## Canonical model — every field is a triple

Never a bare value:

```python
{"value": 2,
 "state": "mapped",                      # mapped | defaulted | unknown
 "evidence": {"line": 88,
              "mapping_id": "ios.ssh.version",
              "pack_version": "cisco_ios@1.4.0"}}
```

Without `state` the three-state verdict collapses. Without `evidence` findings
cannot cite config lines, and the report stops being auditable. Validate against
`schemas/canonical.schema.json` on write and on read.

---

## Verdict logic

`PASS | FAIL | NOT_DETERMINED`. Three rules, in order:

1. If any field in the rule's `requires` list has `state == unknown`, return
   `NOT_DETERMINED` and **do not evaluate the assertion**.
2. An empty collection whose provenance is unknown is `NOT_DETERMINED`, never
   `PASS`. A quantifier like "no interface has proxy-arp" is vacuously true over a
   list we failed to parse — that is a false pass on a device we never read. Build
   this into the evaluator, not into each rule author's discipline.
3. Otherwise evaluate the JMESPath assertion.

**Matching is binary.** No similarity thresholds anywhere in this path. Same input
plus same pack versions always produces the same output.

---

## The AI boundary

`src/learning/` must have **no import path to `src/rules/`**. Lexical, embedding
and LLM tiers produce ranked candidate fields for a human to confirm. They never
write to the canonical model and never influence a verdict.

Embeddings rate `ssh version 1` and `ssh version 2` at roughly 0.99 similarity, so
a model allowed to decide would silently invert verdicts. If a task seems to need
that edge "to improve coverage", stop and flag it.

Ranking compares an unknown line against the **canonical field descriptions**, not
against other commands. It is a search box over our own schema.

Clustering normalises a line by replacing IPs, MACs, hostnames, interface names,
quoted strings and integers with typed placeholders, then hashes the result. Emit
clusters sorted by device count descending.

---

## Performance

- Mapping dispatch is keyed on the line's first token. Testing every line against
  every mapping is ~400,000 regex attempts per device.
- `ProcessPoolExecutor`, not threads — regex work is CPU-bound and the GIL would
  serialise it. Do not reach for Celery or Redis at this scale.
- Per-device isolation: each job catches its own failures and records a status.
  One malformed file must never kill a batch.
- Parse cache keyed on `(config_sha256, pack_version)`. Re-running after a
  labelling session touches evaluation only.
- Stream results per device; never block the operator on the slowest file.
