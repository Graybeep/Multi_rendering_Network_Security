# Architecture

Why the system is shaped this way. The literal formats live where the agents work:
canonical field list and pack schemas in `packs/CLAUDE.md`, engine rules in
`src/CLAUDE.md`, API contract in `docs/openapi.yaml`.

If this document and the code disagree, the code is wrong.

---

## 1. The problem

"SSH must be version 2" is written differently on every vendor: `ip ssh version 2`
on Cisco IOS, `set system services ssh protocol-version v2` on Junos. Conventional
tools ship one hand-coded parser per vendor, so every firmware release breaks
something and every new vendor is a software release.

This system inverts that. There are only about **five shapes** a configuration file
can take, so five readers are written as code and everything vendor-specific
becomes a YAML data file loaded at runtime.

| Reader | Structure | Vendors |
|---|---|---|
| `indent_blocks` | indentation defines nesting | Cisco IOS / NX-OS, Arista EOS, Huawei |
| `brace_tree` | `{ }` nesting | Junos hierarchical form |
| `set_commands` | path + value per line | Junos `set`, PAN-OS CLI, FortiOS |
| `structured` | already a tree | PAN-OS XML, SONiC `config_db.json`, cloud SGs |
| `key_value` | flat INI | misc |

---

## 2. The audit path — deterministic

```
config file
  → ingest, redact, fingerprint     vendor, OS family, version, model, serial
  → format reader                   structured tree, every node carries a line number
  → mapping engine                  vendor pack + learned mappings → canonical model
  → rule evaluator                  rule packs → PASS / FAIL / NOT_DETERMINED
  → remediation renderer            fix template → vendor CLI
  → report                          per-device PDF with cited lines
```

No AI anywhere in this path. Same input plus same pack versions always produces
the same output.

### Why reader and mapper are separate boxes

The reader establishes **scope**: an indented `ip proxy-arp` belongs to the
enclosing `interface GigabitEthernet0/1`. It knows nothing about what proxy-arp
means.

The mapper establishes **meaning**: `ip proxy-arp` maps to
`interfaces[].proxy_arp`, but without the tree it would not know which interface.

This split is why five readers cover thirty vendors, and why rules can quantify
over collections instead of only reading scalars.

### Why three verdicts instead of two

A missing `ip ssh version` line could mean *insecurely unset* or *we failed to
parse it*. Conflating them produces false failures, and one false failure on a
device an administrator knows is hardened destroys trust in the whole report.

So every canonical field carries `state` — `mapped`, `defaulted` or `unknown` —
and a rule whose required fields are unknown returns `NOT_DETERMINED` without
evaluating. Details in `src/CLAUDE.md`.

---

## 3. The learning path — probabilistic, human-terminated

```
line matched nothing
  → normalise to a template signature   strip IPs, hostnames, interface names, integers
  → cluster across the whole batch       200 devices → ~12 distinct patterns
  → rank candidate canonical fields      lexical → embedding → LLM draft
  → HUMAN CONFIRMS                       ← the loop always ends here
  → write YAML pack fragment             versioned, with author and source cluster
  → next run matches it exactly          no code change, no redeployment
```

**Clustering is what makes this usable.** Without it, questions scale with device
count: 200 configs sharing 12 unknown commands would raise 2,400 prompts and the
administrator would close the tab. Normalising to a template signature collapses
them to 12, and each answer covers that batch and every future upload.

**Ranking compares the unknown line against the canonical field descriptions**, not
against other commands. It is a search box over our own schema.

**The suggestion service has no edge into the evaluator.** Embeddings rate
`ssh version 1` and `ssh version 2` at roughly 0.99 similarity, and handle negation
poorly — `permit` and `deny` score much the same. A model allowed to decide would
silently invert verdicts, which is worse than a tool that says "I don't know".
Probabilistic tiers pre-fill a form; a human submits it.

---

## 4. Artifacts

Four declarative types, all loaded at runtime from a directory or database — never
from inside the Python package, or "no redeployment" is false.

| Artifact | Scope | Changes when |
|---|---|---|
| Vendor pack | one per vendor | new vendor, new firmware syntax |
| Rule pack | one per framework | benchmark revision |
| Fix template | one per vendor | remediation syntax changes |
| Learned mappings | one per vendor | an administrator confirms a mapping |

Learned mappings use the **same schema** as a vendor pack's mappings block. That
equivalence is the point: learning is authoring, and a labelling session can ship
as a first-class pack.

Formats and the canonical field list: `packs/CLAUDE.md`.

---

## 5. Bulk execution

One scan fans out into N independent device jobs in a SQLite `jobs` table, run on a
process pool. Per-device isolation means one malformed file cannot kill a batch.
A parse cache keyed on `(config_sha256, pack_version)` makes re-running after a
labelling session near-instant and dedupes identically-configured access switches
for free. Results stream per device.

Realistically under a second per device on one core — **measure on your own
fixtures before quoting a number to anyone.**

---

## 6. API surface

`docs/openapi.yaml` is authoritative once written. This is the shape to write it
from, and the contract Codex mocks against.

```
POST   /api/scans                                 upload batch → {scan_id}
GET    /api/scans/{id}                            status, progress, device list
GET    /api/scans/{id}/devices/{device_id}        findings with evidence
GET    /api/scans/{id}/devices/{device_id}/report application/pdf
GET    /api/scans/{id}/clusters                   unknown clusters, device count desc
GET    /api/clusters/{id}/suggestions             ranked candidate fields + scores
POST   /api/clusters/{id}/confirm                 {canonical_field, absent, default}
POST   /api/scans/{id}/reevaluate                 re-run from parse cache
GET    /api/schema/fields                         canonical fields + descriptions
GET    /api/packs                                 installed packs and versions
```

---

## 7. Deployment

Local desktop application. FastAPI bound to `127.0.0.1`, serving the built React
SPA as static files from the same process. SQLite plus a `packs/` directory under
one user-chosen data folder. Runs as a normal user.

The tool is deliberately **out of band**: it reads exported configuration text
after the fact, never sits in the packet path. It cannot drop a packet or break a
session. Worst case it produces a wrong report, not an outage.

Tiers 0–3 are fully local. Only the optional LLM draft tier needs network access,
and it ships off. Every other capability works with the cable unplugged.

---

## 8. Known limits

State them before a judge finds them.

- **Config text is not runtime state.** A declared NTP server may be unreachable.
  We audit what the device was told to do, not what it is doing.
- **We match lines, not semantics.** An ACL denying telnet is useless behind a
  preceding permit-any. Full reachability analysis is out of scope; Batfish does
  that and we do not.
- **Per-device scope.** Segmentation and fleet consistency need fleet-level rules
  over the collection of canonical models, run after the per-device pass.
- **Rule translation is a single point of systematic error.** One mistranslated
  CIS control is wrong on every device, silently. Hence mandatory fixtures.
- **Unsupported vendors start mostly `NOT_DETERMINED`** and climb as an
  administrator teaches the system. This is a trade, not a free lunch — and the
  loop needs an administrator who knows what the command means.
