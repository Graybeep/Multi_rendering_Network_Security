# CLAUDE.md

Loaded on every turn. Keep it short — content that applies to one subtree belongs
in that subtree's `CLAUDE.md`, which loads only when you read files there.

---

## Project

Vendor-agnostic network device configuration compliance auditor. Configuration
files in, canonical security model out, CIS / NIST / STIG / ISO rule packs
evaluated against it, per-device PDF with cited evidence and remediation CLI.

**Thesis:** vendor knowledge lives in YAML data files, not in code. Adding a new
vendor must never require a code change or a redeployment.

SIH 2026 · problem statement 26155 · team Wi-fight.

## You own the backend

Yours: `src/` · `packs/` · `schemas/` · `docs/openapi.yaml`

Not yours: `web/` — Codex owns it, see `AGENTS.md`. If the frontend needs an API
change, edit `docs/openapi.yaml` and say so in your summary. Never edit `web/`.

## Where things are

| Need | File | Loads |
|---|---|---|
| Engine rules — readers, mapping, verdicts | `src/CLAUDE.md` | when you read `src/` |
| Pack formats, canonical field list | `packs/CLAUDE.md` | when you read `packs/` |
| Why the system is shaped this way | `docs/ARCHITECTURE.md` | on demand, open it |
| Current phase and acceptance criteria | `docs/PLAN.md` | humans only |

Open `docs/ARCHITECTURE.md` before your first substantial change in a new area.

---

## Universal invariants

Violating one of these is wrong even if the tests pass.

1. **Parse untrusted input safely.** `yaml.safe_load` only, never `yaml.load`.
   `defusedxml` for XML, never bare `lxml` on user input. Cap regex match time per
   line and run parsing in a killable subprocess — pack regexes are user-authored
   and a pathological pattern must not hang a worker.

2. **Redact at ingest, keep the algorithm token.** `enable secret 9 ****` must still
   let a hash-strength rule evaluate. Never log raw config lines. Never send raw
   config to an LLM — only normalised templates with identifiers stripped.

3. **Bind to `127.0.0.1` only.** Never `0.0.0.0`. This is a local desktop
   application; nothing is exposed to the network. No install step needs `sudo`.

4. **Never invent data.** No placeholder findings, no synthetic scan results, no
   mock numbers that could reach a report, a screenshot or a slide.

5. **Schema changes stop the line.** Renaming a canonical field breaks every pack
   and rule already written. Adding one is free. If a task seems to need a rename,
   stop and flag it — it is a team decision, not a refactor.

---

## Conventions

- Python 3.11+, type hints on public functions, `ruff` clean.
- Pure functions in `src/readers`, `src/mapping`, `src/rules` — no I/O, no globals.
  I/O lives in `src/api` and `src/cli`.
- Fixture-driven tests. Never edit a fixture to make a test pass; fix the code, or
  explain why the fixture was wrong.
- Commit messages: `area: what changed`. Small commits.

## Commands

```
make setup      # venv + deps
make test       # pytest — green before any commit
make lint       # ruff + mypy
make api        # uvicorn on 127.0.0.1:8000
make mock       # prism mock of docs/openapi.yaml on :8001 (for Codex)
scan ./configs --framework cis --out ./reports
```

## Working style

- Restate the task's acceptance criteria from `docs/PLAN.md` in one line before
  starting, and confirm it matches what you are about to build.
- Finish one vertical slice before starting three horizontal layers.
- End every session with three sentences: what landed, what did not, what is now
  unblocked for Codex.
