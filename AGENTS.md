# AGENTS.md

Instructions for Codex, which owns the frontend.

> **If you are Claude Code:** this file is not yours. You own the backend and your
> instructions are in `CLAUDE.md`. Do not edit anything under `web/`.

---

## Project

Vendor-agnostic network device configuration compliance auditor. Configuration
files in, canonical security model out, rule packs evaluated against it,
per-device PDF with cited evidence and remediation CLI.

When the engine meets a command it does not recognise it does not guess — it marks
the finding `NOT_DETERMINED` and raises a labelling task for a human. The training
interface is where that human works. **That screen is the product's
differentiator, not a settings page.**

SIH 2026 · problem statement 26155 · team Wi-fight.

## You own the frontend

Yours: `web/` — the entire React application.

Not yours: `src/` · `packs/` · `schemas/`. Claude Code owns those. If you need an
API change, propose an edit to `docs/openapi.yaml` and say so in your summary.
Never work around a missing endpoint by inventing one client-side.

## Where things are

| Need | File |
|---|---|
| Screen specs, UI invariants, conventions | `web/AGENTS.md` |
| The API contract you build against | `docs/openapi.yaml` |
| Why the system is shaped this way | `docs/ARCHITECTURE.md` |
| Current phase and acceptance criteria | `docs/PLAN.md` (humans) |

---

## Mock first, always

**Never block on the backend and never guess an API shape.**

```
make mock        # prism serves docs/openapi.yaml on 127.0.0.1:8001
make web         # vite dev server on 127.0.0.1:5173
make web-build   # production build into web/dist
make web-test    # vitest
```

Point the dev client at the mock. Build every screen against mocked responses,
including error and empty states. When the real endpoint lands, the only change
should be the base URL. If a screen only works against a live backend, you have
coupled it wrongly.

Regenerate the API client from `docs/openapi.yaml` rather than hand-writing types.

## Universal invariants

1. **No invented data.** No placeholder charts, no sample findings, no lorem
   numbers that could survive into a screenshot or a demo. Empty states say empty.
2. **No browser storage of config content.** `localStorage` may hold UI
   preferences only — never config text, findings or evidence.
3. **Local only.** The app is served from `127.0.0.1`. No external calls, no CDN
   fonts, no analytics.

## Working style

- Restate the task's acceptance criteria from `docs/PLAN.md` in one line before
  starting.
- Build one screen completely — loading, empty, error, populated — before starting
  the next.
- End every session with three sentences: what landed, what did not, what you need
  from the backend.
