# Wi-fight network configuration auditor

Vendor-agnostic compliance auditor for network device configurations. Config files go
in; a canonical security model comes out; CIS, NIST, STIG and ISO rule packs are
evaluated against it; each device gets a PDF that cites the config lines behind every
finding and gives the CLI to fix it.

Vendor knowledge lives in YAML packs under `packs/`, not in code. Adding a vendor is a
new pack file, not a code change or a redeploy.

SIH 2026 · problem statement 26155 · team Wi-fight.

> Status: early build. Cisco IOS with the CIS pack works end to end from the CLI. The
> HTTP API (`make api`) and the Junos, FortiOS and NX-OS packs are not built yet.

## Requirements

- Python 3.11+
- Node.js, current LTS (frontend and API mock only)
- No admin rights or `sudo` needed. Everything binds to `127.0.0.1`.

## Setup

```sh
make setup
```

Without `make` (common on Windows):

```sh
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"     # Windows
.venv/bin/pip install -e ".[dev]"         # macOS / Linux
```

## Audit some configs

```sh
scan fixtures/configs/batfish_example_live --framework cis --out ./reports
# or, without the installed entry point:
python -m src.cli.main fixtures/configs/batfish_example_live --framework cis --out ./reports
```

Each device gets a JSON findings file and a PDF in `./reports`. Every finding is
`PASS`, `FAIL` or `NOT_DETERMINED`. `NOT_DETERMINED` means the tool could not read
what the rule needs, so it does not guess.

Options: `--framework` (repeatable), `--packs <dir>`, `--workers <n>`,
`--timeout <seconds per device>`. Run `scan --help` for the full list.

## Development

| Task | With make | Without make |
|---|---|---|
| Tests | `make test` | `python -m pytest` |
| Lint and types | `make lint` | `python -m ruff check src tests` then `python -m mypy src` |
| API mock for the frontend | `make mock` | `npx -y @stoplight/prism-cli@5 mock docs/openapi.yaml -h 127.0.0.1 -p 8001` |
| Frontend | | `cd web && npm install && npm run dev` |

CI runs the tests, lint and type checks on every push and pull request
(`.github/workflows/ci.yml`).

## Repository layout

| Path | What |
|---|---|
| `src/` | Engine: readers, mapping, rule evaluation, remediation, PDF, CLI |
| `packs/` | Vendor packs, rule packs, fix templates (YAML) |
| `schemas/` | Canonical model and pack JSON Schemas |
| `docs/openapi.yaml` | HTTP API contract shared with the frontend |
| `docs/ARCHITECTURE.md` | Why the system is shaped this way |
| `web/` | Frontend |
| `fixtures/` | Real configs from Batfish (Apache-2.0; see each `SOURCE.md`) and golden outputs |

## Writing a pack

Pack formats are documented in `packs/CLAUDE.md`. A full authoring guide will be added
here.
