# Contributing to BAMF

Contributions are very welcome — including AI-assisted ("vibe") contributions —
as long as they follow the contracts in [`AGENTS.md`](AGENTS.md) and ship with
tests. BAMF is MPL-2.0.

## Setup

Everything builds, lints, and tests in Docker via `make` — there is no local
Go/Python/Node toolchain to install (Docker + a local Kubernetes for the dev
stack is all you need).

```sh
make help          # list every target
make lint          # lint Go + Python + Web
make test          # test Go + Python
make dev           # local Kubernetes dev stack (Tilt on Rancher Desktop)
make dev-down      # stop it
```

First time working on the repo, install the git hooks (pre-commit lint/secret
scan on staged files):

```sh
make hooks
```

See [`docs/development.md`](docs/development.md) for the full local-stack
walkthrough and [`AGENTS.md`](AGENTS.md) for architecture, the API↔consumer and
code↔tests contracts, and the conventions.

## Workflow

**Issue → branch → PR → squash-merge.**

1. **Open a GitHub issue** for anything beyond a genuinely trivial tweak (typo,
   one-line comment, formatting). The issue is where the change is scoped.
2. **Branch off `main`** (`git checkout -b feat/short-description origin/main`).
   Never push to `main`; never stack a PR on another open feature branch.
3. **Make the change with its tests** at the right tier (see the Code↔Tests
   contract in `AGENTS.md`). Update every consumer an API change touches
   (`pkg/apiclient`, `web`, CLI). Keep `values.schema.json` in sync with
   `values.yaml`. Keep `llms.txt` + the README/docs feature tables in sync when
   you add or change a user-visible feature.
4. **Verify locally** for the surface you changed (`make test-go` /
   `make test-python` / `npm run build` in `web/` / `helm lint`).
5. **Open a PR** that references the issue (`closes #N`) with a conventional-
   commit title (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`,
   `ci:`). CI (lint, test, build) must be green.

## Content hygiene (please read)

BAMF's history and source are public forever. Two hard rules:

- **No internal references** — no company, internal hostname, internal
  repo/cluster, or customer names in commits, PRs, comments, or docstrings.
  Anonymise real-world motivation.
- **Respect peer projects** — Teleport and other peers are respected fellow
  projects. Factual, neutral comparison is fine; disparagement is not.

Full detail: [`AGENTS.md` → Content hygiene](AGENTS.md#content-hygiene-hard-requirements).

## Reporting security issues

Please follow [`SECURITY.md`](SECURITY.md) — do not open a public issue for
vulnerabilities.
