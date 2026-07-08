# AGENTS.md

Guidance for contributors and AI coding assistants working in the BAMF
repository. If you are using an AI assistant (Claude Code, Cursor, Copilot,
Aider, etc.), point it at this file — it captures the architecture, the
contracts, the test tiers, and the conventions that keep changes consistent.
For a quick, machine-friendly map of the whole repo — entry points, the
codebase layout, the feature catalogue, and how to enable each feature — see
[`llms.txt`](llms.txt) at the repo root.

New here? Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup and the
contribution workflow, then come back here for the deeper architecture and
contract rules. **Contributions are very welcome — including AI-assisted
("vibe") contributions** — as long as they follow the contracts below and ship
with tests.

---

## What BAMF is

BAMF (Bridge Access Management Fabric) is a free, open-source **infrastructure
access platform** — an alternative to Teleport that gives teams secure, audited
access to SSH servers, databases, Kubernetes clusters, and internal web
applications through short-lived certificates, centralized audit, session
recording, and zero-trust tunnels, with SSO and role-based access control.

It is licensed **MPL-2.0** (file-level copyleft) with no usage, size, or revenue
restrictions.

## Repository layout

| Path | What it is | Language |
|---|---|---|
| `services/` | API server (FastAPI) **and** the HTTP reverse proxy for web-app access — one codebase. Poetry-managed. | Python 3.14 |
| `cmd/` | Go binaries: `bamf` (CLI), `bamf-bridge` (tunnel gateway), `bamf-agent` (target-side agent). | Go |
| `pkg/` | Shared Go packages: `agent`, `apiclient` (typed HTTP client for the Python API), `bridge` (incl. `sshproxy`, `dbaudit`, `webterm`), `tlsutil`, `tunnel`. | Go |
| `web/` | Next.js 16 frontend (React 19, TypeScript). | TypeScript |
| `alembic/` | Async Alembic database migrations. | Python |
| `helm/bamf/` | The Helm chart (the primary, supported deployment mechanism). | YAML |
| `docker/` | One Dockerfile per component (`api`, `bridge`, `agent`, `web`). | Dockerfile |
| `docs/` | User + operator + architecture documentation. | Markdown |
| `packaging/` | DEB/RPM packaging for the agent (nfpm). | YAML |
| `pentest/` | SAST (Semgrep), image-scan (Trivy), DAST (Nuclei) config. | mixed |

The Go module is `github.com/mattrobinsonsre/bamf`.

## Build, lint, and test

**Everything runs in Docker via `make` — there is no local toolchain to set up.**
Run `make help` for the full list. The essentials:

```sh
make lint          # lint all (Go + Python + Web) in Docker
make test          # test all (Go + Python) in Docker
make build         # cross-compile the Go binaries for all platforms
make dev           # local Kubernetes dev stack (Tilt on Rancher Desktop)
make dev-down      # stop the dev stack
make security-scan # govulncheck (Go) + pip-audit (Python)
make pentest       # SAST + image CVE scan + DAST (DAST needs a running stack)
make db-migrate    # run Alembic migrations
```

Per-surface verification before you push (lint alone is **not** enough):

- **Go** changes → `make test-go` (+ `make build-local` if you touched build tags/entrypoints).
- **Python** changes → `make test-python`.
- **Web** changes → `npm run build` from `web/` (the Next.js prerender step
  catches things `tsc` and ESLint cannot).
- **Helm** changes → `helm lint ./helm/bamf` + `helm template ./helm/bamf`
  (and the values profiles it ships).

## Architecture principles

1. **Certificate-based, short-lived access.** Every access path is authorized
   by a BAMF-CA-issued, short-lived certificate — never a long-lived shared
   secret. User certs default to 12h, service certs to 24h.
2. **mTLS is the tunnel security boundary.** CLI ↔ Bridge ↔ Agent all speak
   mTLS with BAMF-CA-issued certs. Internal cluster traffic (Bridge → API, API →
   Postgres/Redis) is plain within the cluster, protected by network policy
   (optionally a service mesh for internal mTLS).
3. **Python for the control plane, Go for the data plane.** The API server,
   auth, RBAC, audit, and the HTTP proxy are Python/FastAPI (string-heavy web
   work). The bridge, agent, and CLI — anything on the hot byte-splicing path —
   are Go. The Go side talks to the API only through `pkg/apiclient`.
4. **Kubernetes-native, Helm-first.** The Helm chart is the supported
   deployment mechanism; there is no separate installer.
5. **Bring your own auth.** Every identity provider (local, OIDC, SAML) is a
   `Connector` behind one abstraction; MFA is delegated to the IdP.
6. **Audit everything.** SSH sessions, DB queries, and HTTP access are recorded
   to an immutable audit log with session recording and redaction.
7. **Reject by default.** Input validation at every API boundary; RBAC denies
   unless a rule allows.
8. **RFC3339 / ISO8601-UTC timestamps.** All datetimes are timezone-aware UTC,
   serialized ISO8601 with a `Z` suffix — never naive datetimes.
9. **Multi-replica safe.** The API runs behind a load balancer with multiple
   replicas; never rely on in-process state for cross-replica coordination.
10. **No sync work in async handlers (hard requirement).** FastAPI + uvicorn
    runs a single event loop per worker. Any synchronous CPU-heavy or blocking
    I/O call inside an `async def` handler starves the whole replica. Wrap such
    calls in `asyncio.to_thread(...)` / `run_in_executor(...)`, or use an
    async-native alternative (`httpx.AsyncClient`, `asyncpg`, `redis.asyncio`).
    When a plain `def` endpoint genuinely needs sync libraries, prefer `def` —
    FastAPI runs it in a threadpool for you; that rescue does **not** apply to
    `async def`.

## The API ↔ Consumer contract (hard)

The Python API (`/api/v1/`) has several classes of consumer, each with its own
contract. **Every API change must update every consumer it affects.** Breaking
the API without updating consumers creates silent failures that are hard to
debug.

- **Web UI** (`web/`) — SSR fetches + client `fetch()` calls (`web/src/lib/`).
- **`pkg/apiclient`** (Go) — the typed HTTP client the CLI, bridge, and agent
  use for every API call. This is the source of truth for the Go-side view of
  every endpoint; the Go components do **not** roll their own request shapes.
- **CLI / bridge / agent** (`cmd/`) — consume the API through `pkg/apiclient`.

The workflow when extending the API:

1. Add the endpoint to the appropriate router (`services/bamf/api/routers/`),
   with a Pydantic request/response model (no raw dicts) under
   `bamf/api/models/`.
2. Add/adjust the typed method in **`pkg/apiclient`** + a Go test if any Go
   component consumes it.
3. Add the consumer code that needs it (web page, CLI command).

When a response field name changes, update `pkg/apiclient`'s struct/tag, every
`web` `fetch` that references it, and the CLI. Responses are **flat** (no
envelope): `GET /users` returns `[...]`, not `{"data": [...]}`. Errors use the
FastAPI default shape (`{"detail": "..."}`).

## The Code ↔ Tests contract (hard)

Every code change ships with tests at the right tier(s). **No new endpoint,
service function, CLI command, protocol handler, UI surface, or hard invariant
lands without its accompanying tests.**

| Tier | Where | What it exercises | DB / stack |
|---|---|---|---|
| **Go unit** | `pkg/**/*_test.go`, `cmd/**/*_test.go` | Protocol handlers, routing, cert parsing, tunnel splicing, CLI logic. Table-driven, `testify/require`. | none / fakes |
| **Python unit / services-API** | `services/tests/{test_api,test_auth,test_services}` | Router contracts, auth/RBAC, service-layer rules with mocked DB. The bulk of Python tests. | mocked |
| **Integration** | `services/tests/` (real engine) + `test/` | Multi-row workflows needing a real Postgres; end-to-end tunnel/agent flows. | `docker-compose.test.yml` |
| **Web E2E** | `web/` (Playwright) | Full user flows through the real UI + API. | full stack |
| **Pentest** | `pentest/` (SAST/Trivy/DAST) | Static analysis, image CVEs, live DAST. | `make pentest` |

Routing rules of thumb:

- A **router** endpoint → a services-API test (happy path + auth/RBAC + error
  responses). Then a `pkg/apiclient` method + Go test if a Go component uses it.
- A **service function** with mockable deps → a services-API test (mocked DB).
  Reach for integration only when it depends on real Postgres semantics.
- A **new Go protocol handler / tunnel path** → a table-driven Go unit test;
  add an integration test if it crosses the CLI↔Bridge↔Agent boundary.
- A **new frontend page / RBAC gate / user-facing flow** → a Playwright E2E
  spec (RBAC gets a negative-path spec with a non-privileged session). `tsc` +
  ESLint are necessary but **not** sufficient — the page must render in the E2E
  stack.
- A **new hard invariant** ("X must never happen") → a source-introspection
  test that asserts the absence of the forbidden pattern, so it fails CI loudly
  if a future change violates it.
- A **behaviour-changing fix for a reported bug** → a regression test named
  after the failure mode that fails pre-fix and passes after.

## Cross-component contract registry

Every cross-language coupling below is joined by **hand-copied string literals**
across Go/Python/TS that are tested in isolation — so a test can stay green while
encoding a contract the peer never honored (this shipped two live bugs: the
`bamf agents` / `bamf tokens list` envelope drift). When you touch one side of a
row, update the other side **and** its guard. Add a `CONTRACT:` comment at each
boundary pointing at the peer.

| Contract | Sides (file:line) | Kept in sync by |
|---|---|---|
| **List-envelope** `CursorPage{items,next_cursor,has_more}` | producer `services/bamf/api/models/common.py` (`CursorPage`) ↔ CLI `cmd/bamf/cmd/agents.go`, `tokens.go`, `users.go`, `roles.go` (`Items` structs) | **Golden fixtures** `services/tests/contracts/{agents,tokens,users,roles}_list.json` — validated by `services/tests/test_api/test_contract_fixtures.py` (producer) **and** `cmd/bamf/cmd/contract_test.go` (consumer). A key/field drift fails both. |
| **Session-cert SAN URIs** (`bamf://session|resource|bridge|role|type`) | issued `services/bamf/auth/ca.py` (`issue_session_certificate`) ↔ parsed `pkg/bridge/server.go` (`extractSessionInfo`) | **Golden cert** `services/tests/contracts/session_cert.pem` (a real issued cert) — the Go parser reads all 5 SANs (`pkg/bridge/contract_test.go`) and current Python issuance must reproduce the same SAN set (`test_contract_fixtures.py`). A dropped/renamed SAN fails both. |
| **Agent SSE command set** (`dial`/`redial`/`relay_connect`/`revoke` → event type; the dial/redial payload keys) | producer `services/bamf/api/agent_commands.py` (`build_tunnel_command`), `routers/agents.py` ↔ consumer `pkg/agent/sse.go`, `agent.go` (`handleTunnelRequest`) | **Golden** `services/tests/contracts/dial_command.json` — the Go agent's expected keys/types must resolve (`pkg/agent/contract_test.go`) and current `build_tunnel_command` must emit the same keys (`test_contract_fixtures.py`). A key rename fails both. Producer maps `command`→event, consumer switches on it. |
| **Helm values ↔ schema ↔ templates** | `helm/bamf/values.yaml` ↔ `values.schema.json` ↔ `templates/` | `helm lint` (schema `additionalProperties:false`) + the 4-topology render matrix in CI. |
| **Redis session-key namespaces** — `session:{id}` (tunnel) vs `bamf:session:{token}` (user); merging them is catastrophic | builders `services/bamf/redis_keys.py` (`tunnel_session_key`) ↔ user prefix `services/bamf/auth/sessions.py` (`SESSION_PREFIX`) | `services/tests/test_redis_keys.py` locks the formats, asserts the two namespaces stay distinct, and bans raw `f"session:{...}"` literals outside the module. *(agent/bridge key families: migrate to `redis_keys.py` incrementally.)* |

## Conventions

- **Issue-first** — every change beyond a genuinely trivial tweak (typo,
  one-line comment, formatting) starts with a GitHub issue, and the PR
  references it (`closes #N`). Flow: **issue → branch → PR → squash-merge**.
- **Conventional commits** — `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`,
  `test:`, `ci:`.
- **Branches** — feature branches off `main`; never push directly to `main`;
  never stack a PR on another open feature branch (always base on `main`). All
  PRs require passing CI (lint, test, build).
- **Python** — FastAPI app via `create_application()` factory + lifespan;
  Pydantic `BaseSettings` for config; `structlog` only (no `print`/stdlib
  `logging`); async everywhere (asyncpg, httpx); Ruff for lint+format; type
  annotations on all signatures; pytest + pytest-asyncio.
- **Go** — follow Effective Go + Go Code Review Comments; `slog` for logging;
  wrap errors with context (`fmt.Errorf("bridge: ...: %w", err)`); table-driven
  tests with `testify/require`; no global mutable state (explicit deps);
  `context.Context` as the first argument.
- **TypeScript / React** — strict TS; functional components + custom hooks
  only; no `any` without an explanatory comment.
- **Migrations** — Alembic with async SQLAlchemy; every migration has a real
  `upgrade()` **and** `downgrade()`.
- **The Helm values-schema contract (hard requirement)** —
  `helm/bamf/values.schema.json` validates chart values with
  `additionalProperties: false` on BAMF-specific objects, so `helm lint` fails
  if `values.yaml` carries an undeclared key. When you add, rename, or remove a
  `values.yaml` key you MUST update the schema to match — including keys that
  only appear in templates via `| default` (e.g. `proxy.internalToken`,
  `postgresql.existingSecretKey`). Kubernetes pass-through objects
  (`podSecurityContext`, `nodeSelector`, `affinity`, `tolerations`) use schema
  `type: object` with no property restrictions. Secrets flow via `secretKeyRef`
  / `existingSecret`, never into a ConfigMap.
- **Endpoint authentication (hard requirement)** — every **state-changing**
  route (`POST`/`PUT`/`PATCH`/`DELETE`) and every credential-bearing stream
  (e.g. the agent SSE, which carries session certs) MUST enforce authentication
  via a recognized dependency: `get_current_session`/`get_current_user`,
  `require_admin`/`require_admin_or_audit`, `get_agent_identity`,
  `get_bridge_identity`, or `verify_internal_token`. An agent may only act as
  itself (assert the cert CN matches the path agent, like
  `agents.py:_require_cert_matches_agent`). This is enforced in CI by
  `services/tests/test_api/test_endpoint_auth.py`, which fails on any mutating
  route lacking auth — a genuinely public route (login/join flow) must be added
  to its `PUBLIC_ROUTES` allowlist **with a reason**, which a reviewer sees.
  (Reject-by-default; see issue #193, where agent endpoints once shipped
  unauthenticated and enabled tunnel hijack.)

## Release discipline

Releases are automated in `.github/workflows/ci.yml`: pushing a semver tag
(`vX.Y.Z`) builds multi-arch images, publishes the Helm chart to the OCI
registry, attaches Go binaries + SBOMs, and creates the GitHub Release. A failed
tag pipeline auto-deletes the tag (reuse the version). The full mechanical
how-to — cutting, verifying artifacts, the version flow, and the release-notes
template — is in [`docs/releasing.md`](docs/releasing.md); the gates below run
**before** you tag.

**Before tagging any minor or major release, run a pre-release audit and land
its fixes as a dedicated `docs:`/`chore:` PR.** Enumerate everything merged
since the previous tag (`git log vPREV..HEAD`) and audit:

- **A. Docs completeness** — every user-visible feature/endpoint/flag merged
  since the last tag is documented across `docs/` and reflected in `README.md`,
  `docs/index.md`, and [`llms.txt`](llms.txt) (see below).
- **B. Helm values↔schema sync** — every added/renamed/removed `values.yaml`
  key is reflected in `values.schema.json` (`additionalProperties: false` ⇒
  `helm lint` fails otherwise).
- **C. Test coverage** — each new endpoint/service/handler/column has tests at
  the right tier.
- **D. Content-hygiene scan (hard gate)** — scan commits + added diff lines for
  the forbidden internal identifiers and for any disparaging framing of peer
  OSS projects (see Content hygiene). Any hit blocks the release.
- **E. Version strings** — no doc hardcodes a stale version.
- **F. Live smoke for destructive / high-blast-radius surfaces** — anything
  that mutates infrastructure, issues certificates, or opens tunnels is smoke-
  tested end-to-end on the live Tilt stack, not only unit-tested.
- **G. Ignored-vulnerability review** — sweep the committed scanner suppression
  allowlists (`pentest/trivy/.trivyignore`, `pentest/pip-audit/ignore-vulns.txt`;
  govulncheck has none) and drop any that a version bump now fixes. The
  suppression policy — when an ignore is permitted and the required justification
  + "drop when" format — is in `SECURITY.md`.
- **H. AI-agent onboarding** — confirm a fresh, repo-only agent pointed at the
  clone can accurately summarise BAMF, enumerate features, and give correct
  getting-started guidance **without hallucinating endpoints or Helm values**.
  The entry-point hierarchy (`README.md` → `AGENTS.md` → `docs/index.md`),
  `llms.txt`, and the feature catalogue must be current with what shipped.

Then run an **independent, adversarial third-party review** of `git diff
vPREV..HEAD` (parallel read-only reviewers per dimension — API/service
correctness + security, consumer-contract drift, test coverage, docs/ops — each
told to find gaps and cite `file:line`). Verify their findings against the code
before acting; fix the blocker tier; re-confirm CI is green; **then** tag. This
review is required for **every** release, patch included — it scales with the
diff.

- **Keep [`llms.txt`](llms.txt) current (first-class deliverable).** It's the
  machine-friendly map AI assistants land on. A change that adds, renames, or
  removes a user-visible feature, a doc page, or a top-level entry point MUST
  update `llms.txt` in the same PR (and the matching feature tables in
  `README.md` / `docs/index.md`). Every entry must resolve to something real in
  the repo — no hallucinated endpoints, Helm values, or config keys.

## Content hygiene (hard requirements)

These protect the public repository. Git history, PRs, and source are
world-readable forever.

- **No internal references** — commit messages, PR text, **and source comments
  / docstrings** must never reference any company, internal hostname, internal
  repo/project name, internal cluster name, or specific customer/deployment
  (this includes `acrolinx`, `acrolinx-cloud.net`, `markup.ai`, `markupai`, and
  anything under a private tailnet). When describing an issue motivated by a
  real deployment, anonymise it ("a multi-cluster estate", "an internal CI
  cluster"), never name the source. If you catch a leak in your own draft,
  scrub it before pushing.
- **Respect peer open-source projects** — Teleport (and any peer project) is a
  respected fellow project, not an enemy to disparage. Never denigrate it — not
  in commits, PRs, comments, docs, issues, release notes, or conversation — and
  never passive-aggressively. Honest, factual, neutral technical/licensing
  comparison is fine (and is core to BAMF's positioning); comparison framed to
  rank or belittle is not. Position BAMF on its own merits.

## Where to learn more

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — setup + the contribution workflow.
- [`llms.txt`](llms.txt) — the machine-friendly repo + feature map.
- [`docs/`](docs/) — user, operator, and architecture documentation
  ([`docs/getting-started.md`](docs/getting-started.md),
  [`docs/architecture/overview.md`](docs/architecture/overview.md),
  [`docs/development.md`](docs/development.md) are good next reads).
