# Verification status

Recorded 2026-11-01. **Research prototype; no production qualification.**

## Render preparation

The Render profile now loads stable environment keys and managed PostgreSQL, normalizes
Render connection URLs with mandatory TLS, honors PORT, and checks database/manifest
readiness. It creates no local state. Automatic deployment is disabled. The operator
will deploy; no Render resources or account configuration were changed here.

Local validation of this slice passes **32 tests**, Ruff lint/format and wheel/sdist build.
The new `render-container` hosted job is pending execution at this documentation revision:
it builds the actual image, tests a TLS PostgreSQL connection, authenticated HTTP operations,
application restart without a state volume, database outage readiness and recovery.
Its outcome must be recorded before claiming container qualification. Local Docker is
unavailable. See [Render setup](render.md) and [slice receipt](render-verification.json).

## Hosted verification

[GitHub run 41282777818](https://github.com/arpitkjaiswal/AegisVault/actions/runs/41282777818)
passes at source commit `54863a6672483271881635567ee1fea9af3d27a2`:

- `postgres16`: 26 tests pass, one Starlette deprecation warning. PostgreSQL 16.15,
  Python 3.12.15, Ubuntu 26.04 x86_64, fresh disposable service container.
- `sqlite-and-package`: 26 tests pass, one Starlette deprecation warning; Ruff lint/format,
  wheel/sdist build, hash-locked runtime installation and installed CLI init/doctor pass.

The initial tested runtime source was unchanged in its immediate documentation update. Hosted
action logs also warn that pinned checkout/setup-python actions target deprecated Node 20
and are forced to Node 24. The successful jobs do not qualify these dependencies or the
system for production security. The application Docker image/Compose recipe was not run
by the PostgreSQL service-container test.

## Executed successfully

| Boundary | Actual observation |
|---|---|
| Environment | Linux x86_64; Python 3.12.14; frozen uv dependency installation |
| SDK + HTTP adapter tests | 26 pytest cases pass on isolated SQLite; includes 40 generated AEAD context examples inside one property test |
| Crypto reference | RFC 8452 C.2 AES-256-GCM-SIV empty-message vector passes |
| Adversarial cases | Ciphertext/key-wrap/context tampering, cross-tenant swaps, missing keys, stale revisions, purpose/role refusal, search substitution |
| Lifecycle | Both bounded rotation modes, host restart between batches, old-generation removal in synthetic test custody, whole-batch rollback on failure |
| Audit | Alteration and missing head detection, externally anchored tail-truncation detection, audit-storage failure blocks reads/writes |
| Plaintext boundary | SQL driver parameter collector sees deliberate plaintext positive control; vault CRUD/search inputs absent from captured binds |
| Typed documents | String, integer, boolean, ISO date, nested JSON, explicit NULL and whole-JSON exact equality |
| Formatting | Ruff lint and format checks pass |
| Packaging | Wheel and sdist build; locked runtime install into an independent venv; installed CLI init/doctor and bundled console assets pass |
| Live service | Same-process-network HTTP smoke passes create/read/normalized search/audit/delete with cache prevention |

One Starlette warning reports deprecation of httpx-backed TestClient in favor of httpx2.
The locked test client still passes; it is not suppressed. An early package attempt failed
before README existed, and an initial static-response test hung because buffered ASGI body
replay failed to delegate subsequent receive calls. Both causes were corrected before the
successful runs. The static console asset tests exercise the repaired response path.
An initial live-service probe from a separate execution network namespace failed to connect;
launching the service and probe in the same execution namespace passes.

## Not executed / not qualified

- Docker build/Compose: definitions provided; Docker runtime unavailable. Base-image tags
  remain mutable demonstration tags.
- Real browser rendering/mobile interaction: Chromium was unavailable and its attempted
  download produced invalid archives. Static assets/API pass; visual/browser QA is UNKNOWN.
- Deployment: no hosting provider, domain or cloud resources provisioned; no live deployment.
- Independent security review, real KMS custody/IAM, externally immutable auditing,
  disaster recovery, destructive key retirement, search-root rotation and performance SLOs.

The [machine-readable receipt](verification.json) binds runtime source hashes, records
exact local dependency versions and links the hosted observation. It is a development receipt,
not independently signed evidence or an audit. Future changes require fresh evidence for
the affected behavior. [Roadmap](roadmap.md) lists unfinished product work.
