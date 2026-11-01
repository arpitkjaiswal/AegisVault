# Verification status

Recorded 2026-11-01. **Research prototype; no production qualification.**

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

- PostgreSQL 16 integration: CI definition provided; no reachable authorized PostgreSQL
  service was available here. SQLAlchemy dialect portability alone is not a passed test.
- Docker build/Compose: definitions provided; Docker runtime unavailable. Base-image tags
  remain mutable demonstration tags.
- Real browser rendering/mobile interaction: Chromium was unavailable and its attempted
  download produced invalid archives. Static assets/API pass; visual/browser QA is UNKNOWN.
- GitHub hosted CI: no run exists until a repository is created and the commit is pushed.
- Deployment: no hosting provider, domain or cloud resources provisioned; no live deployment.
- Independent security review, real KMS custody/IAM, externally immutable auditing,
  disaster recovery, destructive key retirement, search-root rotation and performance SLOs.

The [machine-readable receipt](verification.json) binds runtime source hashes and records
exact installed dependency versions for the local observation. It is a development receipt,
not independently signed evidence or an audit. Future changes require fresh evidence for
the affected behavior. [Roadmap](roadmap.md) lists unfinished product work.
