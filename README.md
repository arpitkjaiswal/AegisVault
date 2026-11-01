# AegisVault

**An encrypted document workspace with policy-gated reads, explicit search leakage,
and an authenticated audit trail.** Python SDK · SQLAlchemy · PostgreSQL · HTTP API · local console.

**Research prototype. Use synthetic data. Not independently audited or production-security-qualified.**
See [verification status](docs/status.md), [security boundaries](docs/security.md), and
[deployment instructions](docs/deployment.md).

[Hosted verification](https://github.com/arpitkjaiswal/AegisVault/actions/runs/41283307678):
32 tests pass in each database job, with packaging/install and Render-style Docker/TLS,
restart and database-outage checks passing at `69bb77c`. Live Render deployment is pending.

## Run it

**Deploying to Render?** Use the included [`render.yaml`](render.yaml) Blueprint and the
[Render guide](docs/render.md). The cloud profile uses environment secrets and PostgreSQL,
honors `PORT`, and checks `/readyz`. No local state directory or persistent app disk is needed.

Python 3.12+ and [uv](https://docs.astral.sh/uv/) are required.

```bash
uv sync --frozen
uv run aegisvault init
uv run aegisvault serve
```

Open <http://127.0.0.1:8000>. Copy the token from the generated private
`.aegisvault/demo-token.json` into the console. Store the sample document, read it,
search for `ADA@example.test`, and verify its audit checkpoint. The token stays in page
memory. Refresh the page to disconnect. No third-party scripts, fonts or telemetry are used
by the console.

Initialization creates **new vault tables**, not a transparent migration of an existing
application. The default SQLite database is for a local demo. PostgreSQL is the intended
service backend; its integration test job is included. Never point `init` at production.

## What works in this version

| Capability | Contract |
|---|---|
| Manifest-first documents | Strict declared fields; string, integer, boolean, ISO date, JSON and explicit NULL |
| Authenticated encryption | Random record DEK; AES-256-GCM-SIV; tenant-derived wrapping keys; bound manifest, tenant, collection, ID and revision |
| Exact / IN search | Independent HMAC-SHA-256 terms, optional casefold, bounded pagination; mandatory equality-leakage acceptance |
| Policy-gated operations | Server-authenticated tenant, actor, roles and purpose; separate read/write/search/delete/rotate permissions |
| Optimistic writes | Create requires revision 0; update/delete require the current revision |
| Two rotation workflows | Bounded wrapping-key rewrap and payload-key regeneration; cursor checkpoints between committed batches |
| Audit verification | Tenant-scoped HMAC chain in the same transaction; optional external trusted-prefix checkpoint |
| API and console | Bearer credentials stored as hashes, request-body limit, redacted errors, cache prevention, restrictive console CSP |
| Local packaging | Frozen dependency lock, wheel/sdist packaging, pytest checks and PostgreSQL CI definition |

Exact search also supports a whole JSON field when explicitly declared; JSON-path, prefix,
fuzzy, range and order queries are not implemented. This version is an explicit repository
API, not SQLAlchemy Session interception. It does not provide transparent SQLModel integration,
online migration, arbitrary joins, unique encrypted constraints, or search-root rotation.

## Python integration

```python
from pathlib import Path
from sqlalchemy import create_engine
from aegisvault import Context, LocalKeyring, Manifest, Vault
from aegisvault.cli import private_json

state = Path(".aegisvault")
manifest = Manifest.load((state / "manifest.json").read_bytes())
provider = LocalKeyring.from_json(private_json(state / "keys.json"))
engine = create_engine(private_json(state / "config.json")["database_url"], hide_parameters=True)
vault = Vault(engine, manifest, provider)
# Authenticate the caller before constructing this host assertion.
ctx = Context("demo", "authenticated-user-id", frozenset({"admin"}), "support")
vault.put(
    ctx,
    "customers",
    "customer-001",
    {"name": "Ada Lovelace", "email": "ada@example.test", "profile": {"plan": "research"}},
)
customer = vault.get(ctx, "customers", "customer-001")
matches = vault.search(ctx, "customers", "email", ["ADA@example.test"])
vault.put(
    ctx,
    "customers",
    customer["id"],
    {**customer["document"], "name": "Ada"},
    expected_revision=customer["revision"],
)
```

`Context` is a trusted application input. The SDK cannot validate that a host authenticated it.
The HTTP adapter never accepts tenant or roles from a record request. Never expose a
constructor for arbitrary `Context` values directly to untrusted clients.

## Operator commands

```bash
uv run aegisvault doctor
uv run aegisvault leakage
uv run aegisvault audit --tenant demo > checkpoint.json
uv run aegisvault audit --tenant demo --checkpoint checkpoint.json
uv run aegisvault rotate customers --tenant demo --mode rewrap
uv run aegisvault rotate customers --tenant demo --mode reencrypt
```

The key-generation configuration must be changed before a wrapping-key rotation; see
[operations](docs/operations.md). Each call handles at most 100 records. Persist the returned
`next` cursor and pass `--after CURSOR` until it is null. A crash before commit rolls back
the entire batch. Restarting without the last committed cursor can reprocess records;
payload re-encryption then increases revisions again. **Old keys are never deleted automatically.**

## Develop and verify

```bash
uv sync --frozen --all-groups
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv build
```

The default suite uses isolated SQLite databases. To exercise the same SDK/API tests with
a freshly created disposable PostgreSQL instance:

```bash
export AEGIS_TEST_DATABASE_URL='postgresql+psycopg://user:password@localhost/disposable_db'
export AEGIS_DISPOSABLE_TEST_TARGET=yes
uv run pytest -q
```

Only the environment variable name, not its value, should appear in shared logs. The suite
creates `av_*` tables and deletes its project-scoped fixture rows. Do not authorize a shared
or production database as a test target.

## Design and direction

The inspiration is [Cryptalis](https://github.com/Debrato2005/cryptalis), whose manifest-first
approach and evidence discipline are useful reference points. AegisVault is an independently
implemented document-vault architecture, not a renamed copy or a claim of overall superiority.
Its current emphasis is a policy/audit/service workflow; Cryptalis has a much broader ORM
and database-lifecycle surface. [Comparison and roadmap](docs/roadmap.md) separates working
features from future ambitions.

Read [architecture](docs/architecture.md), [security](docs/security.md),
[operations](docs/operations.md), [deployment](docs/deployment.md) and [status](docs/status.md).
MIT licensed. No package publication or live deployment has been performed by this checkout.
