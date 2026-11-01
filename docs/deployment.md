# Deployment path

For Render, use the [Render guide](render.md) and root `render.yaml`. That profile uses
stable environment secrets and managed PostgreSQL, with a separate `render` start command.
The file-based commands below remain the local/Compose workflow.

The first deployment target is a **private synthetic-data staging demo**. There is no
production approval or running public deployment. Hosted PostgreSQL 16 integration,
packaging and Render-style Docker/TLS/restart/outage smoke checks pass. Consult status.md
for the actual evidence boundaries; a live Render smoke test is still the operator's step.
Docker and Compose must be installed on the deployment host.

## Local PostgreSQL + application containers

```bash
uv sync --frozen
python scripts/prepare_compose.py
docker compose build
docker compose up -d db
docker compose run --rm init
docker compose up -d app
```

The init service refuses an existing state directory; run it once for a new named volume.
The PostgreSQL port is not published. The console/API bind to host loopback only.
Get the synthetic demo token through an authorized local container read:

```bash
docker compose exec app python -c 'import json; print(json.load(open("/state/vault/demo-token.json"))["token"])'
```

Open <http://127.0.0.1:8000>, connect and exercise create/read/search/audit. Inspect `docker
compose ps` and `/healthz`. Health is liveness only; it does not establish database readiness
or cryptographic correctness. `doctor` provides the separate contract/inventory check:

```bash
docker compose exec app python -m aegisvault.cli --state /state/vault doctor
```

`docker compose down` stops the demo and retains volumes. Deleting volumes destroys data
and key custody; do not add `-v` unless their destruction is explicitly intended.

The container runs without root as UID/GID 10001; named volumes inherit the state directory
ownership. Runtime filesystem is read-only except the state volume and /tmp. For a host
bind mount, provision correct ownership and private permissions yourself. The Compose database
account owns the synthetic demo tables; it is not a least-privilege production role design.
The demo keyring sits in the application state volume, separate from the database volume,
but both remain subject to the Docker host's trust boundary.

## Before any public endpoint

Keep this synthetic-only until independent review and production key custody are qualified.
For a private staging evaluation, first run PostgreSQL CI and the container smoke journey,
then place the loopback app behind your existing TLS/authenticated access proxy. Supply
rate limits, request timeouts, connection limits, controlled credential distribution and
backups under separate custody. Never log authorization headers or request/response bodies.
Don't expose the PostgreSQL port. Choose a hosting provider and region before provisioning;
no cloud resources, billing commitments or domains are created by this project.

Runtime dependencies are exported with hashes from uv.lock into requirements.lock.
Regenerate after deliberate dependency changes:

```bash
uv export --frozen --no-dev --no-emit-project --format requirements-txt -o requirements.lock
```

The Docker/Python/PostgreSQL base tags in this demonstration are mutable. Pin reviewed image
digests and record platform-specific provenance before a qualified deployment. Dependency
locks and hashes are not independent security review or proof of safe upstream packages.

## GitHub publication

The source repository is [arpitkjaiswal/AegisVault](https://github.com/arpitkjaiswal/AegisVault).
Before each publication, verify that
only source/docs/tests/locks are staged and all `.aegisvault`, `.env`, database, key and token
files are ignored. Inspect hosted CI for the published revision. Status.md records the
initial passing source run; a workflow definition alone never establishes a passed run.
