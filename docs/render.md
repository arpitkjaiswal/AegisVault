# Render demo deployment

The Render profile is a **synthetic-data research demo**, not a qualified production
service. It uses a separate PostgreSQL database and stable external environment values;
it never stores live data, roots or credentials on Render's ephemeral application disk.
Code preparation/tests do not create resources or deploy an app in your Render account.

## Deploy using the Blueprint

1. In Render, choose **New → Blueprint**, select `arpitkjaiswal/AegisVault`, branch `main`,
   and load the repository's `render.yaml`.
2. Review the proposed web service and PostgreSQL instance. Both explicitly select the
   **Free** compute plan, with Singapore as the region and PostgreSQL major version 16.
   Choose new names if those resources already exist. Check Render's current costs and
   quota before approving creation. Only one Free PostgreSQL instance per workspace is
   allowed. If that quota is occupied, stop and choose your own existing disposable target
   or deliberately select another plan; never delete a database to make room blindly.
3. Render generates four base64-encoded 256-bit secrets on first creation:
   `AEGIS_WRAPPING_KEY`, `AEGIS_SEARCH_KEY`, `AEGIS_AUDIT_KEY`, `AEGIS_API_TOKEN`.
   `DATABASE_URL` references the database's internal URL. No secret is stored in Git.
4. Create the Blueprint and wait for the web service's `/readyz` health check to succeed.
   Startup creates only the project's `av_*` tables and checks the manifest contract.
5. Open the Render-assigned HTTPS web-service URL. In the service's Environment page,
   reveal/copy **only `AEGIS_API_TOKEN`** and paste that exact string into the console.
   Do not decode the bearer token. Store a synthetic document, read it, search by email,
   and verify the audit checkpoint. The token is never printed by the app or embedded
   in the page. Treat it as an administrative bearer credential.

Automatic deploys are disabled in the Blueprint. When updating the service, review CI,
then manually deploy the tested revision in Render. Keep all existing key variables.
Changing `AEGIS_API_TOKEN` revokes the old token after restart; changing encryption/search/
audit roots breaks access to existing data or history. The service does not regenerate
missing roots and never silently falls back to SQLite or plaintext.

## Manual Web Service setup

If you choose a manual service instead of a Blueprint, create a new disposable Render
PostgreSQL 16 instance in the same region, block external IP access, then configure:

| Setting | Value |
|---|---|
| Repository | `https://github.com/arpitkjaiswal/AegisVault` |
| Branch | `main` |
| Language/runtime | Docker |
| Dockerfile | `./Dockerfile.render` |
| Docker Command | Leave blank (use the image's complete default CMD) |
| Health check | `/readyz` |
| `AEGIS_ALLOW_SYNTHETIC_DEPLOY` | `yes` |
| `DATABASE_URL` | Internal PostgreSQL URL from your new database |
| Four secret variables above | Independent random, base64-encoded 32-byte values |

Leave `PORT` to Render. The process binds `0.0.0.0` and uses Render's `PORT` (default
10000 if absent). The Render image has no ENTRYPOINT and directly runs
`python -m aegisvault.render`. Do **not** use the old file-based `serve` command for this cloud profile.
It expects local private files and is intended for the local/Compose workflow.

### Updating a service created with the earlier configuration

Set **Dockerfile Path** to `./Dockerfile.render`, clear the old **Docker Command** value
`render`, save, and manually deploy the latest commit. If the dashboard requires a
command, enter the complete `python -m aegisvault.render`. The bare word `render` is a
CLI subcommand, not an executable. Retain the existing database and all secret variables;
this correction needs no new keys or database. A previously saved dashboard override can
survive a source change, so inspect that field even after updating the Blueprint.

## Restart, health and custody boundaries

The new process reconstructs the same manifest, provider and hashed server-side credential
from stable environment variables on every boot. It verifies all configuration before
touching the database. Application restarts/redeploys keep data readable when the database
and roots are retained. A changed manifest fingerprint refuses startup. Missing/invalid
roots or an insecure/non-PostgreSQL connection URL refuse startup with redacted diagnostics.

Both `postgres://` and `postgresql://` URLs are normalized to the psycopg SQLAlchemy
driver. Connections require TLS (`sslmode=require`, or a supplied stronger verification
mode); plaintext-fallback modes are refused. Render's internal database certificates are
self-signed, so `require` encrypts the connection without authenticating the server's
certificate chain. It is not a claim of verified database identity.

`/healthz` reports process liveness. `/readyz` checks the database connection and the active
manifest contract; a database outage or contract drift returns HTTP 503 without credentials
or driver error text. SQL pools check stale connections before reuse. Public health checks
do not decrypt the entire database or establish security qualification. The Render host
caps application concurrency at 32, but it does not provide an application rate limiter.
TLS termination, public slow-client limits and platform availability remain Render boundaries.

Use an independent, securely controlled backup of all three roots, the manifest contract,
the database and separately anchored audit checkpoints. Environment variables are development
custody under the service/workspace's trust boundary, not an independently qualified KMS.
The Render profile currently fixes wrapping generation `g1`, one `demo` tenant and one admin
principal. Hosted wrapping-generation rotation, federated identity and live credential reload
remain outside this profile; the richer local SDK lifecycle is separately documented.

## Free-tier limits

Render free web services spin down after 15 idle minutes and lose local files on restart.
This profile stores nothing durable there. Free PostgreSQL currently expires after 30 days,
has no backups and is limited to one active instance per workspace. Export needed synthetic
data before expiry or deliberately select a suitable paid database yourself. This Blueprint
does not configure a paid upgrade. Free compute also has usage limits and potential
workspace-dependent overage behavior; review your workspace's billing/spend settings.

## What is tested

`tests/test_render.py` covers redacted startup refusal, TLS URL handling, environment-key
stability, restart reconstruction and readiness semantics. The `render-container` CI job
builds `Dockerfile.render` and uses its default CMD on port 10000 against a TLS-enabled disposable
PostgreSQL 16 container. It exercises authenticated encrypted writes, reads, search and audit,
restarts the application with a read-only filesystem and no state volume, and then stops and
restarts PostgreSQL to verify readiness and retained data. Consult [status](status.md) for
the actual run outcome. Render's infrastructure, Blueprint creation and public HTTPS routing
still require the operator's post-deployment smoke test.

Official references: [Blueprint specification](https://render.com/docs/blueprint-spec),
[port binding](https://render.com/docs/web-services#port-binding),
[Docker command override](https://render.com/docs/docker),
[PostgreSQL connections](https://render.com/docs/postgresql-creating-connecting),
[free-tier limits](https://render.com/docs/free).
