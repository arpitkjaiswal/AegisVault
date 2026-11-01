# Operations

## Configuration and error handling

`aegisvault init` creates a new private state directory and refuses to overwrite one.
On POSIX, key/config/credential files must be owned by the process user with mode 0600;
the directory starts with mode 0700. Keep the entire state directory out of source control.
Private file loading rejects symlinks. Secure filesystem ownership and backup custody
remain operator responsibilities. The manifest is immutable for an initialized project.

For a new disposable PostgreSQL demo, put its SQLAlchemy URL in an environment variable,
then run `aegisvault init --database-url-env YOUR_VARIABLE`. The name is read, never printed.
The URL is copied into the private config file. `doctor` checks contract and lists current
wrapping generations; it does not scan every record or qualify deployment security.

Errors expose stable codes, not input values, SQL bind parameters or provider exceptions.
`revision_conflict` means refetch current state before retrying a write. In a connection-loss
or response-loss scenario, inspect the record/audit state before assuming rollback. There
is no general HTTP idempotency-key protocol. Retrying a create after an ambiguous commit
returns a conflict if it was committed.

## Wrapping-key rotation

1. Back up the current private configuration and database through an authorized recovery
   process. Prove the existing backup can be read before changing key availability.
2. Generate an independent 32-byte key, store it base64-encoded under a new generation in
   `keys.json`, retain the old generation, and select the new `active_generation`. Use an
   atomic owner-only file replacement. Do not put keys in shell arguments or Git.
3. Stop old writers and restart the application processes so all new writes use the new
   generation. Multi-process authenticated deployment fencing is not implemented.
4. Run `aegisvault rotate customers --tenant TENANT --mode rewrap`; persist `next` and
   continue with `--after CURSOR`. Repeat for each collection and tenant. A batch commits
   its records and audit event together. A failed batch is rolled back.
5. Run `doctor`, read representative records and inspect the generation inventory. Rewrap
   changes the wrapped key, not the payload or document revision. `reencrypt` regenerates
   record data keys/payloads and increments revisions. It keeps existing search terms.
6. Keep the old keys for retained backups and recovery routes. Current-table completion is
   not permission to destroy old keys. No key-retirement command is provided.

The cursor is not a global snapshot or a job fence. Concurrent old-generation writers can
reintroduce old generations, and new IDs behind a cursor may be missed. Quiesce writers
for the supported operator workflow. If a crash happens after a committed batch but before
its cursor was saved, repeating it is safe for data readability, but re-encryption may
increment revisions again. It does not produce exactly-once operation receipts.

## Audit checkpoints and recovery

Save `aegisvault audit --tenant TENANT` output to trusted storage outside the database.
Verify a later restored database with `--checkpoint PATH`. A checkpoint from another
tenant/project fails except for the indistinguishable all-zero empty chain. Store checkpoint
metadata with the project and tenant in the external system. Back up the manifest, keyring,
credentials, DB and external checkpoints with separate access controls. Losing a key root
may permanently destroy access to its data. This prototype has no disaster-recovery claim.

## Export/removal

There is no automatic plaintext reversal/removal of an application's existing tables,
because this version creates its own document tables. An authorized host can read known
record IDs through `get` and transform them into another store. That is not an automated,
verified migration. Do not delete the vault database or keys until the destination and all
retained recovery obligations have been independently verified.
