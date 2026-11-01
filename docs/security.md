# Security contract and limitations

## Threat model

The target is an observer with repository source, manifest and database contents but
without the application's external key roots. This prototype does not defend a compromised
application host, stolen bearer credential, authorized malicious caller, runtime memory
inspection or an operator with key-file access. Python cannot promise key/cleartext zeroization.

Every document is canonical JSON encrypted as a unit using a random 32-byte record data key
and a random 12-byte AES-256-GCM-SIV nonce. The data key is separately wrapped under a
tenant/project-derived wrapping key. The authenticated associated data binds format `AV1`,
project, manifest fingerprint, tenant, collection, record ID and revision. Wrapping additionally
binds the key-generation label. Key derivation uses HKDF-SHA-256 with distinct purpose labels.
Keys never pass to the SQLAlchemy driver as bind parameters. This is not evidence about
OS swap, host logs, memory dumps, driver bugs or a hostile application process.

The independent search root derives per-project, tenant, collection and field HMAC-SHA-256
keys. Full 256-bit terms implement exact equality and bounded IN. The independent audit root
derives per-tenant audit keys. A provider must retain old wrapping generations until all
current data AND retained backups/recovery routes have been handled. Changing the search
or audit root is not a supported rotation workflow.

## Leakage and database attacks

Visible metadata includes project/tenant/collection/record identifiers, record counts,
ciphertext lengths, revisions, key generations, query access patterns and audit actor/purpose/
operation/timing metadata. Do not put sensitive data in identifiers or purpose/actor labels.
Exact terms expose equality and frequency within a tenant/field and can enable inference
against small-domain data. Casefold follows Python `str.casefold`, not a database collation
or a full email-address equivalence rule. Declaring exact search requires explicit leakage
acceptance. All fields, including JSON, are encrypted in the payload.

The SDK authenticates returned candidates and rechecks their normalized field value.
It cannot prove that a hostile database returned all matching rows, retained all records,
or returned the newest valid record. Deleting search terms can hide results. A complete
old row can be replayed. Revision checks provide concurrency control against normal writers,
not freshness against a hostile database. No hostile-database uniqueness guarantee exists.

## Policy and API

The host must authenticate `Context`. The included HTTP adapter resolves high-entropy
bearer-token hashes to server-side principal/tenant/role/purpose records. These static demo
tokens have no built-in expiry, identity federation or live reload; credential changes require
server restart. TLS and request-rate/concurrency limits must be supplied before any public
service. Hashing tokens is suitable here because generated tokens carry 256 bits of entropy;
it is not a password-storage scheme. No cross-origin credentials or cookie authentication
are enabled. The API body cap is 512 KiB; the reverse proxy still needs timeouts and
connection limits. A client can consume resources by sending a slow body below that cap.

Write permission returns only ID/revision. Search requires both search and read permission.
Rotation is privileged and decrypts records in server memory to verify them; grant it only
to principals trusted with that capability. The CLI assumes an already trusted local operator.
It is not a remotely authenticated administrative interface. The manifest is trusted
application configuration, not an authorization policy approved by the database.

The [Render demo host](render.md) reads independent 32-byte wrapping/search/audit secrets
and an admin bearer from stable environment variables; it creates no key files. It refuses
missing secrets, non-PostgreSQL URLs and plaintext-fallback SSL modes, and applies a 32-request
concurrency cap. TLS `require` encrypts the database link but does not verify Render's
self-signed internal server certificate. This profile fixes one demo tenant and generation
g1; it does not qualify cloud KMS custody, advanced identity, remote key rotation or rate limiting.

## Audit integrity

Successful create/update/read/search/delete/rotation operations append one HMAC-authenticated
event in the same database transaction. Audit commit failure prevents successful return.
The chain stores metadata, never payload values or search values. Failed operations,
configuration reads and checkpoint verification are not logged by this chain.

A database-held head alone cannot detect removal of the head and tail together or a full
database rollback. Persist checkpoints in separately trusted, access-controlled storage and
pass one to `verify_audit`. Verification requires that exact trusted prefix to still exist.
It verifies a snapshot prefix; concurrent later appends may not be included in the returned
checkpoint. No external immutable audit sink is implemented. An audit-root holder can forge
the chain. A valid HMAC is not proof that an event's description reflects reality.

## Unqualified boundaries

No independent cryptographic review, production key custody, cloud IAM/KMS adapter,
HSM attestation, crypto-shredding guarantee, backup-erasure proof, disaster-recovery drill,
availability guarantee, hostile-database freshness/completeness proof, performance SLO,
rate limiting or production deployment is qualified. LocalKeyring is for synthetic local
data. A Protocol named KeyProvider does not itself establish secure external custody.

References: [cryptography AEAD documentation](https://cryptography.io/en/latest/hazmat/primitives/aead/),
[RFC 8452](https://www.rfc-editor.org/rfc/rfc8452),
[SQLAlchemy transaction documentation](https://docs.sqlalchemy.org/en/20/core/connections.html).
The test suite includes the zero-length AES-256-GCM-SIV vector from RFC 8452 C.2.
