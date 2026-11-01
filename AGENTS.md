# Working on AegisVault

Read README.md and docs/security.md before implementation. Keep implemented behavior,
executed evidence and roadmap ambitions distinct. Never claim production readiness from
passing tests. Do not invent crypto primitives or claim hostile-database freshness,
completeness, erasure, secure custody or external immutability without appropriate evidence.

Preserve unrelated work. Never commit private state, tokens, key files, database dumps or
connection strings. Tests use isolated SQLite by default; external PostgreSQL tests require
AEGIS_DISPOSABLE_TEST_TARGET=yes and a purpose-created disposable target. Do not run
against production. Run affected tests and Ruff, update docs/status.md, then commit/push
when the user has authorized it. No automatic deployment, key deletion or package release.
