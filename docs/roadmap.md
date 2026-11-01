# Relationship to Cryptalis and delivery roadmap

The baseline inspected on 2026-11-01 is
[Debrato2005/cryptalis](https://github.com/Debrato2005/cryptalis), especially its README,
AGENTS, engineering playbook, requirements, compatibility matrix and status. Its current
capabilities evolve; this table describes architectural focus, not a permanent competitive
ranking or a performance/security benchmark. No upstream source was copied into this SDK.

| Area | AegisVault 0.1 | Future acceptance criterion |
|---|---|---|
| Integration | Explicit document SDK + HTTP service | Optional ORM bridge with native-query differential tests |
| Policies | Role and purpose checks; server-owned tenant | OIDC identity, expiring credentials and live revocation tests |
| Auditing | Transactional HMAC chains + trusted-prefix verification | External checkpoint publication with outage/rollback drills |
| Data | Typed whole documents including JSON | Versioned manifest evolution and resumable schema migration |
| Search | Declared equality/IN | Search-root rotation, constraints, separately reviewed richer leakage profiles |
| Keys | Provider protocol and synthetic-data local keyring | Real KMS envelope API, IAM/outage/backup qualification |
| Lifecycle | Bounded rewrap and payload regeneration | Authenticated job fencing, concurrency/crash fault injection, export/removal |
| Deployability | Local console, package, Compose recipe, CI | Run PostgreSQL/Docker/hosted CI and synthetic staging smoke tests |
| Assurance | Crypto vector, adversarial SDK/API tests | Independent review, supply-chain provenance, measured SLOs |

Cryptalis has a substantially broader transparent SQLAlchemy/SQLModel and PostgreSQL
schema-lifecycle implementation. AegisVault's policy/audit/console workflow is an additional
direction to evaluate; a small new prototype does not supersede that work. Every future
acceptance criterion above remains unfinished until implemented and exercised.
