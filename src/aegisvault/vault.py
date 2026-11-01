"""Explicit SQLAlchemy repository API: no ORM monkey-patching or SQL rewriting."""

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import (
    Column,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    and_,
    delete,
    func,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError

from .crypto import KeyProvider, derive, seal, search_token, unseal
from .errors import (
    AccessDenied,
    Conflict,
    IntegrityFailure,
    InvalidDocument,
    InvalidManifest,
    NotFound,
    UnsupportedQuery,
)
from .manifest import Manifest, canonical

metadata = MetaData()
contracts = Table(
    "av_contracts",
    metadata,
    Column("project", String(128), primary_key=True),
    Column("fingerprint", String(64), nullable=False),
)
records = Table(
    "av_records",
    metadata,
    Column("project", String(128), primary_key=True),
    Column("tenant", String(128), primary_key=True),
    Column("collection", String(128), primary_key=True),
    Column("id", String(128), primary_key=True),
    Column("revision", Integer, nullable=False),
    Column("generation", String(128), nullable=False),
    Column("wrapped_key", LargeBinary, nullable=False),
    Column("payload", LargeBinary, nullable=False),
)
terms = Table(
    "av_terms",
    metadata,
    Column("project", String(128), primary_key=True),
    Column("tenant", String(128), primary_key=True),
    Column("collection", String(128), primary_key=True),
    Column("field", String(128), primary_key=True),
    Column("token", String(64), primary_key=True),
    Column("id", String(128), primary_key=True),
)
heads = Table(
    "av_audit_heads",
    metadata,
    Column("project", String(128), primary_key=True),
    Column("tenant", String(128), primary_key=True),
    Column("seq", Integer, nullable=False),
    Column("head", String(64), nullable=False),
)
events = Table(
    "av_events",
    metadata,
    Column("project", String(128), primary_key=True),
    Column("tenant", String(128), primary_key=True),
    Column("seq", Integer, primary_key=True),
    Column("body", Text, nullable=False),
    Column("mac", String(64), nullable=False),
)


def identifier(value: str) -> None:
    if type(value) is not str or not value or len(value) > 128 or any(ord(c) < 32 for c in value):
        raise InvalidDocument()


@dataclass(frozen=True)
class Context:
    """An authenticated HOST assertion. The SDK cannot authenticate these attributes."""

    tenant: str
    actor: str
    roles: frozenset[str]
    purpose: str

    def __post_init__(self):
        for value in [self.tenant, self.actor, self.purpose]:
            identifier(value)
        if type(self.roles) is not frozenset or any(type(r) is not str for r in self.roles):
            raise AccessDenied()


class Vault:
    def __init__(self, engine: Engine, manifest: Manifest, provider: KeyProvider):
        self.engine = engine
        # Own a validated copy; caller changes to the original cannot alter the contract.
        self._manifest = Manifest.load(manifest.model_dump_json())
        self.provider = provider
        self.project = manifest.project
        self.fingerprint = self._manifest.fingerprint

    @property
    def manifest(self) -> Manifest:
        return Manifest.load(self._manifest.model_dump_json())

    def initialize(self) -> None:
        """Create only AegisVault's new tables. Never migrate existing user tables."""
        metadata.create_all(self.engine)
        try:
            with self.engine.begin() as con:
                found = con.scalar(
                    select(contracts.c.fingerprint).where(contracts.c.project == self.project)
                )
                if found is None:
                    con.execute(
                        insert(contracts).values(project=self.project, fingerprint=self.fingerprint)
                    )
                elif found != self.fingerprint:
                    raise InvalidManifest()
        except IntegrityError:
            raise Conflict() from None

    def _contract(self, con: Connection) -> None:
        if (
            con.scalar(select(contracts.c.fingerprint).where(contracts.c.project == self.project))
            != self.fingerprint
        ):
            raise InvalidManifest()

    def _authorize(self, ctx: Context, collection: str, operation: str):
        identifier(collection)
        spec = self._manifest.collections.get(collection)
        if (
            spec is None
            or ctx.purpose not in spec.purposes
            or not ctx.roles.intersection(spec.roles[operation])
        ):
            raise AccessDenied()
        return spec

    def _scope(self, table, ctx: Context, collection: str | None = None, rid: str | None = None):
        clauses = [table.c.project == self.project, table.c.tenant == ctx.tenant]
        if collection is not None:
            clauses.append(table.c.collection == collection)
        if rid is not None:
            clauses.append(table.c.id == rid)
        return and_(*clauses)

    def _aad(self, ctx: Context, collection: str, rid: str, revision: int) -> bytes:
        return canonical(
            ["AV1", self.project, self.fingerprint, ctx.tenant, collection, rid, revision]
        )

    def _wrap_aad(self, aad: bytes, generation: str) -> bytes:
        return canonical(["AV1/wrap", aad.hex(), generation])

    def _encode(self, ctx: Context, collection: str, rid: str, revision: int, document: dict):
        aad = self._aad(ctx, collection, rid, revision)
        generation = self.provider.active_generation
        identifier(generation)
        key = os.urandom(32)
        kek = derive(self.provider.wrapping_key(generation), "wrap", self.project, ctx.tenant)
        return {
            "revision": revision,
            "generation": generation,
            "payload": seal(key, canonical(document), aad),
            "wrapped_key": seal(kek, key, self._wrap_aad(aad, generation)),
        }

    def _unwrap(self, ctx, collection, row):
        aad = self._aad(ctx, collection, row["id"], row["revision"])
        kek = derive(
            self.provider.wrapping_key(row["generation"]), "wrap", self.project, ctx.tenant
        )
        return aad, unseal(kek, row["wrapped_key"], self._wrap_aad(aad, row["generation"]))

    def _decode(self, ctx: Context, collection: str, row) -> dict:
        try:
            aad, key = self._unwrap(ctx, collection, row)
            document = json.loads(unseal(key, row["payload"], aad))
            self._manifest.collections[collection].validate_document(document)
        except (ValueError, TypeError, InvalidDocument):
            raise IntegrityFailure() from None
        return {"id": row["id"], "revision": row["revision"], "document": document}

    def _token(self, ctx: Context, collection: str, field: str, value: object):
        spec = self._manifest.collections[collection].fields.get(field)
        if spec is None or spec.search != "exact":
            raise UnsupportedQuery()
        return search_token(
            self.provider, self.project, ctx.tenant, collection, field, spec.normalized(value)
        )

    def _index(self, con, ctx, collection, rid, document):
        con.execute(delete(terms).where(self._scope(terms, ctx, collection, rid)))
        values = [
            dict(
                project=self.project,
                tenant=ctx.tenant,
                collection=collection,
                id=rid,
                field=field,
                token=self._token(ctx, collection, field, document[field]),
            )
            for field, spec in self._manifest.collections[collection].fields.items()
            if spec.search == "exact"
        ]
        if values:
            con.execute(insert(terms), values)

    def _audit_key(self, ctx):
        return derive(self.provider.audit_root(), "audit", self.project, ctx.tenant)

    def _audit(self, con, ctx, operation, collection, rid=None, **details):
        scope = self._scope(heads, ctx)
        head = con.execute(select(heads).where(scope).with_for_update()).mappings().first()
        if head is None:
            con.execute(
                insert(heads).values(project=self.project, tenant=ctx.tenant, seq=0, head="0" * 64)
            )
            seq, previous = 0, "0" * 64
        else:
            seq, previous = head["seq"], head["head"]
        body = canonical(
            dict(
                seq=seq + 1,
                previous=previous,
                project=self.project,
                tenant=ctx.tenant,
                actor=ctx.actor,
                purpose=ctx.purpose,
                operation=operation,
                collection=collection,
                record=rid,
                time=datetime.now(UTC).isoformat(),
                **details,
            )
        )
        mac = hmac.new(self._audit_key(ctx), body, hashlib.sha256).hexdigest()
        con.execute(
            insert(events).values(
                project=self.project, tenant=ctx.tenant, seq=seq + 1, body=body.decode(), mac=mac
            )
        )
        changed = con.execute(
            update(heads)
            .where(scope, heads.c.seq == seq, heads.c.head == previous)
            .values(seq=seq + 1, head=mac)
        ).rowcount
        if changed != 1:
            raise Conflict()

    def put(
        self, ctx: Context, collection: str, rid: str, document: dict, expected_revision: int = 0
    ) -> dict:
        spec = self._authorize(ctx, collection, "write")
        identifier(rid)
        if type(expected_revision) is not int or not 0 <= expected_revision < 2**31 - 1:
            raise InvalidDocument()
        spec.validate_document(document)
        encoded = self._encode(ctx, collection, rid, expected_revision + 1, document)
        try:
            with self.engine.begin() as con:
                self._contract(con)
                if expected_revision == 0:
                    con.execute(
                        insert(records).values(
                            project=self.project,
                            tenant=ctx.tenant,
                            collection=collection,
                            id=rid,
                            **encoded,
                        )
                    )
                elif (
                    con.execute(
                        update(records)
                        .where(
                            self._scope(records, ctx, collection, rid),
                            records.c.revision == expected_revision,
                        )
                        .values(**encoded)
                    ).rowcount
                    != 1
                ):
                    raise Conflict()
                self._index(con, ctx, collection, rid, document)
                self._audit(
                    con,
                    ctx,
                    "create" if expected_revision == 0 else "update",
                    collection,
                    rid,
                    revision=encoded["revision"],
                )
        except IntegrityError:
            raise Conflict() from None
        # No plaintext value is re-read or returned to write-only principals.
        return {"id": rid, "revision": encoded["revision"]}

    def get(self, ctx: Context, collection: str, rid: str) -> dict:
        self._authorize(ctx, collection, "read")
        identifier(rid)
        try:
            with self.engine.begin() as con:
                self._contract(con)
                row = (
                    con.execute(select(records).where(self._scope(records, ctx, collection, rid)))
                    .mappings()
                    .first()
                )
                if row is None:
                    raise NotFound()
                result = self._decode(ctx, collection, row)
                self._audit(con, ctx, "read", collection, rid, revision=row["revision"])
        except IntegrityError:
            raise Conflict() from None
        return result

    def search(
        self,
        ctx: Context,
        collection: str,
        field: str,
        values: list,
        limit: int = 50,
        after: str = "",
    ) -> dict:
        spec = self._authorize(ctx, collection, "search")
        self._authorize(ctx, collection, "read")
        if type(values) is not list or not 1 <= len(values) <= 100:
            raise UnsupportedQuery()
        if type(limit) is not int or not 1 <= limit <= 100 or type(after) is not str:
            raise UnsupportedQuery()
        tokens = [self._token(ctx, collection, field, value) for value in values]
        normalized = {spec.fields[field].normalized(value) for value in values}
        try:
            with self.engine.begin() as con:
                self._contract(con)
                candidates = select(terms.c.id).where(
                    self._scope(terms, ctx, collection),
                    terms.c.field == field,
                    terms.c.token.in_(tokens),
                )
                rows = (
                    con.execute(
                        select(records)
                        .where(
                            self._scope(records, ctx, collection),
                            records.c.id.in_(candidates),
                            records.c.id > after,
                        )
                        .order_by(records.c.id)
                        .limit(limit + 1)
                    )
                    .mappings()
                    .all()
                )
                found = [self._decode(ctx, collection, row) for row in rows]
                if any(
                    spec.fields[field].normalized(item["document"][field]) not in normalized
                    for item in found
                ):
                    raise IntegrityFailure()
                self._audit(
                    con, ctx, "search", collection, field=field, count=min(len(found), limit)
                )
        except IntegrityError:
            raise Conflict() from None
        return {
            "records": found[:limit],
            "next": found[limit - 1]["id"] if len(found) > limit else None,
        }

    def delete(self, ctx: Context, collection: str, rid: str, expected_revision: int) -> None:
        self._authorize(ctx, collection, "delete")
        identifier(rid)
        if type(expected_revision) is not int or expected_revision < 1:
            raise InvalidDocument()
        try:
            with self.engine.begin() as con:
                self._contract(con)
                if (
                    con.execute(
                        delete(records).where(
                            self._scope(records, ctx, collection, rid),
                            records.c.revision == expected_revision,
                        )
                    ).rowcount
                    != 1
                ):
                    raise Conflict()
                con.execute(delete(terms).where(self._scope(terms, ctx, collection, rid)))
                self._audit(con, ctx, "delete", collection, rid)
        except IntegrityError:
            raise Conflict() from None

    def rotate(
        self, ctx: Context, collection: str, mode: str = "rewrap", after: str = "", limit: int = 100
    ) -> dict:
        """Bounded transactions; repeat with next cursor. Retain all old recovery keys."""
        self._authorize(ctx, collection, "rotate")
        if mode not in {"rewrap", "reencrypt"} or type(limit) is not int or not 1 <= limit <= 100:
            raise InvalidDocument()
        try:
            with self.engine.begin() as con:
                self._contract(con)
                rows = (
                    con.execute(
                        select(records)
                        .where(self._scope(records, ctx, collection), records.c.id > after)
                        .order_by(records.c.id)
                        .limit(limit + 1)
                        .with_for_update()
                    )
                    .mappings()
                    .all()
                )
                for row in rows[:limit]:
                    # Authentication is checked even in a wrap-only workflow.
                    plain = self._decode(ctx, collection, row)
                    if mode == "rewrap":
                        aad, key = self._unwrap(ctx, collection, row)
                        generation = self.provider.active_generation
                        kek = derive(
                            self.provider.wrapping_key(generation), "wrap", self.project, ctx.tenant
                        )
                        encoded = dict(
                            generation=generation,
                            wrapped_key=seal(kek, key, self._wrap_aad(aad, generation)),
                        )
                    else:
                        if row["revision"] >= 2**31 - 1:
                            raise Conflict()
                        encoded = self._encode(
                            ctx, collection, row["id"], row["revision"] + 1, plain["document"]
                        )
                    if (
                        con.execute(
                            update(records)
                            .where(
                                self._scope(records, ctx, collection, row["id"]),
                                records.c.revision == row["revision"],
                                records.c.wrapped_key == row["wrapped_key"],
                            )
                            .values(**encoded)
                        ).rowcount
                        != 1
                    ):
                        raise Conflict()
                self._audit(con, ctx, mode, collection, count=min(len(rows), limit))
        except IntegrityError:
            raise Conflict() from None
        return {
            "processed": min(len(rows), limit),
            "next": rows[limit - 1]["id"] if len(rows) > limit else None,
        }

    def verify_audit(self, ctx: Context, checkpoint: dict | None = None) -> dict:
        if not any(
            ctx.purpose in s.purposes and ctx.roles.intersection(s.roles["rotate"])
            for s in self._manifest.collections.values()
        ):
            raise AccessDenied()
        seq, previous = 0, "0" * 64
        anchored = checkpoint is None or checkpoint == {"seq": 0, "head": previous}
        try:
            with self.engine.connect() as con:
                # Snapshot head first. Concurrent appends cannot invalidate the verified prefix.
                self._contract(con)
                head = con.execute(select(heads).where(self._scope(heads, ctx))).mappings().first()
                snapshot_seq = head["seq"] if head else 0
                if head is None and con.scalar(
                    select(func.count()).select_from(events).where(self._scope(events, ctx))
                ):
                    raise IntegrityFailure()
                result = con.execution_options(stream_results=True).execute(
                    select(events)
                    .where(self._scope(events, ctx), events.c.seq <= snapshot_seq)
                    .order_by(events.c.seq)
                )
                for row in result.mappings():
                    body = json.loads(row["body"])
                    mac = hmac.new(
                        self._audit_key(ctx), row["body"].encode(), hashlib.sha256
                    ).hexdigest()
                    seq += 1
                    if (
                        row["seq"] != seq
                        or body["seq"] != seq
                        or body["previous"] != previous
                        or body["project"] != self.project
                        or body["tenant"] != ctx.tenant
                        or not hmac.compare_digest(mac, row["mac"])
                    ):
                        raise IntegrityFailure()
                    previous = mac
                    if checkpoint == {"seq": seq, "head": previous}:
                        anchored = True
                if (
                    head is not None
                    and (head["seq"] != seq or head["head"] != previous)
                    or not anchored
                ):
                    raise IntegrityFailure()
        except (ValueError, TypeError, KeyError):
            raise IntegrityFailure() from None
        return {"seq": seq, "head": previous}

    def check_ready(self) -> None:
        """Probe storage and the active manifest contract without decrypting data."""
        with self.engine.connect() as con:
            self._contract(con)

    def doctor(self) -> dict:
        """Configuration/schema inventory only; not a security qualification."""
        self.provider.wrapping_key(self.provider.active_generation)
        with self.engine.connect() as con:
            self._contract(con)
            counts = con.execute(
                select(records.c.generation, func.count())
                .where(records.c.project == self.project)
                .group_by(records.c.generation)
            ).all()
        return {
            "status": "prototype",
            "dialect": self.engine.dialect.name,
            "fingerprint": self.fingerprint,
            "key_generations": dict(counts),
            "leakage": self._manifest.leakage_report(),
            "production_qualified": False,
        }
