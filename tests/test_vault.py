import json
from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy import delete, event, select, update

from aegisvault import LocalKeyring, Manifest, Vault
from aegisvault.crypto import derive, seal, unseal
from aegisvault.errors import (
    AccessDenied,
    Conflict,
    IntegrityFailure,
    InvalidDocument,
    InvalidManifest,
    KeyUnavailable,
    NotFound,
    UnsupportedQuery,
)
from aegisvault.manifest import canonical
from aegisvault.vault import events, heads, records, terms


def test_crud_revision_search_and_restart(vault, ctx, doc):
    assert vault.put(ctx, "customers", "a", doc) == {"id": "a", "revision": 1}
    assert vault.get(ctx, "customers", "a")["document"] == doc
    assert vault.search(ctx, "customers", "email", ["ADA@EXAMPLE.TEST"])["records"][0]["id"] == "a"
    with pytest.raises(Conflict):
        vault.put(ctx, "customers", "a", doc)
    with pytest.raises(Conflict):
        vault.put(ctx, "customers", "a", doc, expected_revision=99)
    updated = {**doc, "email": "new@example.test"}
    vault.put(ctx, "customers", "a", updated, expected_revision=1)
    restarted = Vault(vault.engine, vault.manifest, vault.provider)
    assert restarted.get(ctx, "customers", "a")["document"] == updated
    assert vault.search(ctx, "customers", "email", [doc["email"]])["records"] == []
    assert vault.get(ctx, "customers", "a")["revision"] == 2
    vault.delete(ctx, "customers", "a", expected_revision=2)
    with pytest.raises(NotFound):
        vault.get(ctx, "customers", "a")
    assert vault.search(ctx, "customers", "email", [updated["email"]])["records"] == []
    assert vault.verify_audit(ctx)["seq"] >= 6


def test_in_search_pagination_and_tenant_isolation(vault, ctx, doc):
    for rid in ["a", "b", "c"]:
        vault.put(ctx, "customers", rid, doc)
    other = replace(ctx, tenant="tenant-b")
    vault.put(other, "customers", "a", {**doc, "name": "Other tenant"})
    page = vault.search(ctx, "customers", "email", [doc["email"], "missing"], limit=2)
    assert [r["id"] for r in page["records"]] == ["a", "b"]
    assert page["next"] == "b"
    assert [
        r["id"]
        for r in vault.search(ctx, "customers", "email", [doc["email"]], after=page["next"])[
            "records"
        ]
    ] == ["c"]
    assert vault.get(other, "customers", "a")["document"]["name"] == "Other tenant"
    with pytest.raises(NotFound):
        vault.get(other, "customers", "b")
    with vault.engine.connect() as con:
        rows = con.execute(select(terms)).mappings().all()
    assert len({r["token"] for r in rows}) == 2


def test_policy_and_no_write_only_decryption(vault, ctx, doc):
    writer = replace(ctx, roles=frozenset({"writer"}))
    assert vault.put(writer, "customers", "a", doc) == {"id": "a", "revision": 1}
    for call in [
        lambda: vault.get(writer, "customers", "a"),
        lambda: vault.search(writer, "customers", "email", [doc["email"]]),
        lambda: vault.rotate(writer, "customers"),
        lambda: vault.get(replace(ctx, purpose="advertising"), "customers", "a"),
        lambda: vault.get(ctx, "unknown", "a"),
    ]:
        with pytest.raises(AccessDenied):
            call()


@pytest.mark.parametrize("column", ["payload", "wrapped_key", "revision", "generation", "id"])
def test_tamper_and_record_binding(vault, ctx, doc, column):
    vault.put(ctx, "customers", "a", doc)
    with vault.engine.begin() as con:
        row = (
            con.execute(select(records).where(records.c.project == vault.project)).mappings().one()
        )
        if column in {"payload", "wrapped_key"}:
            value = bytearray(row[column])
            value[-1] ^= 1
            value = bytes(value)
        else:
            value = {"revision": 8, "generation": "g2", "id": "b"}[column]
        con.execute(
            update(records).where(records.c.project == vault.project).values({column: value})
        )
    with pytest.raises(IntegrityFailure):
        vault.get(ctx, "customers", "b" if column == "id" else "a")


def test_cross_tenant_ciphertext_swap_refuses(vault, ctx, doc):
    other = replace(ctx, tenant="tenant-b")
    vault.put(ctx, "customers", "a", doc)
    vault.put(other, "customers", "a", doc)
    with vault.engine.begin() as con:
        row = (
            con.execute(
                select(records).where(
                    records.c.project == vault.project, records.c.tenant == ctx.tenant
                )
            )
            .mappings()
            .one()
        )
        con.execute(
            update(records)
            .where(records.c.project == vault.project, records.c.tenant == other.tenant)
            .values(payload=row["payload"], wrapped_key=row["wrapped_key"])
        )
    with pytest.raises(IntegrityFailure):
        vault.get(other, "customers", "a")


def test_database_and_driver_never_receive_document(vault, ctx, doc):
    observed = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        observed.append(repr(parameters))

    event.listen(vault.engine, "before_cursor_execute", capture)
    try:
        vault.put(ctx, "customers", "a", doc)
        vault.search(ctx, "customers", "email", [doc["email"]])
        assert vault.get(ctx, "customers", "a")["document"] == doc
    finally:
        event.remove(vault.engine, "before_cursor_execute", capture)
    assert any("AV1" in item or "create" in item for item in observed)  # collector is active
    for secret in [doc["email"], doc["name"], "country", "nested"]:
        assert secret not in "".join(observed)
    # Positive control: the same collector sees plaintext when deliberately sent.
    event.listen(vault.engine, "before_cursor_execute", capture)
    try:
        with vault.engine.connect() as con:
            from sqlalchemy import literal

            con.execute(select(literal(doc["email"])))
    finally:
        event.remove(vault.engine, "before_cursor_execute", capture)
    assert doc["email"] in "".join(observed)


@pytest.mark.parametrize("mode", ["rewrap", "reencrypt"])
def test_rotation_bounded_resume_old_key_removed(vault, ctx, doc, mode):
    for rid in ["a", "b", "c"]:
        vault.put(ctx, "customers", rid, doc)
    with vault.engine.connect() as con:
        old_payload = con.scalar(
            select(records.c.payload).where(records.c.project == vault.project, records.c.id == "a")
        )
    provider = replace(vault.provider, active_generation="g2")
    rotated = Vault(vault.engine, vault.manifest, provider)
    page = rotated.rotate(ctx, "customers", mode, limit=2)
    assert page == {"processed": 2, "next": "b"}
    # Reconstruct the host after the first committed batch to simulate an operator restart.
    restarted = Vault(vault.engine, vault.manifest, provider)
    assert restarted.rotate(ctx, "customers", mode, after=page["next"])["processed"] == 1
    only_new = replace(provider, wrapping={"g2": provider.wrapping["g2"]})
    without_old = Vault(vault.engine, vault.manifest, only_new)
    assert without_old.get(ctx, "customers", "a")["document"] == doc
    assert without_old.search(ctx, "customers", "email", [doc["email"]])["records"]
    with vault.engine.connect() as con:
        payload = con.scalar(
            select(records.c.payload).where(records.c.project == vault.project, records.c.id == "a")
        )
    assert (payload == old_payload) == (mode == "rewrap")


def test_rotation_failure_rolls_back_whole_batch(vault, ctx, doc):
    for rid in ["a", "b"]:
        vault.put(ctx, "customers", rid, doc)
    with vault.engine.begin() as con:
        con.execute(
            update(records)
            .where(records.c.project == vault.project, records.c.id == "b")
            .values(payload=b"broken")
        )
    rotated = Vault(vault.engine, vault.manifest, replace(vault.provider, active_generation="g2"))
    with pytest.raises(IntegrityFailure):
        rotated.rotate(ctx, "customers")
    with vault.engine.connect() as con:
        assert set(
            con.scalars(select(records.c.generation).where(records.c.project == vault.project))
        ) == {"g1"}


def test_missing_key_refuses_and_no_plaintext_fallback(vault, ctx, doc):
    vault.put(ctx, "customers", "a", doc)
    missing = LocalKeyring("g2", {"g2": b"x" * 32}, b"s" * 32, b"a" * 32)
    with pytest.raises(KeyUnavailable):
        Vault(vault.engine, vault.manifest, missing).get(ctx, "customers", "a")


def test_audit_tamper_tail_deletion_and_external_anchor(vault, ctx, doc):
    vault.put(ctx, "customers", "a", doc)
    checkpoint = vault.verify_audit(ctx)
    vault.get(ctx, "customers", "a")
    assert vault.verify_audit(ctx, checkpoint)["seq"] == 2
    # An attacker truncates both the tail and the database-held head.
    later = vault.verify_audit(ctx)
    with vault.engine.begin() as con:
        con.execute(delete(events).where(events.c.project == vault.project, events.c.seq == 2))
        con.execute(update(heads).where(heads.c.project == vault.project).values(**checkpoint))
    assert vault.verify_audit(ctx) == checkpoint  # explicit unanchored limitation
    with pytest.raises(IntegrityFailure):
        vault.verify_audit(ctx, later)
    with vault.engine.begin() as con:
        con.execute(update(events).where(events.c.project == vault.project).values(body="{}"))
    with pytest.raises(IntegrityFailure):
        vault.verify_audit(ctx)


def test_index_substitution_detected_but_omission_not_claimed(vault, ctx, doc):
    vault.put(ctx, "customers", "a", doc)
    vault.put(ctx, "customers", "b", {**doc, "email": "different@example.test"})
    with vault.engine.begin() as con:
        token = con.scalar(
            select(terms.c.token).where(terms.c.project == vault.project, terms.c.id == "a")
        )
        con.execute(
            update(terms)
            .where(terms.c.project == vault.project, terms.c.id == "b")
            .values(token=token)
        )
    with pytest.raises(IntegrityFailure):
        vault.search(ctx, "customers", "email", [doc["email"]])
    with vault.engine.begin() as con:
        con.execute(delete(terms).where(terms.c.project == vault.project))
    assert vault.search(ctx, "customers", "email", [doc["email"]])["records"] == []


def test_strict_manifest_invalid_types_and_unsupported_query(vault, ctx, doc):
    source = vault.manifest.model_dump()
    source["collections"]["customers"]["fields"]["email"]["accept_equality_leakage"] = False
    with pytest.raises(InvalidManifest):
        Manifest.load(json.dumps(source))
    for document in [{**doc, "extra": 1}, {**doc, "name": True}, {**doc, "email": None}]:
        with pytest.raises(InvalidDocument):
            vault.put(ctx, "customers", "a", document)
    with pytest.raises(UnsupportedQuery):
        vault.search(ctx, "customers", "name", ["Ada"])
    with pytest.raises(UnsupportedQuery):
        vault.search(ctx, "customers", "email", [])
    # A changed contract cannot be applied as a silent migration.
    changed = vault.manifest.model_dump()
    changed["collections"]["customers"]["purposes"].append("advertising")
    with pytest.raises(InvalidManifest):
        Vault(vault.engine, Manifest.load(json.dumps(changed)), vault.provider).initialize()


@given(
    st.binary(max_size=1024),
    st.text(alphabet=st.characters(exclude_categories=("Cs",)), max_size=60),
)
@settings(max_examples=40)
def test_aead_context_binding_property(payload, tenant):
    key = derive(b"r" * 32, "test")
    aad = canonical(["tenant", tenant])
    encrypted = seal(key, payload, aad)
    assert unseal(key, encrypted, aad) == payload
    with pytest.raises(IntegrityFailure):
        unseal(key, encrypted, canonical(["different", tenant]))


def test_aes_gcm_siv_rfc8452_vector():
    # RFC 8452 Appendix C.2, AES-256-GCM-SIV, zero-length plaintext and AAD.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

    key = bytes.fromhex("01" + "00" * 31)
    nonce = bytes.fromhex("03" + "00" * 11)
    assert AESGCMSIV(key).encrypt(nonce, b"", b"").hex() == "07f5f4169bbf55a8400cd47ea6fd400f"


def test_typed_roundtrip_json_equality_and_null(vault, ctx, doc):
    vault.put(ctx, "customers", "types", doc)
    found = vault.get(ctx, "customers", "types")["document"]
    assert type(found["active"]) is bool and type(found["visits"]) is int
    assert found["note"] is None and found["since"] == "2026-11-01"
    for field, value in [
        ("visits", True),
        ("active", 1),
        ("since", "2026-1-1"),
        ("profile", {"bad": float("nan")}),
    ]:
        with pytest.raises(InvalidDocument):
            vault.put(ctx, "customers", "bad", {**doc, field: value})
    vault.put(ctx, "jsondocs", "a", {"data": {"a": 1, "b": [2, None]}})
    vault.put(ctx, "jsondocs", "b", {"data": None})
    assert (
        vault.search(ctx, "jsondocs", "data", [{"b": [2, None], "a": 1}])["records"][0]["id"] == "a"
    )
    assert vault.search(ctx, "jsondocs", "data", [None])["records"][0]["id"] == "b"


def test_missing_audit_head_is_detected_when_history_remains(vault, ctx, doc):
    vault.put(ctx, "customers", "a", doc)
    with vault.engine.begin() as con:
        con.execute(delete(heads).where(heads.c.project == vault.project))
    with pytest.raises(IntegrityFailure):
        vault.verify_audit(ctx)


def test_manifest_duplicates_and_unbounded_names_refuse(vault):
    with pytest.raises(InvalidManifest):
        Manifest.load('{"version":1,"version":1,"project":"x","collections":{}}')
    source = vault.manifest.model_dump()
    source["collections"]["x" * 129] = source["collections"]["customers"]
    with pytest.raises(InvalidManifest):
        Manifest.load(json.dumps(source))


def test_audit_storage_failure_prevents_plaintext_return(vault, ctx, doc):
    vault.put(ctx, "customers", "a", doc)

    def fail_audit(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO av_events"):
            raise OSError("injected audit sink outage")

    event.listen(vault.engine, "before_cursor_execute", fail_audit)
    try:
        with pytest.raises(OSError):
            vault.get(ctx, "customers", "a")
        with pytest.raises(OSError):
            vault.put(ctx, "customers", "b", doc)
    finally:
        event.remove(vault.engine, "before_cursor_execute", fail_audit)
    assert vault.verify_audit(ctx)["seq"] == 1
    with pytest.raises(NotFound):
        vault.get(ctx, "customers", "b")
