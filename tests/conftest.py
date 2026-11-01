import os
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from aegisvault import Context, LocalKeyring, Manifest, Vault
from aegisvault.cli import EXAMPLE
from aegisvault.vault import metadata


@pytest.fixture
def engine():
    # CI supplies a newly created disposable PostgreSQL service. No default external target.
    url = os.environ.get("AEGIS_TEST_DATABASE_URL")
    if url:
        if os.environ.get("AEGIS_DISPOSABLE_TEST_TARGET") != "yes":
            pytest.fail("external tests require an explicit disposable-target assertion")
        eng = create_engine(url, hide_parameters=True)
    else:
        eng = create_engine(
            "sqlite://",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
            hide_parameters=True,
        )
    yield eng
    eng.dispose()


@pytest.fixture
def provider():
    return LocalKeyring("g1", {"g1": b"w" * 32, "g2": b"x" * 32}, b"s" * 32, b"a" * 32)


@pytest.fixture
def manifest():
    import copy

    spec = copy.deepcopy(EXAMPLE)
    spec["project"] = "test-" + uuid.uuid4().hex
    spec["collections"]["customers"]["fields"].update(
        {
            "visits": {"kind": "integer"},
            "active": {"kind": "boolean"},
            "since": {"kind": "date"},
            "note": {"kind": "string", "nullable": True},
        }
    )
    spec["collections"]["jsondocs"] = {
        "fields": {
            "data": {
                "kind": "json",
                "search": "exact",
                "nullable": True,
                "accept_equality_leakage": True,
            }
        },
        "roles": spec["collections"]["customers"]["roles"],
        "purposes": ["support"],
    }
    return Manifest.model_validate(spec)


@pytest.fixture
def vault(engine, manifest, provider):
    v = Vault(engine, manifest, provider)
    v.initialize()
    yield v
    with engine.begin() as con:
        for table in reversed(metadata.sorted_tables):
            con.execute(table.delete().where(table.c.project == manifest.project))


@pytest.fixture
def ctx():
    return Context("tenant-a", "alice", frozenset({"admin"}), "support")


@pytest.fixture
def doc():
    return {
        "name": "Ada Lovelace",
        "email": "Ada@example.test",
        "profile": {"flags": [True, None, 3], "nested": {"country": "IN"}},
        "visits": 17,
        "active": True,
        "since": "2026-11-01",
        "note": None,
    }
