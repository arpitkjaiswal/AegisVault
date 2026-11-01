import base64
import json
import os
import subprocess
import sys
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update
from sqlalchemy.exc import OperationalError

from aegisvault.api import create_app
from aegisvault.render import RenderConfigError, Settings, build_app, postgres_url
from aegisvault.vault import contracts


def test_render_database_url_normalization_and_tls():
    for scheme in ["postgres", "postgresql", "postgresql+psycopg"]:
        result = postgres_url(scheme + "://user:secret@host/database")
        assert result.startswith("postgresql+psycopg://")
        assert "sslmode=require" in result and "connect_timeout=5" in result
    assert "sslmode=verify-full" in postgres_url(
        "postgresql://user:secret@host/database?sslmode=verify-full"
    )
    for value in [
        "sqlite:///temp.db",
        "postgresql://host/database",
        "bad credential value",
        "postgresql://user:secret@host/db?sslmode=disable",
        "postgresql://user:secret@host/db?sslmode=prefer",
    ]:
        with pytest.raises(RenderConfigError) as exc:
            postgres_url(value)
        assert value not in str(exc.value)


def env_config():
    return {
        "DATABASE_URL": "postgres://user:secret@host/database",
        "AEGIS_ALLOW_SYNTHETIC_DEPLOY": "yes",
        **{
            name: base64.b64encode(bytes([n]) * 32).decode()
            for n, name in enumerate(
                ["AEGIS_WRAPPING_KEY", "AEGIS_SEARCH_KEY", "AEGIS_AUDIT_KEY", "AEGIS_API_TOKEN"], 1
            )
        },
    }


def test_stable_environment_keys_and_no_secret_in_repr():
    env = env_config()
    assert Settings.from_env(env) == Settings.from_env(env)
    assert Settings.from_env({**env, "PORT": "18000"}).port == 18000
    for value in env.values():
        assert value not in repr(Settings.from_env(env))
    for key in ["AEGIS_WRAPPING_KEY", "AEGIS_SEARCH_KEY", "AEGIS_AUDIT_KEY", "AEGIS_API_TOKEN"]:
        for invalid in ["", "bad key", base64.b64encode(b"short").decode()]:
            with pytest.raises(RenderConfigError):
                Settings.from_env({**env, key: invalid})
    with pytest.raises(RenderConfigError):
        Settings.from_env({**env, "AEGIS_AUDIT_KEY": env["AEGIS_SEARCH_KEY"]})
    for port in ["0", "65536", "not-a-port"]:
        with pytest.raises(RenderConfigError):
            Settings.from_env({**env, "PORT": port})


def test_cli_render_refuses_missing_secrets_before_creating_files(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AEGIS_", "DATABASE_URL"))}
    result = subprocess.run(
        [sys.executable, "-m", "aegisvault.cli", "--state", str(tmp_path / "state"), "render"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert json.loads(result.stderr)["error"] == "render_configuration"
    assert not (tmp_path / "state").exists()


def test_render_host_restarts_without_local_state(tmp_path, monkeypatch):
    # Host boot/data persistence boundary. TLS itself is exercised by the container smoke job.
    settings = replace(
        Settings.from_env(env_config()), database_url="sqlite:///" + str(tmp_path / "db")
    )
    monkeypatch.chdir(tmp_path)
    document = {"name": "Synthetic", "email": "restart@example.test", "profile": {"ok": True}}
    auth = {"Authorization": "Bearer " + settings.token}
    first = build_app(settings)
    with TestClient(first) as client:
        assert client.get("/readyz").status_code == 200
        assert (
            client.put(
                "/api/records/customers/a", headers=auth, json={"document": document}
            ).json()["revision"]
            == 1
        )
    first.state.vault.engine.dispose()
    assert set(p.name for p in tmp_path.iterdir()) == {"db"}
    second = build_app(settings)
    with TestClient(second) as client:
        assert client.get("/api/records/customers/a", headers=auth).json()["document"] == document
        assert client.post(
            "/api/search/customers",
            headers=auth,
            json={"field": "email", "values": ["RESTART@example.test"]},
        ).json()["records"]
        assert client.get("/api/audit/checkpoint", headers=auth).json()["seq"] == 3
    second.state.vault.engine.dispose()


def test_readiness_storage_failure_and_contract_drift(vault, engine):
    with TestClient(
        create_app(
            vault,
            [
                {
                    "token_sha256": "a" * 64,
                    "tenant": "test",
                    "actor": "test",
                    "roles": ["admin"],
                    "purpose": "support",
                }
            ],
        )
    ) as client:
        assert client.get("/readyz").status_code == 200
        with engine.begin() as con:
            con.execute(
                update(contracts)
                .where(contracts.c.project == vault.project)
                .values(fingerprint="0" * 64)
            )
        assert client.get("/readyz").status_code == 503
        assert client.get("/healthz").status_code == 200


def test_readiness_database_failure_is_redacted(vault, monkeypatch):
    from sqlalchemy import event

    def outage(conn, cursor, statement, parameters, context, executemany):
        raise OperationalError("secret-database-url", {"password": "secret-value"}, Exception())

    with TestClient(
        create_app(
            vault,
            [
                {
                    "token_sha256": "b" * 64,
                    "tenant": "test",
                    "actor": "test",
                    "roles": ["admin"],
                    "purpose": "support",
                }
            ],
        )
    ) as client:
        event.listen(vault.engine, "before_cursor_execute", outage)
        try:
            response = client.get("/readyz")
            assert response.status_code == 503
            assert "secret" not in response.text
        finally:
            event.remove(vault.engine, "before_cursor_execute", outage)
