"""Restart-safe Render demo host. No key generation or state files at startup."""

import base64
import binascii
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError, SQLAlchemyError

from .api import create_app
from .cli import EXAMPLE
from .crypto import LocalKeyring
from .errors import VaultError
from .manifest import Manifest
from .vault import Vault


class RenderConfigError(ValueError):
    """Only fixed diagnostic text may be passed here; never raw environment values."""


def postgres_url(value: str) -> str:
    try:
        url = make_url(value)
        if url.drivername not in {"postgres", "postgresql", "postgresql+psycopg"}:
            raise ValueError()
        if not all([url.host, url.username, url.password, url.database]):
            raise ValueError()
        if url.query.get("sslmode", "require") not in {"require", "verify-ca", "verify-full"}:
            raise ValueError()
        return (
            url.set(drivername="postgresql+psycopg")
            .update_query_dict(
                {"sslmode": url.query.get("sslmode", "require"), "connect_timeout": "5"}
            )
            .render_as_string(hide_password=False)
        )
    except (ArgumentError, ValueError, TypeError):
        raise RenderConfigError(
            "DATABASE_URL must be a complete PostgreSQL URL using TLS"
        ) from None


def key_secret(env, name):
    try:
        key = base64.b64decode(env[name], validate=True)
        if len(key) != 32:
            raise ValueError()
        return key
    except (KeyError, ValueError, binascii.Error, TypeError):
        raise RenderConfigError(f"{name} must contain a base64-encoded 32-byte secret") from None


@dataclass(frozen=True, repr=False)
class Settings:
    database_url: str = field(repr=False)
    wrapping: bytes = field(repr=False)
    search: bytes = field(repr=False)
    audit: bytes = field(repr=False)
    token: str = field(repr=False)
    port: int = 10000

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        if env.get("AEGIS_ALLOW_SYNTHETIC_DEPLOY") != "yes":
            raise RenderConfigError("set AEGIS_ALLOW_SYNTHETIC_DEPLOY=yes for a synthetic demo")
        wrapping = key_secret(env, "AEGIS_WRAPPING_KEY")
        search = key_secret(env, "AEGIS_SEARCH_KEY")
        audit = key_secret(env, "AEGIS_AUDIT_KEY")
        if len({wrapping, search, audit}) != 3:
            raise RenderConfigError("the three key roots must be independent")
        token = env.get("AEGIS_API_TOKEN", "")
        # Render generates a random base64-encoded 256-bit value. Decode only to check entropy size;
        # the bearer token is the original string, including any padding.
        key_secret(env, "AEGIS_API_TOKEN")
        try:
            port = int(env.get("PORT", "10000"))
            if not 1 <= port <= 65535:
                raise ValueError()
        except (ValueError, TypeError):
            raise RenderConfigError("PORT must be an integer from 1 to 65535") from None
        return cls(postgres_url(env.get("DATABASE_URL", "")), wrapping, search, audit, token, port)


def build_app(settings: Settings):
    engine = create_engine(
        settings.database_url,
        echo=False,
        hide_parameters=True,
        pool_pre_ping=True,
        pool_size=3,
        max_overflow=2,
        pool_timeout=5,
    )
    # The fixed demo principal cannot ingest client-provided tenant claims.
    spec = {**EXAMPLE, "project": "aegis-render-demo"}
    manifest = Manifest.load(json.dumps(spec))
    provider = LocalKeyring("g1", {"g1": settings.wrapping}, settings.search, settings.audit)
    vault = Vault(engine, manifest, provider)
    try:
        vault.initialize()
        vault.doctor()
    except Exception:
        engine.dispose()
        raise
    app = create_app(
        vault,
        [
            {
                "token_sha256": hashlib.sha256(settings.token.encode()).hexdigest(),
                "tenant": "demo",
                "actor": "render-operator",
                "roles": ["admin"],
                "purpose": "support",
            }
        ],
    )
    app.state.vault = vault
    return app


def main():
    import uvicorn

    try:
        settings = Settings.from_env()
        app = build_app(settings)
    except RenderConfigError as exc:
        print(json.dumps({"error": "render_configuration", "remedy": str(exc)}), file=sys.stderr)
        return 1
    except (SQLAlchemyError, VaultError):
        print(
            '{"error":"render_startup_failed","remedy":"check database and manifest state"}',
            file=sys.stderr,
        )
        return 1
    try:
        # Render terminates HTTPS at its edge. No access/bind/body logs or untrusted forwarded IPs.
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=settings.port,
            access_log=False,
            proxy_headers=False,
            limit_concurrency=32,
            timeout_keep_alive=5,
        )
    finally:
        app.state.vault.engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
