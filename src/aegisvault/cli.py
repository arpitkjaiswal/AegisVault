"""Local bootstrap and operator commands. Keys never come from the database."""

import argparse
import base64
import hashlib
import json
import os
import secrets
import stat
import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError

from .crypto import LocalKeyring
from .errors import VaultError
from .manifest import Manifest
from .vault import Context, Vault

EXAMPLE = {
    "version": 1,
    "project": "aegis-demo",
    "collections": {
        "customers": {
            "fields": {
                "name": {"kind": "string"},
                "email": {
                    "kind": "string",
                    "search": "exact",
                    "normalize": "casefold",
                    "accept_equality_leakage": True,
                },
                "profile": {"kind": "json"},
            },
            "roles": {
                "read": ["reader", "admin"],
                "write": ["writer", "admin"],
                "search": ["reader", "admin"],
                "delete": ["admin"],
                "rotate": ["admin"],
            },
            "purposes": ["support", "maintenance"],
        }
    },
}


def private_json(path: Path):
    # Open once, reject symlinks and shared permissions on POSIX.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
            raise ValueError("invalid private file")
        if os.name == "posix" and (
            stat.S_IMODE(info.st_mode) & 0o077 or info.st_uid != os.getuid()
        ):
            raise ValueError("private files must be owned by this user with mode 0600")
        return json.load(stream)


def write_private(path: Path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


def load_vault(directory: Path):
    directory = directory.resolve()
    config = private_json(directory / "config.json")
    manifest = Manifest.load((directory / "manifest.json").read_bytes())
    provider = LocalKeyring.from_json(private_json(directory / "keys.json"))
    kwargs = (
        {"connect_args": {"check_same_thread": False}}
        if config["database_url"].startswith("sqlite:")
        else {}
    )
    engine = create_engine(config["database_url"], echo=False, hide_parameters=True, **kwargs)
    return Vault(engine, manifest, provider)


def main():
    parser = argparse.ArgumentParser(description="AegisVault research prototype")
    parser.add_argument("--state", type=Path, default=Path(".aegisvault"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser(
        "render", help="start a Render demo using stable environment secrets and Postgres"
    )
    init = sub.add_parser("init", help="create a new synthetic local demo; refuses overwrite")
    init.add_argument(
        "--database-url-env", help="environment variable containing a disposable DB URL"
    )
    serve = sub.add_parser("serve", help="serve the authenticated API and console")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    sub.add_parser("doctor")
    sub.add_parser("leakage")
    rotate = sub.add_parser("rotate")
    rotate.add_argument("collection")
    rotate.add_argument("--tenant", required=True)
    rotate.add_argument("--mode", choices=["rewrap", "reencrypt"], default="rewrap")
    rotate.add_argument("--after", default="")
    audit = sub.add_parser("audit")
    audit.add_argument("--tenant", required=True)
    audit.add_argument("--checkpoint", type=Path)
    args = parser.parse_args()
    if args.command == "render":
        from .render import main as render_main

        raise SystemExit(render_main())
    try:
        if args.command == "init":
            args.state.mkdir(mode=0o700, parents=True, exist_ok=False)
            b64 = lambda: base64.b64encode(secrets.token_bytes(32)).decode()  # noqa: E731
            token = secrets.token_urlsafe(32)
            database = (
                os.environ[args.database_url_env]
                if args.database_url_env
                else "sqlite:///" + str((args.state / "vault.db").resolve())
            )
            write_private(args.state / "config.json", {"database_url": database})
            write_private(
                args.state / "keys.json",
                {
                    "active_generation": "g1",
                    "wrapping": {"g1": b64()},
                    "search": b64(),
                    "audit": b64(),
                },
            )
            write_private(args.state / "manifest.json", EXAMPLE)
            write_private(
                args.state / "credentials.json",
                [
                    {
                        "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                        "tenant": "demo",
                        "actor": "local-operator",
                        "roles": ["admin"],
                        "purpose": "support",
                    }
                ],
            )
            write_private(args.state / "demo-token.json", {"token": token})
            vault = load_vault(args.state)
            vault.initialize()
            print(
                "Initialized synthetic demo. Token is in demo-token.json (private; never commit)."
            )
            return
        vault = load_vault(args.state)
        if args.command == "serve":
            import uvicorn

            from .api import create_app

            vault.doctor()
            uvicorn.run(
                create_app(vault, private_json(args.state / "credentials.json")),
                host=args.host,
                port=args.port,
                access_log=False,
            )
            return
        if args.command == "doctor":
            result = vault.doctor()
        elif args.command == "leakage":
            result = vault.manifest.leakage_report()
        else:
            ctx = Context(args.tenant, "local-operator", frozenset({"admin"}), "maintenance")
            if args.command == "rotate":
                result = vault.rotate(ctx, args.collection, args.mode, args.after)
            else:
                checkpoint = json.loads(args.checkpoint.read_text()) if args.checkpoint else None
                result = vault.verify_audit(ctx, checkpoint)
        print(json.dumps(result, indent=2))
    except VaultError as exc:
        print(json.dumps({"error": exc.code}), file=sys.stderr)
        raise SystemExit(1) from None
    except (OSError, ValueError, KeyError, SQLAlchemyError):
        print('{"error":"configuration_or_io_failure"}', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
