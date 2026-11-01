"""Authenticated HTTP adapter. Tenant/roles come only from server-side credentials."""

import hashlib
import hmac
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError
from starlette.types import ASGIApp, Receive, Scope, Send

from .errors import AccessDenied, VaultError
from .vault import Context, Vault


class BodyLimit:
    """Bound actual received bytes, including chunked requests, before JSON parsing."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks, total = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            total += len(message.get("body", b""))
            if total > 512 * 1024:
                return await JSONResponse({"error": "request_too_large"}, 413)(scope, receive, send)
            chunks.append(message)
            if not message.get("more_body", False):
                break
        iterator = iter(chunks)

        async def replay():
            message = next(iterator, None)
            return message if message is not None else await receive()

        await self.app(scope, replay, send)


class WriteBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    document: dict
    expected_revision: int = Field(default=0, ge=0)


class SearchBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    field: str
    values: list = Field(min_length=1, max_length=100)
    limit: int = Field(default=50, ge=1, le=100)
    after: str = Field(default="", max_length=128)


class DeleteBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: int = Field(ge=1)


def create_app(vault: Vault, credentials: list[dict]) -> FastAPI:
    """credentials holds SHA-256 hashes of high-entropy tokens, never raw tokens."""
    principals = []
    for item in credentials:
        digest = item["token_sha256"]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid credential hash")
        principals.append(
            (
                digest,
                Context(item["tenant"], item["actor"], frozenset(item["roles"]), item["purpose"]),
            )
        )
    if not principals or len({p[0] for p in principals}) != len(principals):
        raise ValueError("credentials must be nonempty and unique")
    app = FastAPI(title="AegisVault", version="0.1.0", docs_url=None, redoc_url=None)
    app.add_middleware(BodyLimit)

    def context(request: Request) -> Context:
        value = request.headers.get("authorization", "")
        if not value.startswith("Bearer ") or len(value) > 512:
            raise AccessDenied()
        digest = hashlib.sha256(value[7:].encode()).hexdigest()
        found = None
        for expected, principal in principals:
            if hmac.compare_digest(expected, digest):
                found = principal
        if found is None:
            raise AccessDenied()
        return found

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    @app.exception_handler(VaultError)
    async def vault_error(request, exc):
        return JSONResponse({"error": exc.code}, exc.status)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        # Pydantic's default response can echo plaintext input. Deliberately omit it.
        return JSONResponse({"error": "invalid_request"}, 422)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request, exc):
        return JSONResponse({"error": "storage_unavailable"}, 503)

    @app.get("/healthz")
    def health():
        return {"status": "ok", "production_qualified": False}

    @app.get("/readyz")
    def ready():
        try:
            vault.check_ready()
        except (SQLAlchemyError, VaultError):
            return JSONResponse({"status": "unavailable"}, 503)
        return {"status": "ready", "production_qualified": False}

    @app.get("/api/manifest")
    def manifest(ctx: Annotated[Context, Depends(context)]):
        return {
            "manifest": vault.manifest.model_dump(),
            "leakage": vault.manifest.leakage_report(),
            "tenant": ctx.tenant,
            "actor": ctx.actor,
            "purpose": ctx.purpose,
        }

    @app.put("/api/records/{collection}/{rid}")
    def put(collection: str, rid: str, body: WriteBody, ctx: Annotated[Context, Depends(context)]):
        return vault.put(ctx, collection, rid, body.document, body.expected_revision)

    @app.get("/api/records/{collection}/{rid}")
    def get(collection: str, rid: str, ctx: Annotated[Context, Depends(context)]):
        return vault.get(ctx, collection, rid)

    @app.post("/api/search/{collection}")
    def search(collection: str, body: SearchBody, ctx: Annotated[Context, Depends(context)]):
        return vault.search(ctx, collection, body.field, body.values, body.limit, body.after)

    @app.delete("/api/records/{collection}/{rid}")
    def delete(
        collection: str, rid: str, body: DeleteBody, ctx: Annotated[Context, Depends(context)]
    ):
        vault.delete(ctx, collection, rid, body.expected_revision)
        return {"deleted": True}

    @app.get("/api/audit/checkpoint")
    def checkpoint(ctx: Annotated[Context, Depends(context)]):
        return vault.verify_audit(ctx)

    @app.get("/", include_in_schema=False)
    def console():
        return FileResponse(Path(__file__).parent / "static" / "index.html")

    @app.get("/console.js", include_in_schema=False)
    def script():
        return FileResponse(
            Path(__file__).parent / "static" / "console.js", media_type="application/javascript"
        )

    @app.get("/console.css", include_in_schema=False)
    def stylesheet():
        return FileResponse(Path(__file__).parent / "static" / "console.css", media_type="text/css")

    return app
