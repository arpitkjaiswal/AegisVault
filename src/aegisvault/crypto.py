"""Versioned envelope encryption using established cryptography primitives."""

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import IntegrityFailure, KeyUnavailable
from .manifest import canonical


def derive(root: bytes, *context: object) -> bytes:
    if type(root) is not bytes or len(root) != 32:
        raise KeyUnavailable()
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"aegisvault/v1", info=canonical(context)
    ).derive(root)


def seal(key: bytes, data: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCMSIV(key).encrypt(nonce, data, aad)


def unseal(key: bytes, data: bytes, aad: bytes) -> bytes:
    if len(data) < 28 or len(data) > 300 * 1024:
        raise IntegrityFailure()
    try:
        return AESGCMSIV(key).decrypt(data[:12], data[12:], aad)
    except (InvalidTag, ValueError):
        raise IntegrityFailure() from None


class KeyProvider(Protocol):
    """Host supplies independent 32-byte custody roots. Never persist them in PostgreSQL."""

    @property
    def active_generation(self) -> str: ...

    def wrapping_key(self, generation: str) -> bytes: ...
    def search_root(self) -> bytes: ...
    def audit_root(self) -> bytes: ...


@dataclass(frozen=True, repr=False)
class LocalKeyring:
    """Development provider; not a cloud KMS, HSM, erasure or production-custody claim."""

    active_generation: str
    wrapping: dict[str, bytes]
    search: bytes
    audit: bytes

    def __post_init__(self):
        if self.active_generation not in self.wrapping or any(
            type(k) is not bytes or len(k) != 32
            for k in [*self.wrapping.values(), self.search, self.audit]
        ):
            raise KeyUnavailable()

    def wrapping_key(self, generation: str) -> bytes:
        try:
            return self.wrapping[generation]
        except KeyError:
            raise KeyUnavailable() from None

    def search_root(self) -> bytes:
        return self.search

    def audit_root(self) -> bytes:
        return self.audit

    @classmethod
    def from_json(cls, value: dict):
        try:
            return cls(
                value["active_generation"],
                {g: base64.b64decode(k, validate=True) for g, k in value["wrapping"].items()},
                base64.b64decode(value["search"], validate=True),
                base64.b64decode(value["audit"], validate=True),
            )
        except (ValueError, TypeError, KeyError):
            raise KeyUnavailable() from None


def search_token(
    provider: KeyProvider, project: str, tenant: str, collection: str, field: str, normalized: bytes
) -> str:
    key = derive(provider.search_root(), "exact", project, tenant, collection, field)
    return hmac.new(key, normalized, hashlib.sha256).hexdigest()
