"""Stable public error codes; messages contain no user values or provider details."""


class VaultError(Exception):
    code = "vault_error"
    status = 400

    def __init__(self):
        super().__init__(self.code)


class InvalidManifest(VaultError):
    code = "invalid_manifest"


class InvalidDocument(VaultError):
    code = "invalid_document"


class AccessDenied(VaultError):
    code = "access_denied"
    status = 403


class NotFound(VaultError):
    code = "not_found"
    status = 404


class Conflict(VaultError):
    code = "revision_conflict"
    status = 409


class IntegrityFailure(VaultError):
    code = "integrity_failure"
    status = 409


class KeyUnavailable(VaultError):
    code = "key_unavailable"
    status = 503


class UnsupportedQuery(VaultError):
    code = "unsupported_query"
